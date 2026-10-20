import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real contained filesystem, codecs, mutation owner, reader, agreement adapter
/// and publication. Only device-local storage and native card/provider calls are
/// scripted; no hardware, user vault or installed helper is used.
struct V3RecoveryRegistrationServiceTests {
  private typealias Core = V3RecoveryRegistrationTests

  @Test func prepareExportsOneDurableCandidateWithoutActivatingOrAgreeing() throws {
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let pending = try #require(try f.pending())
    #expect(export.anchor == pending.exportedAnchor)
    #expect(export.operationID == pending.intent.operationID)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 0 && f.core.owner.unwraps == 0)
    #expect(f.core.owner.signatures == 1)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
    #expect(
      try f.service().resumeExport(observation: f.observation(), currentVaultKey: Core.oldKey)
        == export)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 1)
    #expect(f.provider.requests == 0)
  }

  @Test func finishPublishesEntriesFirstManifestLastAndInstallsTheExactKey() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let pending = try #require(try f.pending())
    f.card.anchor = export.anchor
    let observer = Observer { phase in
      if phase == .entriesVerified {
        #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
        #expect(
          !FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
        for entry in pending.stagedEntries {
          let published = try f.published(entry)
          #expect(published == entry.canonicalBytes)
        }
      }
      if phase == .manifestVerified {
        #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
        let published = try Data(contentsOf: f.manifestURL(pending.candidate.digest))
        #expect(published == pending.candidate.canonicalBytes)
      }
    }
    let keys = Keys()
    let result = try f.finish(observer: observer) { checkpoint, key in
      #expect(f.checkpoints.value == checkpoint.canonicalBytes)
      keys.append(key)
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(pending.candidate, vaultKey: key)
    }
    #expect(!result.alreadyActivated && !result.cleanupPending)
    #expect(result.checkpoint.envelopeDigest == pending.candidate.digest)
    #expect(f.provider.requests == 1 && f.core.owner.unwraps == 1)
    #expect(keys.count == 1 && f.ownership.value == nil)
    #expect(FileManager.default.fileExists(atPath: f.bundleURL(pending.intent.operationID).path))
  }

  @Test(arguments: [
    V3RecoveryRegistrationServicePhase.possessionVerified, .artifactsStaged,
    .entryPublished(index: 0), .entriesVerified, .manifestPublished, .manifestVerified,
    .checkpointAdvanced, .localSessionUpdated,
  ])
  func interruptionResumesExactCandidateWithoutRepeatingCommittedPublication(
    phase: V3RecoveryRegistrationServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let pending = try #require(try f.pending())
    let bundle = try Data(contentsOf: f.bundleURL(pending.intent.operationID))
    f.card.anchor = export.anchor
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish(observer: Observer { if $0 == phase { throw Core.FixtureError.cancelled } })
    }
    #expect(try Data(contentsOf: f.bundleURL(pending.intent.operationID)) == bundle)
    #expect(f.ownership.value != nil)
    let committed = phase == .checkpointAdvanced || phase == .localSessionUpdated
    let result = try f.finish()
    #expect(result.alreadyActivated == committed)
    #expect(result.checkpoint.envelopeDigest == pending.candidate.digest)
    #expect(f.provider.requests == (committed ? 1 : 2))
    #expect(f.core.owner.signatures == 1)
    #expect(f.ownership.value == nil)
  }

  @Test(arguments: [V3RecoveryRegistrationServicePhase.candidatePrepared, .exportPrepared])
  func preparationInterruptionCannotReturnAnExportOrRegeneratePendingState(
    phase: V3RecoveryRegistrationServicePhase
  ) throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Core.FixtureError.cancelled) {
      try f.prepare(observer: Observer { if $0 == phase { throw Core.FixtureError.cancelled } })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 0)
    if phase == .exportPrepared {
      let pending = try #require(try f.pending())
      let result = try f.service().resumeExport(
        observation: f.observation(), currentVaultKey: Core.oldKey)
      #expect(result.anchor == pending.exportedAnchor)
      #expect(f.core.owner.signatures == 1)
    } else {
      #expect(f.ownership.value == nil)
    }
  }

  @Test func lostReplyAfterOwnershipCleanupIsRecognizedWithoutAnotherAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish(
        observer: Observer {
          if $0 == .ownershipCleared { throw Core.FixtureError.cancelled }
        })
    }
    #expect(f.ownership.value == nil && f.provider.requests == 1)
    let result = try f.finish()
    #expect(result.alreadyActivated && !result.cleanupPending)
    #expect(f.provider.requests == 1 && f.core.owner.signatures == 1)
    f.card.anchor = nil
    let unwraps = f.core.owner.unwraps
    #expect(throws: V3RecoveryRegistrationServiceError.noPendingRegistration) { try f.finish() }
    #expect(f.core.owner.unwraps == unwraps && f.provider.requests == 1)
  }

  @Test func checkpointAdvanceFailureRetainsPublishedCandidateAndRequiresFreshPossession() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    f.checkpoints.rejectAdvance = true
    #expect(throws: Core.FixtureError.cancelled) { try f.finish() }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
    #expect(f.ownership.value != nil)
    f.checkpoints.rejectAdvance = false
    #expect(try !f.finish().alreadyActivated)
    #expect(f.provider.requests == 2 && f.core.owner.signatures == 1)
  }

  @Test func failedSessionInstallReconcilesCommittedCheckpointWithoutHardware() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish { _, _ in throw Core.FixtureError.cancelled }
    }
    #expect(f.checkpoints.value != f.core.checkpoint.canonicalBytes)
    #expect(f.ownership.value != nil)
    let result = try f.finish()
    #expect(result.alreadyActivated && result.checkpoint.envelopeDigest == pending.candidate.digest)
    #expect(f.provider.requests == 1 && f.core.owner.unwraps == 2)
    #expect(f.ownership.value == nil)
  }

  @Test func cleanupFailureIsReportedAsCommittedNotAsUnpublished() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    f.ownership.rejectClear = true
    let result = try f.finish()
    #expect(!result.alreadyActivated && result.cleanupPending)
    #expect(f.ownership.value != nil)
    f.ownership.rejectClear = false
    let resumed = try f.finish()
    #expect(resumed.alreadyActivated && !resumed.cleanupPending)
    #expect(f.provider.requests == 1)
  }

  @Test func missingMismatchedOrWeakerTokenIsRefusedBeforeLocalAndHardwareOperations() throws {
    guard #available(macOS 26.0, *) else { return }
    for variant in 0..<3 {
      let f = try Fixture()
      defer { f.remove() }
      let export = try f.prepare()
      if variant == 1 { f.card.anchor = Data("unrecognized fixture".utf8) }
      if variant == 2 {
        f.card.anchor = export.anchor
        f.card.pinPolicy = 2
      }
      #expect(throws: (any Error).self) { try f.finish() }
      #expect(f.provider.requests == 0 && f.core.owner.unwraps == 0)
      #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes && f.ownership.value != nil)
    }
  }

  @Test func providerCancellationNeverRetriesOrPublishes() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    f.provider.cancel = true
    #expect(throws: PIVRecoveryAgreementError.cancelled) { try f.finish() }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
  }

  @Test func priorCancellationAndDeadlineStopBeforeLocalApproval() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let cancellation = PIVRecoveryCancellation()
    cancellation.cancel()
    #expect(throws: PIVRecoveryAgreementError.cancelled) {
      try f.service().finish(
        observation: f.observation(), currentVaultKey: Core.oldKey, cancellation: cancellation)
    }
    #expect(throws: PIVRecoveryAgreementError.deadlineExceeded) {
      try f.service().finish(
        observation: f.observation(), currentVaultKey: Core.oldKey, deadline: .now() - .seconds(1))
    }
    #expect(f.core.owner.unwraps == 0 && f.provider.requests == 0)
  }

  @Test func changedSourceAfterLocalApprovalIsDetectedBeforeAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let oldEntry = try #require(f.core.entries.values.first)
    f.core.owner.onUnwrap = {
      try Data("changed fixture bytes".utf8).write(to: f.entryURL(oldEntry))
    }
    #expect(throws: (any Error).self) { try f.finish() }
    #expect(f.core.owner.unwraps == 1 && f.provider.requests == 0)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func tokenChangeDuringAgreementDiscardsTheResultWithoutPublication() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    f.provider.onAgree = { f.card.anchor = Data("changed fixture anchor".utf8) }
    #expect(throws: PIVRecoveryTokenError.tokenChanged) { try f.finish() }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func changedCheckpointOrCompetingStateIsNeverSilentlyRebased() throws {
    guard #available(macOS 26.0, *) else { return }
    for checkpointOnly in [true, false] {
      let f = try Fixture()
      defer { f.remove() }
      f.card.anchor = try f.prepare().anchor
      let other = try f.core.prepare()
      try f.publish(other.candidate.canonicalBytes, digest: other.candidate.digest)
      if checkpointOnly {
        f.checkpoints.value = try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: other.candidate.digest
        ).canonicalBytes
      }
      #expect(throws: (any Error).self) { try f.finish() }
      #expect(f.core.owner.unwraps == 0 && f.provider.requests == 0)
      #expect(f.ownership.value != nil)
    }
  }

  @Test func checkpointChangeAfterPossessionCannotAdvanceThePreparedCandidate() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let changed = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 5, count: 32))
    #expect(throws: V3RecoveryRegistrationServiceError.checkpointChanged) {
      try f.finish(
        observer: Observer {
          if $0 == .possessionVerified { f.checkpoints.value = changed.canonicalBytes }
        })
    }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(f.checkpoints.value == changed.canonicalBytes)
  }

  @Test func corruptPublishedEntryCannotBecomeTheCurrentManifest() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    let entry = try #require(pending.stagedEntries.first)
    #expect(throws: V3RecoveryRegistrationServiceError.invalidPublishedObject) {
      try f.finish(
        observer: Observer {
          if $0 == .entriesVerified {
            try Data("changed fixture".utf8).write(to: f.entryURL(entry))
          }
        })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.ownership.value != nil)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
  }

  @Test func competingManifestAfterPublicationCannotAdvanceLocalTrust() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let other = try f.core.prepare()
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try f.finish(
        observer: Observer {
          if $0 == .manifestPublished {
            try f.publish(other.candidate.canonicalBytes, digest: other.candidate.digest)
          }
        })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
  }

  @Test func prepareRefusesWrongKeyOccupiedObjectAndProjectedLimits() throws {
    for variant in 0..<3 {
      let f = try Fixture()
      defer { f.remove() }
      if variant == 1 { f.card.anchor = Data("occupied fixture".utf8) }
      let service = f.service(limits: variant == 2 ? Core.Fixture.limits(entries: 2) : .standard)
      #expect(throws: (any Error).self) {
        try service.prepare(
          observation: f.observation(), currentVaultKey: variant == 0 ? Core.nextKey : Core.oldKey)
      }
      #expect(f.ownership.value == nil && f.provider.requests == 0)
      #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    }
  }

  @Test func serviceUsesTheSharedMutationOwnerAndStablePreparationID() throws {
    let f = try Fixture()
    defer { f.remove() }
    let fixed = VaultTransactionOperationID()
    let owner = VaultTransactionMutationOwner(makeOperationID: { fixed })
    let result = try f.service(mutationOwner: owner).prepare(
      observation: f.observation(), currentVaultKey: Core.oldKey)
    #expect(result.operationID == fixed)
    #expect(try f.pending()?.intent.operationID == fixed)
  }

  private struct Observer: V3RecoveryRegistrationServicePhaseObserving {
    let action: @Sendable (V3RecoveryRegistrationServicePhase) throws -> Void
    init(_ action: @escaping @Sendable (V3RecoveryRegistrationServicePhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3RecoveryRegistrationServicePhase) throws { try action(phase) }
  }

  private final class Keys: @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [Data] = []
    var count: Int { lock.withLock { keys.count } }
    func append(_ key: Data) { lock.withLock { keys.append(key) } }
  }

  private final class Checkpoints: V3ManifestCheckpointStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    var rejectAdvance = false
    var value: Data? {
      get { lock.withLock { data } }
      set { lock.withLock { data = newValue } }
    }
    init(_ data: Data) { self.data = data }
    func loadCheckpoint(vaultID _: String) throws -> Data? { value }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID _: String) throws
    {
      try lock.withLock {
        if rejectAdvance { throw Core.FixtureError.cancelled }
        guard data == expectedCheckpoint else { throw V3ManifestCheckpointStoreError.conflict }
        data = checkpoint
      }
    }
  }

  private final class Ownership: V3ImmutableTransactionRecoveryAnchorStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    var rejectClear = false
    var value: Data? { lock.withLock { data } }
    func loadRecoveryAnchor(vaultID _: String) throws -> Data? { value }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID _: String) throws {
      try lock.withLock {
        if rejectClear && anchor == nil { throw Core.FixtureError.cancelled }
        guard data == expectedAnchor else {
          throw V3ImmutableTransactionRecoveryAnchorError.conflict
        }
        data = anchor
      }
    }
  }

  private struct Fixture: Sendable {
    let core: Core.Fixture
    let root: URL
    let store: V3FilesystemTransactionArtifactStore
    let checkpoints: Checkpoints
    let ownership = Ownership()
    let mutationOwner = VaultTransactionMutationOwner()
    let card: Card
    let reader: PIVRecoveryTokenReader
    let provider: Provider
    let agreement: PIVRecoveryAgreement
    init() throws {
      core = try Core.Fixture()
      root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true)
      try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
      store = V3FilesystemTransactionArtifactStore(
        rootHandle: try VaultRootDirectoryHandle(opening: root))
      checkpoints = Checkpoints(core.checkpoint.canonicalBytes)
      card = try Card(publicKey: core.credential.publicKey)
      reader = PIVRecoveryTokenReader(
        inventory: Inventory(card: card), gate: PIVTokenOperationGate())
      provider = Provider(token: core.token, card: card)
      agreement = PIVRecoveryAgreement(reader: reader, provider: provider)
      let operation = VaultTransactionOperationID()
      for entry in core.entries.values {
        let digest = Data(SHA256.hash(data: entry.canonicalBytes))
        try store.stageEntry(
          entry.canonicalBytes, entryID: entry.context.entryID, digest: digest,
          operationID: operation)
        try store.publishStagedEntry(
          entry.canonicalBytes, entryID: entry.context.entryID, digest: digest,
          operationID: operation)
      }
      try publish(core.parent.canonicalBytes, digest: core.parent.digest)
    }
    func service(
      observer: (any V3RecoveryRegistrationServicePhaseObserving)? = nil,
      limits: V3ManifestRepositoryLimits = .standard,
      mutationOwner: (any VaultTransactionMutationOwning)? = nil
    ) -> V3RecoveryRegistrationService {
      let observer = observer ?? Observer { _ in }
      return V3RecoveryRegistrationService(
        vaultID: Core.vaultID, identity: core.owner,
        mutationOwner: mutationOwner ?? self.mutationOwner,
        objectStore: store, checkpointStore: checkpoints, registrationOwnershipStore: ownership,
        reader: reader, agreement: agreement, limits: limits, observer: observer)
    }
    func observation() throws -> PIVRecoveryTokenObservation {
      try reader.read(#require(try reader.candidates().first))
    }
    func prepare(observer: (any V3RecoveryRegistrationServicePhaseObserving)? = nil) throws
      -> V3RecoveryRegistrationExport
    {
      try service(observer: observer).prepare(
        observation: observation(), currentVaultKey: Core.oldKey)
    }
    @available(macOS 26.0, *)
    func finish(
      observer: (any V3RecoveryRegistrationServicePhaseObserving)? = nil,
      install: (V3ManifestCheckpoint, Data) throws -> Void = { _, _ in }
    ) throws -> V3RecoveryRegistrationCommit {
      try service(observer: observer).finish(
        observation: observation(), currentVaultKey: Core.oldKey, afterCheckpointAdvance: install)
    }
    func pending() throws -> V3RecoveryRegistrationPreparation? {
      try V3RecoveryRegistrationJournal(bundleStore: store, ownershipStore: ownership).loadPending(
        vaultID: Core.vaultID)
    }
    func publish(_ bytes: Data, digest: Data) throws {
      let operation = VaultTransactionOperationID()
      try store.stageManifest(bytes, digest: digest, operationID: operation)
      try store.publishStagedManifest(bytes, digest: digest, operationID: operation)
    }
    func manifestURL(_ digest: Data) -> URL {
      root.appendingPathComponent("manifests/\(v3LowercaseHex(digest)).json")
    }
    func entryURL(_ entry: V3EncryptedEntry) -> URL {
      root.appendingPathComponent(
        "entries/\(entry.context.entryID)/\(v3LowercaseHex(Data(SHA256.hash(data: entry.canonicalBytes)))).json"
      )
    }
    func bundleURL(_ operation: VaultTransactionOperationID) -> URL {
      root.appendingPathComponent(".recovery-registrations/\(operation)/preparation.json")
    }
    func published(_ entry: V3EncryptedEntry) throws -> Data {
      try Data(contentsOf: entryURL(entry))
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
  }

  private struct Inventory: PIVRecoveryTokenInventoryProviding {
    let card: Card
    func connections(maximumCount _: Int) throws -> [any PIVRecoveryTokenConnection] { [card] }
  }

  private final class Card: PIVRecoveryTokenConnection, @unchecked Sendable {
    let tokenID = "registration-software-token"
    let readerSlotName = "registration-software-reader"
    let isValid = true
    private let lock = NSLock()
    private let certificate: Data
    private let publicKey: Data
    private var record: Data?
    private var pin: UInt8 = 3
    private var active = false
    var inSession: Bool { lock.withLock { active } }
    var anchor: Data? {
      get { lock.withLock { record } }
      set { lock.withLock { record = newValue } }
    }
    var pinPolicy: UInt8 {
      get { lock.withLock { pin } }
      set { lock.withLock { pin = newValue } }
    }
    init(publicKey: Data) throws {
      self.publicKey = publicKey
      // A public container fixture only. Signature/issuer trust is not claimed.
      var der = PIVRecoveryAgreementTests.certificate
      let point = try PIVRecoveryTokenReader.certificatePublicKey(der)
      let range = try #require(der.range(of: point))
      der.replaceSubrange(range, with: publicKey)
      certificate = der
      #expect(try PIVRecoveryTokenReader.certificatePublicKey(der) == publicKey)
    }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      lock.withLock { active = true }
      defer {
        lock.withLock { active = false }
        withExtendedLifetime(lease) {}
      }
      return try consume { command in
        switch command {
        case .selectApplication: return .init(data: nil, status: 0x9000)
        case .keyManagementCertificate:
          return .init(
            data: Self.tlv(0x53, Self.tlv(0x70, self.certificate) + Self.tlv(0x71, Data([0]))),
            status: 0x9000)
        case .keyManagementMetadata:
          return .init(
            data: Self.tlv(1, Data([0x11])) + Self.tlv(2, Data([self.pinPolicy, 2]))
              + Self.tlv(3, Data([1])) + Self.tlv(4, Self.tlv(0x86, self.publicKey)), status: 0x9000
          )
        case .recoveryAnchor:
          guard let anchor = self.anchor else { return .init(data: nil, status: 0x6a82) }
          return .init(data: Self.tlv(0x53, anchor), status: 0x9000)
        }
      }
    }
    private static func tlv(_ tag: UInt8, _ value: Data) -> Data {
      let size =
        value.count < 128
        ? [UInt8(value.count)] : [0x82, UInt8(value.count >> 8), UInt8(value.count & 255)]
      return Data([tag] + size) + value
    }
  }

  private final class Provider: PIVRecoveryAgreementProviding, @unchecked Sendable {
    let token: P256.KeyAgreement.PrivateKey
    let card: Card
    private let lock = NSLock()
    private var count = 0
    var requests: Int { lock.withLock { count } }
    var cancel = false
    var onAgree: @Sendable () throws -> Void = {}
    init(token: P256.KeyAgreement.PrivateKey, card: Card) {
      self.token = token
      self.card = card
    }
    func makeSession() -> any PIVRecoveryAgreementSession { Session(provider: self) }
    func agree(_ peer: Data) throws -> Data {
      lock.withLock { count += 1 }
      #expect(!card.inSession)
      try onAgree()
      if cancel { throw PIVRecoveryAgreementError.cancelled }
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
  }

  private struct Key: PIVRecoveryAgreementKey {
    let tokenID = "registration-software-token"
    let publicKey: Data
    let isP256PrivateKey = true
    let supportsStandardECDH = true
  }

  private struct Session: PIVRecoveryAgreementSession {
    let provider: Provider
    func keys(tokenID _: String, publicKey _: Data) throws -> [any PIVRecoveryAgreementKey] {
      [Key(publicKey: provider.token.publicKey.x963Representation)]
    }
    func agree(key _: any PIVRecoveryAgreementKey, peer: Data) throws -> Data {
      try provider.agree(peer)
    }
    func invalidate() {}
  }
}
