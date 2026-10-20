import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real session binding/invalidation, immutable filesystem/crypto, builders,
/// publishers, catch-up and resolution. Only local persistence races are scripted.
struct V3RecoveryVaultMutationServiceTests {
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = Publication.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private let branches = V3RecoveryManifestReconciliationTests()
  private static let addedID = "018f4d38-7d5a-7b20-b0f1-97d6e96c85a1"
  private static let copiedID = "018f4d38-7d5a-7b20-b0f1-97d6e96c85a2"

  @Test func ordinaryInterfacePreservesCoverageAndEntrySemanticsAcrossTheWholeEditChain() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let owner = VaultTransactionMutationOwner()
    let service: any VaultMutationServicing = service(f, session: session)
    try owner.perform(.addEntry) { c in
      try service.add(name: "temporary", secret: "new", type: .secret, operationID: c.operationID)
    }
    try owner.perform(.editEntry) { c in
      try service.edit(
        name: "fixture/secret", secret: "updated\n密碼", type: .secret, operationID: c.operationID)
    }
    let changed = try current(f)
    let source = try #require(
      changed.envelope.body.fields.entries.first { $0.name == "fixture/secret" })
    try owner.perform(.copyEntry) { c in
      try service.copy(
        source: "fixture/secret", destination: "copied/account", overwrite: false,
        operationID: c.operationID)
    }
    try owner.perform(.moveEntry) { c in
      try service.move(
        source: "fixture/totp", destination: "renamed/otp", overwrite: false,
        operationID: c.operationID)
    }
    try owner.perform(.removeEntry) { c in
      try service.remove(name: "temporary", operationID: c.operationID)
    }
    let last = try current(f)
    let values = try plaintexts(f, current: last)
    #expect(
      values == [
        "fixture/secret": "updated\n密碼", "copied/account": "updated\n密碼",
        "renamed/otp": "JBSWY3DPEHPK3PXP",
      ])
    let records = last.envelope.body.fields.entries
    #expect(records.first { $0.name == "fixture/secret" }?.entryID == source.entryID)
    #expect(records.first { $0.name == "copied/account" }?.entryID != source.entryID)
    #expect(records.first { $0.name == "copied/account" }?.revision == 1)
    #expect(records.first { $0.name == "renamed/otp" }?.revision == 3)
    #expect(last.envelope.body.recovery == f.parent.body.recovery)
    #expect(last.envelope.body.epochSigningKey == f.parent.body.epochSigningKey)
    #expect(last.envelope.body.transitionProof == f.parent.body.transitionProof)
    #expect(f.ownership.value == nil && session.hasResidentKey)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func totpNormalizationAndOverwriteUseTheSharedEntryPolicy() throws {
    let f = try Fixture()
    defer { f.remove() }
    let s = service(f, session: try session(f))
    try s.edit(
      name: "fixture/totp", secret: "jbsw y3dp ehpk 3pxp", type: .totp, operationID: .init())
    #expect(try plaintexts(f, current: current(f))["fixture/totp"] == "JBSWY3DPEHPK3PXP")
    #expect(throws: (any Error).self) {
      try s.copy(
        source: "fixture/secret", destination: "fixture/totp", overwrite: false,
        operationID: .init())
    }
    try s.copy(
      source: "fixture/secret", destination: "fixture/totp", overwrite: true, operationID: .init())
    let last = try current(f)
    #expect(last.envelope.body.fields.entries.count == 2)
    #expect(last.envelope.body.fields.entries.first { $0.name == "fixture/totp" }?.type == .secret)
    let values = try plaintexts(f, current: last)
    #expect(values["fixture/totp"] == values["fixture/secret"])
  }

  @Test func ordinaryWriteCatchesUpBeforePlanningAgainstNewerEntryContents() throws {
    let f = try Fixture()
    defer { f.remove() }
    let newer = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "remote")])
    let s = service(f, session: try session(f))
    try s.copy(
      source: "fixture/secret", destination: "copied/account", overwrite: false,
      operationID: .init())
    let last = try current(f)
    #expect(last.envelope.parents == [newer.envelope.digest])
    #expect(try plaintexts(f, current: last)["copied/account"] == "remote")
    #expect(last.envelope.body.recovery == f.parent.body.recovery)
  }

  @Test func independentChangesMergeBeforeTheRequestedSaveWithSeparateOperationIdentity() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "remote")])
    let b = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let trace = Traces()
    let store = Store(f.store, onIntent: { id, data in try trace.append(id, data) })
    let s = service(f, session: try session(f), store: store)
    let operation = VaultTransactionOperationID()
    try s.add(name: "new/account", secret: "new", type: .secret, operationID: operation)
    let last = try current(f)
    let merge = try V3RecoveryManifestCodec().parseEnvelope(
      Data(contentsOf: f.manifestURL(try #require(last.envelope.parents.first))))
    #expect(Set(merge.parents) == [a.envelope.digest, b.envelope.digest])
    #expect(
      trace.values.count == 2 && trace.values[0].0 != operation && trace.values[1].0 == operation)
    #expect(trace.values[0].1.kind == .mergeHeads && trace.values[1].1.kind == .addEntry)
    #expect(try plaintexts(f, current: last) == ["fixture/secret": "remote", "new/account": "new"])
    #expect(f.ownership.value == nil && f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func explicitConflictChoicesUseFreshMetadataAndContinueOrdinarySaving() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, _) = try conflictingBranches(f)
    let s = service(f, session: try session(f))
    #expect(throws: VaultUXServiceError.contentConflict) {
      try s.edit(
        name: "fixture/secret", secret: "must not publish", type: .secret, operationID: .init())
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
    let choices = try resolutions(s, selected: a.envelope.digest)
    try s.resolve(choices, operationID: .init())
    let resolved = try current(f)
    #expect(resolved.envelope.parents.count == 2)
    #expect(try plaintexts(f, current: resolved)["fixture/secret"] == "selected")
    #expect(throws: VaultUXServiceError.expectedHeadsChanged) {
      try s.resolve(choices, operationID: .init())
    }
    try s.edit(name: "fixture/secret", secret: "following", type: .secret, operationID: .init())
    #expect(try plaintexts(f, current: current(f))["fixture/secret"] == "following")
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func staleConflictChoicesCannotApplyToANewVisibleHeadSet() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try conflictingBranches(f)
    let s = service(f, session: try session(f))
    let choices = try resolutions(s, selected: a.envelope.digest)
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "later")], from: b,
      entries: branches.entryMap(f, envelope: b.envelope))
    #expect(throws: AppError.self) {
      try s.resolve(choices, operationID: .init())
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func lateSiblingIsResolvedFromTheAdvancedCheckpoint(automatic: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "selected")])
    _ = try branches.publishBranch(
      f,
      requests: automatic
        ? [.remove(name: "fixture/totp")]
        : [.edit(name: "fixture/secret", type: .secret, plaintext: "other")])
    f.checkpoints.value = a.checkpoint.canonicalBytes
    let s = service(f, session: try session(f))
    if !automatic {
      try s.resolve(resolutions(s, selected: a.envelope.digest), operationID: .init())
    }
    try s.add(name: "new/account", secret: "new", type: .secret, operationID: .init())
    let last = try current(f)
    #expect(try plaintexts(f, current: last)["fixture/secret"] == "selected")
    #expect(last.envelope.body.recovery == a.envelope.body.recovery)
    #expect(f.ownership.value == nil)
  }

  @Test(arguments: 0..<3)
  func ordinaryPinnedInterruptionResumesBeforeTheRequestedChange(phase: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.edit(name: "fixture/secret", type: .secret, plaintext: "resumed"))
    let phases: [V3ImmutableTransactionPhase] = [
      .manifestStaged, .manifestPublished, .checkpointAdvanced,
    ]
    #expect(throws: Publication.Stop.interrupted) {
      try f.publisher(observer: Interrupt(phase: phases[phase])).publish(
        candidate, vaultKey: Core.nextKey)
    }
    let s = service(f, session: try session(f))
    try s.copy(
      source: "fixture/secret", destination: "copied/account", overwrite: false,
      operationID: .init())
    let last = try current(f)
    #expect(last.envelope.parents == [candidate.envelope.digest])
    #expect(try plaintexts(f, current: last)["copied/account"] == "resumed")
    #expect(f.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func interruptedServiceMergeRoutesTheExactPinnedIntentBeforeAFollowingSave(automatic: Bool) throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let (a, _) = try conflictingBranches(f, automatic: automatic)
    let store = Store(f.store, afterManifest: { _, _ in throw Publication.Stop.interrupted })
    let session = try session(f)
    let s = service(f, session: session, store: store)
    #expect(throws: Publication.Stop.interrupted) {
      if automatic {
        try s.add(name: "new/account", secret: "new", type: .secret, operationID: .init())
      } else {
        try s.resolve(resolutions(s, selected: a.envelope.digest), operationID: .init())
      }
    }
    let pin = try V3ImmutableTransactionRecoveryAnchor(canonicalBytes: #require(f.ownership.value))
    guard
      case .available(let data) = try f.store.readRecoveryIntent(
        operationID: pin.operationID,
        maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes)
    else { throw Publication.Stop.interrupted }
    let intent = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: data)
    #expect(intent.recoveryMergeResolutions != nil)
    let next = service(f, session: session)
    try next.edit(name: "fixture/secret", secret: "following", type: .secret, operationID: .init())
    let last = try current(f)
    #expect(last.envelope.parents == [intent.candidateManifestDigest])
    #expect(try plaintexts(f, current: last)["fixture/secret"] == "following")
    #expect(f.ownership.value == nil)
  }

  @Test(arguments: 0..<3)
  func unavailableOrMalformedPinnedIntentCannotTriggerGuessedRecovery(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Publication.Stop.interrupted) {
      try f.publisher(observer: Interrupt(phase: .manifestStaged)).publish(
        candidate, vaultKey: Core.nextKey)
    }
    let path = f.root.appendingPathComponent(".transactions/\(f.operationID)/intent.json")
    let original = try #require(f.ownership.value)
    if variant == 0 {
      try FileManager.default.removeItem(at: path)
    } else if variant == 1 {
      try Data("changed intent fixture".utf8).write(to: path)
    } else {
      f.ownership.value = Data("malformed local ownership".utf8)
    }
    let s = service(f, session: try session(f))
    #expect(throws: (any Error).self) { try s.remove(name: "fixture/secret", operationID: .init()) }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.ownership.value == (variant == 2 ? Data("malformed local ownership".utf8) : original))
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
  }

  @Test func preparedReservationWithNoIntentCanBeAbandonedButUnownedIntentsAreIgnored() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Publication.Stop.interrupted) {
      try f.publisher(observer: Interrupt(phase: .recoveryAnchorPrepared)).publish(
        candidate, vaultKey: Core.nextKey)
    }
    try service(f, session: session(f)).edit(
      name: "fixture/secret", secret: "saved", type: .secret, operationID: .init())
    #expect(f.ownership.value == nil)
    let current = try current(f)
    let operation = VaultTransactionOperationID()
    let orphan = try V3ImmutableTransactionRecoveryIntent(
      operationID: operation, kind: .removeEntry, vaultID: Core.vaultID,
      expectedCheckpoint: f.checkpoint, expectedHeads: [f.parent.digest],
      candidateManifestDigest: candidate.envelope.digest, stagedEntries: []
    ).canonicalBytes
    try f.store.persistRecoveryIntent(orphan, operationID: operation)
    try service(f, session: session(f)).remove(name: "fixture/totp", operationID: .init())
    guard
      case .available(let retained) = try f.store.readRecoveryIntent(
        operationID: operation, maximumBytes: 1_024)
    else { throw Publication.Stop.interrupted }
    #expect(retained == orphan)
    #expect(try self.current(f).envelope.parents == [current.envelope.digest])
  }

  @Test(arguments: [false, true])
  func changedOwnershipBetweenDispatchAndRecovererCannotResumeAnotherReservation(missing: Bool)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.build(.remove(name: "fixture/totp"))
    #expect(throws: Publication.Stop.interrupted) {
      try f.publisher(observer: Interrupt(phase: .manifestStaged)).publish(
        candidate, vaultKey: Core.nextKey)
    }
    let winner = try V3ImmutableTransactionRecoveryAnchor(
      operationID: .init(), vaultID: Core.vaultID,
      intentDigest: Data(repeating: 0x44, count: 32), phase: .prepared)
    let changed = OwnershipRace(f.ownership) { count in
      if count == 3 { f.ownership.value = missing ? nil : winner.canonicalBytes }
    }
    let s = service(f, session: try session(f), ownership: changed)
    #expect(throws: VaultUXServiceError.recoveryRequired) {
      try s.remove(name: "fixture/secret", operationID: .init())
    }
    #expect(
      f.checkpoints.value == f.checkpoint.canonicalBytes
        && f.ownership.value == (missing ? nil : winner.canonicalBytes))
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(candidate.envelope.digest).path))
  }

  @Test(arguments: [false, true])
  func pendingRegistrationOrAdoptionBlocksBeforeSourceRecoveryAndPublication(registration: Bool)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let marker = Data([1])
    (registration ? f.registration : f.adoption).value = marker
    let s = service(f, session: try session(f))
    #expect(throws: VaultUXServiceError.vaultIncomplete) {
      try s.remove(name: "fixture/secret", operationID: .init())
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  @Test(arguments: 0..<4)
  func exactSessionBindingAndInvalidationRefuseWithoutCreatingOrUnwrappingAKey(variant: Int) throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let session = V3DeviceWrappedVaultKeySessionStore()
    if variant == 1 {
      try session.install(
        Core.oldKey, vaultID: Core.vaultID, keyID: f.core.parent.body.fields.keyID)
    } else if variant == 2 {
      let vaultID = Self.addedID
      try session.install(
        Core.nextKey, vaultID: vaultID,
        keyID: V3VaultKeyID.derive(vaultKey: Core.nextKey, vaultID: vaultID))
    } else if variant == 3 {
      try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
      session.invalidate()
    }
    #expect(throws: (any Error).self) {
      try service(f, session: session).remove(name: "fixture/secret", operationID: .init())
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func missingOrChangedCurrentProviderObjectsCannotBeBypassedBySessionOrCache(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    try s.authorizeMutation()
    let entry = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    switch variant {
    case 0: try FileManager.default.removeItem(at: f.manifestURL(f.parent.digest))
    case 1:
      try Data("changed provider manifest fixture".utf8).write(to: f.manifestURL(f.parent.digest))
    default: try FileManager.default.removeItem(at: f.entryURL(entry))
    }
    #expect(throws: (any Error).self) { try s.remove(name: "fixture/totp", operationID: .init()) }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(session.hasResidentKey)
  }

  @Test func entryIDCollisionsAndInvalidUserInputsLeaveNoTransaction() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let existing = try #require(f.parent.body.fields.entries.first).entryID
    let collisions = Core.Counter()
    let s = service(
      f, session: session,
      makeEntryID: {
        collisions.increment()
        return existing
      })
    #expect(throws: VaultUXServiceError.recoveryRequired) {
      try s.add(name: "new/account", secret: "new", type: .secret, operationID: .init())
    }
    #expect(collisions.value == 16)
    #expect(throws: (any Error).self) {
      try s.edit(
        name: "fixture/totp", secret: "not valid base32!", type: .totp, operationID: .init())
    }
    #expect(throws: (any Error).self) {
      try s.move(
        source: "fixture/totp", destination: "fixture/totp", overwrite: false, operationID: .init())
    }
    #expect(throws: (any Error).self) { try s.remove(name: "missing", operationID: .init()) }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  @Test func failedRequestedSaveKeepsTheAlreadyCommittedAutomaticMerge() throws {
    let f = try Fixture()
    defer { f.remove() }
    let (a, b) = try conflictingBranches(f, automatic: true)
    let existing = try #require(f.parent.body.fields.entries.first { $0.name == "fixture/secret" })
    let s = service(f, session: try session(f), makeEntryID: { existing.entryID })
    #expect(throws: VaultUXServiceError.recoveryRequired) {
      try s.add(name: "new/account", secret: "new", type: .secret, operationID: .init())
    }
    let merged = try current(f)
    #expect(Set(merged.envelope.parents) == [a.envelope.digest, b.envelope.digest])
    #expect(try plaintexts(f, current: merged) == ["fixture/secret": "selected"])
    #expect(f.ownership.value == nil)
    try service(f, session: session(f)).add(
      name: "new/account", secret: "new", type: .secret, operationID: .init())
    #expect(try current(f).envelope.parents == [merged.envelope.digest])
  }

  @Test(arguments: [false, true])
  func authorityWorkAppearingAtIntentPersistencePreventsActivation(registration: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let marker = Data([1])
    let store = Store(
      f.store,
      onIntent: { _, _ in
        (registration ? f.registration : f.adoption).value = marker
      })
    let s = service(f, session: try session(f), store: store)
    #expect(throws: VaultUXServiceError.vaultIncomplete) {
      try s.remove(name: "fixture/totp", operationID: .init())
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect((registration ? f.registration : f.adoption).value == marker)
    #expect(f.ownership.value != nil)
    guard case .available(let digests, _) = try f.store.manifestDigests(maximumCount: 10) else {
      throw Publication.Stop.interrupted
    }
    #expect(Set(digests) == [f.parent.digest, f.core.parent.digest])
  }

  @Test func serviceSavedContentsRecoverAfterOriginalSessionAndOwnerLeaveScope() throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchor, token, digest) = try saveForRecovery(root)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let selected = try V3RecoveryHistorySelector(source: store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      let secret = try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer))
      return secret.withUnsafeBytes { Data($0) }
    }
    let snapshot = try V3RecoverySnapshotVerifier(source: store).open(
      selected, boundAnchor: anchor, receiver: receiver)
    #expect(selected.head.digest == digest && calls.value == 1)
    #expect(snapshot.entries.map(\.plaintext) == ["latest", "latest", "JBSWY3DPEHPK3PXP"])
    #expect(snapshot.entries.map(\.name) == ["copied/account", "fixture/secret", "fixture/totp"])
  }

  private func saveForRecovery(_ root: URL) throws -> (
    V3RecoveryAnchor, P256.KeyAgreement.PrivateKey, Data
  ) {
    let f = try Fixture(root: root)
    let session = try session(f)
    let s = service(f, session: session)
    let owner = VaultTransactionMutationOwner()
    try owner.perform(.editEntry) { c in
      try s.edit(
        name: "fixture/secret", secret: "latest", type: .secret, operationID: c.operationID)
    }
    try owner.perform(.copyEntry) { c in
      try s.copy(
        source: "fixture/secret", destination: "copied/account", overwrite: false,
        operationID: c.operationID)
    }
    let digest = try current(f).envelope.digest
    session.invalidate()
    #expect(!session.hasResidentKey && f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
    return (f.anchor, f.core.token, digest)
  }
  private func session(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    return session
  }
  private func service(
    _ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore,
    store: (any V3TransactionArtifactStore)? = nil,
    ownership: (any V3ImmutableTransactionRecoveryAnchorStoring)? = nil,
    makeEntryID: @escaping V3RecoveryVaultMutationService.EntryIDGenerator = {
      UUID().uuidString.lowercased()
    }
  ) -> V3RecoveryVaultMutationService {
    .init(
      vaultID: Core.vaultID, session: session, objectStore: store ?? f.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: ownership ?? f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache,
      makeEntryID: makeEntryID)
  }
  private func current(_ f: Fixture) throws -> V3RecoveryContentCommit {
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    let envelope = try V3RecoveryManifestCodec().parseEnvelope(
      Data(contentsOf: f.manifestURL(checkpoint.envelopeDigest)))
    return .init(checkpoint: checkpoint, envelope: envelope)
  }
  private func plaintexts(_ f: Fixture, current: V3RecoveryContentCommit) throws -> [String: String]
  {
    let entries = try branches.entryMap(f, envelope: current.envelope)
    let values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: current.envelope.body.fields, entries: entries, vaultKey: Core.nextKey)
    let pairs = try current.envelope.body.fields.entries.map { record in
      let data = try #require(values[record.entryID])
      let text = try #require(String(data: data, encoding: .utf8))
      return (record.name, text)
    }
    return Dictionary(uniqueKeysWithValues: pairs)
  }
  private func conflictingBranches(_ f: Fixture, automatic: Bool = false) throws -> (
    V3RecoveryContentCommit, V3RecoveryContentCommit
  ) {
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "selected")])
    let b = try branches.publishBranch(
      f,
      requests: automatic
        ? [.remove(name: "fixture/totp")]
        : [.edit(name: "fixture/secret", type: .secret, plaintext: "other")])
    return (a, b)
  }
  private func resolutions(_ s: V3RecoveryVaultMutationService, selected: Data) throws
    -> [VaultConflictResolution]
  {
    try s.conflicts(operationID: .init()).map { detail in
      let version = try #require(
        detail.versions.first { v3LowercaseHex(selected).hasPrefix($0.id) })
      return .init(
        conflictID: detail.summary.id,
        versionID: version.id)
    }
  }
  private struct Interrupt: V3ImmutableTransactionPhaseObserving {
    let phase: V3ImmutableTransactionPhase
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      if phase == self.phase { throw Publication.Stop.interrupted }
    }
  }
  private final class Traces: @unchecked Sendable {
    private let lock = NSLock()
    private var data: [(VaultTransactionOperationID, V3ImmutableTransactionRecoveryIntent)] = []
    var values: [(VaultTransactionOperationID, V3ImmutableTransactionRecoveryIntent)] {
      lock.withLock { data }
    }
    func append(_ id: VaultTransactionOperationID, _ bytes: Data) throws {
      let intent = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes)
      lock.withLock { data.append((id, intent)) }
    }
  }
  private final class OwnershipRace: V3ImmutableTransactionRecoveryAnchorStoring, Sendable {
    let base: Publication.Ownership
    let calls = Core.Counter()
    let action: @Sendable (Int) throws -> Void
    init(_ base: Publication.Ownership, action: @escaping @Sendable (Int) throws -> Void) {
      self.base = base
      self.action = action
    }
    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
      calls.increment()
      try action(calls.value)
      return try base.loadRecoveryAnchor(vaultID: vaultID)
    }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID: String) throws {
      try base.replaceRecoveryAnchor(anchor, expectedAnchor: expectedAnchor, vaultID: vaultID)
    }
  }
  private struct Store: V3TransactionArtifactStore {
    let base: any V3TransactionArtifactStore
    let onIntent: @Sendable (VaultTransactionOperationID, Data) throws -> Void
    let afterManifest: @Sendable (VaultTransactionOperationID, Data) throws -> Void
    init(
      _ base: any V3TransactionArtifactStore,
      onIntent: @escaping @Sendable (VaultTransactionOperationID, Data) throws -> Void = { _, _ in
      },
      afterManifest: @escaping @Sendable (VaultTransactionOperationID, Data) throws -> Void = {
        _, _ in
      }
    ) {
      self.base = base
      self.onIntent = onIntent
      self.afterManifest = afterManifest
    }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      try base.manifestDigests(maximumCount: maximumCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    { try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes) }
    func persistRecoveryIntent(_ data: Data, operationID: VaultTransactionOperationID) throws {
      try onIntent(operationID, data)
      try base.persistRecoveryIntent(data, operationID: operationID)
    }
    func readRecoveryIntent(operationID: VaultTransactionOperationID, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    { try base.readRecoveryIntent(operationID: operationID, maximumBytes: maximumBytes) }
    func removeRecoveryIntent(_ data: Data, operationID: VaultTransactionOperationID) throws {
      try base.removeRecoveryIntent(data, operationID: operationID)
    }
    func stageEntry(
      _ data: Data, entryID: String, digest: Data, operationID: VaultTransactionOperationID
    ) throws {
      try base.stageEntry(data, entryID: entryID, digest: digest, operationID: operationID)
    }
    func stageManifest(_ data: Data, digest: Data, operationID: VaultTransactionOperationID) throws
    { try base.stageManifest(data, digest: digest, operationID: operationID) }
    func readStagedEntry(
      entryID: String, digest: Data, operationID: VaultTransactionOperationID, maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
      try base.readStagedEntry(
        entryID: entryID, digest: digest, operationID: operationID, maximumBytes: maximumBytes)
    }
    func readStagedManifest(
      digest: Data, operationID: VaultTransactionOperationID, maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
      try base.readStagedManifest(
        digest: digest, operationID: operationID, maximumBytes: maximumBytes)
    }
    func publishStagedEntry(
      _ data: Data, entryID: String, digest: Data, operationID: VaultTransactionOperationID
    ) throws {
      try base.publishStagedEntry(data, entryID: entryID, digest: digest, operationID: operationID)
    }
    func publishStagedManifest(_ data: Data, digest: Data, operationID: VaultTransactionOperationID)
      throws
    {
      try base.publishStagedManifest(data, digest: digest, operationID: operationID)
      try afterManifest(operationID, data)
    }
    func removeStagedEntry(
      _ data: Data, entryID: String, digest: Data, operationID: VaultTransactionOperationID
    ) throws {
      try base.removeStagedEntry(data, entryID: entryID, digest: digest, operationID: operationID)
    }
    func removeStagedManifest(_ data: Data, digest: Data, operationID: VaultTransactionOperationID)
      throws
    { try base.removeStagedManifest(data, digest: digest, operationID: operationID) }
    func removeEmptyTransactionDirectories(
      operationID: VaultTransactionOperationID, entryIDs: [String]
    ) throws {
      try base.removeEmptyTransactionDirectories(operationID: operationID, entryIDs: entryIDs)
    }
  }
}
