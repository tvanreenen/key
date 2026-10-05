import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Production crypto, complete snapshots and contained filesystem publication.
/// Only non-sync local persistence and interruption/sync failures are scripted.
/// No native authentication, real vault or hardware operation occurs.
struct V3RecoveryAdoptionServiceTests {
  private typealias Core = V3RecoveryRegistrationTests

  @Test func entriesPrecedeManifestAndCheckpointPrecedesSession() throws {
    let f = try Fixture()
    defer { f.remove() }
    let observer = Observer { phase in
      if phase == .entriesVerified || phase == .manifestVerified {
        let p = try f.pending()
        #expect(f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
        for entry in p.candidate.stagedEntries {
          #expect(try Data(contentsOf: f.entryURL(entry)) == entry.canonicalBytes)
        }
        #expect(
          FileManager.default.fileExists(atPath: f.manifestURL(p.candidate.envelope.digest).path)
            == (phase == .manifestVerified))
      }
    }
    let result = try f.service(observer: observer).adopt(currentVaultKey: Core.oldKey) { cp, key in
      #expect(f.checkpoints.value == cp.canonicalBytes)
      let p = try f.pending()
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(p.candidate.envelope, vaultKey: key)
      try V3RecoveryProfileAdoptionValidator().validate(
        p.candidate, parent: f.core.base, currentEntries: f.core.entries,
        currentVaultKey: Core.oldKey, nextVaultKey: key, expectedOwner: f.core.owner.publicIdentity)
    }
    #expect(!result.alreadyAdopted && !result.cleanupPending && f.ownership.value == nil)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 1)
    #expect(FileManager.default.fileExists(atPath: f.bundleURL(result.operationID).path))
    #expect(
      try Data(contentsOf: f.manifestURL(f.core.base.checkpoint.envelopeDigest))
        == f.core.base.envelope.canonicalBytes)
  }

  @Test(arguments: [
    V3RecoveryAdoptionPhase.bundlePersisted, .localWrapperVerified, .bundleVerified,
    .ownershipArmed, .artifactsStaged, .entryPublished(index: 0), .entryPublished(index: 1),
    .entriesVerified, .manifestPublished, .manifestVerified, .checkpointAdvanced, .sessionUpdated,
    .ownershipCleared,
  ])
  func restartUsesExactPreparationWithoutResigning(phase: V3RecoveryAdoptionPhase) throws {
    let f = try Fixture()
    defer { f.remove() }
    let capture = Capture()
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service(
        observer: Observer {
          if $0 == .bundlePersisted { capture.set(try f.pending()) }
          if $0 == phase { throw Core.FixtureError.cancelled }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    let preparation = try #require(capture.value)
    let committed = [.checkpointAdvanced, .sessionUpdated, .ownershipCleared].contains(phase)
    #expect(
      f.checkpoints.value
        == (committed
          ? try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: preparation.candidate.envelope.digest
          ).canonicalBytes
          : f.core.base.checkpoint.canonicalBytes))
    let result = try f.service().resume(
      operationID: preparation.operationID, currentVaultKey: Core.oldKey)
    #expect(result.alreadyAdopted == committed && !result.cleanupPending)
    #expect(result.checkpoint.envelopeDigest == preparation.candidate.envelope.digest)
    #expect(
      try Data(contentsOf: f.bundleURL(preparation.operationID)) == preparation.canonicalBytes)
    #expect(f.core.owner.signatures == 1 && f.ownership.value == nil)
    #expect(f.core.owner.unwraps == (phase == .bundlePersisted ? 1 : 2))
  }

  @Test func interruptionBeforeReservationHasNoPendingAuthority() throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service(
        observer: Observer {
          if $0 == .candidateConstructed { throw Core.FixtureError.cancelled }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    #expect(f.ownership.value == nil && f.core.owner.unwraps == 0)
    #expect(f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
  }

  @Test func missingBundleRequiresExplicitAbandonOfOnlyTheUnarmedReservation() throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service(
        observer: Observer {
          if $0 == .ownershipReserved { throw Core.FixtureError.cancelled }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    let local = try f.anchor()
    #expect(local.phase == .prepared)
    #expect(throws: V3RecoveryAdoptionServiceError.preparationUnavailable) {
      try f.service().resume(operationID: local.operationID, currentVaultKey: Core.oldKey)
    }
    #expect(throws: V3RecoveryAdoptionServiceError.adoptionPending) {
      try f.service().adopt(currentVaultKey: Core.oldKey)
    }
    #expect(throws: V3RecoveryAdoptionServiceError.ownershipChanged) {
      try f.service().abandonUnarmedPreparation(operationID: VaultTransactionOperationID())
    }
    #expect(f.ownership.value == local.canonicalBytes && f.core.owner.unwraps == 0)
    try f.service().abandonUnarmedPreparation(operationID: local.operationID)
    #expect(
      f.ownership.value == nil && f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
  }

  @Test func failedDurabilityConfirmationCannotArmOrPublish() throws {
    let f = try Fixture()
    defer { f.remove() }
    f.store.failConfirmation = true
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service().adopt(currentVaultKey: Core.oldKey)
    }
    let preparation = try f.pending()
    #expect(try f.anchor().phase == .prepared && f.store.confirmations == 1)
    #expect(
      !FileManager.default.fileExists(
        atPath: f.manifestURL(preparation.candidate.envelope.digest).path))
    f.store.failConfirmation = false
    _ = try f.service().resume(operationID: preparation.operationID, currentVaultKey: Core.oldKey)
    #expect(f.store.confirmations == 2 && f.core.owner.signatures == 1 && f.core.owner.unwraps == 2)
  }

  @Test func failedCheckpointCASRetainsPublishedCandidateForExactResume() throws {
    let f = try Fixture()
    defer { f.remove() }
    f.checkpoints.rejectAdvance = true
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service().adopt(currentVaultKey: Core.oldKey)
    }
    let p = try f.pending()
    #expect(FileManager.default.fileExists(atPath: f.manifestURL(p.candidate.envelope.digest).path))
    #expect(f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
    #expect(throws: V3RecoveryAdoptionServiceError.ownershipChanged) {
      try f.service().abandonUnarmedPreparation(operationID: p.operationID)
    }
    f.checkpoints.rejectAdvance = false
    let result = try f.service().resume(operationID: p.operationID, currentVaultKey: Core.oldKey)
    #expect(!result.alreadyAdopted && f.core.owner.signatures == 1)
  }

  @Test func committedSessionRepairDoesNotReopenOldEntries() throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service().adopt(currentVaultKey: Core.oldKey) { _, _ in
        throw Core.FixtureError.cancelled
      }
    }
    let p = try f.pending()
    for entry in f.core.entries.values { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    let result = try f.service().resume(operationID: p.operationID, currentVaultKey: Data())
    #expect(result.alreadyAdopted && f.core.owner.signatures == 1 && f.core.owner.unwraps == 2)
    #expect(f.ownership.value == nil)
  }

  @Test func failedOwnershipCleanupReportsCommittedThenReconciles() throws {
    let f = try Fixture()
    defer { f.remove() }
    f.ownership.rejectClear = true
    let first = try f.service().adopt(currentVaultKey: Core.oldKey)
    #expect(first.cleanupPending && !first.alreadyAdopted && f.ownership.value != nil)
    f.ownership.rejectClear = false
    let resumed = try f.service().resume(operationID: first.operationID, currentVaultKey: Data())
    #expect(resumed.alreadyAdopted && !resumed.cleanupPending && f.ownership.value == nil)
    #expect(f.core.owner.signatures == 1)
  }

  @Test func providerPreparationAloneCannotCreateOwnershipOrAdvanceCheckpoint() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.core.build()
    let p = try V3RecoveryAdoptionPreparation(
      operationID: VaultTransactionOperationID(),
      ownerDeviceID: f.core.owner.publicIdentity.deviceID,
      candidate: candidate)
    try f.store.persistAdoptionPreparation(p.canonicalBytes, operationID: p.operationID)
    #expect(throws: V3RecoveryAdoptionServiceError.noPendingAdoption) {
      try f.service().resume(operationID: p.operationID, currentVaultKey: Core.oldKey)
    }
    #expect(f.core.owner.unwraps == 0 && f.ownership.value == nil)
    #expect(f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
  }

  @Test(arguments: 0..<4)
  func changedPendingBindingsAreRefusedBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service(
        observer: Observer {
          if $0 == .bundlePersisted { throw Core.FixtureError.cancelled }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    let p = try f.pending()
    if variant == 0 { try Data("{}".utf8).write(to: f.bundleURL(p.operationID)) }
    if variant == 1 {
      let replacement = try V3RecoveryAdoptionPreparation(
        operationID: p.operationID, ownerDeviceID: f.core.owner.publicIdentity.deviceID,
        candidate: f.core.build())
      try replacement.canonicalBytes.write(to: f.bundleURL(p.operationID))
    }
    if variant == 2 {
      f.checkpoints.value = try V3ManifestCheckpoint(
        vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x92, count: 32)
      ).canonicalBytes
    }
    #expect(throws: (any Error).self) {
      try f.service().resume(
        operationID: variant == 3 ? VaultTransactionOperationID() : p.operationID,
        currentVaultKey: Core.oldKey)
    }
    #expect(f.core.owner.unwraps == 0 && f.ownership.value != nil)
  }

  @Test(arguments: [false, true])
  func pendingOtherWorkBlocksBeforeSigning(registration: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let barrier = registration ? f.registration : f.transactions
    try barrier.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    #expect(throws: V3RecoveryAdoptionServiceError.otherMutationPending) {
      try f.service().adopt(currentVaultKey: Core.oldKey)
    }
    #expect(f.core.owner.signatures == 0 && f.core.owner.unwraps == 0 && f.ownership.value == nil)
  }

  @Test(arguments: [
    V3RecoveryAdoptionPhase.candidateConstructed, .localWrapperVerified, .entriesVerified,
  ])
  func sourceChangeDuringApprovalOrPublicationCannotAdvance(phase: V3RecoveryAdoptionPhase) throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: (any Error).self) {
      try f.service(
        observer: Observer {
          if $0 == phase {
            let entry =
              phase == .entriesVerified
              ? try #require(try f.pending().candidate.stagedEntries.first)
              : try #require(f.core.entries.values.first)
            try Data("changed".utf8).write(to: f.entryURL(entry))
          }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    #expect(f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
    #expect(try f.manifestCount() == 1)
    if phase == .candidateConstructed { #expect(f.ownership.value == nil) }
  }

  @Test func checkpointAndOtherOwnershipAreRecheckedAfterLocalApproval() throws {
    for changeCheckpoint in [false, true] {
      let f = try Fixture()
      defer { f.remove() }
      f.core.owner.onUnwrap = {
        if changeCheckpoint {
          f.checkpoints.value = try V3ManifestCheckpoint(
            vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x91, count: 32)
          ).canonicalBytes
        } else {
          try f.transactions.replaceRecoveryAnchor(
            Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
        }
      }
      #expect(throws: (any Error).self) { try f.service().adopt(currentVaultKey: Core.oldKey) }
      #expect(try f.manifestCount() == 1 && f.ownership.value != nil)
    }
  }

  @Test func cancellationIsOneOperationAndRetainsExactPreparation() throws {
    let f = try Fixture()
    defer { f.remove() }
    f.core.owner.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) {
      try f.service().adopt(currentVaultKey: Core.oldKey)
    }
    let p = try f.pending()
    #expect(f.core.owner.unwraps == 1 && f.core.owner.signatures == 1)
    #expect(
      try f.anchor().phase == .prepared
        && f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
    f.core.owner.cancelUnwrap = false
    _ = try f.service().resume(operationID: p.operationID, currentVaultKey: Core.oldKey)
    #expect(f.core.owner.unwraps == 2 && f.core.owner.signatures == 1)
  }

  @Test func competingSameVaultManifestCannotBeSilentlyAdopted() throws {
    let f = try Fixture()
    defer { f.remove() }
    let competing = try f.core.build().envelope
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try f.service(
        observer: Observer {
          if $0 == .artifactsStaged {
            let op = VaultTransactionOperationID()
            try f.store.stageManifest(
              competing.canonicalBytes, digest: competing.digest, operationID: op)
            try f.store.publishStagedManifest(
              competing.canonicalBytes, digest: competing.digest, operationID: op)
          }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    let pending = try f.pending()
    #expect(f.checkpoints.value == f.core.base.checkpoint.canonicalBytes)
    #expect(
      !FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.envelope.digest).path)
    )
    let unwraps = f.core.owner.unwraps
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try f.service().resume(operationID: pending.operationID, currentVaultKey: Core.oldKey)
    }
    #expect(f.core.owner.unwraps == unwraps)
  }

  @Test func checkpointRaceAfterManifestReadbackNeverOverwritesAnotherFloor() throws {
    let f = try Fixture()
    defer { f.remove() }
    let other = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x93, count: 32))
    #expect(throws: V3RecoveryAdoptionServiceError.checkpointChanged) {
      try f.service(
        observer: Observer {
          if $0 == .manifestVerified { f.checkpoints.value = other.canonicalBytes }
        }
      ).adopt(currentVaultKey: Core.oldKey)
    }
    #expect(f.checkpoints.value == other.canonicalBytes && f.ownership.value != nil)
    #expect(f.core.owner.unwraps == 1 && f.core.owner.signatures == 1)
  }

  @Test func projectedBudgetRejectsMigrationBeforeOwnershipOrUnwrap() throws {
    let f = try Fixture()
    defer { f.remove() }
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumReferencedEntryObjects: 2)
    #expect(throws: (any Error).self) {
      try f.service(limits: limits).adopt(currentVaultKey: Core.oldKey)
    }
    #expect(f.ownership.value == nil && f.core.owner.unwraps == 0)
    #expect(try f.manifestCount() == 1)
  }

  @Test func preparationCodecIsCanonicalBoundedAndContainsOnlyEncryptedSnapshot() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.core.build()
    let p = try V3RecoveryAdoptionPreparation(
      operationID: VaultTransactionOperationID(),
      ownerDeviceID: f.core.owner.publicIdentity.deviceID,
      candidate: candidate)
    #expect(try V3RecoveryAdoptionPreparation(canonicalBytes: p.canonicalBytes) == p)
    let text = String(decoding: p.canonicalBytes, as: UTF8.self)
    for secret in [
      "Adoption fixture secret", "JBSWY3DPEHPK3PXP", Base64URL.encode(Core.oldKey),
      Base64URL.encode(Core.nextKey),
    ] {
      #expect(!text.contains(secret))
    }
    #expect(throws: (any Error).self) {
      try V3RecoveryAdoptionPreparation(canonicalBytes: p.canonicalBytes + Data([0x20]))
    }
    let root = try #require(try CanonicalJSON.parse(p.canonicalBytes).objectValue)
    for fields in [
      root + [("extra", .integer(1))], root.map { $0.0 == "version" ? ($0.0, .integer(2)) : $0 },
    ] {
      #expect(throws: (any Error).self) {
        try V3RecoveryAdoptionPreparation(canonicalBytes: CanonicalJSON.encode(.object(fields)))
      }
    }
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumReferencedEntryObjects: 1)
    #expect(throws: (any Error).self) {
      try V3RecoveryAdoptionPreparation(canonicalBytes: p.canonicalBytes, limits: limits)
    }
    let maximumEntryBytes = try #require(
      candidate.stagedEntries.map { $0.canonicalBytes.count }.max())
    let totalEntryBytes = candidate.stagedEntries.reduce(0) { $0 + $1.canonicalBytes.count }
    for bounds in [
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumManifestBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumEntryBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10,
        maximumEntryBytes: maximumEntryBytes, maximumTotalEntryBytes: totalEntryBytes - 1),
    ] {
      #expect(throws: (any Error).self) {
        try V3RecoveryAdoptionPreparation(canonicalBytes: p.canonicalBytes, limits: bounds)
      }
    }
    let incomplete = V3RecoveryProfileAdoptionCandidate(
      expectedCheckpoint: candidate.expectedCheckpoint,
      envelope: candidate.envelope, stagedEntries: Array(candidate.stagedEntries.dropFirst()))
    #expect(throws: (any Error).self) {
      try V3RecoveryAdoptionPreparation(
        operationID: p.operationID,
        ownerDeviceID: p.ownerDeviceID, candidate: incomplete)
    }
  }

  @Test func filesystemPreparationIsNoOverwriteAndContained() throws {
    let f = try Fixture()
    defer { f.remove() }
    let p = try V3RecoveryAdoptionPreparation(
      operationID: VaultTransactionOperationID(),
      ownerDeviceID: f.core.owner.publicIdentity.deviceID, candidate: f.core.build())
    try f.store.persistAdoptionPreparation(p.canonicalBytes, operationID: p.operationID)
    try f.store.persistAdoptionPreparation(p.canonicalBytes, operationID: p.operationID)
    try f.store.confirmAdoptionPreparation(p.canonicalBytes, operationID: p.operationID)
    #expect(throws: (any Error).self) {
      try f.store.persistAdoptionPreparation(
        p.canonicalBytes, operationID: VaultTransactionOperationID())
    }
    let different = try V3RecoveryAdoptionPreparation(
      operationID: p.operationID,
      ownerDeviceID: p.ownerDeviceID, candidate: f.core.build())
    #expect(throws: (any Error).self) {
      try f.store.persistAdoptionPreparation(different.canonicalBytes, operationID: p.operationID)
    }
    #expect(try Data(contentsOf: f.bundleURL(p.operationID)) == p.canonicalBytes)
    try FileManager.default.removeItem(at: f.bundleURL(p.operationID))
    let target = f.root.appendingPathComponent("unrelated")
    try Data("retain".utf8).write(to: target)
    try FileManager.default.createSymbolicLink(
      at: f.bundleURL(p.operationID), withDestinationURL: target)
    #expect(throws: (any Error).self) {
      try f.store.persistAdoptionPreparation(p.canonicalBytes, operationID: p.operationID)
    }
    #expect(throws: (any Error).self) {
      try f.store.confirmAdoptionPreparation(p.canonicalBytes, operationID: p.operationID)
    }
    #expect(try Data(contentsOf: target) == Data("retain".utf8))
  }

  @Test(arguments: [VaultTransactionMutationKind.adoptRecoveryProfile, .registerRecoveryRecipient])
  func dedicatedWorkflowsCannotBecomeOrdinaryRecoveryIntents(kind: VaultTransactionMutationKind)
    throws
  {
    let cp = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 1, count: 32))
    #expect(throws: V3ImmutableTransactionRecoveryIntentError.invalidFormat) {
      try V3ImmutableTransactionRecoveryIntent(
        operationID: VaultTransactionOperationID(), kind: kind,
        vaultID: Core.vaultID, expectedCheckpoint: cp, expectedHeads: [cp.envelopeDigest],
        candidateManifestDigest: Data(repeating: 2, count: 32), stagedEntries: [])
    }
  }

  private struct Observer: V3RecoveryAdoptionPhaseObserving {
    let body: @Sendable (V3RecoveryAdoptionPhase) throws -> Void
    init(_ body: @escaping @Sendable (V3RecoveryAdoptionPhase) throws -> Void) { self.body = body }
    func didReach(_ phase: V3RecoveryAdoptionPhase) throws { try body(phase) }
  }
  private final class Capture: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: V3RecoveryAdoptionPreparation?
    var value: V3RecoveryAdoptionPreparation? { lock.withLock { stored } }
    func set(_ value: V3RecoveryAdoptionPreparation) { lock.withLock { stored = value } }
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
    let core: V3RecoveryProfileAdoptionTests.Fixture
    let root: URL
    let store: Store
    let checkpoints: Checkpoints
    let ownership = Ownership()
    let transactions = Ownership()
    let registration = Ownership()
    let mutationOwner = VaultTransactionMutationOwner()
    init() throws {
      core = try V3RecoveryProfileAdoptionTests.Fixture()
      root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
      store = Store(
        V3FilesystemTransactionArtifactStore(
          rootHandle: try VaultRootDirectoryHandle(opening: root)))
      checkpoints = Checkpoints(core.base.checkpoint.canonicalBytes)
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
      try store.stageManifest(
        core.base.envelope.canonicalBytes, digest: core.base.checkpoint.envelopeDigest,
        operationID: operation)
      try store.publishStagedManifest(
        core.base.envelope.canonicalBytes, digest: core.base.checkpoint.envelopeDigest,
        operationID: operation)
    }
    func service(
      limits: V3ManifestRepositoryLimits = .standard,
      observer: any V3RecoveryAdoptionPhaseObserving = Observer { _ in }
    ) -> V3RecoveryAdoptionService {
      V3RecoveryAdoptionService(
        vaultID: Core.vaultID, identity: core.owner, mutationOwner: mutationOwner,
        objectStore: store, checkpointStore: checkpoints, adoptionOwnershipStore: ownership,
        transactionOwnershipStore: transactions, registrationOwnershipStore: registration,
        limits: limits, observer: observer)
    }
    func anchor() throws -> V3ImmutableTransactionRecoveryAnchor {
      try V3ImmutableTransactionRecoveryAnchor(canonicalBytes: #require(ownership.value))
    }
    func pending() throws -> V3RecoveryAdoptionPreparation {
      try V3RecoveryAdoptionPreparation(
        canonicalBytes: Data(contentsOf: bundleURL(anchor().operationID)))
    }
    func bundleURL(_ operation: VaultTransactionOperationID) -> URL {
      root.appendingPathComponent(".recovery-adoptions/\(operation.rawValue)/preparation.json")
    }
    func entryURL(_ entry: V3EncryptedEntry) -> URL {
      root.appendingPathComponent(
        "entries/\(entry.context.entryID)/\(v3LowercaseHex(Data(SHA256.hash(data: entry.canonicalBytes)))).json"
      )
    }
    func manifestURL(_ digest: Data) -> URL {
      root.appendingPathComponent("manifests/\(v3LowercaseHex(digest)).json")
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
    func manifestCount() throws -> Int {
      guard case .available(let digests, _) = try store.manifestDigests(maximumCount: 10) else {
        throw Core.FixtureError.cancelled
      }
      return digests.count
    }
  }

  /// All object operations use the real filesystem implementation. The sole
  /// injected transport failure is confirmation, including its ambiguous retry.
  private final class Store: V3ImmutableObjectPublishing, V3RecoveryAdoptionPreparationStoring,
    @unchecked Sendable
  {
    let base: V3FilesystemTransactionArtifactStore
    var failConfirmation = false
    private(set) var confirmations = 0
    init(_ base: V3FilesystemTransactionArtifactStore) { self.base = base }
    func persistAdoptionPreparation(_ data: Data, operationID: VaultTransactionOperationID) throws {
      try base.persistAdoptionPreparation(data, operationID: operationID)
    }
    func readAdoptionPreparation(operationID: VaultTransactionOperationID, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readAdoptionPreparation(operationID: operationID, maximumBytes: maximumBytes)
    }
    func confirmAdoptionPreparation(_ data: Data, operationID: VaultTransactionOperationID) throws {
      confirmations += 1
      if failConfirmation { throw Core.FixtureError.cancelled }
      try base.confirmAdoptionPreparation(data, operationID: operationID)
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
    func stageEntry(
      _ data: Data, entryID: String, digest: Data, operationID: VaultTransactionOperationID
    ) throws {
      try base.stageEntry(data, entryID: entryID, digest: digest, operationID: operationID)
    }
    func stageManifest(_ data: Data, digest: Data, operationID: VaultTransactionOperationID) throws
    { try base.stageManifest(data, digest: digest, operationID: operationID) }
    func publishStagedEntry(
      _ data: Data, entryID: String, digest: Data, operationID: VaultTransactionOperationID
    ) throws {
      try base.publishStagedEntry(data, entryID: entryID, digest: digest, operationID: operationID)
    }
    func publishStagedManifest(_ data: Data, digest: Data, operationID: VaultTransactionOperationID)
      throws
    { try base.publishStagedManifest(data, digest: digest, operationID: operationID) }
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
