import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real random-key generation, epoch crypto, session and contained filesystem
/// publication. Private identity calls use the established software fixture.
struct V3RecoveryKeyRotationServiceTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = Publication.Fixture
  private typealias Stop = Publication.Stop
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test func preparationAuthenticatesCompleteSourceWithoutPrivateOperationsOrReservation() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let reviewed = try service(f, session: session).prepare()
    #expect(reviewed.checkpoint == f.checkpoint && reviewed.envelope == f.parent)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
    #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == Core.nextKey)
  }

  @Test(arguments: [false, true])
  func rotationInstallsFreshAuthenticatedKeyAndOrdinarySavingContinues(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let session = try session(f)
    let service = service(f, session: session)
    let owner = VaultTransactionMutationOwner()
    let reviewed = try service.prepare()
    let commit = try owner.perform(.rotateVaultKey) { c in
      try service.rotate(expectedCheckpoint: reviewed.checkpoint, operationID: c.operationID)
    }
    let key = try session.load(vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID)
    #expect(key.count == 32 && key != Core.nextKey)
    #expect(commit.envelope.body.fields.keyID != f.parent.body.fields.keyID)
    #expect(f.checkpoints.value == commit.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(commit.envelope.body.recovery.recipients == f.parent.body.recovery.recipients)
    #expect(commit.envelope.body.recovery.generationID == f.parent.body.recovery.generationID)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
    let ordinary = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: f.ownership, registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: f.cache)
    try owner.perform(.addEntry) { c in
      try ordinary.add(
        name: "after/rotation", secret: "new value", type: .secret, operationID: c.operationID)
    }
    let last = try current(f)
    #expect(last.envelope.parents == [commit.envelope.digest])
    #expect(last.envelope.body.fields.keyID == commit.envelope.body.fields.keyID)
    #expect(last.envelope.body.recovery == commit.envelope.body.recovery)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test(arguments: 0..<14)
  func everyInterruptedBoundaryRetainsOldSessionOrLocksAfterCommit(phase: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let s = service(
      f, session: session,
      observer: Observer {
        if $0 == Self.phases[phase] { throw Stop.interrupted }
      })
    #expect(throws: Stop.interrupted) {
      try s.rotate(expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    if phase < 12 {
      #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
      #expect(
        try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == Core.nextKey)
    } else {
      #expect(f.checkpoints.value != f.checkpoint.canonicalBytes && !session.hasResidentKey)
    }
    #expect((f.ownership.value != nil) == (phase != 13))
    if phase != 13 {
      #expect(throws: (any Error).self) {
        try service(f, session: session).rotate(
          expectedCheckpoint: f.checkpoint, operationID: .init())
      }
    }
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test func failedCheckpointCASRetainsOldSessionAndExactPendingOperation() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    f.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) {
      try service(f, session: session).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.ownership.value != nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == Core.nextKey)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      canonicalBytes: #require(f.ownership.value))
    #expect(anchor.operationID == f.operationID)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test func cleanupFailureStillInstallsCommittedKeyButRetainsPinnedWork() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    f.ownership.rejectClear = true
    let commit = try service(f, session: session).rotate(
      expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    #expect(f.checkpoints.value == commit.checkpoint.canonicalBytes && f.ownership.value != nil)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID).count == 32)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test(arguments: [false, true])
  func signingOrWrapperCancellationDoesNotReserveWorkOrReplaceSession(signing: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    f.core.owner.cancelSigning = signing
    f.core.owner.cancelUnwrap = !signing
    #expect(throws: Core.FixtureError.cancelled) {
      try service(f, session: session).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == Core.nextKey)
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == (signing ? 0 : 1))
  }

  @Test(arguments: 0..<7)
  func invalidSourceIdentitySessionAndPendingWorkRefuseBeforePrivateOperations(variant: Int) throws
  {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    if variant == 0 { session.invalidate() }
    if variant == 1 { f.ownership.value = Data([1]) }
    if variant == 2 { f.registration.value = Data([1]) }
    if variant == 3 { f.adoption.value = Data([1]) }
    if variant == 4 {
      try FileManager.default.removeItem(at: f.entryURL(try #require(f.entries.values.first)))
    }
    if variant == 5 {
      let branch = try f.build(.remove(name: "fixture/totp"))
      try f.seed(branch.envelope, entries: branch.stagedEntries)
    }
    let pending = f.ownership.value
    let s = service(f, session: session, identity: variant == 6 ? try Core.Owner() : f.core.owner)
    #expect(throws: (any Error).self) { try s.prepare() }
    #expect(throws: (any Error).self) {
      try s.rotate(expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
    #expect(f.ownership.value == pending && f.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test func changedReviewedCheckpointRefusesAndDiscardsStaleSession() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let branch = try f.build(.remove(name: "fixture/totp"))
    try f.seed(branch.envelope, entries: branch.stagedEntries)
    f.checkpoints.value = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: branch.envelope.digest
    ).canonicalBytes
    #expect(throws: V3ImmutableTransactionError.expectedHeadsChanged) {
      try service(f, session: session).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(!session.hasResidentKey && f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<6)
  func changesDuringSigningRefuseBeforeWrapperVerificationOrReservation(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let branch = try f.build(.remove(name: "fixture/totp"))
    let identity = SigningObserverIdentity(base: f.core.owner) {
      switch variant {
      case 0: try f.seed(branch.envelope, entries: branch.stagedEntries)
      case 1: f.registration.value = Data([1])
      case 2: f.adoption.value = Data([1])
      case 3: f.checkpoints.value = Data([1])
      case 4: session.invalidate()
      default:
        session.invalidate()
        try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
      }
    }
    #expect(throws: (any Error).self) {
      try service(f, session: session, identity: identity).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.ownership.value == nil && f.core.owner.signatures == 2 && f.core.owner.unwraps == 0)
    if variant == 3 || variant == 4 { #expect(!session.hasResidentKey) }
    if variant == 5 {
      #expect(
        try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == Core.nextKey)
    }
  }

  @Test(arguments: [false, true])
  func lockOrSameKeyReauthenticationDuringWrapperCannotBeUndone(reinstall: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    f.core.owner.onUnwrap = {
      session.invalidate()
      if reinstall {
        try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
      }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try service(f, session: session).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.checkpoints.value != f.checkpoint.canonicalBytes && f.ownership.value == nil)
    #expect(!session.hasResidentKey && f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  @Test func missingCommittedSnapshotLocksWithoutRollingBackCheckpointOrDeletingIntent() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let s = service(
      f, session: session,
      observer: Observer {
        if $0 == .checkpointAdvanced {
          let commit = try current(f)
          let record = try #require(commit.envelope.body.fields.entries.first)
          let data = try V3ExactTransitionRepository(source: f.store, limits: .standard).readEntry(
            Core.Fixture.address(record))
          try FileManager.default.removeItem(at: f.entryURL(try V3EntryCipher().parse(data)))
          f.ownership.rejectClear = true
        }
      })
    #expect(throws: (any Error).self) {
      try s.rotate(expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.checkpoints.value != f.checkpoint.canonicalBytes && f.ownership.value != nil)
    #expect(!session.hasResidentKey)
  }

  @Test func sourceBudgetRefusesBeforeSigning() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    #expect(throws: (any Error).self) {
      try service(f, session: session, limits: Core.Fixture.limits(entries: 1)).rotate(
        expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0 && f.ownership.value == nil)
  }

  @Test(arguments: 0..<8)
  func changedStateAfterCommitRefusesSessionSwitchWithoutRollback(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let ownership = ReadFailureOwnership(base: f.ownership)
    let branch = try f.build(.remove(name: "fixture/totp"))
    let s = service(
      f, session: session, ownership: ownership,
      observer: Observer {
        if $0 == .cleanupCompleted {
          switch variant {
          case 0: f.registration.value = Data([1])
          case 1: f.adoption.value = Data([1])
          case 2: try f.seed(branch.envelope, entries: branch.stagedEntries)
          case 3: f.checkpoints.value = nil
          case 4: f.ownership.value = Data([1])
          case 5:
            f.ownership.value = try V3ImmutableTransactionRecoveryAnchor(
              operationID: .init(), vaultID: Core.vaultID,
              intentDigest: Data(repeating: 1, count: 32), phase: .recoverable
            ).canonicalBytes
          case 6: ownership.rejectReads = true
          default:
            f.ownership.value = try V3ImmutableTransactionRecoveryAnchor(
              operationID: f.operationID, vaultID: Core.vaultID,
              intentDigest: Data(repeating: 1, count: 32), phase: .recoverable
            ).canonicalBytes
          }
        }
      })
    #expect(throws: (any Error).self) {
      try s.rotate(expectedCheckpoint: f.checkpoint, operationID: f.operationID)
    }
    #expect(f.checkpoints.value != f.checkpoint.canonicalBytes && !session.hasResidentKey)
    #expect((f.ownership.value != nil) == (variant == 4 || variant == 5 || variant == 7))
    #expect(f.core.owner.signatures == 2 && f.core.owner.unwraps == 1)
  }

  private func session(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    return session
  }
  private func service(
    _ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryKeyRotationService.Identity? = nil,
    ownership: (any V3ImmutableTransactionRecoveryAnchorStoring)? = nil,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) -> V3RecoveryKeyRotationService {
    .init(
      vaultID: Core.vaultID, identity: identity ?? f.core.owner, session: session,
      objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: ownership ?? f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption, cache: f.cache,
      limits: limits, phaseObserver: observer)
  }
  private static func current(_ f: Fixture) throws -> V3RecoveryKeyRotationCommit {
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return .init(
      checkpoint: checkpoint,
      envelope: try V3RecoveryManifestCodec().parseEnvelope(
        Data(contentsOf: f.manifestURL(checkpoint.envelopeDigest))))
  }
  private func current(_ f: Fixture) throws -> V3RecoveryKeyRotationCommit { try Self.current(f) }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3ImmutableTransactionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      try action(phase)
    }
  }
  private struct SigningObserverIdentity: V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
  {
    let base: Core.Owner
    let action: @Sendable () throws -> Void
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func signature(for input: Data, reason: String) throws -> Data {
      let signature = try base.signature(for: input, reason: reason)
      try action()
      return signature
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
    }
  }
  private final class ReadFailureOwnership: V3ImmutableTransactionRecoveryAnchorStoring,
    @unchecked Sendable
  {
    let base: Publication.Ownership
    private let lock = NSLock()
    private var failing = false
    var rejectReads: Bool {
      get { lock.withLock { failing } }
      set { lock.withLock { failing = newValue } }
    }
    init(base: Publication.Ownership) { self.base = base }
    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
      if rejectReads { throw Stop.interrupted }
      return try base.loadRecoveryAnchor(vaultID: vaultID)
    }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID: String) throws {
      try base.replaceRecoveryAnchor(anchor, expectedAnchor: expectedAnchor, vaultID: vaultID)
    }
  }
}
