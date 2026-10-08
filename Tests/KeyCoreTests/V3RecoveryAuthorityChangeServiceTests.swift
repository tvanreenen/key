import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Actual epoch cryptography, random keys, in-memory sessions and contained
/// filesystem publication. Only local failures and Mac identity UI are scripted.
struct V3RecoveryAuthorityChangeServiceTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Revocation = V3RecoveryDeviceRevocationPublisherTests
  private typealias Stop = Publication.Stop
  enum Action: CaseIterable, Sendable { case revoke, remove, removeLast }
  enum Review {
    case device(V3DeviceWrappedRevocationPlan)
    case recipient(V3RecoveryRecipientRemovalPlan)
  }
  struct Commit {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
  }
  private static let phases: [V3ImmutableTransactionPhase] = [
    .recoveryAnchorPrepared, .recoveryIntentPersisted, .recoveryArmed,
    .entryStaged(index: 0), .entryStaged(index: 1), .manifestStaged,
    .repositoryStateRechecked, .entryPublished(index: 0), .entryPublished(index: 1),
    .publishedEntriesValidated, .manifestPublished, .publishedManifestValidated,
    .checkpointAdvanced, .cleanupCompleted,
  ]

  @Test(arguments: Action.allCases)
  func preparesAuthenticatedReviewWithoutPrivateOperationsOrReservation(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    _ = try f.prepare(service(f, session: session))
    #expect(f.owner.signatures == f.signatures && f.owner.unwraps == f.unwraps)
    #expect(
      f.disk.ownership.value == nil && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
  }

  @Test(arguments: Action.allCases, [false, true])
  func installsFreshAuthenticatedSessionAndOrdinarySaveContinues(action: Action, empty: Bool) throws
  {
    let f = try Fixture(action, empty: empty)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    let review = try f.prepare(s)
    let owner = VaultTransactionMutationOwner()
    let commit = try owner.perform(action == .revoke ? .revokeDevice : .removeRecoveryRecipient) {
      c in
      try f.execute(s, review: review, operationID: c.operationID)
    }
    let key = try session.load(vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID)
    #expect(key.count == 32 && key != f.key)
    #expect(
      f.disk.checkpoints.value == commit.checkpoint.canonicalBytes && f.disk.ownership.value == nil)
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
    switch review {
    case .device(let plan):
      #expect(commit.envelope.body.fields.devices == plan.resultingDevices)
      #expect(commit.envelope.body.recovery.recipients == f.parent.body.recovery.recipients)
      #expect(commit.envelope.body.recovery.generationID == f.parent.body.recovery.generationID)
      #expect(commit.envelope.body.recovery.wrappedKeys != f.parent.body.recovery.wrappedKeys)
      #expect(
        !commit.envelope.body.fields.wrappedKeys.contains {
          $0.recipientDeviceID == plan.revokedDevice.identity.deviceID
        })
    case .recipient(let plan):
      #expect(commit.envelope.body.recovery.recipients == plan.resultingRecipients)
      #expect(commit.envelope.body.recovery.generationID != f.parent.body.recovery.generationID)
      #expect(commit.envelope.body.fields.devices == f.parent.body.fields.devices)
      #expect(commit.envelope.body.recovery.wrappedKeys.isEmpty == (action == .removeLast))
      #expect(
        commit.envelope.body.recovery.recipients.filter { $0.status == .active }.isEmpty
          == (action == .removeLast))
    }
    try owner.perform(.addEntry) { c in
      try ordinary(f, session: session).add(
        name: "after/access-change", secret: "still saving", type: .secret,
        operationID: c.operationID)
    }
    let current = try current(f)
    #expect(current.envelope.parents == [commit.envelope.digest])
    #expect(current.envelope.body.fields.keyID == commit.envelope.body.fields.keyID)
    #expect(current.envelope.body.recovery == commit.envelope.body.recovery)
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
    if action != .removeLast {
      try assertSoftwareRecovery(f, expected: "still saving")
    } else {
      #expect(throws: (any Error).self) {
        try V3RecoveryHistorySelector(source: f.disk.store).select(
          anchor: f.disk.anchor, credentialPublicKey: f.disk.core.token.publicKey.x963Representation
        )
      }
    }
  }

  @Test(arguments: Action.allCases, 0..<14)
  func everyBoundaryRetainsOldSessionOrLocksAfterCommit(action: Action, phase: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(
      f, session: session,
      observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
    let review = try f.prepare(s)
    #expect(throws: Stop.interrupted) { try f.execute(s, review: review) }
    if phase < 12 {
      #expect(f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
      #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
    } else {
      #expect(f.disk.checkpoints.value != f.checkpoint.canonicalBytes && !session.hasResidentKey)
    }
    #expect((f.disk.ownership.value != nil) == (phase != 13))
    if phase != 13 {
      #expect(throws: (any Error).self) {
        try f.execute(service(f, session: session), review: review)
      }
    }
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: Action.allCases)
  func failedCheckpointCASKeepsOldSessionAndExactPendingOperation(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    let review = try f.prepare(s)
    f.disk.checkpoints.rejectAdvance = true
    #expect(throws: Stop.interrupted) { try f.execute(s, review: review) }
    #expect(f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
    let anchor = try V3ImmutableTransactionRecoveryAnchor(
      canonicalBytes: #require(f.disk.ownership.value))
    #expect(anchor.operationID == f.disk.operationID)
  }

  @Test(arguments: Action.allCases)
  func cleanupFailureCanInstallOnlyExactCommittedSession(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    let review = try f.prepare(s)
    f.disk.ownership.rejectClear = true
    let commit = try f.execute(s, review: review)
    #expect(
      f.disk.ownership.value != nil && f.disk.checkpoints.value == commit.checkpoint.canonicalBytes)
    #expect(
      try session.load(vaultID: Core.vaultID, keyID: commit.envelope.body.fields.keyID).count == 32)
    #expect(throws: (any Error).self) { try f.prepare(s) }
    #expect(throws: (any Error).self) {
      try ordinary(f, session: session).add(
        name: "blocked", secret: "value", type: .secret, operationID: .init())
    }
  }

  @Test(arguments: Action.allCases, [false, true])
  func signingOrWrapperCancellationDoesNotReserveOrReplaceSession(action: Action, signing: Bool)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    let review = try f.prepare(s)
    f.owner.cancelSigning = signing
    f.owner.cancelUnwrap = !signing
    #expect(throws: Core.FixtureError.cancelled) { try f.execute(s, review: review) }
    #expect(
      f.disk.ownership.value == nil && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
    #expect(
      f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + (signing ? 0 : 1))
  }

  @Test(arguments: Action.allCases, 0..<8)
  func invalidSourceSessionIdentityAndPendingWorkRefuseBeforePrivateOperations(
    action: Action, variant: Int
  ) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let review = try f.prepare(service(f, session: session))
    switch variant {
    case 0: session.invalidate()
    case 1: f.disk.ownership.value = Data([1])
    case 2: f.disk.registration.value = Data([1])
    case 3: f.disk.adoption.value = Data([1])
    case 4:
      try FileManager.default.removeItem(at: f.disk.entryURL(try #require(f.entries.values.first)))
    case 5: try f.addBranch()
    default: break
    }
    let pending = f.disk.ownership.value
    let s = service(
      f, session: session,
      identity: variant == 6 ? try Core.Owner() : nil,
      vaultID: variant == 7 ? UUID().uuidString.lowercased() : Core.vaultID)
    #expect(throws: (any Error).self) { try f.prepare(s) }
    #expect(throws: (any Error).self) { try f.execute(s, review: review) }
    #expect(f.owner.signatures == f.signatures && f.owner.unwraps == f.unwraps)
    #expect(
      f.disk.ownership.value == pending && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
  }

  @Test(arguments: Action.allCases)
  func wrongMacWrapperResultCannotReserveOrReplaceSession(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let review = try f.prepare(service(f, session: session))
    let identity = SigningObserverIdentity(
      base: f.owner, unwrapOverride: Data(repeating: 0, count: 32)
    ) {}
    #expect(throws: (any Error).self) {
      try f.execute(service(f, session: session, identity: identity), review: review)
    }
    #expect(
      f.disk.ownership.value == nil && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: Action.allCases, 0..<3)
  func changedIndependentReviewRefusesBeforeSigning(action: Action, variant: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    let review = try f.prepare(s)
    let wrongCheckpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 0x99, count: 32))
    let otherOwner = try Core.Owner()
    let wrong: Review
    switch review {
    case .device(let p):
      wrong = .device(
        .init(
          expectedCheckpoint: variant == 0 ? wrongCheckpoint : p.expectedCheckpoint,
          authorizingDevice: variant == 1
            ? .init(identity: otherOwner.publicIdentity, status: .active) : p.authorizingDevice,
          revokedDevice: p.revokedDevice,
          resultingDevices: variant == 2 ? f.parent.body.fields.devices : p.resultingDevices))
    case .recipient(let p):
      wrong = .recipient(
        .init(
          expectedCheckpoint: variant == 0 ? wrongCheckpoint : p.expectedCheckpoint,
          authorizingDevice: variant == 1
            ? .init(identity: otherOwner.publicIdentity, status: .active) : p.authorizingDevice,
          removedRecipient: p.removedRecipient,
          resultingRecipients: variant == 2
            ? f.parent.body.recovery.recipients : p.resultingRecipients))
    }
    #expect(throws: (any Error).self) { try f.execute(s, review: wrong) }
    #expect(
      f.disk.ownership.value == nil && f.disk.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.owner.signatures == f.signatures && f.owner.unwraps == f.unwraps)
  }

  @Test(arguments: 0..<3)
  func missingMismatchedOrUnexpectedProtectionLossAcknowledgementRefusesBeforeSigning(variant: Int)
    throws
  {
    let f = try Fixture(variant == 2 ? .remove : .removeLast)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    guard case .recipient(let plan) = try f.prepare(s) else { throw Stop.interrupted }
    let otherOwner = try Core.Owner()
    let wrongPlan = V3RecoveryRecipientRemovalPlan(
      expectedCheckpoint: plan.expectedCheckpoint,
      authorizingDevice: variant == 1
        ? .init(identity: otherOwner.publicIdentity, status: .active) : plan.authorizingDevice,
      removedRecipient: plan.removedRecipient,
      resultingRecipients: try plan.resultingRecipients.map {
        try .init(
          registrationID: $0.registrationID, publicKey: $0.publicKey, slot: $0.slot,
          status: .revoked)
      })
    let acknowledgement =
      try variant == 0 ? nil : V3RecoveryProtectionLossAcknowledgement(plan: wrongPlan)
    #expect(throws: (any Error).self) {
      try s.remove(
        plan, operationID: f.disk.operationID, protectionLossAcknowledgement: acknowledgement)
    }
    #expect(
      f.owner.signatures == f.signatures && f.owner.unwraps == f.unwraps
        && f.disk.ownership.value == nil)
  }

  @Test(arguments: Action.allCases, 0..<7)
  func changesDuringSigningStopBeforeWrapperVerification(action: Action, variant: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let review = try f.prepare(service(f, session: session))
    let identity = SigningObserverIdentity(base: f.owner) {
      switch variant {
      case 0: try f.addBranch()
      case 1: f.disk.registration.value = Data([1])
      case 2: f.disk.adoption.value = Data([1])
      case 3: f.disk.checkpoints.value = Data([1])
      case 4: session.invalidate()
      case 5:
        session.invalidate()
        try session.install(f.key, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
      default: f.disk.ownership.value = Data([1])
      }
    }
    #expect(throws: (any Error).self) {
      try f.execute(service(f, session: session, identity: identity), review: review)
    }
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps)
    #expect(f.disk.ownership.value == (variant == 6 ? Data([1]) : nil))
    if variant == 3 || variant == 4 { #expect(!session.hasResidentKey) }
    if variant == 5 {
      #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == f.key)
    }
  }

  @Test(arguments: Action.allCases, [false, true])
  func lockOrSameKeyReauthenticationDuringWrapperCannotBeUndone(action: Action, reinstall: Bool)
    throws
  {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(f, session: session)
    let review = try f.prepare(s)
    f.owner.onUnwrap = {
      session.invalidate()
      if reinstall {
        try session.install(f.key, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
      }
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try f.execute(s, review: review)
    }
    #expect(
      f.disk.checkpoints.value != f.checkpoint.canonicalBytes && f.disk.ownership.value == nil)
    #expect(!session.hasResidentKey && f.owner.unwraps == f.unwraps + 1)
  }

  @Test(arguments: Action.allCases, 0..<6)
  func changedPostCommitStateLocksWithoutRollback(action: Action, variant: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(
      f, session: session,
      observer: Observer {
        if $0 == .cleanupCompleted {
          switch variant {
          case 0: f.disk.registration.value = Data([1])
          case 1: f.disk.adoption.value = Data([1])
          case 2: try f.addBranch()
          case 3: f.disk.checkpoints.value = nil
          case 4: f.disk.ownership.value = Data([1])
          default:
            f.disk.ownership.value = try V3ImmutableTransactionRecoveryAnchor(
              operationID: .init(), vaultID: Core.vaultID,
              intentDigest: Data(repeating: 1, count: 32), phase: .recoverable
            ).canonicalBytes
          }
        }
      })
    let review = try f.prepare(s)
    #expect(throws: (any Error).self) { try f.execute(s, review: review) }
    #expect(f.disk.checkpoints.value != f.checkpoint.canonicalBytes && !session.hasResidentKey)
    #expect(f.owner.signatures == f.signatures + 1 && f.owner.unwraps == f.unwraps + 1)
    #expect((f.disk.ownership.value != nil) == (variant >= 4))
  }

  @Test(arguments: Action.allCases)
  func missingCommittedSnapshotLocksAndRetainsPendingWork(action: Action) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let s = service(
      f, session: session,
      observer: Observer {
        if $0 == .checkpointAdvanced {
          let commit = try Self.current(f)
          let record = try #require(commit.envelope.body.fields.entries.first)
          let data = try V3ExactTransitionRepository(source: f.disk.store, limits: .standard)
            .readEntry(Core.Fixture.address(record))
          try FileManager.default.removeItem(at: f.disk.entryURL(try V3EntryCipher().parse(data)))
          f.disk.ownership.rejectClear = true
        }
      })
    let review = try f.prepare(s)
    #expect(throws: (any Error).self) { try f.execute(s, review: review) }
    #expect(
      f.disk.checkpoints.value != f.checkpoint.canonicalBytes && f.disk.ownership.value != nil)
    #expect(!session.hasResidentKey)
  }

  @Test(arguments: Action.allCases, 0..<3)
  func sourceBoundsRefuseBeforeSigning(action: Action, variant: Int) throws {
    let f = try Fixture(action)
    defer { f.disk.remove() }
    let session = try session(f)
    let review = try f.prepare(service(f, session: session))
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) {
      try f.execute(service(f, session: session, limits: limits), review: review)
    }
    #expect(
      f.disk.ownership.value == nil && f.owner.signatures == f.signatures
        && f.owner.unwraps == f.unwraps)
  }

  struct Fixture: Sendable {
    let action: Action
    let disk: V3RecoveryContentMutationPublisherTests.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let key: Data
    let deviceID: String?
    let signatures: Int
    let unwraps: Int
    var owner: V3RecoveryRegistrationTests.Owner { disk.core.owner }
    init(_ action: Action, empty: Bool = false) throws {
      self.action = action
      if action == .revoke {
        let f = try Revocation.Fixture(empty: empty)
        disk = f.enrollment.disk
        parent = f.parent
        checkpoint = f.checkpoint
        entries = f.entries
        key = f.currentKey
        deviceID = f.enrollment.joiner.publicIdentity.deviceID
      } else {
        disk = try Publication.Fixture(empty: empty, backup: action != .removeLast)
        parent = disk.parent
        checkpoint = disk.checkpoint
        entries = disk.entries
        key = Core.nextKey
        deviceID = nil
      }
      signatures = disk.core.owner.signatures
      unwraps = disk.core.owner.unwraps
    }
    func prepare(_ service: V3RecoveryAuthorityChangeService) throws -> Review {
      if let deviceID { return .device(try service.prepareRevocation(revoking: deviceID)) }
      return .recipient(try service.prepareRemoval(removing: disk.anchor.recipientID))
    }
    func execute(
      _ service: V3RecoveryAuthorityChangeService, review: Review,
      operationID: VaultTransactionOperationID? = nil
    ) throws -> Commit {
      switch review {
      case .device(let p):
        let c = try service.revoke(p, operationID: operationID ?? disk.operationID)
        return .init(checkpoint: c.checkpoint, envelope: c.envelope)
      case .recipient(let p):
        let c = try service.remove(
          p, operationID: operationID ?? disk.operationID,
          protectionLossAcknowledgement: p.removesLastActiveRecipient ? .init(plan: p) : nil)
        return .init(checkpoint: c.checkpoint, envelope: c.envelope)
      }
    }
    func addBranch() throws {
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "different branch"),
        checkpoint: checkpoint, parent: parent, currentEntries: entries, vaultKey: key)
      try disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
  }

  private func session(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(f.key, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    return session
  }
  private func service(
    _ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore,
    identity: V3RecoveryAuthorityChangeService.Identity? = nil, vaultID: String = Core.vaultID,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
  ) -> V3RecoveryAuthorityChangeService {
    .init(
      vaultID: vaultID, identity: identity ?? f.owner, session: session,
      objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
      recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache, limits: limits, phaseObserver: observer)
  }
  private func ordinary(_ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore)
    -> V3RecoveryVaultMutationService
  {
    .init(
      vaultID: Core.vaultID, session: session, objectStore: f.disk.store,
      checkpointStore: f.disk.checkpoints, recoveryAnchorStore: f.disk.ownership,
      registrationAnchorStore: f.disk.registration, adoptionAnchorStore: f.disk.adoption,
      cache: f.disk.cache)
  }
  private static func current(_ f: Fixture) throws -> Commit {
    let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(f.disk.checkpoints.value))
    return .init(
      checkpoint: checkpoint,
      envelope: try V3RecoveryManifestCodec().parseEnvelope(
        Data(contentsOf: f.disk.manifestURL(checkpoint.envelopeDigest))))
  }
  private func current(_ f: Fixture) throws -> Commit { try Self.current(f) }
  private func assertSoftwareRecovery(_ f: Fixture, expected: String) throws {
    guard #available(macOS 26.0, *) else { return }
    let backup = try #require(f.disk.core.parent.body.recovery.recipients.first)
    let anchor =
      f.action == .revoke
      ? f.disk.anchor
      : try V3RecoveryAnchor(
        floor: .init(vaultID: Core.vaultID, envelopeDigest: f.disk.core.parent.digest),
        recipientID: backup.recipientID, registrationID: backup.registrationID, slot: .keyManagement
      )
    let token = f.action == .revoke ? f.disk.core.token : f.disk.core.backupToken
    let selection = try V3RecoveryHistorySelector(source: f.disk.store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: f.disk.store).open(
      selection, boundAnchor: anchor, receiver: receiver)
    #expect(calls.value == 1)
    #expect(opened.entries.first { $0.name == "after/access-change" }?.plaintext == expected)
    if f.action == .remove {
      #expect(throws: (any Error).self) {
        try V3RecoveryHistorySelector(source: f.disk.store).select(
          anchor: f.disk.anchor, credentialPublicKey: f.disk.core.token.publicKey.x963Representation
        )
      }
    }
  }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3ImmutableTransactionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    { try action(phase) }
  }
  private struct SigningObserverIdentity: V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
  {
    let base: Core.Owner
    let unwrapOverride: Data?
    let action: @Sendable () throws -> Void
    init(
      base: Core.Owner, unwrapOverride: Data? = nil, action: @escaping @Sendable () throws -> Void
    ) {
      self.base = base
      self.unwrapOverride = unwrapOverride
      self.action = action
    }
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func signature(for input: Data, reason: String) throws -> Data {
      let result = try base.signature(for: input, reason: reason)
      try action()
      return result
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      let key = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      return unwrapOverride ?? key
    }
  }
}
