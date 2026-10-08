import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Separate owner/joiner local state over actual immutable filesystem output.
/// Private operations use owned software Mac identities, never a real token.
struct V3RecoveryEnrollmentAdoptionTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Enrollment = V3RecoveryDeviceEnrollmentPublisherTests
  private typealias Stop = Publication.Stop
  private static let phases: [V3EnrollmentAdoptionPhase] = [
    .approvalVerified, .checkpointInstalled, .ceremonyConsumed,
  ]

  @Test(arguments: [false, true])
  func joinsActualOwnerApprovalAndCanSaveWithoutRecoveryOperations(empty: Bool) throws {
    let f = try Fixture(empty: empty)
    defer { f.owner.disk.remove() }
    let result = try adopt(f)
    #expect(result.envelope == f.envelope && result.checkpoint == f.checkpoint)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(try f.state().phase == .consumed && f.local.consumptions == 1)
    #expect(
      try f.session.load(vaultID: Core.vaultID, keyID: f.envelope.body.fields.keyID) == f.key)
    #expect(f.owner.joiner.unwraps == 1 && f.owner.joiner.signatures == 1)
    #expect(f.owner.disk.core.owner.signatures == f.owner.signatures + 1)
    #expect(try f.owner.disk.cache.load(for: f.checkpoint) == .available(f.envelope.canonicalBytes))
    // Shared publication is unchanged by adoption itself. Ordinary writes use
    // only the joined session and independently guarded publisher afterward.
    let ordinary = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: f.session, objectStore: f.owner.disk.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption,
      cache: f.owner.disk.cache)
    try ordinary.add(name: "after/join", secret: "continued", type: .secret, operationID: .init())
    #expect(f.owner.joiner.unwraps == 1 && f.owner.joiner.signatures == 1)
  }

  @Test func warmRepeatIsExactIdempotentWithoutAnotherPrivateOperation() throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    let result = try adopt(f)
    #expect(try adopt(f) == result)
    #expect(f.owner.joiner.unwraps == 1 && f.local.consumptions == 1)
    f.session.invalidate()
    #expect(try adopt(f) == result)
    #expect(f.owner.joiner.unwraps == 2 && f.local.consumptions == 1)
  }

  @Test(arguments: [false, true])
  func joinedMacSaveRemainsRecoverableByPrimaryAndBackup(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    _ = try adopt(f)
    try V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: f.session, objectStore: f.owner.disk.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption,
      cache: f.owner.disk.cache
    ).edit(name: "fixture/secret", secret: "after joining", type: .secret, operationID: .init())
    f.session.invalidate()
    for entry in Array(f.owner.disk.entries.values) + Array(f.owner.disk.core.entries.values) {
      try FileManager.default.removeItem(at: f.owner.disk.entryURL(entry))
    }
    let recipient = try #require(f.owner.disk.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.owner.disk.core.parent.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
    let anchor = backup ? backupAnchor : f.owner.disk.anchor
    let token = backup ? f.owner.disk.core.backupToken : f.owner.disk.core.token
    let selected = try V3RecoveryHistorySelector(source: f.owner.disk.store).select(
      anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: f.owner.disk.store).open(
      selected, boundAnchor: anchor, receiver: receiver)
    #expect(calls.value == 1 && f.owner.joiner.unwraps == 1 && f.owner.joiner.signatures == 1)
    #expect(opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "after joining")
    #expect(opened.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
  }

  @Test(arguments: [false, true])
  func mismatchedLocalMessageSignaturesFailBeforePrivateOperation(joinRequest: Bool) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    let state = try f.state()
    let join = try #require(state.signedJoinRequest)
    let invalid = try V3EnrollmentMessageAuthentication(
      signerDeviceID: joinRequest
        ? f.owner.joiner.publicIdentity.deviceID
        : f.owner.disk.core.owner.publicIdentity.deviceID,
      signature: Data(repeating: 0, count: 64))
    f.local.value = try V3EnrollmentCeremonyState(
      vaultID: Core.vaultID, invitationDigest: state.invitationDigest, role: .joiner,
      phase: .awaitingComparison,
      signedInvitation: joinRequest
        ? state.signedInvitation
        : .init(invitation: state.signedInvitation.invitation, authentication: invalid),
      signedJoinRequest: joinRequest
        ? .init(joinRequest: join.joinRequest, authentication: invalid) : join
    ).canonicalBytes
    #expect(throws: V3EnrollmentAuthenticationError.invalidSignature) { try adopt(f) }
    #expect(f.owner.joiner.unwraps == 0 && f.checkpoints.value == nil)
  }

  @Test(arguments: 0..<3)
  func interruptionRetainsOnlyExactLocalTrustAndColdRetryFinishes(phase: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    #expect(throws: Stop.interrupted) {
      try adopt(f, observer: Observer { if $0 == Self.phases[phase] { throw Stop.interrupted } })
    }
    #expect(!f.session.hasResidentKey && f.owner.joiner.unwraps == 1)
    #expect(f.checkpoints.value == (phase == 0 ? nil : f.checkpoint.canonicalBytes))
    #expect(try f.state().phase == (phase == 2 ? .consumed : .awaitingComparison))
    #expect(try adopt(f).checkpoint == f.checkpoint)
    #expect(f.owner.joiner.unwraps == 2 && f.local.consumptions == 1)
    #expect(f.ownership.value == nil && f.registration.value == nil && f.adoption.value == nil)
  }

  @Test(arguments: 0..<3)
  func localWriteFailureNeverInstallsSessionAndCanRetry(variant: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    f.checkpoints.rejectAdvance = variant == 0
    f.local.rejectConsume = variant == 1
    #expect(throws: Stop.interrupted) {
      try adopt(f, cache: variant == 2 ? FailingCache(base: f.owner.disk.cache) : nil)
    }
    #expect(!f.session.hasResidentKey && f.owner.joiner.unwraps == 1)
    #expect(f.checkpoints.value == (variant == 1 ? f.checkpoint.canonicalBytes : nil))
    #expect(try f.state().phase == .awaitingComparison)
    f.checkpoints.rejectAdvance = false
    f.local.rejectConsume = false
    #expect(try adopt(f).checkpoint == f.checkpoint)
  }

  @Test(arguments: 0..<10)
  func comparisonIdentityCheckpointAndPendingGuardsRunBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    if variant == 0 { f.local.value = nil }
    if variant == 1 { f.local.value = Data([1]) }
    if variant == 2 { f.local.value = f.owner.state.canonicalBytes }
    if variant == 3 { f.checkpoints.value = f.owner.disk.checkpoint.canonicalBytes }
    if variant == 4 { f.ownership.value = Data([1]) }
    if variant == 5 { f.registration.value = Data([1]) }
    if variant == 6 { f.adoption.value = Data([1]) }
    let checkpoint = f.checkpoints.value
    let state = f.local.value
    let wrongIdentity = try Core.Owner()
    #expect(throws: (any Error).self) {
      try adopt(
        f, digest: variant == 7 ? Data(repeating: 1, count: 32) : nil,
        invitation: variant == 8 ? Data([1]) : nil,
        identity: variant == 9 ? wrongIdentity : nil)
    }
    #expect(f.owner.joiner.unwraps == 0 && wrongIdentity.unwraps == 0 && !f.session.hasResidentKey)
    #expect(f.checkpoints.value == checkpoint && f.local.value == state)
    #expect(f.ownership.value == (variant == 4 ? Data([1]) : nil))
  }

  @Test func cancelledMacAuthenticationHasNoLocalTrustAndNoRetry() throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    f.owner.joiner.cancelUnwrap = true
    #expect(throws: Core.FixtureError.cancelled) { try adopt(f) }
    #expect(f.owner.joiner.unwraps == 1 && f.checkpoints.value == nil && !f.session.hasResidentKey)
    #expect(try f.state().phase == .awaitingComparison)
  }

  @Test func incorrectProviderResultFailsCurrentAuthenticationWithoutInstallingTrust() throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    #expect(throws: (any Error).self) {
      try adopt(f, identity: IncorrectUnwrapper(base: f.owner.joiner))
    }
    #expect(f.owner.joiner.unwraps == 1 && f.checkpoints.value == nil && !f.session.hasResidentKey)
  }

  @Test(arguments: 0..<8)
  func changesDuringWrapperOperationCannotInstallOrConsume(variant: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    f.owner.joiner.onUnwrap = {
      switch variant {
      case 0: f.session.invalidate()
      case 1:
        try f.session.install(f.key, vaultID: Core.vaultID, keyID: f.envelope.body.fields.keyID)
      case 2: f.local.value = nil
      case 3: f.ownership.value = Data([1])
      case 4: f.registration.value = Data([1])
      case 5: f.adoption.value = Data([1])
      case 6: f.checkpoints.value = f.owner.disk.checkpoint.canonicalBytes
      default: try f.addNewerHead()
      }
    }
    #expect(throws: (any Error).self) { try adopt(f) }
    #expect(f.owner.joiner.unwraps == 1 && !f.session.hasResidentKey)
    #expect(f.checkpoints.value == (variant == 6 ? f.owner.disk.checkpoint.canonicalBytes : nil))
    #expect(f.local.consumptions == 0)
  }

  @Test(arguments: 0..<3)
  func lockAtEachLocalBoundaryNeverRevivesSession(phase: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try adopt(f, observer: Observer { if $0 == Self.phases[phase] { f.session.invalidate() } })
    }
    #expect(!f.session.hasResidentKey && f.owner.joiner.unwraps == 1)
    #expect(f.checkpoints.value == (phase == 0 ? nil : f.checkpoint.canonicalBytes))
    #expect(try adopt(f).checkpoint == f.checkpoint)
  }

  @Test(arguments: 0..<4)
  func missingApprovalParentOrCurrentCiphertextRefusesBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    if variant == 0 {
      try FileManager.default.removeItem(at: f.owner.disk.manifestURL(f.envelope.digest))
    } else if variant == 1 {
      try FileManager.default.removeItem(at: f.owner.disk.manifestURL(f.owner.disk.parent.digest))
    } else if variant == 2 {
      try FileManager.default.removeItem(
        at: f.owner.disk.entryURL(try #require(f.currentEntries.values.first)))
    } else {
      try f.addNewerHead()
    }
    #expect(throws: (any Error).self) { try adopt(f) }
    #expect(f.owner.joiner.unwraps == 0 && f.checkpoints.value == nil && !f.session.hasResidentKey)
    #expect(try f.state().phase == .awaitingComparison)
  }

  @Test func obsoleteCiphertextIsNotNeededForJoiningOrColdRetry() throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    for entry in f.owner.disk.entries.values {
      try FileManager.default.removeItem(at: f.owner.disk.entryURL(entry))
    }
    for entry in f.owner.disk.core.entries.values {
      try FileManager.default.removeItem(at: f.owner.disk.entryURL(entry))
    }
    #expect(try adopt(f).checkpoint == f.checkpoint)
    f.session.invalidate()
    #expect(try adopt(f).checkpoint == f.checkpoint)
    #expect(f.owner.joiner.unwraps == 2)
  }

  @Test func twoIndividuallyValidApprovalsForSameComparisonAreNeverChosenBetween() throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    let alternate = try V3RecoveryDeviceEnrollmentBuilder().build(
      checkpoint: f.owner.disk.checkpoint, parent: f.owner.disk.parent,
      currentEntries: f.owner.disk.entries, state: f.owner.state,
      currentVaultKey: Core.nextKey, nextVaultKey: Data(repeating: 0x72, count: 32),
      owner: f.owner.disk.core.owner, at: 4_102_444_800, reason: "Owned software fixture")
    try f.owner.disk.seed(alternate.envelope, entries: alternate.stagedEntries)
    #expect(throws: V3RecoveryEnrollmentAdoptionError.ambiguousApproval) { try adopt(f) }
    #expect(f.owner.joiner.unwraps == 0 && f.checkpoints.value == nil)
  }

  @Test(arguments: 0..<7)
  func invalidInventoryNeverReachesAuthentication(variant: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    #expect(throws: (any Error).self) {
      try adopt(f, source: InvalidListing(base: f.owner.disk.store, variant: variant))
    }
    #expect(f.owner.joiner.unwraps == 0 && f.checkpoints.value == nil)
  }

  @Test(arguments: 0..<6)
  func objectDepthAndSnapshotBudgetsFailBeforePrivateOperation(variant: Int) throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    let largestManifest = max(
      f.envelope.canonicalBytes.count, f.owner.disk.parent.canonicalBytes.count)
    let entryBytes = try #require(f.currentEntries.values.first).canonicalBytes.count
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: variant == 0 ? 1 : 4_096,
      maximumHistoryDepth: variant == 1 ? 0 : 1_024,
      maximumReferencedEntryObjects: variant == 2 ? 1 : 16_384,
      maximumManifestBytes: variant == 3 ? 1 : largestManifest,
      maximumEntryBytes: variant == 4 ? 1 : entryBytes,
      maximumTotalManifestBytes: variant == 5 ? largestManifest : 64 * 1_024 * 1_024,
      maximumTotalEntryBytes: 256 * 1_024 * 1_024)
    #expect(throws: (any Error).self) { try adopt(f, limits: limits) }
    #expect(f.owner.joiner.unwraps == 0 && f.checkpoints.value == nil)
  }

  @Test func unrelatedResidentSessionIsNotSilentlyReplacedByJoining() throws {
    let f = try Fixture()
    defer { f.owner.disk.remove() }
    try f.session.install(
      Core.nextKey, vaultID: Core.vaultID, keyID: f.owner.disk.parent.body.fields.keyID)
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) { try adopt(f) }
    #expect(f.owner.joiner.unwraps == 0 && f.checkpoints.value == nil && !f.session.hasResidentKey)
  }

  private struct Fixture: Sendable {
    let owner: Enrollment.Fixture
    let envelope: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let key: Data
    let currentEntries: [V3EntryObjectKey: V3EncryptedEntry]
    let local: Enrollment.StateStore
    let checkpoints: Publication.Checkpoints
    let ownership = Publication.Ownership()
    let registration = Publication.Ownership()
    let adoption = Publication.Ownership()
    let session = V3DeviceWrappedVaultKeySessionStore()
    init(empty: Bool = false) throws {
      owner = try Enrollment.Fixture(empty: empty)
      let ownerSession = V3DeviceWrappedVaultKeySessionStore()
      try ownerSession.install(
        Core.nextKey, vaultID: Core.vaultID, keyID: owner.disk.parent.body.fields.keyID)
      let commit = try V3RecoveryEnrollmentOwnerService(
        vaultID: Core.vaultID, identity: owner.disk.core.owner, session: ownerSession,
        objectStore: owner.disk.store, checkpointStore: owner.disk.checkpoints,
        recoveryAnchorStore: owner.disk.ownership, registrationAnchorStore: owner.disk.registration,
        adoptionAnchorStore: owner.disk.adoption, ceremonyStore: owner.local,
        cache: owner.disk.cache
      ).approve(
        invitationDigest: owner.state.invitationDigest,
        approvedTranscriptDigest: #require(owner.state.transcript?.digest),
        expectedCheckpoint: owner.disk.checkpoint, at: 4_102_444_800, operationID: .init())
      envelope = commit.envelope
      checkpoint = commit.checkpoint
      key = try ownerSession.load(vaultID: Core.vaultID, keyID: envelope.body.fields.keyID)
      currentEntries = try V3ExactTransitionRepository(source: owner.disk.store, limits: .standard)
        .observe(checkpoint: checkpoint, expectedBase: envelope.canonicalBytes).entries
      let joinerState = try V3EnrollmentCeremonyState(
        vaultID: Core.vaultID, invitationDigest: owner.state.invitationDigest, role: .joiner,
        phase: .awaitingComparison, signedInvitation: owner.state.signedInvitation,
        signedJoinRequest: owner.state.signedJoinRequest)
      local = Enrollment.StateStore(joinerState.canonicalBytes)
      checkpoints = Publication.Checkpoints(checkpoint.canonicalBytes)
      checkpoints.value = nil
    }
    func state() throws -> V3EnrollmentCeremonyState {
      try .init(canonicalBytes: #require(local.value))
    }
    func addNewerHead() throws {
      let next = try V3RecoveryContentMutationBuilder().build(
        .add(
          entryID: UUID().uuidString.lowercased(), name: "newer", type: .secret, plaintext: "later"),
        checkpoint: checkpoint, parent: envelope, currentEntries: currentEntries, vaultKey: key)
      try owner.disk.seed(next.envelope, entries: next.stagedEntries)
    }
  }

  private func adopt(
    _ f: Fixture, digest: Data? = nil, invitation: Data? = nil,
    identity: (any V3DeviceWrappedVaultKeyUnwrapping)? = nil,
    source: (any V3ImmutableObjectReading)? = nil, cache: (any V3CheckpointManifestCaching)? = nil,
    limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3EnrollmentAdoptionPhaseObserving = V3RecoveryEnrollmentNoopAdoptionObserver()
  ) throws -> V3RecoveryEnrollmentAdoptionCommit {
    try V3RecoveryEnrollmentAdoptionService(
      vaultID: Core.vaultID, identity: identity ?? f.owner.joiner,
      source: source ?? f.owner.disk.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.ownership,
      registrationAnchorStore: f.registration, adoptionAnchorStore: f.adoption,
      ceremonyStore: f.local, cache: cache ?? f.owner.disk.cache, session: f.session,
      limits: limits, phaseObserver: observer
    ).adopt(
      invitationDigest: invitation ?? f.owner.state.invitationDigest,
      approvedTranscriptDigest: try digest ?? #require(f.owner.state.transcript?.digest),
      operationID: .init())
  }

  private struct Observer: V3EnrollmentAdoptionPhaseObserving {
    let action: @Sendable (V3EnrollmentAdoptionPhase) throws -> Void
    init(_ action: @escaping @Sendable (V3EnrollmentAdoptionPhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3EnrollmentAdoptionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      try action(phase)
    }
  }
  private struct FailingCache: V3CheckpointManifestCaching {
    let base: any V3CheckpointManifestCaching
    func load(for checkpoint: V3ManifestCheckpoint) throws -> V3CheckpointManifestCacheLookup {
      try base.load(for: checkpoint)
    }
    func store(_: Data, for _: V3ManifestCheckpoint) throws { throw Stop.interrupted }
  }
  private struct IncorrectUnwrapper: V3DeviceWrappedVaultKeyUnwrapping {
    let base: Core.Owner
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      _ = try base.unwrapDeviceWrappedVaultKey(wrappedKey, context: context, reason: reason)
      return Core.nextKey
    }
  }
  private struct InvalidListing: V3ImmutableObjectReading {
    let base: any V3ImmutableObjectReading
    let variant: Int
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      guard
        case .available(let digests, let count) = try base.manifestDigests(
          maximumCount: maximumCount)
      else { throw Stop.interrupted }
      switch variant {
      case 0: return .available(digests: digests + [digests[0]], objectCount: count + 1)
      case 1: return .available(digests: [Data([1])], objectCount: 1)
      case 2: return .available(digests: digests, objectCount: 0)
      case 3: return .available(digests: digests, objectCount: maximumCount + 1)
      case 4: return .unavailable
      case 5: return .invalid
      default: return .limitExceeded
      }
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try base.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try base.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
    }
  }
}
