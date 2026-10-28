import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryDeviceRevocationProductTests {
  private typealias Core = V3RecoveryRegistrationTestSupport
  private typealias Disk = V3RecoveryPublicationTestSupport
  private typealias Revocation = V3RecoveryRevocationTestSupport

  @Test func reviewedCommandRevokesOnlySelectedMacAndKeepsRecoveryAndOrdinaryUse() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.disk.remove() }
    let handler = f.handler()
    let review = try #require(
      handler.handle(.share(.reviewRevocation(deviceID: f.deviceID)))
        .deviceRevocationReview)
    #expect(review.revokedDevice.deviceID == f.deviceID)
    let signatures = f.owner.signatures
    #expect(
      handler.handle(
        .share(
          .revoke(
            deviceID: f.deviceID,
            confirmationToken: review.confirmationToken))
      ).exitCode == EXIT_SUCCESS)
    let current = try f.current()
    #expect(
      current.envelope.body.fields.devices.contains(where: {
        $0.identity.deviceID == f.deviceID && $0.status == .revoked
      }))
    #expect(
      !current.envelope.body.fields.wrappedKeys.contains(where: {
        $0.recipientDeviceID == f.deviceID
      }))
    #expect(current.envelope.body.recovery.recipients == f.fixture.parent.body.recovery.recipients)
    #expect(f.owner.signatures == signatures + 1)
    let repeated = try f.workflow().revokeReviewed(
      deviceID: f.deviceID,
      confirmationToken: review.confirmationToken, operationID: .init())
    #expect(repeated == current.checkpoint && f.owner.signatures == signatures + 1)
    try f.ordinary.add(
      name: "after/revoke", secret: "continued", type: .secret, operationID: .init())
    #expect(try f.current().envelope.body.fields.keyID == current.envelope.body.fields.keyID)
    let recipient = try #require(f.disk.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(
        vaultID: Core.vaultID,
        envelopeDigest: f.disk.core.parent.digest), recipientID: recipient.recipientID,
      registrationID: recipient.registrationID, slot: .keyManagement)
    for (anchor, token) in [
      (f.disk.anchor, f.disk.core.token), (backupAnchor, f.disk.core.backupToken),
    ] {
      let selected = try V3RecoveryHistorySelector(source: f.disk.store).select(
        anchor: anchor, credentialPublicKey: token.publicKey.x963Representation)
      let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
        try token.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: peer)
        )
        .withUnsafeBytes { Data($0) }
      }
      let opened = try V3RecoverySnapshotVerifier(source: f.disk.store).open(
        selected, boundAnchor: anchor, receiver: receiver)
      #expect(
        opened.entries.contains(where: { $0.name == "after/revoke" && $0.plaintext == "continued" })
      )
    }
  }

  @Test func oldTokenCannotAcknowledgeAnUnrelatedLaterHead() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let review = try f.workflow().review(revoking: f.deviceID, operationID: .init())
    _ = try f.workflow().revokeReviewed(
      deviceID: f.deviceID,
      confirmationToken: review.confirmationToken, operationID: .init())
    try f.ordinary.add(name: "later", secret: "retained", type: .secret, operationID: .init())
    let checkpoint = f.disk.checkpoints.value
    let signatures = f.owner.signatures
    #expect(throws: V3DeviceWrappedRevocationWorkflowError.reviewedStateChanged) {
      try f.workflow().revokeReviewed(
        deviceID: f.deviceID,
        confirmationToken: review.confirmationToken, operationID: .init())
    }
    #expect(f.disk.checkpoints.value == checkpoint && f.owner.signatures == signatures)
  }

  @Test func changedReviewStopsBeforeSigningAndAllowsOnlyOrdinaryCatchUpPrefix() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let review = try f.workflow().review(revoking: f.deviceID, operationID: .init())
    let branch = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "newer edit"),
      checkpoint: f.fixture.checkpoint, parent: f.fixture.parent,
      currentEntries: f.fixture.entries, vaultKey: f.fixture.currentKey)
    try f.disk.seed(branch.envelope, entries: branch.stagedEntries)
    let signatures = f.owner.signatures
    #expect(throws: V3DeviceWrappedRevocationWorkflowError.reviewedStateChanged) {
      try f.workflow().revokeReviewed(
        deviceID: f.deviceID,
        confirmationToken: review.confirmationToken, operationID: .init())
    }
    #expect(f.owner.signatures == signatures && f.disk.ownership.value == nil)
    #expect(try f.current().envelope == branch.envelope)
    #expect(
      try f.current().envelope.body.fields.devices.contains(where: {
        $0.identity.deviceID == f.deviceID && $0.status == .active
      }))
  }

  @Test func interruptedRevocationChecksExactTokenBeforePrivateResumeAndNeverSignsAgain() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let review = try f.workflow().review(revoking: f.deviceID, operationID: .init())
    #expect(throws: Disk.Stop.interrupted) {
      try f.workflow(
        observer: Observer {
          if $0 == .manifestStaged { throw Disk.Stop.interrupted }
        }
      ).revokeReviewed(
        deviceID: f.deviceID, confirmationToken: review.confirmationToken,
        operationID: f.disk.operationID)
    }
    let anchor = f.disk.ownership.value
    let signatures = f.owner.signatures
    let unwraps = f.owner.unwraps
    f.session.invalidate()
    #expect(throws: V3DeviceWrappedRevocationWorkflowError.reviewedStateChanged) {
      try f.workflow().revokeReviewed(
        deviceID: f.deviceID,
        confirmationToken: String(repeating: "0", count: 64), operationID: .init())
    }
    #expect(
      f.owner.unwraps == unwraps && f.owner.signatures == signatures
        && f.disk.ownership.value == anchor)
    let pendingReview = try f.workflow().review(revoking: f.deviceID, operationID: .init())
    #expect(pendingReview == review && f.owner.unwraps == unwraps)
    let restored = try f.workflow().revokeReviewed(
      deviceID: f.deviceID,
      confirmationToken: review.confirmationToken, operationID: .init())
    #expect(try f.current().checkpoint == restored && f.disk.ownership.value == nil)
    #expect(f.owner.signatures == signatures && f.owner.unwraps == unwraps + 2)
  }

  @Test func cancelledRequestCannotSignOrPublishAfterAuthentication() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let review = try f.workflow().review(revoking: f.deviceID, operationID: .init())
    f.session.invalidate()
    let signatures = f.owner.signatures
    f.owner.onUnwrap = { f.scope.cancellation.cancel() }
    #expect(throws: (any Error).self) {
      try f.workflow().revokeReviewed(
        deviceID: f.deviceID,
        confirmationToken: review.confirmationToken, operationID: .init())
    }
    #expect(f.owner.signatures == signatures && f.disk.ownership.value == nil)
    #expect(f.disk.checkpoints.value == f.fixture.checkpoint.canonicalBytes)
  }

  private struct Fixture: Sendable {
    let fixture: Revocation.Fixture
    let session = V3DeviceWrappedVaultKeySessionStore()
    let scope = KeyRecoveryRequestScope(authentication: .init(), deadline: .now() + 90)
    var disk: Disk.Fixture { fixture.enrollment.disk }
    var owner: Core.Owner { fixture.owner }
    var deviceID: String { fixture.enrollment.joiner.publicIdentity.deviceID }
    init() throws { fixture = try .init() }
    var unlock: V3RecoveryVaultUnlockRuntime {
      .init(
        vaultID: Core.vaultID, checkpointStore: disk.checkpoints, source: disk.store,
        cache: disk.cache, identityLoader: Loader(owner: owner, scope: scope), session: session,
        transactionOwnershipStore: disk.ownership, registrationOwnershipStore: disk.registration,
        adoptionOwnershipStore: disk.adoption)
    }
    var ordinary: V3RecoveryVaultMutationService {
      .init(
        vaultID: Core.vaultID, session: session, objectStore: disk.store,
        checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
        registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
        cache: disk.cache)
    }
    func current() throws -> V3RecoveryContentCommit {
      let checkpoint = try V3ManifestCheckpoint(canonicalBytes: #require(disk.checkpoints.value))
      return .init(
        checkpoint: checkpoint,
        envelope: try V3RecoveryManifestCodec().parseEnvelope(
          V3ExactTransitionRepository(source: disk.store, limits: .standard).readManifest(
            checkpoint.envelopeDigest)))
    }
    func workflow(
      observer: any V3ImmutableTransactionPhaseObserving = V3NoopContentTransactionPhaseObserver()
    )
      -> V3RecoveryDeviceRevocationWorkflow
    {
      let identity = V3ScopedEnrollmentIdentity(
        base: owner, validate: { try scope.requireCurrent() })
      return .init(
        session: session, loadIdentity: { identity },
        authenticate: { operationID in
          try scope.requireCurrent()
          let context = try unlock.authenticatedReadContext(reason: "Software revocation test")
          let ticket = try context.authenticationTicket()
          let result = try V3RecoveryCatchUpCoordinator(
            mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
            identity: identity, session: session, source: disk.store,
            checkpointStore: disk.checkpoints,
            recoveryAnchorStore: disk.ownership, registrationAnchorStore: disk.registration,
            adoptionAnchorStore: disk.adoption, cache: disk.cache,
            validateScope: { try scope.requireCurrent() }
          ).catchUp(from: context.current, continuing: ticket, allowStale: false)
          guard case .verified(.current(let current, _)) = result.selection else {
            throw VaultUXServiceError.catchUpContentConflict
          }
          try result.revalidatePublishedSource()
          return try unlock.continuedReadContext(current: current, ticket: result.ticket)
        },
        makeService: { identity in
          .init(
            vaultID: Core.vaultID, identity: identity, session: session,
            objectStore: disk.store, checkpointStore: disk.checkpoints,
            recoveryAnchorStore: disk.ownership, registrationAnchorStore: disk.registration,
            adoptionAnchorStore: disk.adoption, cache: disk.cache, phaseObserver: observer,
            validateScope: { try scope.requireCurrent() })
        }, validateScope: { try scope.requireCurrent() })
    }
    func handler() -> KeyServiceHandler {
      .init(
        keyStore: MemoryVaultKeyStore(), entryStore: EntryStore(rootURL: disk.root),
        mutationOwner: VaultTransactionMutationOwner(), revocationService: workflow(),
        configuredVaultID: Core.vaultID)
    }
  }
  private struct Loader: V3DeviceWrappedIdentityLoading {
    let owner: Core.Owner
    let scope: KeyRecoveryRequestScope
    func loadDeviceIdentity(vaultID: String, reason: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      try scope.requireCurrent()
      return V3ScopedDeviceUnwrapper(base: owner, validate: { try scope.requireCurrent() })
    }
  }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID: VaultTransactionOperationID)
      throws
    {
      try action(phase)
    }
  }
}
