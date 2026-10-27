import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryRecipientRemovalProductTests {
  private typealias Core = V3RecoveryRegistrationTestSupport
  private typealias Support = V3RecoveryAuthorityChangeTestSupport
  private typealias Disk = V3RecoveryPublicationTestSupport

  @Test(arguments: [false, true])
  func reviewedRemovalChangesOnlyItsRecipientAndOrdinaryUseContinues(last: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(last: last)
    defer { f.data.disk.remove() }
    let review = try f.review()
    let result = try f.workflow.handle(f.request(review, acknowledge: last))
    guard case .completed(_, let recipient, _, let pending, let already) = result else {
      Issue.record("Expected committed removal")
      return
    }
    #expect(recipient == f.id && !pending && !already)
    let current = try f.current()
    #expect(
      current.body.recovery.recipients.first(where: { $0.recipientID.rawValue == f.id })?.status
        == .revoked)
    #expect(!current.body.recovery.wrappedKeys.contains(where: { $0.recipientID.rawValue == f.id }))
    #expect(current.body.fields.devices == f.data.parent.body.fields.devices)
    #expect(
      current.body.recovery.recipients.filter { $0.status == .active }.count == (last ? 0 : 1))
    try f.ordinary.add(
      name: "after/removal", secret: "continued", type: .secret, operationID: .init())
    #expect(try f.current().body.fields.keyID == current.body.fields.keyID)
    let repeated = try f.workflow.handle(.review(recipientID: f.id))
    guard case .completed(_, _, _, _, let repeatedStatus) = repeated else {
      Issue.record("Expected removed status")
      return
    }
    #expect(repeatedStatus)
    #expect(throws: (any Error).self) {
      try V3RecoveryHistorySelector(source: f.data.disk.store).select(
        anchor: f.data.disk.anchor,
        credentialPublicKey: f.data.disk.core.token.publicKey.x963Representation)
    }
    if !last {
      let remaining = try #require(f.data.disk.core.parent.body.recovery.recipients.first)
      let anchor = try V3RecoveryAnchor(
        floor: .init(vaultID: Core.vaultID, envelopeDigest: f.data.disk.core.parent.digest),
        recipientID: remaining.recipientID, registrationID: remaining.registrationID,
        slot: .keyManagement)
      let token = f.data.disk.core.backupToken
      let selected = try V3RecoveryHistorySelector(source: f.data.disk.store).select(
        anchor: anchor,
        credentialPublicKey: token.publicKey.x963Representation)
      let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
        try token.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: peer)
        )
        .withUnsafeBytes { Data($0) }
      }
      let opened = try V3RecoverySnapshotVerifier(source: f.data.disk.store).open(
        selected, boundAnchor: anchor, receiver: receiver)
      #expect(
        opened.entries.contains(where: { $0.name == "after/removal" && $0.plaintext == "continued" }
        ))
    }
  }

  @Test(arguments: [false, true])
  func missingOrMisappliedLastKeyAcknowledgmentRefusesBeforeAnyPrivateWork(last: Bool) throws {
    let f = try Fixture(last: last)
    defer { f.data.disk.remove() }
    let review = V3RecoveryRecipientRemovalReviewBinding().review(try f.publicPlan())
    #expect(throws: (any Error).self) {
      try f.workflow.handle(f.request(review, acknowledge: !last))
    }
    #expect(f.data.owner.unwraps == f.data.unwraps && f.data.owner.signatures == f.data.signatures)
    #expect(
      f.data.disk.ownership.value == nil
        && f.data.disk.checkpoints.value == f.data.checkpoint.canonicalBytes)
  }

  @Test func staleReviewCannotPublishAReplacementPlan() throws {
    let f = try Fixture(last: false)
    defer { f.data.disk.remove() }
    let review = try f.review()
    try f.ordinary.edit(
      name: "fixture/secret", secret: "newer", type: .secret, operationID: .init())
    let checkpoint = f.data.disk.checkpoints.value
    let signatures = f.data.owner.signatures
    f.session.invalidate()
    let unwraps = f.data.owner.unwraps
    #expect(throws: (any Error).self) {
      try f.workflow.handle(f.request(review, acknowledge: false))
    }
    #expect(f.data.owner.unwraps == unwraps && f.data.owner.signatures == signatures)
    #expect(f.data.disk.checkpoints.value == checkpoint && f.data.disk.ownership.value == nil)
  }

  @Test(arguments: [false, true])
  func pendingRemovalRequiresExactReviewedOperationBeforePrivateResume(last: Bool) throws {
    let f = try Fixture(last: last)
    defer { f.data.disk.remove() }
    try f.interrupt()
    let unwraps = f.data.owner.unwraps
    let signatures = f.data.owner.signatures
    let review = try f.review()
    #expect(
      review.pendingOperationID == f.data.disk.operationID.rawValue
        && f.data.owner.unwraps == unwraps)
    let wrong = KeyRecoveryRecipientRemovalRequest.remove(
      recipientID: f.id, confirmationToken: review.confirmationToken,
      pendingOperationID: VaultTransactionOperationID().rawValue, acknowledgesProtectionLoss: last)
    #expect(throws: (any Error).self) { try f.workflow.handle(wrong) }
    #expect(f.data.owner.unwraps == unwraps && f.data.owner.signatures == signatures)
    let result = try f.workflow.handle(f.request(review, acknowledge: last))
    guard case .completed(_, _, _, let pending, _) = result else {
      Issue.record("Expected completion")
      return
    }
    #expect(!pending && f.data.disk.ownership.value == nil)
    #expect(f.data.owner.signatures == signatures && f.data.owner.unwraps == unwraps + 2)
  }

  @Test(arguments: [false, true])
  func retainedCleanupIsReportedAndCanFinishWithoutAnotherSignature(last: Bool) throws {
    let f = try Fixture(last: last)
    defer { f.data.disk.remove() }
    let review = try f.review()
    f.data.disk.ownership.rejectClear = true
    let result = try f.workflow.handle(f.request(review, acknowledge: last))
    guard case .completed(_, _, _, let pending, _) = result else {
      Issue.record("Expected commitment")
      return
    }
    #expect(pending && f.data.disk.ownership.value != nil)
    #expect(throws: (any Error).self) {
      try f.ordinary.add(name: "blocked", secret: "value", type: .secret, operationID: .init())
    }
    let signatures = f.data.owner.signatures
    f.data.disk.ownership.rejectClear = false
    let saved = try f.review()
    _ = try f.workflow.handle(f.request(saved, acknowledge: last))
    #expect(f.data.disk.ownership.value == nil && f.data.owner.signatures == signatures)
  }

  @Test func stoppedOrCompetingOwnershipRefusesWithoutNewAuthority() throws {
    let f = try Fixture(last: true)
    defer { f.data.disk.remove() }
    let review = V3RecoveryRecipientRemovalReviewBinding().review(try f.publicPlan())
    f.scope.cancellation.cancel()
    #expect(throws: (any Error).self) {
      try f.workflow.handle(f.request(review, acknowledge: true))
    }
    #expect(f.data.owner.unwraps == f.data.unwraps && f.data.owner.signatures == f.data.signatures)
    #expect(f.data.disk.ownership.value == nil)
  }

  @Test func reviewBindingCommitsEveryPlanFieldAndNotOnlyTheRecipientName() throws {
    let f = try Fixture(last: false)
    defer { f.data.disk.remove() }
    let plan = try f.publicPlan()
    let token = V3RecoveryRecipientRemovalReviewBinding().token(plan)
    let changed = V3RecoveryRecipientRemovalPlan(
      expectedCheckpoint: plan.expectedCheckpoint,
      authorizingDevice: plan.authorizingDevice, removedRecipient: plan.removedRecipient,
      resultingRecipients: [])
    #expect(token != V3RecoveryRecipientRemovalReviewBinding().token(changed))
  }

  private final class Fixture: @unchecked Sendable {
    let data: Support.Fixture
    let session = V3DeviceWrappedVaultKeySessionStore()
    let scope = KeyRecoveryRequestScope(authentication: .init(), deadline: .now() + 90)
    var id: String { data.disk.anchor.recipientID.rawValue }
    init(last: Bool) throws { data = try .init(last ? .removeLast : .remove) }
    var workflow: KeyRecoveryRecipientRemovalWorkflow {
      .init(
        vaultID: Core.vaultID, identity: data.owner, session: session, source: data.disk.store,
        checkpoints: data.disk.checkpoints, transaction: data.disk.ownership,
        registration: data.disk.registration, adoption: data.disk.adoption, cache: data.disk.cache,
        owner: VaultTransactionMutationOwner(), validateScope: { try self.scope.requireCurrent() })
    }
    func publicPlan() throws -> V3RecoveryRecipientRemovalPlan {
      try V3RecoveryRecipientRemovalPlanner().planMetadata(
        checkpoint: data.checkpoint, parent: data.parent,
        authorizingDeviceID: data.owner.publicIdentity.deviceID, removing: .init(rawValue: id))
    }
    func review() throws -> KeyRecoveryRecipientRemovalReview {
      guard case .review(let result) = try workflow.handle(.review(recipientID: id)) else {
        throw Disk.Stop.interrupted
      }
      return result
    }
    func request(_ review: KeyRecoveryRecipientRemovalReview, acknowledge: Bool)
      -> KeyRecoveryRecipientRemovalRequest
    {
      .remove(
        recipientID: id, confirmationToken: review.confirmationToken,
        pendingOperationID: review.pendingOperationID, acknowledgesProtectionLoss: acknowledge)
    }
    var ordinary: V3RecoveryVaultMutationService {
      .init(
        vaultID: Core.vaultID, session: session, objectStore: data.disk.store,
        checkpointStore: data.disk.checkpoints, recoveryAnchorStore: data.disk.ownership,
        registrationAnchorStore: data.disk.registration, adoptionAnchorStore: data.disk.adoption,
        cache: data.disk.cache)
    }
    func current() throws -> V3RecoveryManifestEnvelope {
      let checkpoint = try V3ManifestCheckpoint(
        canonicalBytes: #require(data.disk.checkpoints.value))
      return try V3RecoveryManifestCodec().parseEnvelope(
        V3ExactTransitionRepository(source: data.disk.store, limits: .standard)
          .readManifest(checkpoint.envelopeDigest))
    }
    func interrupt() throws {
      try session.install(data.key, vaultID: Core.vaultID, keyID: data.parent.body.fields.keyID)
      let service = V3RecoveryAuthorityChangeService(
        vaultID: Core.vaultID, identity: data.owner, session: session,
        objectStore: data.disk.store, checkpointStore: data.disk.checkpoints,
        recoveryAnchorStore: data.disk.ownership, registrationAnchorStore: data.disk.registration,
        adoptionAnchorStore: data.disk.adoption, cache: data.disk.cache,
        phaseObserver: Observer { if $0 == .manifestStaged { throw Disk.Stop.interrupted } })
      let plan = try service.prepareRemoval(removing: .init(rawValue: id))
      #expect(throws: Disk.Stop.interrupted) {
        try service.remove(
          plan, operationID: data.disk.operationID,
          protectionLossAcknowledgement: plan.removesLastActiveRecipient ? .init(plan: plan) : nil)
      }
      session.invalidate()
    }
  }
  private struct Observer: V3ImmutableTransactionPhaseObserving {
    let action: @Sendable (V3ImmutableTransactionPhase) throws -> Void
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID: VaultTransactionOperationID)
      throws
    { try action(phase) }
  }
}
