import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Concrete publication, independent Mac trust, reciprocal catch-up and recovery
/// from files after both software Macs leave scope. No native or PIV operation.
struct V3RecoveryLifecycleIntegrationTests {
  private typealias Epochs = V3RecoveryKeyTransitionCatchUpTests
  private typealias Fixture = Epochs.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests

  @Test func completeMixedLifecycleSurvivesBothMacsWithOneSoftwareRecipientOpening() throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let evidence = try publishLifecycle(root: root, removeAllRecipients: false)
    let source = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let selected = try V3RecoveryHistorySelector(source: source).select(
      anchor: evidence.anchor, credentialPublicKey: evidence.token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: evidence.token.publicKey.x963Representation) {
      peer in
      calls.increment()
      return try evidence.token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
    let recovered = try V3RecoverySnapshotVerifier(source: source).open(
      selected, boundAnchor: evidence.anchor, receiver: receiver)
    #expect(calls.value == 1 && selected.head.digest == evidence.head)
    #expect(recovered.entries.first { $0.name == "after/receiver" }?.plaintext == "receiver save")
    #expect(recovered.entries.first { $0.name == "after/owner" }?.plaintext == "owner save")
    #expect(recovered.entries.first { $0.name == "fixture/secret" }?.plaintext == "latest edit")
    #expect(recovered.entries.contains { $0.name == "fixture/totp" && $0.type == .totp })
  }

  @Test func explicitlyRemovingAllRecipientsEndsRecoveryWithoutPreventingOrdinaryCatchUp() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let evidence = try publishLifecycle(root: root, removeAllRecipients: true)
    let source = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    #expect(throws: V3RecoveryValidationError.recipientRevoked) {
      try V3RecoveryHistorySelector(source: source).select(
        anchor: evidence.anchor, credentialPublicKey: evidence.token.publicKey.x963Representation)
    }
  }

  private struct Evidence: Sendable {
    let anchor: V3RecoveryAnchor
    let token: P256.KeyAgreement.PrivateKey
    let head: Data
  }

  private func publishLifecycle(root: URL, removeAllRecipients: Bool) throws -> Evidence {
    let f = try Fixture(root: root)
    // All but recipient addition use the actual publication services. Addition
    // reuses the domain builder/materialization fixture, not a possession claim.
    for action in [Epochs.Action.enrollment, .rotation, .addition, .revocation, .removal] {
      _ = try f.publish(action)
      try f.edit("after \(action)")
    }
    if removeAllRecipients {
      let remaining = f.parent.body.recovery.recipients.filter { $0.status == .active }
      for recipient in remaining {
        let ownerSession = try f.ownerSession()
        let service = V3RecoveryAuthorityChangeService(
          vaultID: Core.vaultID, identity: f.owner, session: ownerSession,
          objectStore: f.disk.store, checkpointStore: f.disk.checkpoints,
          recoveryAnchorStore: f.disk.ownership, registrationAnchorStore: f.disk.registration,
          adoptionAnchorStore: f.disk.adoption, cache: f.disk.cache)
        let plan = try service.prepareRemoval(removing: recipient.recipientID)
        f.parent = try service.remove(
          plan, operationID: .init(),
          protectionLossAcknowledgement: plan.removesLastActiveRecipient ? .init(plan: plan) : nil
        ).envelope
        f.key = try ownerSession.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
        f.entries = try f.loadEntries(f.parent)
      }
      #expect(f.parent.body.recovery.recipients.allSatisfy { $0.status == .revoked })
    }
    try f.edit("latest edit")
    let ownerFloor = try commit(f.parent)
    let ownerSession = try f.ownerSession()
    let recipient = try #require(f.disk.core.parent.body.recovery.recipients.first)
    let anchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.disk.core.parent.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
    let signed = f.owner.signatures
    let before = f.receiver.unwraps
    let revokedCheckpoint = Publication.Checkpoints(f.floor.checkpoint.canonicalBytes)
    let revokedSession = V3DeviceWrappedVaultKeySessionStore()
    try revokedSession.install(
      f.initialKey, vaultID: Core.vaultID, keyID: f.floor.envelope.body.fields.keyID)
    let revokedUnwraps = f.target.unwraps
    #expect(throws: V3RecoveryKeyTransitionCatchUpError.deviceRevoked) {
      try V3RecoveryCatchUpCoordinator(
        mutationOwner: VaultTransactionMutationOwner(), identity: f.target,
        session: revokedSession, source: f.disk.store, checkpointStore: revokedCheckpoint,
        recoveryAnchorStore: Publication.Ownership(),
        registrationAnchorStore: Publication.Ownership(),
        adoptionAnchorStore: Publication.Ownership(), cache: f.localCache
      ).catchUp(from: f.floor)
    }
    #expect(f.target.unwraps == revokedUnwraps && !revokedSession.hasResidentKey)
    #expect(revokedCheckpoint.value == f.floor.checkpoint.canonicalBytes)
    let caughtUp = try current(coordinator(f, receiver: true).catchUp(from: f.floor))
    #expect(caughtUp.0.envelope == f.parent)
    #expect(caughtUp.1.keyEpochCount == (removeAllRecipients ? 7 : 5))
    #expect(
      caughtUp.1.contentManifestCount == (removeAllRecipients ? 1 : 2)
        && f.receiver.unwraps == before + caughtUp.1.keyEpochCount)
    #expect(f.local.value == f.disk.checkpoints.value && f.owner.signatures == signed)
    try mutation(f, receiver: true, session: f.session).add(
      name: "after/receiver", secret: "receiver save", type: .secret, operationID: .init())
    let receiverHead = try V3ManifestCheckpoint(canonicalBytes: #require(f.local.value))
    #expect(f.disk.checkpoints.value == ownerFloor.checkpoint.canonicalBytes)
    let ownerUnwraps = f.owner.unwraps
    let ownerCurrent = try current(
      coordinator(f, receiver: false, session: ownerSession).catchUp(
        from: ownerFloor))
    #expect(ownerCurrent.0.checkpoint == receiverHead && ownerCurrent.1.totalStepCount == 1)
    #expect(f.owner.unwraps == ownerUnwraps && f.owner.signatures == signed)
    try mutation(f, receiver: false, session: ownerSession).add(
      name: "after/owner", secret: "owner save", type: .secret, operationID: .init())
    let final = try current(
      coordinator(f, receiver: true).catchUp(
        from: caughtUpReceiverFloor(
          f, checkpoint: receiverHead)))
    #expect(final.0.checkpoint.canonicalBytes == f.disk.checkpoints.value)
    #expect(final.1 == .init(contentManifestCount: 1, keyEpochCount: 0))
    #expect(f.receiver.unwraps == before + caughtUp.1.keyEpochCount && f.owner.signatures == signed)
    #expect(f.pending.allSatisfy { $0.value == nil } && f.disk.ownership.value == nil)
    f.session.invalidate()
    ownerSession.invalidate()
    try FileManager.default.removeItem(at: f.disk.cacheRoot)
    try FileManager.default.removeItem(at: root.appendingPathComponent("other-mac-cache"))
    // Evidence contains no Mac key, identity, session, checkpoint store or cache.
    // Only recovery credentials and immutable files outlive this helper.
    return .init(anchor: anchor, token: f.disk.core.backupToken, head: final.0.envelope.digest)
  }

  private func commit(_ envelope: V3RecoveryManifestEnvelope) throws -> V3RecoveryContentCommit {
    .init(
      checkpoint: try .init(vaultID: Core.vaultID, envelopeDigest: envelope.digest),
      envelope: envelope)
  }

  private func caughtUpReceiverFloor(_ f: Fixture, checkpoint: V3ManifestCheckpoint) throws
    -> V3RecoveryContentCommit
  {
    guard
      case .available(let bytes) = try f.disk.store.readManifest(
        digest: checkpoint.envelopeDigest,
        maximumBytes: V3ManifestRepositoryLimits.standard.maximumManifestBytes)
    else { throw Publication.Stop.interrupted }
    return .init(
      checkpoint: checkpoint, envelope: try V3RecoveryManifestCodec().parseEnvelope(bytes))
  }

  private func current(_ outcome: V3RecoveryCatchUpCoordinatorOutcome) throws
    -> (V3RecoveryContentCommit, V3RecoveryCatchUpProgress)
  {
    guard case .current(let state, let progress) = outcome else {
      throw Publication.Stop.interrupted
    }
    return (state, progress)
  }

  private func coordinator(
    _ f: Fixture, receiver: Bool, session: V3DeviceWrappedVaultKeySessionStore? = nil
  ) -> V3RecoveryCatchUpCoordinator {
    .init(
      mutationOwner: VaultTransactionMutationOwner(), identity: receiver ? f.receiver : f.owner,
      session: session ?? f.session, source: f.disk.store,
      checkpointStore: receiver ? f.local : f.disk.checkpoints,
      recoveryAnchorStore: receiver ? f.pending[0] : f.disk.ownership,
      registrationAnchorStore: receiver ? f.pending[1] : f.disk.registration,
      adoptionAnchorStore: receiver ? f.pending[2] : f.disk.adoption,
      cache: receiver ? f.localCache : f.disk.cache)
  }

  private func mutation(
    _ f: Fixture, receiver: Bool, session: V3DeviceWrappedVaultKeySessionStore
  ) -> V3RecoveryVaultMutationService {
    .init(
      vaultID: Core.vaultID, session: session, objectStore: f.disk.store,
      checkpointStore: receiver ? f.local : f.disk.checkpoints,
      recoveryAnchorStore: receiver ? f.pending[0] : f.disk.ownership,
      registrationAnchorStore: receiver ? f.pending[1] : f.disk.registration,
      adoptionAnchorStore: receiver ? f.pending[2] : f.disk.adoption,
      cache: receiver ? f.localCache : f.disk.cache)
  }
}
