import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Owned software credentials and disposable storage only. Enrollment epochs
/// are materialized by test setup, not a durable enrollment publisher/service.
struct V3RecoveryDeviceEnrollmentTests {
  private typealias Core = V3RecoveryRegistrationTests
  private static let now: UInt64 = 4_102_444_800

  @Test(arguments: 0..<3)
  func comparedAdditionPreservesValuesAndRecoveryCoverage(variant: Int) throws {
    let f = try Fixture(empty: variant == 1, backup: variant != 2)
    let candidate = try f.build()
    let old = f.core.parent.body
    let new = candidate.envelope.body
    #expect(candidate.expectedCheckpoint == f.core.checkpoint)
    #expect(candidate.transcriptDigest == f.state.transcript?.digest)
    #expect(candidate.envelope.parents == [f.core.parent.digest])
    #expect(new.fields.devices.count == old.fields.devices.count + 1)
    #expect(new.fields.devices.contains(.init(identity: f.joiner.publicIdentity, status: .active)))
    #expect(old.fields.devices.allSatisfy { new.fields.devices.contains($0) })
    #expect(new.recovery.recipients == old.recovery.recipients)
    #expect(new.recovery.generationID == old.recovery.generationID)
    #expect(new.recovery.wrappedKeys.isEmpty == old.recovery.wrappedKeys.isEmpty)
    #expect(new.fields.keyID != old.fields.keyID)
    #expect(new.epochSigningKey.publicKey != old.epochSigningKey.publicKey)
    #expect(
      try new.fields.authorityTransitionID
        == v3EnrollmentAuthorityTransitionID(
          transcriptDigest: candidate.transcriptDigest))
    let snapshots = V3EntrySnapshotValidator(limits: .standard)
    #expect(
      try snapshots.plaintexts(
        fields: old.fields, entries: f.core.entries, vaultKey: Core.oldKey)
        == snapshots.plaintexts(
          fields: new.fields, entries: snapshots.entryMap(candidate.stagedEntries),
          vaultKey: Core.nextKey))
    #expect(f.core.owner.signatures == f.ownerSignatures + 1 && f.core.owner.unwraps == 0)
    #expect(f.joiner.signatures == 1 && f.joiner.unwraps == 0)
    for device in [f.core.owner, f.joiner] {
      let wrapper = try #require(
        new.fields.wrappedKeys.first {
          $0.recipientDeviceID == device.publicIdentity.deviceID
        })
      #expect(
        try V3VaultKeyHPKE().unwrap(
          wrapper.wrappedKey, recipientPrivateKey: device.wrappingKey,
          context: new.deviceContext(recipientDeviceID: device.publicIdentity.deviceID))
          == Core.nextKey)
    }
  }

  @Test(arguments: 0..<5)
  func wrongExpiredOrConsumedCeremonyRefusesBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let state: V3EnrollmentCeremonyState
    switch variant {
    case 0, 1:
      state = try V3EnrollmentCeremonyState(
        vaultID: Core.vaultID, invitationDigest: f.state.invitationDigest,
        role: variant == 0 ? .joiner : .inviter,
        phase: variant == 0 ? .awaitingComparison : .consumed,
        signedInvitation: f.state.signedInvitation, signedJoinRequest: f.state.signedJoinRequest)
    case 2:
      state = try V3EnrollmentCeremonyState(
        vaultID: Core.vaultID, invitationDigest: f.state.invitationDigest,
        role: .inviter, phase: .awaitingJoinRequest,
        signedInvitation: f.state.signedInvitation, signedJoinRequest: nil)
    case 3:
      state = try ceremony(
        parentDigest: Data(repeating: 0x99, count: 32), owner: f.core.owner, joiner: f.joiner)
    default: state = f.state
    }
    let before = f.core.owner.signatures
    #expect(throws: (any Error).self) {
      try f.build(state: state, at: variant == 4 ? Self.now + 1 : Self.now)
    }
    #expect(f.core.owner.signatures == before && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func invalidMessageAuthenticationRefusesBeforeSigning(joinRequest: Bool) throws {
    let f = try Fixture()
    let signedJoin = try #require(f.state.signedJoinRequest)
    let invitation = f.state.signedInvitation
    let invalid = try V3EnrollmentMessageAuthentication(
      signerDeviceID: joinRequest
        ? f.joiner.publicIdentity.deviceID : f.core.owner.publicIdentity.deviceID,
      signature: Data(repeating: 0, count: 64))
    let state = try V3EnrollmentCeremonyState(
      vaultID: Core.vaultID, invitationDigest: f.state.invitationDigest,
      role: .inviter, phase: .awaitingComparison,
      signedInvitation: joinRequest
        ? invitation
        : .init(
          invitation: invitation.invitation, authentication: invalid),
      signedJoinRequest: joinRequest
        ? .init(
          joinRequest: signedJoin.joinRequest, authentication: invalid) : signedJoin)
    #expect(throws: V3EnrollmentAuthenticationError.invalidSignature) { try f.build(state: state) }
    #expect(f.core.owner.signatures == f.ownerSignatures && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<4)
  func invalidOwnerReasonAndVaultKeysRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let other = try Core.Owner()
    #expect(throws: (any Error).self) {
      try f.build(
        currentKey: variant == 0 ? Core.nextKey : Core.oldKey,
        nextKey: variant == 1 ? Core.oldKey : Core.nextKey,
        owner: variant == 2 ? other : f.core.owner, reason: variant == 3 ? "" : "Software fixture")
    }
    #expect(f.core.owner.signatures == f.ownerSignatures && other.signatures == 0)
  }

  @Test(arguments: [false, true])
  func enrolledIdentityOrReusedDeviceKeyRefusesBeforeSigning(reusedKey: Bool) throws {
    let f = try Fixture()
    let first = try f.build()
    let parent = first.envelope
    let checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    let signer = try RelatedJoiner(
      existing: f.joiner, reuseWrappingKey: reusedKey)
    let state = try ceremony(parentDigest: parent.digest, owner: f.core.owner, joiner: signer)
    let before = f.core.owner.signatures
    #expect(throws: V3RecoveryDeviceEnrollmentError.joiningIdentityConflict) {
      try V3RecoveryDeviceEnrollmentBuilder().build(
        checkpoint: checkpoint, parent: parent,
        currentEntries: V3EntrySnapshotValidator(limits: .standard).entryMap(first.stagedEntries),
        state: state, currentVaultKey: Core.nextKey, nextVaultKey: Data(repeating: 0x44, count: 32),
        owner: f.core.owner, at: Self.now, reason: "Software fixture")
    }
    #expect(f.core.owner.signatures == before)
  }

  @Test(arguments: 0..<3)
  func independentValidationBindsExactCeremonyAndTransition(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build()
    let otherState = try ceremony(
      parentDigest: f.core.parent.digest, owner: f.core.owner, joiner: f.joiner)
    let other = try f.build(state: otherState)
    let changed = V3RecoveryDeviceEnrollmentCandidate(
      expectedCheckpoint: candidate.expectedCheckpoint,
      envelope: variant == 0 ? other.envelope : candidate.envelope,
      stagedEntries: candidate.stagedEntries,
      transcriptDigest: variant == 1 ? Data(repeating: 0x99, count: 32) : candidate.transcriptDigest
    )
    #expect(throws: (any Error).self) {
      try f.validate(changed, state: variant == 2 ? otherState : f.state)
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func rotationOrRecipientRegistrationCannotStandInForEnrollment(registration: Bool) throws {
    let f = try Fixture()
    let envelope: V3RecoveryManifestEnvelope
    let entries: [V3EncryptedEntry]
    if registration {
      let result = try f.core.prepare()
      envelope = result.candidate
      entries = result.stagedEntries
    } else {
      let result = try V3RecoveryKeyRotationBuilder().build(
        checkpoint: f.core.checkpoint, parent: f.core.parent,
        currentEntries: f.core.entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        owner: f.core.owner, reason: "Software fixture")
      envelope = result.envelope
      entries = result.stagedEntries
    }
    #expect(throws: V3RecoveryDeviceEnrollmentError.invalidCandidate) {
      try f.validate(
        .init(
          expectedCheckpoint: f.core.checkpoint, envelope: envelope, stagedEntries: entries,
          transcriptDigest: #require(f.state.transcript).digest))
    }
  }

  @Test(arguments: 0..<4)
  func constructionBudgetsRefuseBeforeSigning(variant: Int) throws {
    let f = try Fixture()
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
      Core.Fixture.limits(manifestBytes: f.core.parent.canonicalBytes.count),
    ][variant]
    #expect(throws: (any Error).self) { try f.build(limits: limits) }
    #expect(f.core.owner.signatures == f.ownerSignatures && f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<5)
  func exactRosterPolicyRejectsOtherWellFormedEpochDecisions(variant: Int) throws {
    let f = try Fixture()
    let joined = V3DeviceWrappedManifestDevice(identity: f.joiner.publicIdentity, status: .active)
    var devices = (f.core.parent.body.fields.devices + [joined]).sorted {
      $0.identity.deviceID < $1.identity.deviceID
    }
    if variant == 0 { devices = f.core.parent.body.fields.devices }
    if variant == 1 {
      devices.append(.init(identity: try Core.Owner().publicIdentity, status: .active))
      devices.sort { $0.identity.deviceID < $1.identity.deviceID }
    }
    if variant == 2 {
      devices = devices.map {
        $0.identity == f.core.owner.publicIdentity
          ? .init(identity: $0.identity, status: .revoked) : $0
      }
    }
    var recipients = f.core.parent.body.recovery.recipients
    if variant == 3 {
      recipients.append(
        try V3RecoveryRecipient(
          registrationID: UUID().uuidString.lowercased(),
          publicKey: f.core.token.publicKey.x963Representation, slot: .keyManagement,
          status: .active))
      recipients.sort { $0.recipientID.rawValue < $1.recipientID.rawValue }
    }
    let values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: f.core.parent.body.fields, entries: f.core.entries, vaultKey: Core.oldKey)
    let transcript = try #require(f.state.transcript)
    let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
      fields: f.core.parent.body.fields, plaintexts: values, nextVaultKey: Core.nextKey,
      authorityTransitionID: v3EnrollmentAuthorityTransitionID(transcriptDigest: transcript.digest),
      devices: devices,
      generationID: variant >= 3
        ? UUID().uuidString.lowercased() : f.core.parent.body.recovery.generationID,
      recipients: recipients)
    let envelope = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: f.core.parent,
      currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
      signer: f.core.owner, reason: "Owned software roster-policy fixture")
    #expect(throws: V3RecoveryDeviceEnrollmentError.invalidCandidate) {
      try f.validate(
        .init(
          expectedCheckpoint: f.core.checkpoint, envelope: envelope,
          stagedEntries: material.stagedEntries,
          transcriptDigest: transcript.digest))
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: 0..<3)
  func independentBudgetsRejectBeforeLocalUnwrap(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build()
    let limits = [
      Core.Fixture.limits(entries: 1), Core.Fixture.limits(entryBytes: 1),
      Core.Fixture.limits(totalBytes: 1),
    ][variant]
    #expect(throws: (any Error).self) {
      try V3RecoveryDeviceEnrollmentValidator(limits: limits).validateForPublication(
        candidate, parent: f.core.parent, currentEntries: f.core.entries, state: f.state,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        identity: f.core.owner, at: Self.now, reason: "Software bounds fixture")
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test func enrollmentPreservesRevokedTombstonesAndOmitsTheirWrappers() throws {
    let f = try Fixture()
    let first = try f.build()
    let retiredDevices = first.envelope.body.fields.devices.map {
      $0.identity == f.joiner.publicIdentity
        ? V3DeviceWrappedManifestDevice(identity: $0.identity, status: .revoked) : $0
    }
    let firstEntries = try V3EntrySnapshotValidator(limits: .standard).entryMap(first.stagedEntries)
    let values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: first.envelope.body.fields, entries: firstEntries, vaultKey: Core.nextKey)
    let retirementKey = Data(repeating: 0x44, count: 32)
    // Materialized retired-device setup, not an implemented revocation publisher.
    let material = try V3RecoveryEpochMaterialBuilder(limits: .standard).build(
      fields: first.envelope.body.fields, plaintexts: values, nextVaultKey: retirementKey,
      authorityTransitionID: UUID().uuidString.lowercased(), devices: retiredDevices,
      generationID: first.envelope.body.recovery.generationID,
      recipients: first.envelope.body.recovery.recipients)
    let parent = try V3RecoveryEpochBoundary().authorize(
      candidate: material.body, parent: first.envelope, currentVaultKey: Core.nextKey,
      nextVaultKey: retirementKey, signer: f.core.owner, reason: "Owned retired-device fixture")
    let checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    let joiner = try Core.Owner()
    let state = try ceremony(parentDigest: parent.digest, owner: f.core.owner, joiner: joiner)
    let result = try V3RecoveryDeviceEnrollmentBuilder().build(
      checkpoint: checkpoint, parent: parent,
      currentEntries: V3EntrySnapshotValidator(limits: .standard).entryMap(material.stagedEntries),
      state: state, currentVaultKey: retirementKey, nextVaultKey: Data(repeating: 0x55, count: 32),
      owner: f.core.owner, at: Self.now, reason: "Software enrollment fixture")
    #expect(
      result.envelope.body.fields.devices.contains(
        .init(identity: f.joiner.publicIdentity, status: .revoked)))
    #expect(
      !result.envelope.body.fields.wrappedKeys.contains {
        $0.recipientDeviceID == f.joiner.publicIdentity.deviceID
      })
    #expect(
      parent.body.fields.devices.allSatisfy { result.envelope.body.fields.devices.contains($0) })
  }

  @Test(arguments: 0..<5)
  func incompleteSnapshotsAndWrongKeysRefuseBeforePrivateUnwrap(variant: Int) throws {
    let f = try Fixture()
    let candidate = try f.build()
    let entries =
      variant == 1
      ? []
      : (variant == 2 ? candidate.stagedEntries + candidate.stagedEntries : candidate.stagedEntries)
    let changed = V3RecoveryDeviceEnrollmentCandidate(
      expectedCheckpoint: candidate.expectedCheckpoint, envelope: candidate.envelope,
      stagedEntries: entries, transcriptDigest: candidate.transcriptDigest)
    #expect(throws: (any Error).self) {
      try V3RecoveryDeviceEnrollmentValidator().validateForPublication(
        changed, parent: f.core.parent, currentEntries: variant == 0 ? [:] : f.core.entries,
        state: f.state, currentVaultKey: variant == 3 ? Core.nextKey : Core.oldKey,
        nextVaultKey: variant == 4 ? Core.oldKey : Core.nextKey,
        identity: f.core.owner, at: Self.now, reason: "Software fixture")
    }
    #expect(f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func publicationVerificationUsesOneAddressedUnwrapAndDoesNotRetry(cancel: Bool) throws {
    let f = try Fixture()
    let candidate = try f.build()
    f.core.owner.cancelUnwrap = cancel
    if cancel {
      #expect(throws: Core.FixtureError.cancelled) { try f.verifyLocalWrapper(candidate) }
    } else {
      try f.verifyLocalWrapper(candidate)
    }
    #expect(f.core.owner.unwraps == 1 && f.joiner.unwraps == 0)
  }

  @Test func cancelledSigningDoesNotProduceACandidateOrRetry() throws {
    let f = try Fixture()
    f.core.owner.cancelSigning = true
    #expect(throws: Core.FixtureError.cancelled) { try f.build() }
    #expect(f.core.owner.signatures == f.ownerSignatures + 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func primaryAndBackupRecoverAfterTwoEnrollmentsAndAnOrdinarySave(backup: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let (anchors, tokens, digest) = try enrollmentChain(root)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let index = backup ? 1 : 0
    let token = tokens[index]
    let selected = try V3RecoveryHistorySelector(source: store).select(
      anchor: anchors[index], credentialPublicKey: token.publicKey.x963Representation)
    let calls = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: token.publicKey.x963Representation) { peer in
      calls.increment()
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      )
      .withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: store).open(
      selected, boundAnchor: anchors[index], receiver: receiver)
    #expect(selected.head.digest == digest && calls.value == 1)
    #expect(opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "after enrollment")
    #expect(opened.entries.first { $0.name == "fixture/totp" }?.plaintext == "JBSWY3DPEHPK3PXP")
  }

  private func enrollmentChain(_ root: URL) throws -> (
    [V3RecoveryAnchor], [P256.KeyAgreement.PrivateKey], Data
  ) {
    let f = try V3RecoveryContentMutationPublisherTests.Fixture(root: root)
    let recipient = try #require(f.core.parent.body.recovery.recipients.first)
    let backupAnchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Core.vaultID, envelopeDigest: f.core.parent.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
    var parent = f.parent
    var entries = f.entries
    var key = Core.nextKey
    var owner = f.core.owner
    var obsolete = Array(f.core.entries.values) + Array(f.entries.values)
    for byte: UInt8 in [0x33, 0x44] {
      let next = Data(repeating: byte, count: 32)
      let joiner = try Core.Owner()
      let checkpoint = try V3ManifestCheckpoint(
        vaultID: Core.vaultID, envelopeDigest: parent.digest)
      let state = try ceremony(parentDigest: parent.digest, owner: owner, joiner: joiner)
      let candidate = try V3RecoveryDeviceEnrollmentBuilder().build(
        checkpoint: checkpoint, parent: parent, currentEntries: entries, state: state,
        currentVaultKey: key, nextVaultKey: next, owner: owner, at: Self.now,
        reason: "Software fixture")
      try f.seed(candidate.envelope, entries: candidate.stagedEntries)
      parent = candidate.envelope
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(candidate.stagedEntries)
      key = next
      owner = joiner
      if byte == 0x33 { obsolete += candidate.stagedEntries }
    }
    // Exact setup only, not publication, ceremony consumption or joining-Mac adoption.
    let checkpoint = try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    f.checkpoints.value = checkpoint.canonicalBytes
    try f.cache.store(parent.canonicalBytes, for: checkpoint)
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(key, vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
    let mutationOwner = VaultTransactionMutationOwner()
    let service = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: f.ownership, registrationAnchorStore: f.registration,
      adoptionAnchorStore: f.adoption, cache: f.cache)
    try mutationOwner.perform(.editEntry) { context in
      try service.edit(
        name: "fixture/secret", secret: "after enrollment", type: .secret,
        operationID: context.operationID)
    }
    session.invalidate()
    for entry in obsolete { try FileManager.default.removeItem(at: f.entryURL(entry)) }
    let last = try V3ManifestCheckpoint(canonicalBytes: #require(f.checkpoints.value))
    return ([f.anchor, backupAnchor], [f.core.token, f.core.backupToken], last.envelopeDigest)
  }

  private struct RelatedJoiner: V3EnrollmentMessageSigning {
    let vaultID = Core.vaultID
    let signingKey: P256.Signing.PrivateKey
    let publicIdentity: V3EnrollmentDeviceIdentity
    init(existing: Core.Owner, reuseWrappingKey: Bool) throws {
      signingKey = reuseWrappingKey ? P256.Signing.PrivateKey() : existing.signingKey
      publicIdentity = try V3EnrollmentDeviceIdentity(
        displayName: existing.publicIdentity.displayName,
        signingPublicKey: signingKey.publicKey.x963Representation,
        wrappingPublicKey: existing.publicIdentity.wrappingPublicKey)
    }
    func signature(for input: Data, reason _: String) throws -> Data {
      try signingKey.signature(for: input).rawRepresentation
    }
  }

  private struct Fixture {
    let core: Core.Fixture
    let joiner: Core.Owner
    let state: V3EnrollmentCeremonyState
    let ownerSignatures: Int
    init(empty: Bool = false, backup: Bool = true) throws {
      core = try Core.Fixture(empty: empty, backup: backup)
      joiner = try Core.Owner()
      state = try V3RecoveryDeviceEnrollmentTests().ceremony(
        parentDigest: core.parent.digest, owner: core.owner, joiner: joiner)
      ownerSignatures = core.owner.signatures
    }
    func build(
      state: V3EnrollmentCeremonyState? = nil, at: UInt64 = V3RecoveryDeviceEnrollmentTests.now,
      currentKey: Data = Core.oldKey, nextKey: Data = Core.nextKey,
      owner: Core.Owner? = nil, reason: String = "Software enrollment fixture",
      limits: V3ManifestRepositoryLimits = .standard
    ) throws -> V3RecoveryDeviceEnrollmentCandidate {
      try V3RecoveryDeviceEnrollmentBuilder(limits: limits).build(
        checkpoint: core.checkpoint, parent: core.parent, currentEntries: core.entries,
        state: state ?? self.state, currentVaultKey: currentKey, nextVaultKey: nextKey,
        owner: owner ?? core.owner, at: at, reason: reason)
    }
    func validate(
      _ candidate: V3RecoveryDeviceEnrollmentCandidate, state: V3EnrollmentCeremonyState? = nil
    ) throws {
      try V3RecoveryDeviceEnrollmentValidator().validate(
        candidate, parent: core.parent, currentEntries: core.entries, state: state ?? self.state,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        expectedOwner: core.owner.publicIdentity,
        at: V3RecoveryDeviceEnrollmentTests.now)
    }
    func verifyLocalWrapper(_ candidate: V3RecoveryDeviceEnrollmentCandidate) throws {
      try V3RecoveryDeviceEnrollmentValidator().validateForPublication(
        candidate, parent: core.parent, currentEntries: core.entries, state: state,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey, identity: core.owner,
        at: V3RecoveryDeviceEnrollmentTests.now, reason: "Software local wrapper fixture")
    }
  }

  func ceremony(
    parentDigest: Data, owner: any V3EnrollmentMessageSigning,
    joiner: any V3EnrollmentMessageSigning
  ) throws -> V3EnrollmentCeremonyState {
    let invitation = try V3EnrollmentInvitation(
      vaultID: Core.vaultID, parentManifestDigest: parentDigest,
      invitingDevice: owner.publicIdentity,
      nonce: P256.KeyAgreement.PrivateKey().rawRepresentation, expiresAt: Self.now)
    let authenticator = V3EnrollmentMessageAuthenticator()
    let signedInvitation = try authenticator.sign(
      invitation, using: owner, reason: "Software invitation fixture")
    let request = try V3EnrollmentJoinRequest(
      invitationDigest: invitation.digest, joiningDevice: joiner.publicIdentity,
      nonce: P256.KeyAgreement.PrivateKey().rawRepresentation)
    let signedRequest = try authenticator.sign(
      request, answering: authenticator.verify(signedInvitation), using: joiner,
      reason: "Software join fixture")
    return try V3EnrollmentCeremonyState(
      vaultID: Core.vaultID, invitationDigest: invitation.digest, role: .inviter,
      phase: .awaitingComparison,
      signedInvitation: signedInvitation, signedJoinRequest: signedRequest)
  }
}
