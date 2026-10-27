import Foundation

/// Product ceremony for an existing recovery-profile owner. Wire messages and
/// comparisons are shared with permanent enrollment; authority stays in the
/// recovery-specific service. No recovery token is needed for device sharing.
struct V3RecoveryEnrollmentOwnerWorkflow: V3EnrollmentWorkflowServicing, Sendable {
  typealias Identity = V3RecoveryEnrollmentOwnerService.Identity
  let vaultID: String
  let unlock: V3RecoveryVaultUnlockRuntime
  let session: V3DeviceWrappedVaultKeySessionStore
  let exchange: V3EnrollmentExchangeCoordinator
  let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  let loadIdentity: @Sendable () throws -> Identity
  let makeService: @Sendable (Identity) -> V3RecoveryEnrollmentOwnerService
  var validateScope: @Sendable () throws -> Void = {}

  func deviceInventory() throws -> V3VaultDeviceInventory {
    try validateScope()
    let context = try unlock.authenticatedReadContext(
      reason: "Unlock the vault to check which Macs have access.")
    let identity = try loadIdentity()
    try context.revalidate()
    try validateScope()
    return .init(
      vaultID: vaultID, mode: .shared,
      currentDeviceID: identity.publicIdentity.deviceID,
      devices: context.current.envelope.body.fields.devices.map {
        .init(
          deviceID: $0.identity.deviceID, displayName: $0.identity.displayName, status: $0.status)
      })
  }

  func listInvitations() throws -> String {
    try validateScope()
    let digests = try exchange.availableInvitationDigests(maximumCount: 4_096)
      .sorted { $0.lexicographicallyPrecedes($1) }
    try validateScope()
    return digests.isEmpty
      ? "No enrollment invitations are available yet.\n"
      : digests.map(v3LowercaseHex).joined(separator: "\n") + "\n"
  }

  func createInvitation(deviceName: String, at unixTime: UInt64) throws -> String {
    try validateScope()
    let context = try unlock.authenticatedReadContext(
      reason: "Unlock the vault to invite another Mac.")
    let identity = try loadIdentity()
    let fields = context.current.envelope.body.fields
    guard identity.vaultID == vaultID, identity.publicIdentity.displayName == deviceName,
      fields.devices.contains(.init(identity: identity.publicIdentity, status: .active))
    else {
      throw AppError.operationRefused(
        "Only an active Mac recorded by this vault can invite another Mac. Use this Mac's existing device name."
      )
    }
    guard unixTime <= UInt64.max - 600 else { throw V3EnrollmentProtocolError.invalidFormat }
    let invitation = try V3EnrollmentInvitation(
      vaultID: vaultID,
      parentManifestDigest: context.current.checkpoint.envelopeDigest,
      invitingDevice: identity.publicIdentity,
      nonce: Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }), expiresAt: unixTime + 600)
    try context.revalidate()
    try validateScope()
    let signed = try V3EnrollmentMessageAuthenticator().sign(
      invitation,
      using: V3ScopedEnrollmentIdentity(
        base: identity,
        validate: {
          try context.revalidate()
          try validateScope()
        }),
      reason: "Create a 10-minute invitation for another Mac.")
    try context.revalidate()
    try validateScope()
    _ = try exchange.beginInviting(signed, at: unixTime)
    try context.revalidate()
    try validateScope()
    return [
      "Enrollment invitation created.", "Vault: \(vaultID)",
      "Invitation: \(v3LowercaseHex(invitation.digest))", "Expires in 10 minutes.",
      "On the other Mac, run `key share join \(v3LowercaseHex(invitation.digest)) --name <device-name>` from the existing vault folder, or add `--vault-dir <existing-folder>`.",
    ].joined(separator: "\n") + "\n"
  }

  func listJoinRequests(invitationDigest: Data, at unixTime: UInt64) throws -> String {
    try validateScope()
    let digests = try exchange.availableJoinRequestDigests(
      vaultID: vaultID,
      invitationDigest: invitationDigest, at: unixTime, maximumCount: 4_096
    )
    .sorted { $0.lexicographicallyPrecedes($1) }
    try validateScope()
    return digests.isEmpty
      ? "No join requests are available for that invitation yet.\n"
      : digests.map(v3LowercaseHex).joined(separator: "\n") + "\n"
  }

  func compare(
    vaultID requested: String, invitationDigest: Data, joinRequestDigest: Data?,
    at unixTime: UInt64
  ) throws -> String {
    try validateScope()
    guard requested == vaultID else { throw V3EnrollmentCeremonyStateError.wrongRole }
    let state: V3EnrollmentCeremonyState
    if let joinRequestDigest {
      state = try exchange.receiveJoinRequest(
        vaultID: vaultID, invitationDigest: invitationDigest,
        joinRequestDigest: joinRequestDigest, at: unixTime)
    } else {
      state = try exchange.resume(
        vaultID: vaultID, invitationDigest: invitationDigest, at: unixTime)
    }
    guard let transcript = state.transcript else { throw V3EnrollmentAdoptionError.invalidCeremony }
    try validateScope()
    return [
      "Compare these details on both Macs.", "Vault: \(vaultID)",
      "Existing Mac: \(transcript.invitation.invitingDevice.displayName)",
      "Joining Mac: \(transcript.joinRequest.joiningDevice.displayName)",
      "Comparison code: \(transcript.comparisonCode)",
      "Only if both Macs show this exact code and both Mac names, run `key share approve \(vaultID) \(v3LowercaseHex(invitationDigest)) \(transcript.comparisonCode)`.",
    ].joined(separator: "\n") + "\n"
  }

  func approve(
    vaultID requested: String, invitationDigest: Data, comparisonCode: String,
    at unixTime: UInt64, operationID: VaultTransactionOperationID
  ) throws -> String {
    try validateScope()
    guard requested == vaultID else { throw V3EnrollmentCeremonyStateError.wrongRole }
    let state = try exchange.resumeDeviceWrappedOwnerApproval(
      vaultID: vaultID,
      invitationDigest: invitationDigest)
    guard let transcript = state.transcript, transcript.comparisonCode == comparisonCode else {
      throw V3EnrollmentAdoptionError.invalidCeremony
    }
    let identity = try loadIdentity()
    if try ownership.loadRecoveryAnchor(vaultID: vaultID) != nil {
      let result = try makeService(identity).recoverInterruptedEnrollment(
        invitationDigest: invitationDigest, operationID: operationID)
      switch result {
      case .completed, .alreadyCompleted: break
      case .nothingToRecover, .abandoned:
        throw AppError.operationRefused(
          "The incomplete enrollment was not approved. Compare the current invitation again before explicitly approving a new attempt."
        )
      }
    } else {
      let context = try unlock.authenticatedReadContext(
        reason: "Unlock the vault to approve the Mac whose code you compared.")
      let ticket = try context.authenticationTicket()
      let bound = V3ScopedEnrollmentIdentity(
        base: identity,
        validate: {
          try validateScope()
          try session.requireCurrent(ticket)
        })
      let service = makeService(bound)
      if state.phase == .consumed {
        try service.confirmCompletedEnrollment(
          invitationDigest: invitationDigest, approvedTranscriptDigest: transcript.digest,
          continuing: ticket)
      } else {
        let review = try service.prepare(
          invitationDigest: invitationDigest, at: unixTime, continuing: ticket)
        _ = try service.approve(
          invitationDigest: invitationDigest,
          approvedTranscriptDigest: transcript.digest, expectedCheckpoint: review.checkpoint,
          at: unixTime, operationID: operationID, continuing: ticket)
      }
    }
    try validateScope()
    return
      "Enrollment approved. From the same vault folder, the other Mac can now run `key share accept \(vaultID) \(v3LowercaseHex(invitationDigest)) \(comparisonCode)`; when running elsewhere, add `--vault-dir <existing-folder>`.\n"
  }

  func join(invitationDigest: Data, deviceName: String, at unixTime: UInt64) throws -> String {
    throw AppError.operationRefused(
      "This Mac is already configured to use a vault. Joining cannot switch it to another vault.")
  }
  func accept(
    vaultID: String, invitationDigest: Data, comparisonCode: String,
    at unixTime: UInt64, operationID: VaultTransactionOperationID
  ) throws -> String {
    throw AppError.operationRefused(
      "This Mac is already configured to use a vault. It cannot accept another invitation here.")
  }
}

/// Shared process-local guard around private operations. It owns no grant and
/// cannot create a replacement authentication after the caller's scope stops.
struct V3ScopedEnrollmentIdentity: V3EnrollmentMessageSigning, V3DeviceWrappedVaultKeyUnwrapping {
  let base: V3RecoveryEnrollmentOwnerService.Identity
  let validate: @Sendable () throws -> Void
  var vaultID: String { base.vaultID }
  var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
  func signature(for input: Data, reason: String) throws -> Data {
    try validate()
    let result = try base.signature(for: input, reason: reason)
    try validate()
    return result
  }
  func unwrapDeviceWrappedVaultKey(
    _ ciphertext: V3HPKEWrappedVaultKey,
    context: V3VaultKeyHPKEContext, reason: String
  ) throws -> Data {
    try validate()
    let result = try base.unwrapDeviceWrappedVaultKey(ciphertext, context: context, reason: reason)
    try validate()
    return result
  }
}
