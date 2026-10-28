import Foundation

/// Product confirmation uses the existing exact review token. Cryptographic
/// roster policy, fresh-key publication and exact resume stay in the domain.
struct V3RecoveryDeviceRevocationWorkflow: V3DeviceRevocationWorkflowServicing, Sendable {
  typealias Identity = V3RecoveryAuthorityChangeService.Identity
  let session: V3DeviceWrappedVaultKeySessionStore
  let loadIdentity: @Sendable () throws -> Identity
  let authenticate:
    @Sendable (VaultTransactionOperationID) throws -> V3RecoveryVaultUnlockRuntime.ReadContext
  let makeService: @Sendable (Identity) -> V3RecoveryAuthorityChangeService
  var validateScope: @Sendable () throws -> Void = {}
  private var binding: V3DeviceRevocationReviewBinding { .init() }

  func review(revoking deviceID: String, operationID: VaultTransactionOperationID) throws
    -> V3VaultDeviceRevocationReview
  {
    try validateScope()
    let identity = try loadIdentity()
    if let pending = try makeService(identity).pendingRevocation(operationID: operationID) {
      guard pending.plan.revokedDevice.identity.deviceID == deviceID else {
        throw V3DeviceWrappedRevocationWorkflowError.reviewedStateChanged
      }
      try validateScope()
      return binding.review(for: pending.plan)
    }
    let context = try authenticate(operationID)
    let ticket = try context.authenticationTicket()
    let service = boundService(identity, ticket: ticket)
    let plan = try service.prepareRevocation(revoking: deviceID, continuing: ticket)
    try context.revalidate()
    try validateScope()
    return binding.review(for: plan)
  }

  func revokeReviewed(
    deviceID: String, confirmationToken: String, operationID: VaultTransactionOperationID
  ) throws -> V3ManifestCheckpoint {
    try validateScope()
    guard binding.isCanonicalConfirmationToken(confirmationToken) else {
      throw V3DeviceWrappedRevocationWorkflowError.invalidConfirmationToken
    }
    let identity = try loadIdentity()
    let service = makeService(identity)
    if let pending = try service.pendingRevocation(operationID: operationID) {
      try requireConfirmation(pending.plan, deviceID: deviceID, token: confirmationToken)
      let outcome = try service.recoverInterruptedRevocation(
        operationID: operationID, expectedAnchor: pending.anchor)
      switch outcome {
      case .completed, .alreadyCompleted:
        try validateScope()
        return pending.checkpoint
      case .nothingToRecover, .abandoned:
        throw AppError.operationRefused(
          "The saved revocation did not finish. Review its retained state before another attempt.")
      }
    }
    let context = try authenticate(operationID)
    let ticket = try context.authenticationTicket()
    let bound = boundService(identity, ticket: ticket)
    if context.current.envelope.body.fields.devices.contains(where: {
      $0.identity.deviceID == deviceID && $0.status == .revoked
    }) {
      let completed: V3DeviceWrappedRevocationPlan
      do {
        completed = try bound.completedRevocationPlan(continuing: ticket)
      } catch is V3RecoveryDeviceRevocationError {
        throw V3DeviceWrappedRevocationWorkflowError.reviewedStateChanged
      }
      try requireConfirmation(completed, deviceID: deviceID, token: confirmationToken)
      try context.revalidate()
      try validateScope()
      return context.current.checkpoint
    }
    let plan = try bound.prepareRevocation(revoking: deviceID, continuing: ticket)
    try requireConfirmation(plan, deviceID: deviceID, token: confirmationToken)
    let commit = try bound.revoke(plan, operationID: operationID, continuing: ticket)
    try validateScope()
    return commit.checkpoint
  }

  private func boundService(
    _ identity: Identity,
    ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  ) -> V3RecoveryAuthorityChangeService {
    makeService(
      V3ScopedEnrollmentIdentity(
        base: identity,
        validate: {
          try validateScope()
          try session.requireCurrent(ticket)
        }))
  }
  private func requireConfirmation(
    _ plan: V3DeviceWrappedRevocationPlan, deviceID: String, token: String
  ) throws {
    guard plan.revokedDevice.identity.deviceID == deviceID,
      binding.review(for: plan).confirmationToken == token
    else { throw V3DeviceWrappedRevocationWorkflowError.reviewedStateChanged }
  }
}
