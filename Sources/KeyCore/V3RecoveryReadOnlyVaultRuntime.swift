import Foundation

/// Exact-checkpoint profile-3 read adapter, not provider-current selection or
/// shipping dispatch. A surrounding runtime must compose catch-up/stale policy.
/// Entry planning, encrypted closure checks and decryption use existing modules.
struct V3RecoveryReadOnlyVaultRuntime: VaultReadServicing, VaultUXServicing, Sendable {
  private let source: any V3ImmutableObjectReading
  private let unlockRuntime: V3RecoveryVaultUnlockRuntime
  private let limits: V3ManifestRepositoryLimits
  private let planner = V3AuthenticatedReadPlanner()
  private let contentValidator: V3DeviceWrappedCheckpointContentValidator

  init(
    source: any V3ImmutableObjectReading, unlockRuntime: V3RecoveryVaultUnlockRuntime,
    limits: V3ManifestRepositoryLimits = .standard
  ) {
    self.source = source
    self.unlockRuntime = unlockRuntime
    self.limits = limits
    contentValidator = .init(source: source, limits: limits)
  }

  func unlock() throws {
    try translatingV3RecoveryRuntimeErrors {
      _ = try unlockRuntime.unlock(reason: "Unlock the vault.")
    }
  }

  func read(name: String, allowStale _: Bool) throws -> VaultReadValue {
    let name = try normalizedV3EntryName(name)
    return try translatingV3RecoveryRuntimeErrors {
      let context = try unlockRuntime.authenticatedReadContext(
        reason: "Unlock the vault to read '\(name)'.")
      return try read(name: name, context: context)
    }
  }

  func read(name: String, context: V3RecoveryVaultUnlockRuntime.ReadContext) throws
    -> VaultReadValue
  {
    try translatingV3RecoveryRuntimeErrors {
      try context.revalidate()
      let plan = try planner.planCheckpointRead(
        named: name, entries: context.current.envelope.body.fields.entries,
        checkpoint: context.current.checkpoint)
      let plaintext = try V3AuthenticatedReadExecutor(
        source: source, maximumEntryBytes: limits.maximumEntryBytes,
        vaultKeyProvider: { try context.loadVaultKey(keyID: $0) },
        authorityValidator: authorityValidator(context)
      ).execute(plan)
      return .init(type: plan.entry.type, plaintext: plaintext)
    }
  }

  func list(allowStale: Bool) throws -> [String] {
    try translatingV3RecoveryRuntimeErrors {
      let context = try unlockRuntime.authenticatedReadContext(
        reason: "Unlock the vault to list saved entries.")
      return try list(allowStale: allowStale, context: context)
    }
  }

  func list(allowStale: Bool, context: V3RecoveryVaultUnlockRuntime.ReadContext) throws -> [String]
  {
    try translatingV3RecoveryRuntimeErrors {
      switch try validation(context) {
      case .ready: break
      case .incomplete:
        guard allowStale else { throw VaultUXServiceError.vaultIncomplete }
      case .invalid, .resourceLimitExceeded: throw VaultUXServiceError.recoveryRequired
      }
      let plan = planner.planCheckpointList(
        entries: context.current.envelope.body.fields.entries,
        checkpoint: context.current.checkpoint)
      try authorityValidator(context).validate(plan.authority)
      return plan.entries.map(\.name)
    }
  }

  func status() throws -> VaultStatus {
    try translatingV3RecoveryRuntimeErrors {
      let context = try unlockRuntime.authenticatedReadContext(
        reason: "Unlock the vault to check its status.")
      return try status(context: context)
    }
  }

  func status(context: V3RecoveryVaultUnlockRuntime.ReadContext) throws -> VaultStatus {
    try translatingV3RecoveryRuntimeErrors {
      let result = try validation(context)
      try context.revalidate()
      let count = context.current.envelope.body.fields.entries.count
      let health: VaultHealth
      let entries: VaultEntrySummary
      let issues: [VaultIssue]
      switch result {
      case .ready:
        health = .ready
        entries = .effective(count)
        issues = []
      case .incomplete:
        health = .incomplete
        entries = .lastTrusted(count)
        issues = [
          .init(
            code: .referencedObjectUnavailable,
            message: "A required encrypted entry file is unavailable.")
        ]
      case .invalid:
        health = .recoveryRequired
        entries = .lastTrusted(count)
        issues = [
          .init(
            code: .invalidReferencedObject,
            message:
              "A required encrypted entry failed verification. Keep the files intact for investigation."
          )
        ]
      case .resourceLimitExceeded:
        health = .recoveryRequired
        entries = .lastTrusted(count)
        issues = [
          .init(
            code: .resourceLimitExceeded,
            message:
              "Checking the last verified vault state exceeded Key's size or item-count limits.")
        ]
      }
      return .init(
        format: .version3, health: health, entries: entries,
        trustedVersionID: String(
          v3LowercaseHex(context.current.checkpoint.envelopeDigest).prefix(16)),
        issues: issues)
    }
  }

  func authorizeRead(name: String, allowStale _: Bool) throws {
    let name = try normalizedV3EntryName(name)
    try translatingV3RecoveryRuntimeErrors {
      let context = try unlockRuntime.authenticatedReadContext(
        reason: "Unlock the vault to verify '\(name)'.")
      try authorizeRead(name: name, context: context)
    }
  }

  func authorizeRead(name: String, context: V3RecoveryVaultUnlockRuntime.ReadContext) throws {
    try translatingV3RecoveryRuntimeErrors {
      try context.revalidate()
      _ = try planner.planCheckpointRead(
        named: name,
        entries: context.current.envelope.body.fields.entries,
        checkpoint: context.current.checkpoint)
      try context.revalidate()
    }
  }

  func authorizeMutation() throws { throw readOnlyError() }
  func resolve(_: [VaultConflictResolution]) throws { throw readOnlyError() }

  // This adapter has no graph observation. It must not report an empty conflict
  // set merely because a selected checkpoint is readable.
  func conflicts() throws -> [VaultConflictSummary] { throw historyUnavailable() }
  func conflict(id _: String) throws -> VaultConflictDetail { throw historyUnavailable() }
  func conflictValue(id _: String, versionID _: String) throws -> String {
    throw historyUnavailable()
  }

  private func validation(_ context: V3RecoveryVaultUnlockRuntime.ReadContext) throws
    -> V3DeviceWrappedCheckpointContentValidation
  {
    try context.revalidate()
    let result = try contentValidator.validate(
      entries: context.current.envelope.body.fields.entries,
      vaultID: context.current.checkpoint.vaultID)
    try context.revalidate()
    return result
  }

  private func authorityValidator(_ context: V3RecoveryVaultUnlockRuntime.ReadContext)
    -> V3ReadAuthorityValidator
  {
    .init(
      currentStateProvider: { _ in throw V3AuthenticatedReadError.authorityChanged },
      checkpointProvider: { vaultID in
        guard vaultID == context.current.checkpoint.vaultID else {
          throw V3AuthenticatedReadError.authorityChanged
        }
        try context.revalidate()
        return context.current.checkpoint
      })
  }

  private func readOnlyError() -> AppError {
    .operationRefused("Recovery-profile writes are not composed through this read adapter.")
  }

  private func historyUnavailable() -> AppError {
    .operationRefused("Recovery-profile history review is not composed through this read adapter.")
  }
}

/// Profile-specific UX translation shared by exact reads and their orchestrator.
func translatingV3RecoveryRuntimeErrors<T>(_ operation: () throws -> T) throws -> T {
  do { return try operation() } catch let error as V3RecoveryVaultUnlockError {
    switch error {
    case .locked:
      throw AppError.authFailed(
        "The vault session was locked or authentication was cancelled. Unlock it to continue.")
    case .temporaryUnavailable, .checkpointChanged: throw VaultUXServiceError.vaultIncomplete
    case .deviceRevoked: throw VaultUXServiceError.deviceRevoked
    case .identityUnavailable:
      throw AppError.operationRefused(
        "This Mac's vault credentials are unavailable. Use another enrolled Mac or a configured recovery method to restore access."
      )
    case .unsupportedProfile:
      throw AppError.operationRefused(
        "This vault profile is not supported by the recovery-profile runtime.")
    case .mutationPending, .recoveryRequired: throw VaultUXServiceError.recoveryRequired
    }
  } catch is V3DeviceWrappedVaultKeySessionError {
    throw AppError.authFailed(
      "The vault session changed before the operation completed. Unlock it to continue.")
  } catch let error as V3AuthenticatedReadError {
    switch error {
    case .entryUnavailable, .authorityChanged: throw VaultUXServiceError.vaultIncomplete
    case .invalidEntryObject, .entryObjectTooLarge: throw VaultUXServiceError.recoveryRequired
    }
  } catch is V3EncryptedEntryError {
    throw VaultUXServiceError.recoveryRequired
  } catch let error as V3RecoveryValidationError {
    switch error {
    case .sourceUnavailable, .entryUnavailable: throw VaultUXServiceError.vaultIncomplete
    case .sourceChanged: throw VaultUXServiceError.expectedHeadsChanged
    case .authorityConflict, .closedEpochBranch: throw VaultUXServiceError.securityConflict
    case .contentConflict: throw VaultUXServiceError.catchUpContentConflict
    default: throw VaultUXServiceError.recoveryRequired
    }
  } catch let error as V3RecoveryContentCatchUpError {
    switch error {
    case .checkpointChanged: throw VaultUXServiceError.expectedHeadsChanged
    case .localMutationPending, .stepLimitExceeded: throw VaultUXServiceError.vaultIncomplete
    case .epochTransitionRequired: throw VaultUXServiceError.recoveryRequired
    }
  } catch let error as V3RecoveryKeyTransitionCatchUpError {
    switch error {
    case .deviceRevoked: throw VaultUXServiceError.deviceRevoked
    case .invalidDevice: throw VaultUXServiceError.recoveryRequired
    }
  } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
    throw AppError.authFailed("Authentication was cancelled. No automatic retry was attempted.")
  }
}
