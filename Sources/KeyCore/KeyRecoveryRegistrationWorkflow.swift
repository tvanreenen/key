import CryptoKit
import Foundation

/// Configured setup composition. The host owns its exclusive barrier and
/// connection scope; domain services retain publication and resume ownership.
/// No token writer, credential input or decrypted key appears in its protocol.
struct KeyRecoveryRegistrationWorkflow: Sendable {
  let vaultID: String
  let store:
    any V3TransactionArtifactStore & V3RecoveryRegistrationBundleStoring
      & V3RecoveryAdoptionPreparationStoring
  let checkpoints: any V3ManifestCheckpointStoring
  let transaction: any V3ImmutableTransactionRecoveryAnchorStoring
  let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  let cache: any V3CheckpointManifestCaching
  let identities: any V3DeviceWrappedIdentityLoading
  let reader: PIVRecoveryTokenReader
  let agreement: PIVRecoveryAgreement
  let owner: any VaultTransactionMutationOwning
  var validateLocation: @Sendable () throws -> Void = {}

  func handle(_ request: KeyRecoveryRegistrationRequest, scope: KeyRecoveryRequestScope) throws
    -> KeyServiceResponse
  {
    guard #available(macOS 26.0, *) else {
      throw AppError.operationRefused("Recovery setup requires macOS 26 or later.")
    }
    try scope.requireCurrent()
    try validateLocation()
    try request.validate()
    let kind: VaultTransactionMutationKind =
      switch request {
      case .adopt, .resumeAdoption: .adoptRecoveryProfile
      default: .registerRecoveryRecipient
      }
    return try owner.perform(kind) { context in
      if case .pending = request {
        let stores:
          [(
            KeyRecoveryRegistrationResult.PendingOperation.Namespace,
            any V3ImmutableTransactionRecoveryAnchorStoring
          )] = [
            (.transaction, transaction), (.registration, registration), (.adoption, adoption),
          ]
        let bytes = try stores.map { try $0.1.loadRecoveryAnchor(vaultID: vaultID) }
        let operations = try zip(stores, bytes).compactMap {
          pair, bytes
            -> KeyRecoveryRegistrationResult.PendingOperation? in
          guard let bytes else { return nil }
          guard bytes.count <= 1_024,
            let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
            anchor.vaultID == vaultID
          else { throw V3RecoveryVaultUnlockError.mutationPending }
          return .init(namespace: pair.0, operationID: anchor.operationID.rawValue)
        }
        try requireOwnership(transaction: bytes[0], registration: bytes[1], adoption: bytes[2])
        try scope.requireCurrent()
        try validateLocation()
        return .init(
          exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil,
          recoveryRegistration: .pending(vaultID: vaultID, operations: operations))
      }
      let direct = DirectVaultTransactionMutationOwner(operationID: context.operationID)
      let session = V3DeviceWrappedVaultKeySessionStore()
      defer { session.invalidate() }
      let validate: @Sendable () throws -> Void = {
        try scope.requireCurrent()
        try validateLocation()
      }
      let loader = ScopedLoader(base: identities, scope: scope, validateLocation: validateLocation)
      let selected = try v3SelectedCheckpointProfile(
        vaultID: vaultID, checkpoints: checkpoints, source: store, cache: cache)
      let authentication: Authentication
      switch (request, selected.profile) {
      case (.adopt, .permanent), (.resumeAdoption, .permanent):
        let pending = try adoption.loadRecoveryAnchor(vaultID: vaultID)
        if case .adopt = request, pending != nil {
          throw V3RecoveryAdoptionServiceError.adoptionPending
        }
        if case .resumeAdoption(let operation) = request {
          try requireSelectedOwnership(pending, operation: operation)
        }
        try requireOwnership(transaction: nil, registration: nil, adoption: pending)
        let runtime = V3DeviceWrappedVaultUnlockRuntime(
          vaultID: vaultID, checkpointStore: checkpoints, source: store, cache: cache,
          identityLoader: loader, session: session)
        let current = try runtime.authenticatedCheckpoint(
          reason: "Authenticate explicit recovery format adoption.")
        guard current.checkpoint == selected.checkpoint else {
          throw V3RecoveryVaultUnlockError.checkpointChanged
        }
        try requireOwnership(transaction: nil, registration: nil, adoption: pending)
        authentication = .init(
          key: try session.load(vaultID: vaultID, keyID: current.envelope.body.keyID),
          ticket: session.beginAuthentication())
      case (.adopt, .recovery):
        throw AppError.operationRefused(
          "This vault already uses the recovery-capable format. Inspect registration status; adoption is not registration."
        )
      case (_, .permanent):
        throw AppError.operationRefused(
          "Explicitly adopt the recovery-capable format before registration.")
      case (_, .recovery):
        let runtime = V3RecoveryVaultUnlockRuntime(
          vaultID: vaultID, checkpointStore: checkpoints, source: store, cache: cache,
          identityLoader: loader, session: session, transactionOwnershipStore: transaction,
          registrationOwnershipStore: registration, adoptionOwnershipStore: adoption)
        let namespace: V3RecoveryOwnershipNamespace?
        switch request {
        case .resumeAdoption(let operation):
          let pending = try adoption.loadRecoveryAnchor(vaultID: vaultID)
          if let pending { try requireSelectedOwnership(pending, operation: operation) }
          namespace = pending == nil ? nil : .adoption
        case .status, .finish:
          namespace =
            try registration.loadRecoveryAnchor(vaultID: vaultID) == nil ? nil : .registration
        case .resumeExport: namespace = .registration
        case .prepare: namespace = nil
        case .adopt, .pending: preconditionFailure("Handled above")
        }
        if let namespace {
          let pending = try runtime.authenticatedPendingContext(
            namespace: namespace, reason: "Authenticate this Mac's exact pending recovery setup.",
            continuing: session.beginAuthentication())
          guard pending.current.checkpoint == selected.checkpoint else {
            throw V3RecoveryVaultUnlockError.checkpointChanged
          }
          authentication = .init(
            key: try pending.loadVaultKey(), ticket: try pending.authenticationTicket())
        } else {
          let current = try runtime.authenticatedReadContext(
            reason: "Authenticate configured recovery setup.")
          guard current.current.checkpoint == selected.checkpoint else {
            throw V3RecoveryVaultUnlockError.checkpointChanged
          }
          authentication = .init(
            key: try current.loadVaultKey(keyID: current.current.envelope.body.fields.keyID),
            ticket: try current.authenticationTicket())
        }
      }
      try scope.requireCurrent()
      try session.requireCurrent(authentication.ticket)
      let result: KeyRecoveryRegistrationResult
      switch request {
      case .status:
        let status = try V3RecoveryRegistrationStatusService(
          vaultID: vaultID, mutationOwner: direct, source: store, checkpointStore: checkpoints,
          registrationOwnershipStore: registration, transactionOwnershipStore: transaction,
          adoptionOwnershipStore: adoption
        ).status(currentVaultKey: authentication.key)
        switch status {
        case .unregistered:
          result = .status(
            state: .unregistered, vaultID: vaultID, recipients: [], activationCommitted: false)
        case .registered(_, let recipients):
          result = .status(
            state: .registered, vaultID: vaultID, recipients: recipients.map(\.rawValue),
            activationCommitted: false)
        case .pending(_, let committed):
          result = .status(
            state: .pending, vaultID: vaultID, recipients: [], activationCommitted: committed)
        case .attentionRequired:
          result = .status(
            state: .attentionRequired, vaultID: vaultID, recipients: [], activationCommitted: false)
        }
      default:
        guard
          let identity = try loader.loadDeviceIdentity(
            vaultID: vaultID, reason: "Use this Mac's recovery setup authority.")
            as? any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
        else { throw V3RecoveryVaultUnlockError.identityUnavailable }
        try session.requireCurrent(authentication.ticket)
        switch request {
        case .adopt, .resumeAdoption:
          let service = V3RecoveryAdoptionService(
            vaultID: vaultID, identity: identity, mutationOwner: direct, objectStore: store,
            checkpointStore: checkpoints, adoptionOwnershipStore: adoption,
            transactionOwnershipStore: transaction, registrationOwnershipStore: registration,
            validateScope: validate)
          let commit: V3RecoveryAdoptionCommit
          if case .resumeAdoption(let operation) = request {
            commit = try service.resume(
              operationID: .init(validating: operation), currentVaultKey: authentication.key)
          } else {
            commit = try service.adopt(currentVaultKey: authentication.key)
          }
          result = completed(commit.checkpoint, cleanup: commit.cleanupPending)
        case .prepare(let token, let recipient), .resumeExport(let token, let recipient),
          .finish(let token, let recipient):
          let observation = try observe(token: token, recipient: recipient, scope: scope)
          let service = V3RecoveryRegistrationService(
            vaultID: vaultID, identity: identity, mutationOwner: direct, objectStore: store,
            checkpointStore: checkpoints, registrationOwnershipStore: registration,
            transactionOwnershipStore: transaction, adoptionOwnershipStore: adoption,
            reader: reader, agreement: agreement, validateScope: validate)
          if case .finish = request {
            let commit = try service.finish(
              observation: observation, currentVaultKey: authentication.key,
              cancellation: scope.cancellation, deadline: scope.deadline)
            result = completed(commit.checkpoint, cleanup: commit.cleanupPending)
          } else {
            let exported: V3RecoveryRegistrationExport
            if case .prepare = request {
              exported = try service.prepare(
                observation: observation, currentVaultKey: authentication.key)
            } else {
              exported = try service.resumeExport(
                observation: observation, currentVaultKey: authentication.key)
            }
            result = .export(
              operationID: exported.operationID.rawValue, vaultID: vaultID,
              recipientID: exported.recipientID.rawValue, anchor: Base64URL.encode(exported.anchor))
          }
        case .status, .pending: preconditionFailure("Handled above")
        }
      }
      try session.requireCurrent(authentication.ticket)
      try scope.requireCurrent()
      try validateLocation()
      return .init(
        exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil, recoveryRegistration: result)
    }
  }

  private struct Authentication {
    let key: Data
    let ticket: V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
  }

  /// Configured key change shares location/scope admission, not registration
  /// semantics. Its domain service cannot contact a recovery token.
  func rotate(_ request: KeyRecoveryRotationRequest, scope: KeyRecoveryRequestScope) throws
    -> KeyServiceResponse
  {
    guard #available(macOS 26.0, *) else {
      throw AppError.operationRefused("Recovery-capable key rotation requires macOS 26 or later.")
    }
    try request.validate()
    let validate: @Sendable () throws -> Void = {
      try scope.requireCurrent()
      try validateLocation()
    }
    try validate()
    return try owner.perform(.rotateVaultKey) { context in
      try validate()
      let selected = try v3SelectedCheckpointProfile(
        vaultID: vaultID, checkpoints: checkpoints, source: store, cache: cache)
      guard case .recovery = selected.profile else {
        throw AppError.operationRefused(
          "This command requires the recovery-capable format; it does not adopt it.")
      }
      let pending: Data?
      switch request {
      case .rotate:
        pending = nil
        try requireOwnership(transaction: nil, registration: nil, adoption: nil)
      case .resume(let operation):
        pending = try transaction.loadRecoveryAnchor(vaultID: vaultID)
        let anchor = try requireSelectedOwnership(pending, operation: operation)
        guard
          case .available(let bytes) = try store.readRecoveryIntent(
            operationID: anchor.operationID,
            maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes),
          Data(SHA256.hash(data: bytes)) == anchor.intentDigest,
          let intent = try? V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes),
          intent.vaultID == vaultID, intent.operationID == anchor.operationID,
          intent.kind == .rotateVaultKey
        else {
          throw AppError.operationRefused(
            "The exact locally owned intent is not a readable key rotation. Preserve all records; no replacement or cleanup was authorized."
          )
        }
        try requireOwnership(transaction: pending, registration: nil, adoption: nil)
      }
      let session = V3DeviceWrappedVaultKeySessionStore()
      defer { session.invalidate() }
      let loader = ScopedLoader(base: identities, scope: scope, validateLocation: validateLocation)
      let runtime = V3RecoveryVaultUnlockRuntime(
        vaultID: vaultID, checkpointStore: checkpoints, source: store, cache: cache,
        identityLoader: loader, session: session, transactionOwnershipStore: transaction,
        registrationOwnershipStore: registration, adoptionOwnershipStore: adoption)
      let authenticated: V3ManifestCheckpoint
      if pending != nil {
        let current = try runtime.authenticatedPendingContext(
          namespace: .transaction,
          reason: "Authenticate this Mac's exact pending vault-key rotation.",
          continuing: session.beginAuthentication())
        authenticated = current.current.checkpoint
        _ = try current.loadVaultKey()
      } else {
        let current = try runtime.authenticatedReadContext(
          reason: "Authenticate an explicit vault-key rotation.")
        authenticated = current.current.checkpoint
        _ = try current.loadVaultKey(keyID: current.current.envelope.body.fields.keyID)
      }
      guard authenticated == selected.checkpoint else {
        throw V3RecoveryVaultUnlockError.checkpointChanged
      }
      try validate()
      guard
        let identity = try loader.loadDeviceIdentity(
          vaultID: vaultID, reason: "Use this Mac's vault-key rotation authority.")
          as? any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
      else {
        throw V3RecoveryVaultUnlockError.identityUnavailable
      }
      let service = V3RecoveryKeyRotationService(
        vaultID: vaultID, identity: identity, session: session, objectStore: store,
        checkpointStore: checkpoints, recoveryAnchorStore: transaction,
        registrationAnchorStore: registration, adoptionAnchorStore: adoption,
        cache: cache, validateScope: validate)
      let result: KeyRecoveryRotationResult
      switch request {
      case .rotate:
        let commit = try service.rotate(
          expectedCheckpoint: authenticated, operationID: context.operationID)
        result = .completed(
          vaultID: vaultID, manifestDigest: Base64URL.encode(commit.checkpoint.envelopeDigest),
          cleanupPending: try transaction.loadRecoveryAnchor(vaultID: vaultID) != nil)
      case .resume:
        // The service selects the exact original pinned intent. This owner ID
        // scopes serialization only and never substitutes new epoch work.
        let outcome = try service.recoverInterruptedRotation(
          operationID: context.operationID, expectedAnchor: pending)
        switch outcome {
        case .completed, .alreadyCompleted:
          let selected = try v3SelectedCheckpointProfile(
            vaultID: vaultID, checkpoints: checkpoints, source: store, cache: cache)
          let envelope = try V3RecoveryManifestCodec().parseEnvelope(
            V3ExactTransitionRepository(source: store, limits: .standard).readManifest(
              selected.checkpoint.envelopeDigest))
          try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
            envelope,
            vaultKey: session.load(vaultID: vaultID, keyID: envelope.body.fields.keyID))
          guard
            try checkpoints.loadCheckpoint(vaultID: vaultID) == selected.checkpoint.canonicalBytes
          else {
            throw V3RecoveryVaultUnlockError.checkpointChanged
          }
          result = .completed(
            vaultID: vaultID, manifestDigest: Base64URL.encode(selected.checkpoint.envelopeDigest),
            cleanupPending: false)
        case .abandoned: result = .abandoned(vaultID: vaultID)
        case .nothingToRecover:
          throw AppError.operationRefused(
            "The selected rotation is no longer pending. Inspect status; no new rotation was started."
          )
        }
      }
      // A successful rotation installs a new local session generation inside
      // the validated service. The independent host scope still rejects lock,
      // disconnect, deadline or location changes; never capture fresh consent.
      try validate()
      return .init(exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil, recoveryRotation: result)
    }
  }
  private func completed(_ checkpoint: V3ManifestCheckpoint, cleanup: Bool)
    -> KeyRecoveryRegistrationResult
  {
    .completed(
      vaultID: vaultID, manifestDigest: Base64URL.encode(checkpoint.envelopeDigest),
      cleanupPending: cleanup)
  }
  @discardableResult
  private func requireSelectedOwnership(_ bytes: Data?, operation: String) throws
    -> V3ImmutableTransactionRecoveryAnchor
  {
    guard let bytes, bytes.count <= 1_024,
      let anchor = try? V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes),
      anchor.vaultID == vaultID, anchor.operationID.rawValue == operation
    else { throw V3RecoveryAdoptionServiceError.ownershipChanged }
    return anchor
  }
  private func requireOwnership(
    transaction expectedTransaction: Data?, registration expectedRegistration: Data?,
    adoption expectedAdoption: Data?
  ) throws {
    for (store, expected) in [
      (transaction, expectedTransaction), (registration, expectedRegistration),
      (adoption, expectedAdoption),
    ] {
      guard try store.loadRecoveryAnchor(vaultID: vaultID) == expected else {
        throw V3RecoveryVaultUnlockError.mutationPending
      }
    }
  }
  private func observe(token: String, recipient: String, scope: KeyRecoveryRequestScope) throws
    -> PIVRecoveryTokenObservation
  {
    try scope.requireCurrent()
    let candidates = try reader.candidates().filter { $0.tokenID == token }
    guard candidates.count == 1, let candidate = candidates.first else {
      throw PIVRecoveryTokenError.invalidSelection
    }
    let observation = try reader.read(candidate)
    try scope.requireCurrent()
    guard observation.recipientID.rawValue == recipient else {
      throw PIVRecoveryTokenError.anchorCredentialMismatch
    }
    try observation.keyMetadata.requireRecoveryPolicy()
    return observation
  }

  private struct ScopedLoader: V3DeviceWrappedIdentityLoading {
    let base: any V3DeviceWrappedIdentityLoading
    let scope: KeyRecoveryRequestScope
    let validateLocation: @Sendable () throws -> Void
    func loadDeviceIdentity(vaultID: String, reason: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      try scope.requireCurrent()
      try validateLocation()
      guard
        let identity = try base.loadDeviceIdentity(vaultID: vaultID, reason: reason)
          as? any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
      else { return nil }
      try scope.requireCurrent()
      try validateLocation()
      return ScopedIdentity(base: identity, scope: scope, validateLocation: validateLocation)
    }
  }
  private struct ScopedIdentity: V3EnrollmentMessageSigning, V3DeviceWrappedVaultKeyUnwrapping {
    let base: any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
    let scope: KeyRecoveryRequestScope
    let validateLocation: @Sendable () throws -> Void
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func signature(for input: Data, reason: String) throws -> Data {
      try scope.requireCurrent()
      try validateLocation()
      let result = try base.signature(for: input, reason: reason)
      try scope.requireCurrent()
      try validateLocation()
      return result
    }
    func unwrapDeviceWrappedVaultKey(
      _ ciphertext: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      try scope.requireCurrent()
      try validateLocation()
      let result = try base.unwrapDeviceWrappedVaultKey(
        ciphertext, context: context, reason: reason)
      try scope.requireCurrent()
      try validateLocation()
      return result
    }
  }
}

/// Closed format dispatch from the exact bounded device-local checkpoint.
/// This verifies its byte binding, not its MAC, snapshot or provider head.
func v3SelectedCheckpointProfile(
  vaultID: String, checkpoints: any V3ManifestCheckpointStoring,
  source: any V3ImmutableObjectReading, cache: any V3CheckpointManifestCaching
) throws -> (checkpoint: V3ManifestCheckpoint, profile: V3DeviceWrappedManifestProfile) {
  guard let data = try checkpoints.loadCheckpoint(vaultID: vaultID), data.count <= 1_024,
    let checkpoint = try? V3ManifestCheckpoint(canonicalBytes: data), checkpoint.vaultID == vaultID
  else { throw V3RecoveryVaultUnlockError.recoveryRequired }
  let bytes: Data
  if case .available(let cached) = try? cache.load(for: checkpoint) {
    bytes = cached
  } else {
    bytes = try V3ExactTransitionRepository(source: source, limits: .standard).readManifest(
      checkpoint.envelopeDigest)
  }
  guard bytes.count <= V3RecoveryManifestCodec.maximumBytes,
    Data(SHA256.hash(data: bytes)) == checkpoint.envelopeDigest
  else {
    throw V3RecoveryVaultUnlockError.recoveryRequired
  }
  let container = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(bytes)
  let profile = try V3RecoveryManifestCodec().decodeBody(container.manifestValue)
  guard try checkpoints.loadCheckpoint(vaultID: vaultID) == checkpoint.canonicalBytes else {
    throw V3RecoveryVaultUnlockError.checkpointChanged
  }
  return (checkpoint, profile)
}

extension KeyRecoveryRegistrationWorkflow {
  /// Constructs dependencies only. No key, token or vendor administration is
  /// opened here. The host must supply its exact request scope to handle().
  static func live(configStore: KeyConfigStore, configuration: RuntimeConfiguration) throws -> Self
  {
    let selected = try configStore.load()
    guard case .v3(let vaultID) = selected.authority else {
      throw AppError.operationRefused(
        "Recovery setup requires an existing device-wrapped v3 vault. Migrate v2 separately first.")
    }
    let root = try VaultRootDirectoryHandle(opening: selected.vaultDirectoryURL)
    let verifySelection = configStore.selectionValidator(expected: selected)
    let reader = PIVRecoveryTokenReader.live()
    return Self(
      vaultID: vaultID, store: V3FilesystemTransactionArtifactStore(rootHandle: root),
      checkpoints: V3ManifestCheckpointKeychainStore(configuration: configuration),
      transaction: V3ImmutableTransactionRecoveryAnchorKeychainStore(configuration: configuration),
      registration: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .registration),
      adoption: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .adoption),
      cache: try KeyServiceHandler.makeV3CheckpointManifestCache(keyConfiguration: selected),
      identities: V3EnrollmentDeviceIdentityManager(
        recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(configuration: configuration),
        keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations()),
      reader: reader, agreement: .live(reader: reader), owner: VaultTransactionMutationOwner(),
      validateLocation: {
        try root.requireConfiguredRootIdentity()
        try verifySelection()
      })
  }
}
