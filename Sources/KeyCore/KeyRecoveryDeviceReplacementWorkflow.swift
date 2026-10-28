import Foundation

/// Composes the existing reviewed cleanup and joining workflow. After cleanup
/// starts, exact durable intent—not an unavailable old credential—owns resume.
enum KeyRecoveryDeviceReplacementWorkflow {
  static func prepare(
    _ request: KeyShareRequest, selected: KeyConfiguration, configStore: KeyConfigStore,
    keyStore: any VaultKeyStoring, configuration: RuntimeConfiguration,
    scope: KeyRecoveryRequestScope
  ) throws -> KeyRecoverySharingInvocation {
    try scope.requireCurrent()
    guard case .v3(let vaultID) = selected.authority else {
      throw V3ReplacementEnrollmentCoordinatorError.invalidRequest
    }
    let root = try VaultRootDirectoryHandle(opening: selected.vaultDirectoryURL)
    let transaction = V3ImmutableTransactionRecoveryAnchorKeychainStore(
      configuration: configuration)
    let registration = V3ImmutableTransactionRecoveryAnchorKeychainStore(
      configuration: configuration, namespace: .registration)
    let adoption = V3ImmutableTransactionRecoveryAnchorKeychainStore(
      configuration: configuration, namespace: .adoption)
    let verifySelection = configStore.selectionValidator(expected: selected)
    let validate: @Sendable () throws -> Void = {
      try scope.requireCurrent()
      try root.requireConfiguredRootIdentity()
      try verifySelection()
      for store in [transaction, registration, adoption] {
        guard try store.loadRecoveryAnchor(vaultID: vaultID) == nil else {
          throw AppError.operationRefused(
            "A saved vault change must finish before replacing this Mac's credentials. No replacement cleanup was authorized."
          )
        }
      }
    }
    try validate()
    let source = V3FilesystemTransactionArtifactStore(rootHandle: root)
    let checkpoints = V3ManifestCheckpointKeychainStore(configuration: configuration)
    let cache = try KeyServiceHandler.makeV3CheckpointManifestCache(keyConfiguration: selected)
    let records = V3EnrollmentDeviceKeyRecordKeychainStore(configuration: configuration)
    let identities = V3EnrollmentDeviceIdentityManager(
      recordStore: records, keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations(),
      validateScope: validate)
    let deleter = V3EnrollmentDeviceIdentityDeleter(recordStore: records)
    let intents = V3ReplacementEnrollmentIntentKeychainStore(configuration: configuration)
    let admission = V3ReplacementEnrollmentAdmission(intentStore: intents)
    let state = try admission.state(vaultID: vaultID)
    let session = V3DeviceWrappedVaultKeySessionStore()
    _ = scope.cancellation.register { session.invalidate() }
    let unlock = V3RecoveryVaultUnlockRuntime(
      vaultID: vaultID, checkpointStore: checkpoints, source: source, cache: cache,
      identityLoader: V3ScopedDeviceIdentityLoader(base: identities, validate: validate),
      session: session,
      transactionOwnershipStore: transaction, registrationOwnershipStore: registration,
      adoptionOwnershipStore: adoption)
    let authority = V3RecoveryReplacementDeviceIdentityAuthorityAdapter(
      vaultID: vaultID, source: source, unlock: unlock,
      loadIdentity: {
        try validate()
        guard
          let identity = try identities.loadDeviceIdentity(
            vaultID: vaultID, reason: "Inspect this Mac's old vault credentials.")
        else { throw V3RecoveryVaultUnlockError.identityUnavailable }
        try validate()
        return V3ScopedDeviceUnwrapper(base: identity, validate: validate)
      }, validateScope: validate)
    let workflow = V3ReplacementEnrollmentWorkflow(
      vaultID: vaultID,
      loadTarget: { id in
        try validate()
        let result = try deleter.deletionTarget(vaultID: id)
        try validate()
        return result
      }, authorityClassifier: authority, intentStore: intents,
      coordinator: V3ReplacementEnrollmentCoordinator(
        vaultID: vaultID, mutationOwner: VaultTransactionMutationOwner(),
        authorityClassifier: authority, identityDeleter: deleter, checkpointStore: checkpoints,
        intentStore: intents, validateScope: validate), validateScope: validate)
    let exchange = V3EnrollmentExchangeCoordinator(
      mailbox: V3FilesystemEnrollmentMailbox(rootHandle: root),
      stateStore: V3EnrollmentCeremonyStateKeychainStore(configuration: configuration))
    let enrollment = try makeLiveV3EnrollmentWorkflowService(
      rootHandle: root, selectedVaultID: state == .enrollmentPending ? nil : vaultID,
      replacementVaultID: state == .enrollmentPending ? vaultID : nil,
      replacementAdmission: state == .enrollmentPending ? admission : nil,
      keyStore: keyStore, keyConfiguration: selected, configStore: configStore,
      runtimeConfiguration: configuration, deviceWrappedSession: session, validateScope: validate)
    let changesCheckpoint: Bool
    switch request {
    case .replaceCurrentDevice, .accept: changesCheckpoint = true
    default: changesCheckpoint = false
    }
    return .init(changesCheckpoint: changesCheckpoint) {
      defer { session.invalidate() }
      try validate()
      return KeyServiceHandler(
        keyStore: keyStore, entryStore: EntryStore(rootURL: root.rootURL), configStore: configStore,
        mutationOwner: VaultTransactionMutationOwner(), enrollmentService: enrollment,
        validateJoinInvitation: { digest, now in
          try validate()
          let invitation = try exchange.receiveInvitation(digest: digest, at: now)
          guard invitation.invitation.vaultID == vaultID else {
            throw V3EnrollmentCeremonyStateError.wrongRole
          }
          try validate()
        }, replacementService: workflow, configuredVaultID: vaultID,
        replacementAdmissionState: state
      ).handle(.share(request))
    }
  }
}
