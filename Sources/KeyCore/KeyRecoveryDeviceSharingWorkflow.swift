import Foundation

/// Composes a fresh profile-specific sharing workflow inside the host's exclusive
/// request scope. Detection reads only public format data; the services establish
/// authority from exact checkpoints, compared messages and Mac credentials.
extension KeyRecoverySharingCapability {
  static func live(
    configStore: KeyConfigStore, keyStore: any VaultKeyStoring,
    configuration: RuntimeConfiguration
  ) -> Self {
    Self { request, path, scope in
      try scope.requireCurrent()
      guard try configStore.hasConfiguration() else {
        guard let path else { return nil }
        let root = try VaultRootDirectoryHandle(
          opening: URL(fileURLWithPath: path, isDirectory: true))
        let source = V3FilesystemTransactionArtifactStore(rootHandle: root)
        let exchange = V3EnrollmentExchangeCoordinator(
          mailbox: V3FilesystemEnrollmentMailbox(rootHandle: root),
          stateStore: V3EnrollmentCeremonyStateKeychainStore(configuration: configuration))
        let invitation: V3EnrollmentInvitation
        let now = UInt64(max(0, Date().timeIntervalSince1970))
        switch request {
        case .join(let invitationID, _):
          invitation = try exchange.receiveInvitation(
            digest: enrollmentDigest(invitationID), at: now
          ).invitation
        case .compare(let vaultID, let invitationID, _), .accept(let vaultID, let invitationID, _):
          invitation = try exchange.resumeJoinerAdoption(
            vaultID: vaultID, invitationDigest: enrollmentDigest(invitationID), at: now
          ).signedInvitation.invitation
        default: return nil
        }
        guard case .recovery = try v3EnrollmentParentProfile(invitation, source: source) else {
          return nil
        }
        try scope.requireCurrent()
        let joining = V3UnconfiguredEnrollmentService.live(
          configStore: configStore, keyStore: keyStore, runtimeConfiguration: configuration,
          validateScope: { try scope.requireCurrent() })
        return .init(changesCheckpoint: request.isEnrollmentAcceptance) {
          try joining.handle(request, path: path)
        }
      }
      let selected = try configStore.load()
      guard case .v3(let vaultID) = selected.authority else { return nil }
      let root = try VaultRootDirectoryHandle(opening: selected.vaultDirectoryURL)
      let source = V3FilesystemTransactionArtifactStore(rootHandle: root)
      let checkpoints = V3ManifestCheckpointKeychainStore(configuration: configuration)
      let cache = try KeyServiceHandler.makeV3CheckpointManifestCache(keyConfiguration: selected)
      let replacementState = try V3ReplacementEnrollmentAdmission(
        intentStore: V3ReplacementEnrollmentIntentKeychainStore(configuration: configuration)
      ).state(vaultID: vaultID)
      if [.cleanupPending, .enrollmentPending].contains(replacementState) {
        return try KeyRecoveryDeviceReplacementWorkflow.prepare(
          request, selected: selected, configStore: configStore, keyStore: keyStore,
          configuration: configuration, scope: scope)
      }
      guard
        case .recovery = try v3SelectedCheckpointProfile(
          vaultID: vaultID, checkpoints: checkpoints, source: source, cache: cache
        ).profile
      else { return nil }
      guard #available(macOS 26.0, *) else {
        throw AppError.operationRefused(
          "Recovery-capable vaults require macOS 26 or later in this experimental build.")
      }
      switch request {
      case .devices, .invitations, .invite, .requests, .compare, .approve,
        .reviewRevocation, .revoke:
        break
      case .accept(let requestedVaultID, let invitationID, _):
        guard requestedVaultID == vaultID else { throw V3EnrollmentCeremonyStateError.wrongRole }
        let exchange = V3EnrollmentExchangeCoordinator(
          mailbox: V3FilesystemEnrollmentMailbox(rootHandle: root),
          stateStore: V3EnrollmentCeremonyStateKeychainStore(configuration: configuration))
        let state = try exchange.resumeJoinerAdoption(
          vaultID: vaultID, invitationDigest: enrollmentDigest(invitationID),
          at: UInt64(max(0, Date().timeIntervalSince1970)))
        guard state.phase == .consumed else { throw V3EnrollmentAdoptionError.invalidCeremony }
        let verifySelection = configStore.selectionValidator(expected: selected)
        let session = V3DeviceWrappedVaultKeySessionStore()
        let validate: @Sendable () throws -> Void = {
          try scope.requireCurrent()
          try root.requireConfiguredRootIdentity()
          try verifySelection()
        }
        let enrollment = try makeLiveV3EnrollmentWorkflowService(
          rootHandle: root, selectedVaultID: nil, keyStore: keyStore,
          keyConfiguration: selected, configStore: configStore, runtimeConfiguration: configuration,
          unconfiguredSelection: { id in
            guard id == vaultID else { throw V3EnrollmentAdoptionError.invalidCeremony }
            try validate()
          }, deviceWrappedSession: session, validateScope: validate)
        return .init(changesCheckpoint: true) {
          defer { session.invalidate() }
          try validate()
          return KeyServiceHandler(
            keyStore: keyStore, entryStore: EntryStore(rootURL: root.rootURL),
            mutationOwner: VaultTransactionMutationOwner(), enrollmentService: enrollment
          )
          .handle(.share(request))
        }
      case .join, .reviewReplacement, .replaceCurrentDevice:
        return try KeyRecoveryDeviceReplacementWorkflow.prepare(
          request, selected: selected, configStore: configStore, keyStore: keyStore,
          configuration: configuration, scope: scope)
      default: return nil
      }
      let verifySelection = configStore.selectionValidator(expected: selected)
      let validate: @Sendable () throws -> Void = {
        try scope.requireCurrent()
        try root.requireConfiguredRootIdentity()
        try verifySelection()
      }
      try validate()
      let session = V3DeviceWrappedVaultKeySessionStore()
      let transaction = V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration)
      let registration = V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .registration)
      let adoption = V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: configuration, namespace: .adoption)
      let ceremonies = V3EnrollmentCeremonyStateKeychainStore(configuration: configuration)
      let identities = V3EnrollmentDeviceIdentityManager(
        recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(configuration: configuration),
        keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations(), validateScope: validate)
      let unlock = V3RecoveryVaultUnlockRuntime(
        vaultID: vaultID, checkpointStore: checkpoints, source: source, cache: cache,
        identityLoader: V3ScopedDeviceIdentityLoader(base: identities, validate: validate),
        session: session, transactionOwnershipStore: transaction,
        registrationOwnershipStore: registration, adoptionOwnershipStore: adoption)
      _ = scope.cancellation.register { session.invalidate() }
      let loadOwner: @Sendable () throws -> V3RecoveryAuthorityChangeService.Identity = {
        try validate()
        guard
          let identity = try identities.loadIdentity(
            vaultID: vaultID, reason: "Use this Mac's vault access credentials.")
        else { throw V3RecoveryEnrollmentAdoptionError.identityUnavailable }
        try validate()
        return V3ScopedEnrollmentIdentity(base: identity, validate: validate)
      }
      let workflow = V3RecoveryEnrollmentOwnerWorkflow(
        vaultID: vaultID, unlock: unlock, session: session,
        exchange: V3EnrollmentExchangeCoordinator(
          mailbox: V3FilesystemEnrollmentMailbox(rootHandle: root), stateStore: ceremonies),
        ownership: transaction,
        loadIdentity: loadOwner,
        makeService: { identity in
          V3RecoveryEnrollmentOwnerService(
            vaultID: vaultID, identity: identity, session: session, objectStore: source,
            checkpointStore: checkpoints, recoveryAnchorStore: transaction,
            registrationAnchorStore: registration, adoptionAnchorStore: adoption,
            ceremonyStore: ceremonies, cache: cache, validateScope: validate)
        }, validateScope: validate)
      let revocation = V3RecoveryDeviceRevocationWorkflow(
        session: session, loadIdentity: loadOwner,
        authenticate: { operationID in
          try validate()
          let opened = try unlock.authenticatedReadContext(
            reason: "Unlock the vault to review or remove a Mac's access.")
          let identity = try loadOwner()
          let ticket = try opened.authenticationTicket()
          let result = try V3RecoveryCatchUpCoordinator(
            mutationOwner: DirectVaultTransactionMutationOwner(operationID: operationID),
            identity: identity, session: session, source: source, checkpointStore: checkpoints,
            recoveryAnchorStore: transaction, registrationAnchorStore: registration,
            adoptionAnchorStore: adoption, cache: cache, validateScope: validate
          ).catchUp(from: opened.current, continuing: ticket, allowStale: false)
          guard case .verified(.current(let current, _)) = result.selection else {
            throw VaultUXServiceError.catchUpContentConflict
          }
          try result.revalidatePublishedSource()
          try validate()
          return try unlock.continuedReadContext(current: current, ticket: result.ticket)
        },
        makeService: { identity in
          .init(
            vaultID: vaultID, identity: identity, session: session,
            objectStore: source, checkpointStore: checkpoints, recoveryAnchorStore: transaction,
            registrationAnchorStore: registration, adoptionAnchorStore: adoption,
            cache: cache, validateScope: validate)
        }, validateScope: validate)
      return .init(changesCheckpoint: request.changesDeviceCheckpoint) {
        defer { session.invalidate() }
        try validate()
        return KeyServiceHandler(
          keyStore: keyStore, entryStore: EntryStore(rootURL: root.rootURL),
          mutationOwner: VaultTransactionMutationOwner(), enrollmentService: workflow,
          revocationService: revocation, configuredVaultID: vaultID
        ).handle(.share(request))
      }
    }
  }
}

struct V3ScopedDeviceIdentityLoader: V3DeviceWrappedIdentityLoading {
  let base: any V3DeviceWrappedIdentityLoading
  let validate: @Sendable () throws -> Void
  func loadDeviceIdentity(vaultID: String, reason: String) throws
    -> (any V3DeviceWrappedVaultKeyUnwrapping)?
  {
    try validate()
    let identity = try base.loadDeviceIdentity(vaultID: vaultID, reason: reason)
    try validate()
    return identity.map { V3ScopedDeviceUnwrapper(base: $0, validate: validate) }
  }
}

extension KeyShareRequest {
  fileprivate var changesDeviceCheckpoint: Bool {
    switch self {
    case .approve, .reviewRevocation, .revoke: true
    default: false
    }
  }
  fileprivate var isEnrollmentAcceptance: Bool { if case .accept = self { true } else { false } }
}
