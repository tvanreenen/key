import CryptoKit
import Foundation

public final class KeyServiceHandler {
    private static let defaultSessionTimeout: TimeInterval = 15 * 60

    private let keyStore: VaultKeyStoring
    private let entryStore: EntryStore
    private let configStore: KeyConfigStore?
    private let cipher: VaultCipher
    private let now: () -> Date
    private let mutationOwner: any VaultTransactionMutationOwning
    private let migrationService: (any V3LocalMigrationServicing)?
    private let enrollmentService: (any V3EnrollmentWorkflowServicing)?
    private let validateJoinInvitation:
        (@Sendable (_ digest: Data, _ unixTime: UInt64) throws -> Void)?
    private let revocationService:
        (any V3DeviceWrappedRevocationWorkflowServicing)?
    private let replacementService:
        (any V3ReplacementEnrollmentWorkflowServicing)?
    private let vaultUXService: any VaultUXServicing
    private let vaultReader: (any VaultReadServicing)?
    private let vaultMutator: (any VaultMutationServicing)?
    private let vaultSession: (any VaultSessionServicing)?
    private let configuredVaultID: String?
    private let replacementAdmissionState:
        V3ReplacementEnrollmentAdmissionState
    private let requestQueue = DispatchQueue(
        label: "work.tvr.key.service-handler.requests",
        attributes: .concurrent
    )
    private let stateQueue = DispatchQueue(label: "work.tvr.key.service-handler")
    private var currentKeychainMode: KeychainMode
    private var vaultRootChangePending = false

    public convenience init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        keychainMode: KeychainMode = .local,
        configStore: KeyConfigStore? = nil,
        cipher: VaultCipher = VaultCipher(),
        now: @escaping () -> Date = Date.init
    ) {
        self.init(
            keyStore: keyStore,
            entryStore: entryStore,
            keychainMode: keychainMode,
            configStore: configStore,
            cipher: cipher,
            now: now,
            mutationOwner: VaultTransactionMutationOwner(),
            migrationService: nil,
            enrollmentService: nil,
            vaultUXService: V2VaultUXService(entryStore: entryStore),
            vaultReader: nil,
            vaultMutator: nil,
            configuredVaultID: nil
        )
    }

    init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        keychainMode: KeychainMode = .local,
        configStore: KeyConfigStore? = nil,
        cipher: VaultCipher = VaultCipher(),
        now: @escaping () -> Date = Date.init,
        mutationOwner: any VaultTransactionMutationOwning,
        migrationService: (any V3LocalMigrationServicing)? = nil,
        enrollmentService: (any V3EnrollmentWorkflowServicing)? = nil,
        validateJoinInvitation:
            (@Sendable (Data, UInt64) throws -> Void)? = nil,
        revocationService:
            (any V3DeviceWrappedRevocationWorkflowServicing)? = nil,
        replacementService:
            (any V3ReplacementEnrollmentWorkflowServicing)? = nil,
        vaultUXService: (any VaultUXServicing)? = nil,
        vaultReader: (any VaultReadServicing)? = nil,
        vaultMutator: (any VaultMutationServicing)? = nil,
        vaultSession: (any VaultSessionServicing)? = nil,
        configuredVaultID: String? = nil,
        replacementAdmissionState:
            V3ReplacementEnrollmentAdmissionState = .inactive
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.configStore = configStore
        self.cipher = cipher
        self.now = now
        self.mutationOwner = mutationOwner
        self.migrationService = migrationService
        self.enrollmentService = enrollmentService
        self.validateJoinInvitation = validateJoinInvitation
        self.revocationService = revocationService
        self.replacementService = replacementService
        self.vaultUXService = vaultUXService
            ?? V2VaultUXService(entryStore: entryStore)
        self.vaultReader = vaultReader
        self.vaultMutator = vaultMutator
        self.vaultSession = vaultSession
        self.configuredVaultID = configuredVaultID
        self.replacementAdmissionState = replacementAdmissionState
        self.currentKeychainMode = keychainMode
    }

    public static func live(bundle: Bundle = .main) throws -> KeyServiceHandler {
        let configuration = RuntimeConfiguration.live(bundle: bundle)
        let configStore = KeyConfigStore(
            productIdentity: configuration.productIdentity
        )
        let keyConfiguration = try configStore.load()
        return try live(
            keyStore: VaultKeyStore(configuration: configuration),
            keyConfiguration: keyConfiguration,
            configStore: configStore,
            runtimeConfiguration: configuration
        )
    }

    /// Composes the helper runtime selected by device-local configuration.
    ///
    /// A missing vault ID retains v2. A configured vault ID enables the v3
    /// runtime and never creates a replacement key.
    public static func live(
        keyStore: VaultKeyStoring,
        keyConfiguration: KeyConfiguration,
        configStore: KeyConfigStore,
        runtimeConfiguration: RuntimeConfiguration
    ) throws -> KeyServiceHandler {
        let entryStore = EntryStore(
            rootURL: keyConfiguration.vaultDirectoryURL
        )
        guard let vaultID = keyConfiguration.vaultID else {
            let mutationOwner = VaultTransactionMutationOwner()
            let migrationService = DeferredV3LocalMigrationService {
                try makeV3DeviceWrappedMigrationService(
                    keyStore: keyStore,
                    entryStore: entryStore,
                    keyConfiguration: keyConfiguration,
                    configStore: configStore,
                    runtimeConfiguration: runtimeConfiguration
                )
            }
            let enrollmentService = DeferredV3EnrollmentWorkflowService {
                let rootHandle = try VaultRootDirectoryHandle(
                    opening: keyConfiguration.vaultDirectoryURL
                )
                return try makeLiveV3EnrollmentWorkflowService(
                    rootHandle: rootHandle,
                    selectedVaultID: nil,
                    keyStore: keyStore,
                    keyConfiguration: keyConfiguration,
                    configStore: configStore,
                    runtimeConfiguration: runtimeConfiguration
                )
            }
            return KeyServiceHandler(
                keyStore: keyStore,
                entryStore: entryStore,
                keychainMode: keyConfiguration.keychainMode,
                configStore: configStore,
                mutationOwner: mutationOwner,
                migrationService: migrationService,
                enrollmentService: enrollmentService
            )
        }

        let rootHandle = try VaultRootDirectoryHandle(
            opening: keyConfiguration.vaultDirectoryURL
        )
        let checkpointStore = V3ManifestCheckpointKeychainStore(
            configuration: runtimeConfiguration
        )
        let recoveryAnchorStore =
            V3ImmutableTransactionRecoveryAnchorKeychainStore(
                configuration: runtimeConfiguration
            )
        let cache = try makeV3CheckpointManifestCache(
            keyConfiguration: keyConfiguration
        )
        let identityRecordStore =
            V3EnrollmentDeviceKeyRecordKeychainStore(
                configuration: runtimeConfiguration
            )
        let identityManager = V3EnrollmentDeviceIdentityManager(
            recordStore: identityRecordStore,
            keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations()
        )
        let objectStore = V3FilesystemTransactionArtifactStore(
            rootHandle: rootHandle
        )
        let session = V3DeviceWrappedVaultKeySessionStore()
        let unlockRuntime = V3DeviceWrappedVaultUnlockRuntime(
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            source: objectStore,
            cache: cache,
            identityLoader: identityManager,
            session: session
        )
        let mutationOwner = VaultTransactionMutationOwner()
        let repositoryObserver = V3LiveDeviceWrappedRepositoryObserver(
            source: objectStore,
            checkpointStore: checkpointStore,
            cache: cache
        )
        let contentCatchUpSteps =
            V3DeviceWrappedSameEpochCatchUpStepService(
                vaultID: vaultID,
                repositoryObserver: repositoryObserver,
                source: objectStore,
                checkpointStore: checkpointStore,
                cache: cache
            )
        let keyTransitionDiscovery =
            V3DeviceWrappedKeyTransitionDiscovery(source: objectStore)
        let keyTransitionCatchUpSteps =
            V3DeviceWrappedKeyTransitionCatchUpStepService(
                vaultID: vaultID,
                stateManager: unlockRuntime,
                source: objectStore,
                cache: cache,
                loadIdentity: { requestedVaultID, reason in
                    try identityManager.loadIdentity(
                        vaultID: requestedVaultID,
                        reason: reason
                    )
                }
            )
        let makeCatchUpCoordinator: @Sendable (
            any VaultTransactionMutationOwning
        ) -> V3DeviceWrappedCatchUpCoordinator = { owner in
            V3DeviceWrappedCatchUpCoordinator(
                vaultID: vaultID,
                mutationOwner: owner,
                stateLoader: unlockRuntime,
                contentSteps: contentCatchUpSteps,
                keyTransitionDiscovery: keyTransitionDiscovery,
                keyTransitionSteps: keyTransitionCatchUpSteps
            )
        }
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: V3DeviceWrappedReadOnlyVaultRuntime(
                source: objectStore,
                unlockRuntime: unlockRuntime
            ),
            mutationService: V3DeviceWrappedVaultMutationService(
                stateLoader: unlockRuntime,
                objectStore: objectStore,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: recoveryAnchorStore,
                cache: cache,
                catchUp: { operationID in
                    try makeCatchUpCoordinator(
                        DirectVaultTransactionMutationOwner(
                            operationID: operationID
                        )
                    ).catchUp()
                }
            ),
            session: session,
            catchUp: {
                try makeCatchUpCoordinator(mutationOwner).catchUp()
            },
            lockSession: { unlockRuntime.lock() }
        )
        let exchange = V3EnrollmentExchangeCoordinator(
            mailbox: V3FilesystemEnrollmentMailbox(rootHandle: rootHandle),
            stateStore: V3EnrollmentCeremonyStateKeychainStore(
                configuration: runtimeConfiguration
            )
        )
        let replacementIntentStore =
            V3ReplacementEnrollmentIntentKeychainStore(
                configuration: runtimeConfiguration
            )
        let replacementAdmission = V3ReplacementEnrollmentAdmission(
            intentStore: replacementIntentStore
        )
        let approvalService =
            V3DeviceWrappedEnrollmentOwnerApprovalService(
                vaultID: vaultID,
                stateLoader: unlockRuntime,
                source: objectStore,
                objectStore: objectStore,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: recoveryAnchorStore,
                cache: cache,
                exchange: exchange,
                loadIdentity: { requestedVaultID, reason in
                    try identityManager.loadIdentity(
                        vaultID: requestedVaultID,
                        reason: reason
                    )
                },
                session: session
            )
        let replacementAdmissionState = try replacementAdmission.state(
            vaultID: vaultID
        )
        let enrollmentService: any V3EnrollmentWorkflowServicing
        if replacementAdmissionState == .enrollmentPending {
            enrollmentService = try makeLiveV3EnrollmentWorkflowService(
                rootHandle: rootHandle,
                selectedVaultID: nil,
                replacementVaultID: vaultID,
                replacementAdmission: replacementAdmission,
                keyStore: keyStore,
                keyConfiguration: keyConfiguration,
                configStore: configStore,
                runtimeConfiguration: runtimeConfiguration
            )
        } else {
            enrollmentService = V3DeviceWrappedEnrollmentOwnerWorkflow(
                vaultID: vaultID,
                stateLoader: unlockRuntime,
                exchange: exchange,
                loadIdentity: { requestedVaultID, reason in
                    try identityManager.loadIdentity(
                        vaultID: requestedVaultID,
                        reason: reason
                    )
                },
                loadPublicIdentity: { requestedVaultID in
                    try identityManager.loadRecordedPublicIdentity(
                        vaultID: requestedVaultID
                    )
                },
                approvalService: approvalService
            )
        }
        let revocationService = V3DeviceWrappedRevocationWorkflow(
            service: V3DeviceWrappedRevocationService(
                vaultID: vaultID,
                stateLoader: unlockRuntime,
                source: objectStore,
                objectStore: objectStore,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: recoveryAnchorStore,
                cache: cache,
                loadIdentity: { requestedVaultID, reason in
                    try identityManager.loadIdentity(
                        vaultID: requestedVaultID,
                        reason: reason
                    )
                },
                loadPublicIdentity: { requestedVaultID in
                    try identityManager.loadRecordedPublicIdentity(
                        vaultID: requestedVaultID
                    )
                },
                session: session
            ),
            catchUp: { operationID in
                try makeCatchUpCoordinator(
                    DirectVaultTransactionMutationOwner(
                        operationID: operationID
                    )
                ).catchUp()
            }
        )
        let replacementIdentityDeleter =
            V3EnrollmentDeviceIdentityDeleter(
                recordStore: identityRecordStore
            )
        let replacementAuthority =
            V3ReplacementDeviceIdentityAuthorityAdapter(
                vaultID: vaultID,
                stateManager: unlockRuntime,
                contentSteps: contentCatchUpSteps,
                keyTransitionDiscovery: keyTransitionDiscovery
            )
        let replacementService = V3ReplacementEnrollmentWorkflow(
            vaultID: vaultID,
            loadTarget: { requestedVaultID in
                try replacementIdentityDeleter.deletionTarget(
                    vaultID: requestedVaultID
                )
            },
            authorityClassifier: replacementAuthority,
            intentStore: replacementIntentStore,
            coordinator: V3ReplacementEnrollmentCoordinator(
                vaultID: vaultID,
                mutationOwner: mutationOwner,
                authorityClassifier: replacementAuthority,
                identityDeleter: replacementIdentityDeleter,
                checkpointStore: checkpointStore,
                intentStore: replacementIntentStore
            )
        )
        return KeyServiceHandler(
            keyStore: keyStore,
            entryStore: entryStore,
            keychainMode: keyConfiguration.keychainMode,
            configStore: configStore,
            mutationOwner: mutationOwner,
            enrollmentService: enrollmentService,
            validateJoinInvitation: { invitationDigest, unixTime in
                let invitation = try exchange.receiveInvitation(
                    digest: invitationDigest,
                    at: unixTime
                )
                guard invitation.invitation.vaultID == vaultID else {
                    throw AppError.operationRefused(
                        "The selected invitation belongs to a different vault."
                    )
                }
            },
            revocationService: revocationService,
            replacementService: replacementService,
            vaultUXService: runtime,
            vaultReader: runtime,
            vaultMutator: runtime,
            vaultSession: runtime,
            configuredVaultID: vaultID,
            replacementAdmissionState: replacementAdmissionState
        )
    }

    private static func makeV3DeviceWrappedMigrationService(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        keyConfiguration: KeyConfiguration,
        configStore: KeyConfigStore,
        runtimeConfiguration: RuntimeConfiguration
    ) throws -> V3DeviceWrappedMigrationService {
        let rootHandle = try VaultRootDirectoryHandle(
            opening: keyConfiguration.vaultDirectoryURL
        )
        let installer = V3DeviceWrappedGenesisInstaller(
            entryStore: entryStore,
            cipher: VaultCipher(),
            objectStore: V3FilesystemTransactionArtifactStore(
                rootHandle: rootHandle
            ),
            checkpointStore: V3ManifestCheckpointKeychainStore(
                configuration: runtimeConfiguration
            ),
            cache: try makeV3CheckpointManifestCache(
                keyConfiguration: keyConfiguration
            ),
            session: V3DeviceWrappedVaultKeySessionStore(),
            identityManager: V3EnrollmentDeviceIdentityManager(
                recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(
                    configuration: runtimeConfiguration
                ),
                keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations()
            ),
            loadV2VaultKey: { reason, createIfMissing in
                try keyStore.loadKey(
                    mode: keyConfiguration.keychainMode,
                    reason: reason,
                    createIfMissing: createIfMissing
                )
            },
            selectVault: { vaultID in
                _ = try configStore.selectV3Vault(
                    vaultID: vaultID,
                    expectedRootHandle: rootHandle,
                    expectedKeychainMode: keyConfiguration.keychainMode
                )
            }
        )
        return V3DeviceWrappedMigrationService(
            installer: installer,
            deviceName: currentDeviceDisplayName()
        )
    }

    static func makeV3CheckpointManifestCache(
        keyConfiguration: KeyConfiguration,
        fileManager: FileManager = .default
    ) throws -> V3CheckpointManifestFilesystemCache {
        let cacheDirectory = keyConfiguration.configFileURL
            .deletingLastPathComponent()
            .appendingPathComponent(
                "v3-checkpoint-manifests",
                isDirectory: true
            )
        do {
            try fileManager.createDirectory(
                at: cacheDirectory,
                withIntermediateDirectories: true
            )
        } catch {
            throw AppError.io(
                "Failed to prepare the device-local version 3 checkpoint cache at '\(cacheDirectory.path(percentEncoded: false))': \(error.localizedDescription)"
            )
        }
        return V3CheckpointManifestFilesystemCache(
            rootHandle: try VaultRootDirectoryHandle(
                opening: cacheDirectory
            )
        )
    }

    static func currentDeviceDisplayName(
        localizedName: String? = Host.current().localizedName,
        hostName: String = ProcessInfo.processInfo.hostName
    ) -> String {
        for candidate in [localizedName, hostName] {
            let normalized = candidate?
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .precomposedStringWithCanonicalMapping
            if let normalized,
               isValidV3DeviceDisplayName(normalized)
            {
                return normalized
            }
        }
        return "This Mac"
    }

    public func handle(_ request: KeyServiceRequest) -> KeyServiceResponse {
        guard request.isAllowed(
            during: replacementAdmissionState
        ) else {
            let message = switch replacementAdmissionState {
            case .cleanupPrepared:
                "Device replacement cleanup is prepared but has not started. Review or resume the pending replacement before using or changing the vault."
            case .cleanupPending:
                "Device replacement cleanup is still in progress. Review or resume the pending replacement before using or changing the vault."
            case .enrollmentPending:
                "Device replacement enrollment is still in progress. Finish the pending join, comparison, and acceptance before using or changing the vault."
            case .inactive:
                preconditionFailure("Inactive replacement cannot block work.")
            }
            return .failure(message)
        }

        if request.requiresExclusiveRuntimeSelectionChange {
            return requestQueue.sync(flags: .barrier) {
                guard !vaultRootChangePending else {
                    return .failure(
                        "The vault directory changed and Key Agent is restarting. Run `key lock`, then retry the command."
                    )
                }
                let response = handleWithMutationOwnership(request)
                if response.exitCode == EXIT_SUCCESS {
                    vaultRootChangePending = true
                }
                return response
            }
        }

        return requestQueue.sync {
            guard !vaultRootChangePending || request == .lock else {
                return .failure(
                    "The vault directory changed and Key Agent is restarting. Run `key lock`, then retry the command."
                )
            }
            return handleWithMutationOwnership(request)
        }
    }

    private func handleWithMutationOwnership(
        _ request: KeyServiceRequest
    ) -> KeyServiceResponse {
        guard let mutationKind = request.transactionMutationKind else {
            return handleRequest(request)
        }
        do {
            return try mutationOwner.perform(mutationKind) { context in
                if !request.isConflictResolution
                    && !request.ownsMutationAuthorization
                {
                    try vaultUXService.authorizeMutation()
                }
                return handleRequest(
                    request,
                    mutationContext: context
                )
            }
        } catch let error as AppError {
            return .failure(error)
        } catch let error as VaultUXServiceError {
            return .failure(error)
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func handleRequest(
        _ request: KeyServiceRequest,
        mutationContext: VaultTransactionMutationContext? = nil
    ) -> KeyServiceResponse {
        do {
            try verifyConfiguredVaultRoot(for: request)

            switch request {
            case .unlock:
                if let vaultReader {
                    try vaultReader.unlock()
                } else {
                    _ = try loadVaultKey(
                        reason: "Unlock key vault.",
                        createIfMissing: true
                    )
                }
                return .success()
            case .lock:
                vaultSession?.lock()
                keyStore.invalidate()
                return .success()
            case .status:
                let helperStatus = vaultSession?.sessionStatus(at: nil)
                    ?? (keyStore as? KeySessionStatusReporting)?
                    .sessionStatus(at: nil) ?? .locked(inactivityTimeoutSeconds: Self.defaultSessionTimeout)
                return .success(helperStatus: helperStatus)
            case .vaultStatus:
                return .vaultStatus(try vaultUXService.status())
            case .listConflicts:
                return .conflicts(try vaultUXService.conflicts())
            case let .showConflict(id):
                return .conflict(try vaultUXService.conflict(id: id))
            case let .getConflictValue(id, versionID):
                return .success(
                    try vaultUXService.conflictValue(
                        id: id,
                        versionID: versionID
                    )
                )
            case let .resolveConflicts(resolutions):
                if let vaultMutator {
                    guard let mutationContext else {
                        throw AppError.operationRefused(
                            "Conflict resolution requires the helper's serialized mutation boundary."
                        )
                    }
                    try vaultMutator.resolve(
                        resolutions,
                        operationID: mutationContext.operationID
                    )
                } else {
                    try vaultUXService.resolve(resolutions)
                }
                return .success()
            case let .share(action):
                return try handleShare(
                    action,
                    mutationContext: mutationContext
                )
            case .list:
                let entries = if let vaultReader {
                    try vaultReader.list(allowStale: false)
                } else {
                    try entryStore.listEntries()
                }
                guard !entries.isEmpty else {
                    return .success()
                }
                return .success(entries.joined(separator: "\n") + "\n")
            case .migrationPreflight:
                guard vaultReader == nil else {
                    throw v3ReadOnlyOperationError()
                }
                return migrationPreflightResponse()
            case .migrationApply:
                guard vaultReader == nil else {
                    throw v3ReadOnlyOperationError()
                }
                guard let migrationService,
                      let mutationContext,
                      mutationContext.kind == .migrateToV3
                else {
                    throw AppError.operationRefused(
                        "Version 3 migration is unavailable in this helper runtime."
                    )
                }
                return .success(
                    try migrationService.migrate(
                        operationID: mutationContext.operationID
                    ).rendered
                )
            case let .setVaultDirectory(path):
                try setVaultDirectory(path)
                return .success()
            case let .setKeychainMode(mode):
                guard vaultReader == nil else {
                    throw v3ReadOnlyOperationError()
                }
                try setKeychainMode(mode)
                return .success()
            case let .get(name, allowStale):
                if let vaultReader {
                    let value = try vaultReader.read(
                        name: name,
                        allowStale: allowStale
                    )
                    return .success(
                        try renderValue(
                            for: value.type,
                            decryptedValue: value.plaintext
                        )
                    )
                }
                try vaultUXService.authorizeRead(
                    name: name,
                    allowStale: allowStale
                )
                let encrypted = try entryStore.load(name)
                let keyData = try loadVaultKey(
                    reason: "Unlock key vault to read '\(name)'.",
                    createIfMissing: false
                )
                let decrypted = try decryptSecret(encrypted, named: name, keyData: keyData)
                return .success(try renderValue(for: encrypted.type, decryptedValue: decrypted))
            case let .addManual(name, secret, type):
                if let vaultMutator {
                    try vaultMutator.add(
                        name: name,
                        secret: secret,
                        type: type,
                        operationID: try requiredOperationID(
                            mutationContext,
                            kind: .addEntry
                        )
                    )
                } else {
                    try storeAddedSecret(secret, as: name, type: type)
                }
                return .success()
            case let .editManual(name, secret, type):
                if let vaultMutator {
                    try vaultMutator.edit(
                        name: name,
                        secret: secret,
                        type: type,
                        operationID: try requiredOperationID(
                            mutationContext,
                            kind: .editEntry
                        )
                    )
                } else {
                    try storeEditedSecret(secret, as: name, type: type)
                }
                return .success()
            case let .copyEntry(source, destination, force):
                if let vaultMutator {
                    try vaultMutator.copy(
                        source: source,
                        destination: destination,
                        overwrite: force,
                        operationID: try requiredOperationID(
                            mutationContext,
                            kind: .copyEntry
                        )
                    )
                } else {
                    try entryStore.copyEntry(from: source, to: destination, overwrite: force)
                }
                return .success()
            case let .moveEntry(source, destination, force):
                if let vaultMutator {
                    try vaultMutator.move(
                        source: source,
                        destination: destination,
                        overwrite: force,
                        operationID: try requiredOperationID(
                            mutationContext,
                            kind: .moveEntry
                        )
                    )
                } else {
                    try entryStore.moveEntry(from: source, to: destination, overwrite: force)
                }
                return .success()
            case let .removeEntry(name):
                if let vaultMutator {
                    try vaultMutator.remove(
                        name: name,
                        operationID: try requiredOperationID(
                            mutationContext,
                            kind: .removeEntry
                        )
                    )
                } else {
                    try entryStore.removeEntry(name)
                }
                return .success()
            }
        } catch let error as AppError {
            return .failure(error)
        } catch let error as VaultUXServiceError {
            return .failure(error)
        } catch let error as V3EnrollmentAdoptionError {
            return enrollmentFailure(error)
        } catch let error as V3DeviceWrappedEnrollmentAdoptionError {
            return deviceWrappedEnrollmentFailure(error)
        } catch let error as V3ReplacementEnrollmentIntentError {
            return replacementFailure(error)
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func handleShare(
        _ request: KeyShareRequest,
        mutationContext: VaultTransactionMutationContext?
    ) throws -> KeyServiceResponse {
        let unixTime = UInt64(max(0, now().timeIntervalSince1970))
        switch request {
        case .devices:
            return .deviceInventory(
                try requiredEnrollmentService().deviceInventory()
            )
        case let .reviewRevocation(deviceID):
            return revocationResponse {
                guard let mutationContext,
                      mutationContext.kind == .catchUpVault
                else {
                    throw AppError.operationRefused(
                        "Device revocation review requires the helper's serialized mutation boundary."
                    )
                }
                return .deviceRevocationReview(
                    try requiredRevocationService().review(
                        revoking: deviceID,
                        operationID: mutationContext.operationID
                    )
                )
            }
        case let .revoke(deviceID, confirmationToken):
            return revocationResponse {
                guard let mutationContext,
                      mutationContext.kind == .revokeDevice
                else {
                    throw AppError.operationRefused(
                        "Device revocation requires the helper's serialized mutation boundary."
                    )
                }
                _ = try requiredRevocationService().revoke(
                    deviceID: deviceID,
                    confirmationToken: confirmationToken,
                    operationID: mutationContext.operationID
                )
                return .success(
                    "Device revoked. The vault key was rotated for the remaining active devices.\n"
                )
            }
        case .reviewReplacement:
            return replacementResponse {
                guard let mutationContext,
                      mutationContext.kind == .catchUpVault
                else {
                    throw AppError.operationRefused(
                        "Device replacement review requires the helper's serialized mutation boundary."
                    )
                }
                return .deviceReplacementReview(
                    V3VaultDeviceReplacementReview(
                        review: try requiredReplacementService().review()
                    )
                )
            }
        case let .replaceCurrentDevice(
            invitationID,
            confirmationToken
        ):
            return replacementResponse {
                let invitationDigest = try enrollmentDigest(invitationID)
                let confirmedReviewDigest = try replacementDigest(
                    confirmationToken
                )
                if replacementAdmissionState != .cleanupPending {
                    guard let validateJoinInvitation else {
                        throw AppError.operationRefused(
                            "Device rejoin invitation validation is unavailable in this helper runtime."
                        )
                    }
                    try validateJoinInvitation(invitationDigest, unixTime)
                    let currentReview = try requiredReplacementService()
                        .review()
                    guard confirmedReviewDigest
                        == v3ReplacementEnrollmentConfirmationDigest(
                            reviewDigest: currentReview.digest,
                            invitationDigest: invitationDigest
                        )
                    else {
                        throw V3ReplacementEnrollmentWorkflowError
                            .invalidConfirmation
                    }
                    let intent = try requiredReplacementService().replace(
                        confirmedReviewDigest: currentReview.digest
                    )
                    return try completedReplacementResponse(intent)
                }
                let intent = try requiredReplacementService().replace(
                    confirmedReviewDigest: confirmedReviewDigest
                )
                return try completedReplacementResponse(intent)
            }
        case .invitations:
            return .success(try requiredEnrollmentService().listInvitations())
        case let .invite(deviceName):
            return .success(try requiredEnrollmentService().createInvitation(
                deviceName: deviceName,
                at: unixTime
            ))
        case let .join(invitationID, deviceName):
            let invitationDigest = try enrollmentDigest(invitationID)
            if configuredVaultID != nil,
               replacementAdmissionState != .enrollmentPending
            {
                return replacementResponse {
                    guard let mutationContext,
                          mutationContext.kind == .catchUpVault
                    else {
                        throw AppError.operationRefused(
                            "Device rejoin review requires the helper's serialized mutation boundary."
                        )
                    }
                    if replacementAdmissionState != .cleanupPending {
                        guard let validateJoinInvitation else {
                            throw AppError.operationRefused(
                                "Device rejoin invitation validation is unavailable in this helper runtime."
                            )
                        }
                        try validateJoinInvitation(invitationDigest, unixTime)
                    }
                    do {
                        return .deviceReplacementReview(
                            V3VaultDeviceReplacementReview(
                                review: try requiredReplacementService()
                                    .review(),
                                invitationDigest:
                                    replacementAdmissionState
                                        == .cleanupPending
                                        ? nil
                                        : invitationDigest
                            )
                        )
                    } catch V3ReplacementEnrollmentWorkflowError
                        .deviceStillActive
                    {
                        return .success(try requiredEnrollmentService().join(
                            invitationDigest: invitationDigest,
                            deviceName: deviceName,
                            at: unixTime
                        ))
                    }
                }
            }
            return .success(try requiredEnrollmentService().join(
                invitationDigest: invitationDigest,
                deviceName: deviceName,
                at: unixTime
            ))
        case let .requests(invitationID):
            return .success(try requiredEnrollmentService().listJoinRequests(
                invitationDigest: try enrollmentDigest(invitationID),
                at: unixTime
            ))
        case let .compare(vaultID, invitationID, joinRequestID):
            return .success(try requiredEnrollmentService().compare(
                vaultID: vaultID,
                invitationDigest: try enrollmentDigest(invitationID),
                joinRequestDigest: try joinRequestID.map(enrollmentDigest),
                at: unixTime
            ))
        case let .approve(
            vaultID,
            invitationID,
            comparisonCode
        ):
            guard let mutationContext,
                mutationContext.kind == .enrollDevice
            else {
                throw AppError.operationRefused(
                    "Enrollment approval requires the helper's serialized mutation boundary."
                )
            }
            return .success(try requiredEnrollmentService().approve(
                vaultID: vaultID,
                invitationDigest: try enrollmentDigest(invitationID),
                comparisonCode: comparisonCode,
                at: unixTime,
                operationID: mutationContext.operationID
            ))
        case let .accept(
            vaultID,
            invitationID,
            comparisonCode
        ):
            guard let mutationContext,
                mutationContext.kind == .enrollDevice
            else {
                throw AppError.operationRefused(
                    "Enrollment acceptance requires the helper's serialized mutation boundary."
                )
            }
            return .success(try requiredEnrollmentService().accept(
                vaultID: vaultID,
                invitationDigest: try enrollmentDigest(invitationID),
                comparisonCode: comparisonCode,
                at: unixTime,
                operationID: mutationContext.operationID
            ))
        }
    }

    private func requiredEnrollmentService() throws
        -> any V3EnrollmentWorkflowServicing
    {
        guard let enrollmentService else {
            throw AppError.operationRefused(
                "Version 3 device sharing is unavailable in this helper runtime."
            )
        }
        return enrollmentService
    }

    private func requiredRevocationService() throws
        -> any V3DeviceWrappedRevocationWorkflowServicing
    {
        guard let revocationService else {
            throw AppError.operationRefused(
                "Device revocation is unavailable in this helper runtime."
            )
        }
        return revocationService
    }

    private func requiredReplacementService() throws
        -> any V3ReplacementEnrollmentWorkflowServicing
    {
        guard let replacementService else {
            throw AppError.operationRefused(
                "Device replacement is unavailable in this helper runtime."
            )
        }
        return replacementService
    }

    private func completedReplacementResponse(
        _ intent: V3ReplacementEnrollmentIntent
    ) throws -> KeyServiceResponse {
        guard intent.phase == .checkpointDeleted else {
            throw AppError.operationRefused(
                "Device replacement cleanup did not complete."
            )
        }
        vaultSession?.lock()
        return .success(
            "Revoked device state removed. This Mac is ready to create a new enrollment identity.\n"
        )
    }

    private func replacementResponse(
        _ operation: () throws -> KeyServiceResponse
    ) -> KeyServiceResponse {
        do {
            return try operation()
        } catch let error as AppError {
            return .failure(error)
        } catch let error as VaultUXServiceError {
            return .failure(error)
        } catch let error as V3ReplacementEnrollmentWorkflowError {
            return replacementFailure(error)
        } catch let error as V3ReplacementDeviceIdentityClassificationError {
            return replacementFailure(error)
        } catch let error as V3ReplacementEnrollmentCoordinatorError {
            return replacementFailure(error)
        } catch let error as V3ReplacementEnrollmentIntentError {
            return replacementFailure(error)
        } catch let error as V3EnrollmentDeviceIdentityStoreError {
            return replacementFailure(error)
        } catch let error as V3DeviceWrappedCatchUpError {
            return revocationFailure(error)
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            return revocationFailure(error)
        } catch let error as V3ManifestCheckpointStoreError {
            return revocationFailure(error)
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func revocationResponse(
        _ operation: () throws -> KeyServiceResponse
    ) -> KeyServiceResponse {
        do {
            return try operation()
        } catch let error as AppError {
            return .failure(error)
        } catch let error as VaultUXServiceError {
            return .failure(error)
        } catch let error as V3DeviceWrappedRevocationWorkflowError {
            return revocationFailure(error)
        } catch let error as V3DeviceWrappedRevocationPlanningError {
            return revocationFailure(error)
        } catch let error as V3DeviceWrappedRevocationTransitionError {
            return revocationFailure(error)
        } catch let error as V3DeviceWrappedRevocationValidationError {
            return revocationFailure(error)
        } catch let error as V3DeviceWrappedCatchUpError {
            return revocationFailure(error)
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            return revocationFailure(error)
        } catch let error as V3ImmutableTransactionRecoveryError {
            return revocationFailure(error)
        } catch let error as V3ImmutableTransactionError {
            return revocationFailure(error)
        } catch let error as V3ManifestCheckpointStoreError {
            return revocationFailure(error)
        } catch let error as V3ImmutableTransactionRecoveryAnchorError {
            return revocationFailure(error)
        } catch let error as V3EncryptedEntryError {
            return .failure(
                error.localizedDescription,
                code: .recoveryRequired
            )
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func requiredOperationID(
        _ context: VaultTransactionMutationContext?,
        kind: VaultTransactionMutationKind
    ) throws -> VaultTransactionOperationID {
        guard let context, context.kind == kind else {
            throw AppError.operationRefused(
                "Version 3 publication requires the helper's serialized mutation boundary."
            )
        }
        return context.operationID
    }

    private func verifyConfiguredVaultRoot(
        for request: KeyServiceRequest
    ) throws {
        guard
            request != .lock,
            !request.isVaultDirectoryChange,
            let configStore
        else {
            return
        }

        let configured: ConfiguredVaultRuntimeSelection
        do {
            configured = try configStore
                .configuredVaultRuntimeSelection()
        } catch {
            keyStore.invalidate()
            throw error
        }
        guard configured.rootURL.standardizedFileURL
                == entryStore.rootURL.standardizedFileURL,
              configured.vaultID == configuredVaultID,
              configured.keychainMode == keychainMode()
        else {
            keyStore.invalidate()
            throw AppError.operationRefused(
                "The vault configuration changed while Key Agent was running. Run `key lock`, then retry the command."
            )
        }
    }

    private func setVaultDirectory(_ path: String) throws {
        guard let configStore else {
            throw AppError.service(
                "Key Agent cannot update the vault directory without its configuration store."
            )
        }

        _ = try configStore.setValue(path, for: .vaultDir)
        keyStore.invalidate()
    }

    private func migrationPreflightResponse() -> KeyServiceResponse {
        do {
            let report = try V2MigrationPreflight(
                entryStore: entryStore,
                cipher: cipher
            ).inspect {
                try keyStore.loadKey(
                    mode: keychainMode(),
                    reason: "Unlock key vault to check migration readiness.",
                    createIfMissing: false
                )
            }
            if report.isReady {
                return .success(report.rendered + "\n")
            }
            return .failure(report.rendered)
        } catch {
            return .failure(V2MigrationPreflightReport.blockedInspection(error))
        }
    }

    private func storeAddedSecret(_ secret: String, as name: String, type: SecretEntryType) throws {
        let keyData = try loadVaultKey(
            reason: "Unlock key vault to store '\(name)'.",
            createIfMissing: true
        )
        let normalized = try normalizeSecret(secret, for: type)
        let encrypted = try cipher.encrypt(normalized, type: type, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: false)
    }

    private func storeEditedSecret(_ secret: String, as name: String, type: SecretEntryType) throws {
        guard try entryStore.exists(name) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }

        let existing = try entryStore.load(name)
        let keyData = try loadVaultKey(
            reason: "Unlock key vault to update '\(name)'.",
            createIfMissing: false
        )
        _ = try decryptSecret(existing, named: name, keyData: keyData)
        let normalized = try normalizeSecret(secret, for: type)
        let encrypted = try cipher.encrypt(normalized, type: type, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: true)
    }

    private func loadVaultKey(reason: String, createIfMissing: Bool) throws -> Data {
        switch keychainMode() {
        case .local:
            return try loadVaultKeyFromLocal(reason: reason, createIfMissing: createIfMissing)
        case .icloud:
            return try loadVaultKeyFromICloud(reason: reason, createIfMissing: createIfMissing)
        }
    }

    private func loadVaultKeyFromLocal(reason: String, createIfMissing: Bool) throws -> Data {
        let keyExists = try keyStore.keyExists(mode: .local)
        if createIfMissing, !keyExists, try vaultContainsEntries() {
            throw missingVaultKeyForExistingVaultError()
        }

        do {
            return try keyStore.loadKey(mode: .local, reason: reason, createIfMissing: createIfMissing)
        } catch AppError.entryNotFound {
            if try vaultContainsEntries() {
                throw missingVaultKeyForExistingVaultError()
            }
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
    }

    private func loadVaultKeyFromICloud(reason: String, createIfMissing: Bool) throws -> Data {
        let iCloudKeyExists = try keyStore.keyExists(mode: .icloud)
        let hasEntries = try vaultContainsEntries()

        if !iCloudKeyExists {
            if createIfMissing {
                if hasEntries {
                    throw waitingForICloudVaultKeyError()
                }

                let keyData = try keyStore.loadKey(mode: .icloud, reason: reason, createIfMissing: true)
                try keyStore.storeKey(keyData, mode: .local, overwriteExisting: true)
                return keyData
            }

            if hasEntries {
                throw waitingForICloudVaultKeyError()
            }

            throw AppError.entryNotFound("Vault key does not exist yet.")
        }

        let keyData = try keyStore.loadKey(mode: .icloud, reason: reason, createIfMissing: false)
        try verifyVaultKeyMatchesAllExistingEntries(keyData, sourceMode: .icloud)
        try keyStore.storeKey(keyData, mode: .local, overwriteExisting: true)
        return keyData
    }

    private func setKeychainMode(_ mode: KeychainMode) throws {
        switch mode {
        case .local:
            try switchToLocalMode()
        case .icloud:
            try switchToICloudMode()
        }
    }

    private func switchToICloudMode() throws {
        let hasEntries = try vaultContainsEntries()

        if try keyStore.keyExists(mode: .icloud) {
            let iCloudKey = try keyStore.loadKey(
                mode: .icloud,
                reason: "Unlock key vault to enable iCloud Keychain mode.",
                createIfMissing: false
            )
            try verifyVaultKeyMatchesAllExistingEntries(iCloudKey, sourceMode: .icloud)
            try keyStore.storeKey(iCloudKey, mode: .local, overwriteExisting: true)
            try persistKeychainMode(.icloud)
            return
        }

        if try keyStore.keyExists(mode: .local) {
            let localKey = try keyStore.loadKey(
                mode: .local,
                reason: "Unlock key vault to enable iCloud Keychain mode.",
                createIfMissing: false
            )

            do {
                try verifyVaultKeyMatchesAllExistingEntries(localKey, sourceMode: .local)
            } catch AppError.vaultKeyMismatch {
                if hasEntries {
                    throw waitingForICloudVaultKeyError()
                }
                throw errorForLocalKeyMismatch()
            }

            try keyStore.storeKey(localKey, mode: .icloud, overwriteExisting: false)
            try persistKeychainMode(.icloud)
            return
        }

        if hasEntries {
            throw waitingForICloudVaultKeyError()
        }

        try persistKeychainMode(.icloud)
    }

    private func switchToLocalMode() throws {
        if try keyStore.keyExists(mode: .local) {
            let localKey = try keyStore.loadKey(
                mode: .local,
                reason: "Unlock key vault to enable local Keychain mode.",
                createIfMissing: false
            )
            do {
                try verifyVaultKeyMatchesAllExistingEntries(localKey, sourceMode: .local)
                try persistKeychainMode(.local)
                return
            } catch AppError.vaultKeyMismatch {
                // Fall through and attempt repair from iCloud.
            }
        }

        if try keyStore.keyExists(mode: .icloud) {
            let iCloudKey = try keyStore.loadKey(
                mode: .icloud,
                reason: "Unlock key vault to enable local Keychain mode.",
                createIfMissing: false
            )
            try verifyVaultKeyMatchesAllExistingEntries(iCloudKey, sourceMode: .icloud)
            try keyStore.storeKey(iCloudKey, mode: .local, overwriteExisting: true)
            try persistKeychainMode(.local)
            return
        }

        if try vaultContainsEntries() {
            throw missingVaultKeyForExistingVaultError()
        }

        try persistKeychainMode(.local)
    }

    private func decryptSecret(_ file: SecretFile, named name: String, keyData: Data) throws -> String {
        do {
            return try cipher.decrypt(file, keyData: keyData)
        } catch CryptoKitError.authenticationFailure {
            throw mismatchedVaultKeyError(for: name)
        } catch {
            throw error
        }
    }

    private func vaultContainsEntries() throws -> Bool {
        !(try entryStore.listEntries().isEmpty)
    }

    private func verifyVaultKeyMatchesAllExistingEntries(_ keyData: Data, sourceMode: KeychainMode) throws {
        for name in try entryStore.listEntries() {
            let file = try entryStore.load(name)
            do {
                _ = try cipher.decrypt(file, keyData: keyData)
            } catch CryptoKitError.authenticationFailure {
                throw mismatchError(for: sourceMode)
            } catch {
                throw error
            }
        }
    }

    private func mismatchError(for mode: KeychainMode) -> AppError {
        switch mode {
        case .local:
            return errorForLocalKeyMismatch()
        case .icloud:
            return AppError.vaultKeyMismatch(
                "The iCloud Keychain vault key does not match the encrypted vault at '\(entryStore.rootURL.path(percentEncoded: false))'. Use a Mac that can already unlock this vault to publish the correct iCloud Keychain key first."
            )
        }
    }

    private func missingVaultKeyForExistingVaultError() -> AppError {
        AppError.vaultKeyMismatch(
            "Encrypted secrets already exist in '\(entryStore.rootURL.path(percentEncoded: false))', but no matching vault key was found in Keychain. Refusing to create a new vault key because that would make the existing secrets unreadable."
        )
    }

    private func waitingForICloudVaultKeyError() -> AppError {
        AppError.vaultKeyMismatch(
            "No matching iCloud Keychain vault key is available yet for '\(entryStore.rootURL.path(percentEncoded: false))'. Run `key config set keychain-mode icloud` on a Mac that can already unlock this vault, then wait for iCloud Keychain sync to finish."
        )
    }

    private func errorForLocalKeyMismatch() -> AppError {
        AppError.vaultKeyMismatch(
            "The local Keychain vault key does not match the encrypted vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
        )
    }

    private func mismatchedVaultKeyError(for name: String) -> AppError {
        switch keychainMode() {
        case .local:
            return AppError.vaultKeyMismatch(
                "The local Keychain vault key cannot decrypt '\(name)'. This usually means this Mac is using a different vault key than the one that originally encrypted the vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
            )
        case .icloud:
            return AppError.vaultKeyMismatch(
                "The iCloud Keychain vault key cannot decrypt '\(name)'. This usually means the shared iCloud Keychain key does not match the encrypted vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
            )
        }
    }

    private func persistKeychainMode(_ mode: KeychainMode) throws {
        if let configStore {
            _ = try configStore.setValue(mode.rawValue, for: .keychainMode)
        }
        keyStore.invalidate()
        stateQueue.sync {
            currentKeychainMode = mode
        }
    }

    private func keychainMode() -> KeychainMode {
        stateQueue.sync {
            currentKeychainMode
        }
    }

    private func normalizeSecret(_ secret: String, for type: SecretEntryType) throws -> String {
        switch type {
        case .secret:
            return secret
        case .totp:
            return try TOTPGenerator.normalizeBase32Seed(secret)
        }
    }

    private func renderValue(for type: SecretEntryType, decryptedValue: String) throws -> String {
        switch type {
        case .secret:
            return decryptedValue
        case .totp:
            return try TOTPGenerator.generateCode(fromBase32Seed: decryptedValue, at: now())
        }
    }
}

private func v3ReadOnlyOperationError() -> AppError {
    AppError.operationRefused(
        "This device already selects a version 3 vault. Local version 2 migration is unavailable, and general version 3 writes are not enabled in this release."
    )
}

private extension KeyServiceRequest {
    func isAllowed(
        during state: V3ReplacementEnrollmentAdmissionState
    ) -> Bool {
        switch state {
        case .inactive:
            true
        case .cleanupPrepared, .cleanupPending:
            switch self {
            case .status, .lock,
                .share(.reviewReplacement),
                .share(.replaceCurrentDevice), .share(.join):
                true
            default:
                false
            }
        case .enrollmentPending:
            switch self {
            case .status, .lock,
                .share(.invitations), .share(.join),
                .share(.compare), .share(.accept):
                true
            default:
                false
            }
        }
    }

    var requiresExclusiveRuntimeSelectionChange: Bool {
        switch self {
        case .setVaultDirectory, .migrationApply,
            .share(.accept), .share(.replaceCurrentDevice):
            true
        default:
            false
        }
    }

    var isVaultDirectoryChange: Bool {
        if case .setVaultDirectory = self {
            true
        } else {
            false
        }
    }

    var transactionMutationKind: VaultTransactionMutationKind? {
        switch self {
        case .addManual:
            .addEntry
        case .editManual:
            .editEntry
        case .copyEntry:
            .copyEntry
        case .moveEntry:
            .moveEntry
        case .removeEntry:
            .removeEntry
        case .resolveConflicts:
            .resolveConflict
        case .migrationApply:
            .migrateToV3
        case .share(.approve), .share(.accept):
            .enrollDevice
        case .share(.reviewRevocation), .share(.reviewReplacement),
            .share(.join):
            .catchUpVault
        case .share(.revoke):
            .revokeDevice
        default:
            nil
        }
    }

    var isConflictResolution: Bool {
        if case .resolveConflicts = self {
            true
        } else {
            false
        }
    }

    var ownsMutationAuthorization: Bool {
        switch self {
        case .share(.approve), .share(.accept),
            .share(.reviewRevocation), .share(.reviewReplacement),
            .share(.revoke), .share(.join):
            true
        default:
            false
        }
    }
}

private func enrollmentDigest(_ value: String) throws -> Data {
    guard value.utf8.count == 64,
        value.utf8.allSatisfy({
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        })
    else {
        throw AppError.usage(
            "Enrollment IDs must be complete 64-character lowercase hexadecimal values."
        )
    }
    var result = Data()
    result.reserveCapacity(32)
    var index = value.startIndex
    for _ in 0..<32 {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else {
            throw AppError.usage("Invalid enrollment ID.")
        }
        result.append(byte)
        index = next
    }
    return result
}

private func replacementDigest(_ value: String) throws -> Data {
    guard value.utf8.count == 64,
        value.utf8.allSatisfy({
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        })
    else {
        throw AppError.usage(
            "Replacement confirmation tokens must be complete 64-character lowercase hexadecimal values."
        )
    }
    var result = Data()
    result.reserveCapacity(32)
    var index = value.startIndex
    for _ in 0..<32 {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else {
            throw AppError.usage("Invalid replacement confirmation token.")
        }
        result.append(byte)
        index = next
    }
    return result
}

private func replacementFailure(
    _ error: V3ReplacementEnrollmentWorkflowError
) -> KeyServiceResponse {
    switch error {
    case .noLocalIdentity, .deviceStillActive:
        .failure(error.localizedDescription, code: .operationRefused)
    case .identityUnrecognized:
        .failure(error.localizedDescription, code: .recoveryRequired)
    case .invalidConfirmation:
        .failure(error.localizedDescription, code: .invalidUsage)
    }
}

private func replacementFailure(
    _ error: V3ReplacementDeviceIdentityClassificationError
) -> KeyServiceResponse {
    switch error {
    case .conflictingAuthority:
        .failure(error.localizedDescription, code: .securityConflict)
    case .upgradeRequired:
        .failure(error.localizedDescription, code: .operationRefused)
    case .invalidAuthority, .identityMismatch:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func replacementFailure(
    _ error: V3ReplacementEnrollmentCoordinatorError
) -> KeyServiceResponse {
    switch error {
    case .invalidConfirmation:
        .failure(error.localizedDescription, code: .invalidUsage)
    case .reviewedStateChanged:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .invalidRequest, .replacementAlreadyInProgress,
        .noReplacementInProgress:
        .failure(error.localizedDescription, code: .operationRefused)
    }
}

private func replacementFailure(
    _ error: V3ReplacementEnrollmentIntentError
) -> KeyServiceResponse {
    switch error {
    case .conflict:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .invalidReview, .invalidIntent, .invalidPhaseTransition,
        .invalidConfiguration, .keychainStatus:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func replacementFailure(
    _ error: V3EnrollmentDeviceIdentityStoreError
) -> KeyServiceResponse {
    switch error {
    case .authenticationCancelled:
        .failure(error.localizedDescription, code: .authenticationFailed)
    case .conflict:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .identityAlreadyExists:
        .failure(error.localizedDescription, code: .operationRefused)
    case .invalidRecord, .invalidIdentityRequest, .identityMismatch,
        .secureEnclaveUnavailable, .invalidConfiguration,
        .keyOperationFailed, .keychainStatus:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func revocationFailure(
    _ error: V3DeviceWrappedRevocationWorkflowError
) -> KeyServiceResponse {
    switch error {
    case .invalidConfirmationToken:
        .failure(error.localizedDescription, code: .invalidUsage)
    case .reviewedStateChanged:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    }
}

private func revocationFailure(
    _ error: V3DeviceWrappedRevocationPlanningError
) -> KeyServiceResponse {
    switch error {
    case .invalidTrustedCheckpoint:
        .failure(error.localizedDescription, code: .recoveryRequired)
    case .invalidAuthorizingDevice, .deviceNotFound, .deviceAlreadyRevoked,
        .cannotRevokeAuthorizingDevice, .lastActiveDevice:
        .failure(error.localizedDescription, code: .operationRefused)
    }
}

private func revocationFailure(
    _ error: V3DeviceWrappedRevocationTransitionError
) -> KeyServiceResponse {
    switch error {
    case .invalidPlan:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .invalidTrustedCheckpoint, .invalidCurrentVaultKey,
        .invalidNextVaultKey, .invalidOwner, .incompleteEntrySnapshot,
        .invalidEntry, .invalidCandidate:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func revocationFailure(
    _ error: V3DeviceWrappedRevocationValidationError
) -> KeyServiceResponse {
    switch error {
    case .invalidPlan:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .authenticationCancelled:
        .failure(error.localizedDescription, code: .authenticationFailed)
    case .invalidTrustedCheckpoint, .invalidCurrentVaultKey,
        .invalidNextVaultKey, .invalidTransition,
        .invalidDeviceAuthorization, .localWrapperInvalid,
        .invalidCurrentEntry, .invalidStagedEntry, .objectTooLarge:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func revocationFailure(
    _ error: V3DeviceWrappedCatchUpError
) -> KeyServiceResponse {
    switch error {
    case .temporaryUnavailable, .checkpointChanged:
        .failure(error.localizedDescription, code: .vaultIncomplete)
    case .authenticationCancelled:
        .failure(error.localizedDescription, code: .authenticationFailed)
    case .deviceRevoked, .recoveryRequired:
        .failure(error.localizedDescription, code: .recoveryRequired)
    case .upgradeRequired:
        .failure(error.localizedDescription, code: .operationRefused)
    }
}

private func revocationFailure(
    _ error: V3DeviceWrappedVaultUnlockRuntimeError
) -> KeyServiceResponse {
    switch error {
    case .locked:
        .failure(error.localizedDescription, code: .authenticationFailed)
    case .temporaryUnavailable, .checkpointChanged:
        .failure(error.localizedDescription, code: .vaultIncomplete)
    case .recoveryRequired, .deviceIdentityUnavailable, .deviceRevoked:
        .failure(error.localizedDescription, code: .recoveryRequired)
    case .legacyAlphaProfile, .upgradeRequired:
        .failure(error.localizedDescription, code: .operationRefused)
    }
}

private func revocationFailure(
    _ error: V3ImmutableTransactionRecoveryError
) -> KeyServiceResponse {
    switch error {
    case .transactionDirectoryUnavailable, .interruptedTransactionPending:
        .failure(error.localizedDescription, code: .vaultIncomplete)
    case .invalidRecoveryAnchor, .invalidIntent, .checkpointUnavailable,
        .vaultKeyUnavailable, .invalidRecoveryState:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func revocationFailure(
    _ error: V3ImmutableTransactionError
) -> KeyServiceResponse {
    switch error {
    case .expectedHeadsChanged:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .referencedEntryUnavailable, .publishedManifestUnavailable:
        .failure(error.localizedDescription, code: .vaultIncomplete)
    case .invalidAncestryProof, .unresolvedConflict,
        .candidateDoesNotMatchAutomaticMerge, .duplicateStagedEntry,
        .invalidStagedEntry, .objectTooLarge, .referencedEntryInvalid,
        .publishedManifestInvalid:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func revocationFailure(
    _ error: V3ManifestCheckpointStoreError
) -> KeyServiceResponse {
    switch error {
    case .conflict:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .invalidConfiguration, .keychainStatus:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func revocationFailure(
    _ error: V3ImmutableTransactionRecoveryAnchorError
) -> KeyServiceResponse {
    switch error {
    case .conflict:
        .failure(error.localizedDescription, code: .expectedHeadsChanged)
    case .invalidAnchor, .invalidConfiguration, .keychainStatus:
        .failure(error.localizedDescription, code: .recoveryRequired)
    }
}

private func enrollmentFailure(
    _ error: V3EnrollmentAdoptionError
) -> KeyServiceResponse {
    switch error {
    case .approvalUnavailable:
        return .failure(
            error.localizedDescription,
            code: .vaultIncomplete
        )
    case .invalidCeremony, .selectionFailed:
        return .failure(
            error.localizedDescription,
            code: .operationRefused
        )
    case .ambiguousApproval, .invalidApproval, .identityUnavailable,
        .invalidWrappedKey, .conflictingVaultKey,
        .conflictingCheckpoint:
        return .failure(
            error.localizedDescription,
            code: .recoveryRequired
        )
    }
}

private func deviceWrappedEnrollmentFailure(
    _ error: V3DeviceWrappedEnrollmentAdoptionError
) -> KeyServiceResponse {
    switch error {
    case .approvalUnavailable:
        return .failure(error.localizedDescription, code: .vaultIncomplete)
    case .invalidCeremony, .upgradeRequired, .authenticationCancelled,
        .selectionFailed:
        return .failure(error.localizedDescription, code: .operationRefused)
    case .ambiguousApproval, .invalidApproval, .identityUnavailable,
        .invalidWrappedKey, .conflictingCheckpoint:
        return .failure(error.localizedDescription, code: .recoveryRequired)
    }
}
