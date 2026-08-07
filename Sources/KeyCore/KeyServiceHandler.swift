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
    private let vaultUXService: any VaultUXServicing
    private let vaultReader: (any VaultReadServicing)?
    private let vaultMutator: (any VaultMutationServicing)?
    private let vaultSession: (any VaultSessionServicing)?
    private let configuredVaultID: String?
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
        vaultUXService: (any VaultUXServicing)? = nil,
        vaultReader: (any VaultReadServicing)? = nil,
        vaultMutator: (any VaultMutationServicing)? = nil,
        vaultSession: (any VaultSessionServicing)? = nil,
        configuredVaultID: String? = nil
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.configStore = configStore
        self.cipher = cipher
        self.now = now
        self.mutationOwner = mutationOwner
        self.migrationService = migrationService
        self.enrollmentService = enrollmentService
        self.vaultUXService = vaultUXService
            ?? V2VaultUXService(entryStore: entryStore)
        self.vaultReader = vaultReader
        self.vaultMutator = vaultMutator
        self.vaultSession = vaultSession
        self.configuredVaultID = configuredVaultID
        self.currentKeychainMode = keychainMode
    }

    public static func live(bundle: Bundle = .main) throws -> KeyServiceHandler {
        let configStore = KeyConfigStore()
        let keyConfiguration = try configStore.load()
        let configuration = RuntimeConfiguration.live(bundle: bundle)
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
                return makeLiveV3EnrollmentWorkflowService(
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
        let runtime = V3DeviceWrappedVaultRuntime(
            rootHandle: rootHandle,
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            recoveryAnchorStore:
                V3ImmutableTransactionRecoveryAnchorKeychainStore(
                    configuration: runtimeConfiguration
                ),
            cache: try makeV3CheckpointManifestCache(
                keyConfiguration: keyConfiguration
            ),
            identityLoader: V3EnrollmentDeviceIdentityManager(
                recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(
                    configuration: runtimeConfiguration
                ),
                keyOperations:
                    V3SecureEnclaveEnrollmentDeviceKeyOperations()
            )
        )
        return KeyServiceHandler(
            keyStore: keyStore,
            entryStore: entryStore,
            keychainMode: keyConfiguration.keychainMode,
            configStore: configStore,
            mutationOwner: VaultTransactionMutationOwner(),
            vaultUXService: runtime,
            vaultReader: runtime,
            vaultMutator: runtime,
            vaultSession: runtime,
            configuredVaultID: vaultID
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
                    && !request.isEnrollmentMutation
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
                guard let enrollmentService else {
                    throw AppError.operationRefused(
                        "Version 3 device sharing is unavailable in this helper runtime."
                    )
                }
                return try handleShare(
                    action,
                    service: enrollmentService,
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
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func handleShare(
        _ request: KeyShareRequest,
        service: any V3EnrollmentWorkflowServicing,
        mutationContext: VaultTransactionMutationContext?
    ) throws -> KeyServiceResponse {
        let unixTime = UInt64(max(0, now().timeIntervalSince1970))
        switch request {
        case .devices:
            return .deviceInventory(try service.deviceInventory())
        case .invitations:
            return .success(try service.listInvitations())
        case let .invite(deviceName, role):
            return .success(try service.createInvitation(
                deviceName: deviceName,
                role: role,
                at: unixTime
            ))
        case let .join(invitationID, deviceName):
            return .success(try service.join(
                invitationDigest: try enrollmentDigest(invitationID),
                deviceName: deviceName,
                at: unixTime
            ))
        case let .requests(invitationID):
            return .success(try service.listJoinRequests(
                invitationDigest: try enrollmentDigest(invitationID),
                at: unixTime
            ))
        case let .compare(vaultID, invitationID, joinRequestID):
            return .success(try service.compare(
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
            return .success(try service.approve(
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
            return .success(try service.accept(
                vaultID: vaultID,
                invitationDigest: try enrollmentDigest(invitationID),
                comparisonCode: comparisonCode,
                at: unixTime,
                operationID: mutationContext.operationID
            ))
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
    var requiresExclusiveRuntimeSelectionChange: Bool {
        switch self {
        case .setVaultDirectory, .migrationApply,
            .share(.accept):
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

    var isEnrollmentMutation: Bool {
        switch self {
        case .share(.approve), .share(.accept):
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
