import Foundation

/// Owns first-time initialization, independently of any configured v2/v3 runtime.
/// The helper host serializes it against every other request.
struct V3VaultInitializationService {
    let configStore: KeyConfigStore
    let install: (
        V3NewVaultDirectory,
        VaultTransactionOperationID,
        @escaping (String) throws -> Void
    ) throws -> V3DeviceWrappedGenesisInstallReport

    func initialize(path: String) throws -> String {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else {
            throw AppError.invalidConfiguration("Init requires an absolute directory path from the CLI.")
        }
        try configStore.requireUnconfigured()
        let directory = try V3NewVaultDirectory.prepare(
            at: URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
        )
        let operationID = VaultTransactionOperationID()
        let select = try configStore.reserveNewVaultSelection(
            rootHandle: directory.rootHandle,
            operationID: operationID
        )
        do {
            let report = try install(directory, operationID, select)
            return "Created a new vault at '\(directory.rootHandle.rootURL.path)'.\nVault ID: \(report.vaultID)\nKey will use this vault for future commands on this Mac.\nRun `key status`, then `key add <name>`. Add another Mac before relying on this vault. If every enrolled Mac is lost, the vault folder alone cannot restore access.\n"
        } catch {
            throw AppError.operationRefused("Vault setup did not finish: \(error.localizedDescription)\nLeave the vault folder and local setup record intact. Run `key status` to check whether Key finished configuring this vault. If not, this attempt needs investigation; init cannot safely restart it automatically.")
        }
    }

    static func live(
        configStore: KeyConfigStore,
        runtimeConfiguration: RuntimeConfiguration
    ) -> Self {
        Self(configStore: configStore) { directory, operationID, select in
            let configuration = KeyConfiguration(
                configFileURL: configStore.initializationConfigFileURL,
                vaultDirectoryURL: directory.rootHandle.rootURL,
                vaultPathSource: .appSupportConfigCustom,
                keychainMode: .local
            )
            let session = V3DeviceWrappedVaultKeySessionStore()
            defer { session.invalidate() }
            let installer = V3DeviceWrappedGenesisInstaller(
                entryStore: EntryStore(rootURL: directory.rootHandle.rootURL),
                cipher: VaultCipher(),
                objectStore: V3FilesystemTransactionArtifactStore(rootHandle: directory.rootHandle),
                checkpointStore: V3ManifestCheckpointKeychainStore(configuration: runtimeConfiguration),
                cache: try KeyServiceHandler.makeV3CheckpointManifestCache(keyConfiguration: configuration),
                session: session,
                identityManager: V3EnrollmentDeviceIdentityManager(
                    recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(configuration: runtimeConfiguration),
                    keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations()
                ),
                loadV2VaultKey: { _, _ in
                    throw AppError.operationRefused("Initialization must not access a legacy vault key.")
                },
                selectVault: select
            )
            return try installer.installNewVault(
                in: directory,
                operationID: operationID,
                deviceName: KeyServiceHandler.currentDeviceDisplayName()
            )
        }
    }
}
