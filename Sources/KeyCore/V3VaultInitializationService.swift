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
            return "Created and selected a device-enrolled vault at '\(directory.rootHandle.rootURL.path)'.\nVault ID: \(report.vaultID)\nRun `key status`, then `key add <name>`. Enroll another Mac for device-loss continuity; catastrophe recovery is not yet available.\n"
        } catch {
            throw AppError.operationRefused("Initialization did not finish cleanly: \(error.localizedDescription)\nLeave the directory and local initialization record intact. Run `key status` to check whether selection completed. If it did not, this attempt requires inspection; rerunning init will not silently replace it.")
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
