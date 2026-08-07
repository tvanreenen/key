import Foundation

/// Shipping adapter for the permanent device-wrapped version 3 profile.
///
/// This boundary keeps profile-specific unlock errors and session ownership
/// out of `KeyServiceHandler`. Ordinary writes remain deliberately absent
/// until the permanent mutation service is connected in a later increment.
struct V3DeviceWrappedVaultRuntime:
    VaultReadServicing,
    VaultUXServicing,
    VaultSessionServicing,
    Sendable
{
    private let runtime: any VaultReadServicing & VaultUXServicing
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let lockSession: @Sendable () -> Void

    init(
        rootHandle: VaultRootDirectoryHandle,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        identityLoader: any V3DeviceWrappedIdentityLoading,
        session: V3DeviceWrappedVaultKeySessionStore =
            V3DeviceWrappedVaultKeySessionStore()
    ) {
        let source = V3FilesystemImmutableObjectSource(
            rootHandle: rootHandle
        )
        let unlockRuntime = V3DeviceWrappedVaultUnlockRuntime(
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            source: source,
            cache: cache,
            identityLoader: identityLoader,
            session: session
        )
        self.init(
            runtime: V3DeviceWrappedReadOnlyVaultRuntime(
                source: source,
                unlockRuntime: unlockRuntime
            ),
            session: session,
            lockSession: {
                unlockRuntime.lock()
            }
        )
    }

    init(
        runtime: any VaultReadServicing & VaultUXServicing,
        session: V3DeviceWrappedVaultKeySessionStore,
        lockSession: @escaping @Sendable () -> Void
    ) {
        self.runtime = runtime
        self.session = session
        self.lockSession = lockSession
    }

    func unlock() throws {
        try translatingUnlockErrors {
            try runtime.unlock()
        }
    }

    func read(
        name: String,
        allowStale: Bool
    ) throws -> VaultReadValue {
        try translatingUnlockErrors {
            try runtime.read(name: name, allowStale: allowStale)
        }
    }

    func list(allowStale: Bool) throws -> [String] {
        try translatingUnlockErrors {
            try runtime.list(allowStale: allowStale)
        }
    }

    func status() throws -> VaultStatus {
        try translatingUnlockErrors {
            try runtime.status()
        }
    }

    func authorizeRead(name: String, allowStale: Bool) throws {
        try translatingUnlockErrors {
            try runtime.authorizeRead(
                name: name,
                allowStale: allowStale
            )
        }
    }

    func authorizeMutation() throws {
        try runtime.authorizeMutation()
    }

    func conflicts() throws -> [VaultConflictSummary] {
        try translatingUnlockErrors {
            try runtime.conflicts()
        }
    }

    func conflict(id: String) throws -> VaultConflictDetail {
        try translatingUnlockErrors {
            try runtime.conflict(id: id)
        }
    }

    func conflictValue(
        id: String,
        versionID: String
    ) throws -> String {
        try translatingUnlockErrors {
            try runtime.conflictValue(id: id, versionID: versionID)
        }
    }

    func resolve(_ resolutions: [VaultConflictResolution]) throws {
        try runtime.resolve(resolutions)
    }

    func lock() {
        lockSession()
    }

    func sessionStatus(at date: Date?) -> KeyHelperStatus {
        session.sessionStatus(at: date)
    }

    private func translatingUnlockErrors<Result>(
        _ operation: () throws -> Result
    ) throws -> Result {
        do {
            return try operation()
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            throw serviceError(for: error)
        }
    }

    private func serviceError(
        for error: V3DeviceWrappedVaultUnlockRuntimeError
    ) -> any Error {
        switch error {
        case .locked:
            AppError.authFailed(error.localizedDescription)
        case .temporaryUnavailable, .checkpointChanged:
            VaultUXServiceError.vaultIncomplete
        case .recoveryRequired, .deviceRevoked:
            VaultUXServiceError.recoveryRequired
        case .legacyAlphaProfile, .upgradeRequired:
            AppError.operationRefused(error.localizedDescription)
        }
    }
}
