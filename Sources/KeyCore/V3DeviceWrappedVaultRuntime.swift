import Foundation

/// Shipping adapter for the permanent device-wrapped version 3 profile.
///
/// This boundary keeps profile-specific unlock errors, session ownership, and
/// permanent-profile mutation composition out of `KeyServiceHandler`.
struct V3DeviceWrappedVaultRuntime:
    VaultReadServicing,
    VaultMutationServicing,
    VaultUXServicing,
    VaultSessionServicing,
    Sendable
{
    typealias CatchUp = @Sendable () throws
        -> V3DeviceWrappedCatchUpCoordinatorOutcome

    private let runtime: any VaultReadServicing & VaultUXServicing
    private let mutationService:
        (any V3DeviceWrappedVaultMutationServicing)?
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let lockSession: @Sendable () -> Void
    private let catchUp: CatchUp?
    private let catchUpGate = V3DeviceWrappedCatchUpAccessGate()

    init(
        rootHandle: VaultRootDirectoryHandle,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        identityLoader: any V3DeviceWrappedIdentityLoading,
        session: V3DeviceWrappedVaultKeySessionStore =
            V3DeviceWrappedVaultKeySessionStore()
    ) {
        let objectStore = V3FilesystemTransactionArtifactStore(
            rootHandle: rootHandle
        )
        let unlockRuntime = V3DeviceWrappedVaultUnlockRuntime(
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            source: objectStore,
            cache: cache,
            identityLoader: identityLoader,
            session: session
        )
        let mutationService = V3DeviceWrappedVaultMutationService(
            stateLoader: unlockRuntime,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            cache: cache
        )
        self.init(
            runtime: V3DeviceWrappedReadOnlyVaultRuntime(
                source: objectStore,
                unlockRuntime: unlockRuntime
            ),
            mutationService: mutationService,
            session: session,
            catchUp: nil,
            lockSession: {
                unlockRuntime.lock()
            }
        )
    }

    init(
        runtime: any VaultReadServicing & VaultUXServicing,
        mutationService:
            (any V3DeviceWrappedVaultMutationServicing)? = nil,
        session: V3DeviceWrappedVaultKeySessionStore,
        catchUp: CatchUp? = nil,
        lockSession: @escaping @Sendable () -> Void
    ) {
        self.runtime = runtime
        self.mutationService = mutationService
        self.session = session
        self.catchUp = catchUp
        self.lockSession = lockSession
    }

    func unlock() throws {
        try translatingUnlockErrors {
            if catchUp == nil {
                try runtime.unlock()
            } else {
                // Catch-up authenticates the exact local checkpoint and leaves
                // its matching key resident. Calling the explicit unlock path
                // afterward would invalidate that session and prompt again.
                try requireCaughtUp()
            }
        }
    }

    func read(
        name: String,
        allowStale: Bool
    ) throws -> VaultReadValue {
        try translatingUnlockErrors {
            try requireCaughtUp(allowStale: allowStale)
            return try runtime.read(name: name, allowStale: allowStale)
        }
    }

    func list(allowStale: Bool) throws -> [String] {
        try translatingUnlockErrors {
            try requireCaughtUp(allowStale: allowStale)
            return try runtime.list(allowStale: allowStale)
        }
    }

    func status() throws -> VaultStatus {
        try translatingUnlockErrors {
            if let conflictStatus = try catchUpConflictStatus() {
                return conflictStatus
            }
            return try runtime.status()
        }
    }

    func authorizeRead(name: String, allowStale: Bool) throws {
        try translatingUnlockErrors {
            try requireCaughtUp(allowStale: allowStale)
            try runtime.authorizeRead(
                name: name,
                allowStale: allowStale
            )
        }
    }

    func authorizeMutation() throws {
        try translatingUnlockErrors {
            if let mutationService {
                try mutationService.authorizeMutation()
            } else {
                try runtime.authorizeMutation()
            }
        }
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

    func add(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        try withMutationService {
            try $0.add(
                name: name,
                secret: secret,
                type: type,
                operationID: operationID
            )
        }
    }

    func edit(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        try withMutationService {
            try $0.edit(
                name: name,
                secret: secret,
                type: type,
                operationID: operationID
            )
        }
    }

    func copy(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        try withMutationService {
            try $0.copy(
                source: source,
                destination: destination,
                overwrite: overwrite,
                operationID: operationID
            )
        }
    }

    func move(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        try withMutationService {
            try $0.move(
                source: source,
                destination: destination,
                overwrite: overwrite,
                operationID: operationID
            )
        }
    }

    func remove(
        name: String,
        operationID: VaultTransactionOperationID
    ) throws {
        try withMutationService {
            try $0.remove(name: name, operationID: operationID)
        }
    }

    func resolve(
        _ resolutions: [VaultConflictResolution],
        operationID: VaultTransactionOperationID
    ) throws {
        try withMutationService {
            try $0.resolve(resolutions, operationID: operationID)
        }
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
        } catch let error as V3DeviceWrappedCatchUpError {
            throw serviceError(for: error)
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            throw serviceError(for: error)
        }
    }

    private func requireCaughtUp(allowStale: Bool = false) throws {
        guard let catchUp else {
            return
        }
        try catchUpGate.requireCurrent(
            allowStale: allowStale,
            catchUp: catchUp
        )
    }

    private func catchUpConflictStatus() throws -> VaultStatus? {
        guard let catchUp else {
            return nil
        }
        switch try catchUp() {
        case .current:
            return nil
        case let .contentConflict(trusted, _, _):
            return conflictStatus(
                trusted: trusted,
                health: .contentConflicted,
                issue: VaultIssue(
                    code: .ambiguousHistory,
                    message: "Authenticated content history has competing versions. Key will not choose one automatically; normal writes remain paused, but an explicit stale read can use the version already trusted on this Mac."
                )
            )
        case let .securityConflict(trusted, _, _):
            return conflictStatus(
                trusted: trusted,
                health: .securityConflicted,
                issue: VaultIssue(
                    code: .authorityDiverged,
                    message: "Authenticated history contains competing vault-key or membership changes. Key will not choose one automatically."
                )
            )
        }
    }

    private func conflictStatus(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        health: VaultHealth,
        issue: VaultIssue
    ) -> VaultStatus {
        VaultStatus(
            format: .version3,
            health: health,
            entries: .lastTrusted(trusted.envelope.body.entries.count),
            trustedVersionID: String(
                v3LowercaseHex(trusted.checkpoint.envelopeDigest).prefix(16)
            ),
            issues: [issue]
        )
    }

    private func withMutationService<Result>(
        _ operation:
            (any V3DeviceWrappedVaultMutationServicing) throws -> Result
    ) throws -> Result {
        guard let mutationService else {
            throw AppError.operationRefused(
                "Permanent version 3 vault writes are not enabled."
            )
        }
        return try translatingUnlockErrors {
            try operation(mutationService)
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

    private func serviceError(
        for error: V3DeviceWrappedCatchUpError
    ) -> any Error {
        switch error {
        case .temporaryUnavailable, .checkpointChanged:
            VaultUXServiceError.vaultIncomplete
        case .authenticationCancelled:
            AppError.authFailed(error.localizedDescription)
        case .deviceRevoked, .recoveryRequired:
            VaultUXServiceError.recoveryRequired
        case .upgradeRequired:
            AppError.operationRefused(error.localizedDescription)
        }
    }
}
