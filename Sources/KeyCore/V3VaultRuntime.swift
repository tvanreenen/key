import Foundation

/// Shipping selected-vault adapter for authenticated reads and guarded writes.
///
/// Read and UX behavior reuse the read-only runtime context. Mutations are
/// exposed through a separate service seam so `KeyServiceHandler` can supply
/// the operation identity created by its serialized mutation owner.
struct V3VaultRuntime:
    VaultReadServicing,
    VaultUXServicing,
    VaultMutationServicing,
    Sendable
{
    private let context: V3ReadRuntimeContext
    private let uxService: V3VaultUXService
    private let mutationService: V3VaultMutationService

    init(
        rootHandle: VaultRootDirectoryHandle,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        vaultKeyProvider: @escaping @Sendable (
            _ reason: String
        ) throws -> Data
    ) {
        let objectStore = V3FilesystemTransactionArtifactStore(
            rootHandle: rootHandle
        )
        self.init(
            objectStore: objectStore,
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            vaultKeyProvider: vaultKeyProvider
        )
    }

    init(
        objectStore: any V3TransactionArtifactStore,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        vaultKeyProvider: @escaping @Sendable (
            _ reason: String
        ) throws -> Data
    ) {
        let context = V3ReadRuntimeContext(
            source: objectStore,
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: vaultKeyProvider
        )
        self.context = context
        uxService = V3VaultUXService(
            snapshotProvider: {
                try context.snapshot()
            },
            valueReader: { entry, expectedHeads in
                try context.readConflict(
                    entry: entry,
                    expectedHeads: expectedHeads
                )
            },
            resolutionPublisher: { _, _ in
                throw AppError.operationRefused(
                    "Conflict resolution requires the helper's serialized mutation boundary."
                )
            }
        )
        mutationService = V3VaultMutationService(
            context: context,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore
        )
    }

    func unlock() throws {
        try context.unlock()
    }

    func read(
        name: String,
        allowStale: Bool
    ) throws -> VaultReadValue {
        try context.read(name: name, allowStale: allowStale)
    }

    func list(allowStale: Bool) throws -> [String] {
        try context.list(allowStale: allowStale)
    }

    func status() throws -> VaultStatus {
        try uxService.status()
    }

    func authorizeRead(
        name: String,
        allowStale: Bool
    ) throws {
        try context.authorizeRead(name: name, allowStale: allowStale)
    }

    func authorizeMutation() throws {
        try uxService.authorizeMutation()
    }

    func conflicts() throws -> [VaultConflictSummary] {
        try uxService.conflicts()
    }

    func conflict(id: String) throws -> VaultConflictDetail {
        try uxService.conflict(id: id)
    }

    func conflictValue(
        id: String,
        versionID: String
    ) throws -> String {
        try uxService.conflictValue(id: id, versionID: versionID)
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw AppError.operationRefused(
            "Conflict resolution requires the helper's serialized mutation boundary."
        )
    }

    func add(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        try mutationService.add(
            name: name,
            secret: secret,
            type: type,
            operationID: operationID
        )
    }

    func edit(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        try mutationService.edit(
            name: name,
            secret: secret,
            type: type,
            operationID: operationID
        )
    }

    func copy(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        try mutationService.copy(
            source: source,
            destination: destination,
            overwrite: overwrite,
            operationID: operationID
        )
    }

    func move(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        try mutationService.move(
            source: source,
            destination: destination,
            overwrite: overwrite,
            operationID: operationID
        )
    }

    func remove(
        name: String,
        operationID: VaultTransactionOperationID
    ) throws {
        try mutationService.remove(
            name: name,
            operationID: operationID
        )
    }

    func resolve(
        _ resolutions: [VaultConflictResolution],
        operationID: VaultTransactionOperationID
    ) throws {
        try mutationService.resolve(
            resolutions,
            operationID: operationID
        )
    }
}
