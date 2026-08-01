import Foundation

/// The entry-first, manifest-last immutable publication operations shared by
/// local bootstrap and ordinary authenticated transactions.
///
/// Transaction recovery extends this seam separately; migration does not gain
/// access to recovery intents or general manifest advancement through it.
protocol V3ImmutableObjectPublishing: V3ImmutableObjectReading {
    func readStagedEntry(
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead

    func readStagedManifest(
        digest: Data,
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead

    func stageEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func stageManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func publishStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func publishStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func removeStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func removeStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func removeEmptyTransactionDirectories(
        operationID: VaultTransactionOperationID,
        entryIDs: [String]
    ) throws
}
