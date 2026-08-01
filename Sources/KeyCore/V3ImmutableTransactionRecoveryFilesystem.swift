import Foundation

/// Adds general transaction recovery-intent storage to the narrower immutable
/// publication store. The shipping local migration path depends only on
/// `V3ImmutableObjectPublishing` and cannot create or consume these intents.
extension V3FilesystemTransactionArtifactStore: V3TransactionArtifactStore {
    func persistRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        let intent: V3ImmutableTransactionRecoveryIntent
        do {
            intent = try V3ImmutableTransactionRecoveryIntent(
                canonicalBytes: data
            )
        } catch {
            throw V3ImmutableObjectPublicationError.digestMismatch
        }
        guard intent.operationID == operationID else {
            throw V3ImmutableObjectPublicationError.invalidPath
        }
        try writeStagedObject(
            data,
            at: recoveryIntentPath(operationID: operationID)
        )
    }

    func readRecoveryIntent(
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try readRecoveryObject(
            at: recoveryIntentPath(operationID: operationID),
            maximumBytes: maximumBytes
        )
    }

    func removeRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        let intent = try V3ImmutableTransactionRecoveryIntent(
            canonicalBytes: data
        )
        guard intent.operationID == operationID else {
            throw V3ImmutableObjectPublicationError.invalidPath
        }
        try removeExactRecoveryObject(
            data,
            at: recoveryIntentPath(operationID: operationID)
        )
    }
}

private func recoveryIntentPath(
    operationID: VaultTransactionOperationID
) -> String {
    ".transactions/\(operationID)/intent.json"
}
