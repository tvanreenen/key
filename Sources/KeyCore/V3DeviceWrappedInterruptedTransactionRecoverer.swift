import CryptoKit
import Foundation

private struct V3DeviceWrappedRecoveryEntries {
    let stagedData: [V3EntryObjectKey: Data]
    let availableEntries: [V3EncryptedEntry]
    let entriesToPublish: [V3EntryObjectKey: V3EncryptedEntry]
}

/// Reconstructs one locally anchored permanent-profile publication.
///
/// Synchronized transaction files never authorize recovery. The device-local
/// anchor selects one exact intent; the candidate HMAC, unchanged authority,
/// entry objects, current checkpoint, and vault key are revalidated before any
/// publication or checkpoint replacement resumes.
struct V3DeviceWrappedInterruptedTransactionRecoverer: Sendable {
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let validator: V3DeviceWrappedTransactionValidator
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()

    init(
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits
    ) {
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.cache = cache
        self.limits = limits
        validator = V3DeviceWrappedTransactionValidator(
            objectStore: objectStore,
            cache: cache,
            limits: limits
        )
    }

    func recover(
        vaultID: String,
        vaultKey: Data
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        guard isValidV3UUID(vaultID) else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }
        guard let anchorData = try recoveryAnchorStore.loadRecoveryAnchor(
            vaultID: vaultID
        ) else {
            return .nothingToRecover
        }
        guard let anchor = try? V3ImmutableTransactionRecoveryAnchor(
            canonicalBytes: anchorData
        ), anchor.vaultID == vaultID else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }

        let intentRead = try objectStore.readRecoveryIntent(
            operationID: anchor.operationID,
            maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes
        )
        if case .unavailable = intentRead {
            guard anchor.phase == .prepared else {
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            }
            try recoveryAnchorStore.replaceRecoveryAnchor(
                nil,
                expectedAnchor: anchorData,
                vaultID: vaultID
            )
            return .abandoned(operationID: anchor.operationID)
        }
        guard case let .available(intentData) = intentRead,
              Data(SHA256.hash(data: intentData)) == anchor.intentDigest,
              let intent = try? V3ImmutableTransactionRecoveryIntent(
                  canonicalBytes: intentData
              ),
              intent.operationID == anchor.operationID,
              intent.vaultID == vaultID,
              intent.expectedHeads
                == [intent.expectedCheckpoint.envelopeDigest]
        else {
            throw V3ImmutableTransactionRecoveryError.invalidIntent(
                operationID: anchor.operationID.rawValue
            )
        }
        return try recover(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            vaultKey: vaultKey
        )
    }

    private func recover(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        vaultKey: Data
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        guard let checkpointData = try checkpointStore.loadCheckpoint(
            vaultID: intent.vaultID
        ), let currentCheckpoint = try? V3ManifestCheckpoint(
            canonicalBytes: checkpointData
        ), currentCheckpoint.vaultID == intent.vaultID else {
            throw V3ImmutableTransactionRecoveryError.checkpointUnavailable(
                vaultID: intent.vaultID
            )
        }
        let candidateCheckpoint = try V3ManifestCheckpoint(
            vaultID: intent.vaultID,
            envelopeDigest: intent.candidateManifestDigest
        )
        guard currentCheckpoint == intent.expectedCheckpoint
                || currentCheckpoint == candidateCheckpoint
        else {
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedEntries(intent),
                stagedManifest: try availableStagedManifest(intent)
            )
            return .abandoned(operationID: intent.operationID)
        }

        let manifest: (data: Data, published: Bool, stagedData: Data?)
        do {
            manifest = try recoveryManifest(
                intent,
                checkpointAlreadyAdvanced: currentCheckpoint
                    == candidateCheckpoint
            )
        } catch is V3DeviceWrappedMissingStagedManifest {
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedEntries(intent),
                stagedManifest: nil
            )
            return .abandoned(operationID: intent.operationID)
        }
        let entries = try recoveryEntries(
            intent,
            manifestAlreadyPublished: manifest.published
        )
        guard let entries else {
            if manifest.published {
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            }
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedEntries(intent),
                stagedManifest: manifest.stagedData
            )
            return .abandoned(operationID: intent.operationID)
        }

        let candidateKeyID: V3VaultKeyID
        do {
            candidateKeyID = try envelopeCodec.parse(manifest.data).body.keyID
        } catch {
            throw invalidRecoveryState(intent)
        }
        guard (try? V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: intent.vaultID
        )) == candidateKeyID else {
            throw V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
                keyID: candidateKeyID.rawValue
            )
        }

        let validated: V3DeviceWrappedValidatedContentMutation
        do {
            validated = try validator.validate(
                manifestData: manifest.data,
                manifestDigest: intent.candidateManifestDigest,
                expectedCheckpoint: intent.expectedCheckpoint,
                kind: intent.kind,
                stagedEntries: entries.availableEntries,
                vaultKey: vaultKey
            )
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        } catch {
            throw invalidRecoveryState(intent)
        }

        if currentCheckpoint == candidateCheckpoint {
            do {
                try validator.validatePublishedEntries(validated.envelope)
                try validator.validatePublishedManifest(validated)
            } catch let error as V3ImmutableTransactionError {
                throw recoveryError(for: error, intent: intent)
            }
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: entries.stagedData,
                stagedManifest: manifest.stagedData
            )
            try? cache.store(manifest.data, for: candidateCheckpoint)
            return .alreadyCompleted(operationID: intent.operationID)
        }

        guard try checkpointStore.loadCheckpoint(vaultID: intent.vaultID)
                == intent.expectedCheckpoint.canonicalBytes
        else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
        for key in entries.entriesToPublish.keys.sorted(
            by: entryObjectKeyPrecedes
        ) {
            guard let entry = entries.entriesToPublish[key] else {
                preconditionFailure(
                    "A recoverable staged entry must retain its bytes."
                )
            }
            try objectStore.publishStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        do {
            try validator.validatePublishedEntries(validated.envelope)
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        }
        if !manifest.published {
            try objectStore.publishStagedManifest(
                manifest.data,
                digest: intent.candidateManifestDigest,
                operationID: intent.operationID
            )
        }
        do {
            try validator.validatePublishedManifest(validated)
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        }
        try checkpointStore.replaceCheckpoint(
            candidateCheckpoint.canonicalBytes,
            expectedCheckpoint: intent.expectedCheckpoint.canonicalBytes,
            vaultID: intent.vaultID
        )
        try cleanup(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            stagedEntries: entries.stagedData,
            stagedManifest: manifest.stagedData
        )
        try? cache.store(manifest.data, for: candidateCheckpoint)
        return .completed(operationID: intent.operationID)
    }

    private func recoveryManifest(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        checkpointAlreadyAdvanced: Bool
    ) throws -> (data: Data, published: Bool, stagedData: Data?) {
        switch try objectStore.readManifest(
            digest: intent.candidateManifestDigest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case let .available(data):
            guard Data(SHA256.hash(data: data))
                    == intent.candidateManifestDigest
            else {
                throw invalidRecoveryState(intent)
            }
            return (
                data,
                true,
                try availableStagedManifest(intent)
            )
        case .invalid, .tooLarge:
            throw invalidRecoveryState(intent)
        case .unavailable:
            guard !checkpointAlreadyAdvanced else {
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            }
            guard let staged = try availableStagedManifest(intent) else {
                throw V3DeviceWrappedMissingStagedManifest()
            }
            return (staged, false, staged)
        }
    }

    private func recoveryEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        manifestAlreadyPublished: Bool
    ) throws -> V3DeviceWrappedRecoveryEntries? {
        var stagedData: [V3EntryObjectKey: Data] = [:]
        var available: [V3EncryptedEntry] = []
        var toPublish: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        for intended in intent.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: intended.entryID,
                digest: intended.digest
            )
            let staged = try availableStagedEntry(
                key,
                operationID: intent.operationID
            )
            if let staged {
                stagedData[key] = staged
            }
            let published: Data?
            switch try objectStore.readEntry(
                entryID: key.entryID,
                digest: key.digest,
                maximumBytes: limits.maximumEntryBytes
            ) {
            case let .available(data):
                guard Data(SHA256.hash(data: data)) == key.digest else {
                    throw invalidRecoveryState(intent)
                }
                published = data
            case .unavailable:
                published = nil
            case .invalid, .tooLarge:
                throw invalidRecoveryState(intent)
            }
            guard let data = published ?? staged else {
                return nil
            }
            guard let encrypted = try? validator.parseEncryptedEntry(data)
            else {
                throw invalidRecoveryState(intent)
            }
            if let staged, let published, staged != published {
                throw invalidRecoveryState(intent)
            }
            available.append(encrypted)
            if published == nil {
                guard staged != nil else {
                    return nil
                }
                toPublish[key] = encrypted
            }
        }
        if manifestAlreadyPublished, !toPublish.isEmpty {
            throw V3ImmutableTransactionRecoveryError
                .transactionDirectoryUnavailable
        }
        return V3DeviceWrappedRecoveryEntries(
            stagedData: stagedData,
            availableEntries: available,
            entriesToPublish: toPublish
        )
    }

    private func availableStagedEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent
    ) throws -> [V3EntryObjectKey: Data] {
        var result: [V3EntryObjectKey: Data] = [:]
        for entry in intent.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: entry.entryID,
                digest: entry.digest
            )
            if let data = try availableStagedEntry(
                key,
                operationID: intent.operationID
            ) {
                result[key] = data
            }
        }
        return result
    }

    private func availableStagedEntry(
        _ key: V3EntryObjectKey,
        operationID: VaultTransactionOperationID
    ) throws -> Data? {
        switch try objectStore.readStagedEntry(
            entryID: key.entryID,
            digest: key.digest,
            operationID: operationID,
            maximumBytes: limits.maximumEntryBytes
        ) {
        case let .available(data):
            guard Data(SHA256.hash(data: data)) == key.digest else {
                throw V3ImmutableTransactionRecoveryError
                    .invalidRecoveryState(operationID: operationID.rawValue)
            }
            return data
        case .unavailable:
            return nil
        case .invalid, .tooLarge:
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryState(
                operationID: operationID.rawValue
            )
        }
    }

    private func availableStagedManifest(
        _ intent: V3ImmutableTransactionRecoveryIntent
    ) throws -> Data? {
        switch try objectStore.readStagedManifest(
            digest: intent.candidateManifestDigest,
            operationID: intent.operationID,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case let .available(data):
            guard Data(SHA256.hash(data: data))
                    == intent.candidateManifestDigest
            else {
                throw invalidRecoveryState(intent)
            }
            return data
        case .unavailable:
            return nil
        case .invalid, .tooLarge:
            throw invalidRecoveryState(intent)
        }
    }

    private func cleanup(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        stagedEntries: [V3EntryObjectKey: Data],
        stagedManifest: Data?
    ) throws {
        for key in stagedEntries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let data = stagedEntries[key] else {
                preconditionFailure("Available staging must retain its bytes.")
            }
            try objectStore.removeStagedEntry(
                data,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        if let stagedManifest {
            try objectStore.removeStagedManifest(
                stagedManifest,
                digest: intent.candidateManifestDigest,
                operationID: intent.operationID
            )
        }
        try recoveryAnchorStore.replaceRecoveryAnchor(
            nil,
            expectedAnchor: anchorData,
            vaultID: intent.vaultID
        )
        try? objectStore.removeRecoveryIntent(
            intentData,
            operationID: intent.operationID
        )
        try? objectStore.removeEmptyTransactionDirectories(
            operationID: intent.operationID,
            entryIDs: intent.stagedEntries.map(\.entryID)
        )
    }

    private func recoveryError(
        for error: V3ImmutableTransactionError,
        intent: V3ImmutableTransactionRecoveryIntent
    ) -> Error {
        switch error {
        case .referencedEntryUnavailable, .publishedManifestUnavailable:
            V3ImmutableTransactionRecoveryError
                .transactionDirectoryUnavailable
        case .invalidAncestryProof, .unresolvedConflict,
            .candidateDoesNotMatchAutomaticMerge, .duplicateStagedEntry,
            .invalidStagedEntry, .objectTooLarge, .referencedEntryInvalid,
            .publishedManifestInvalid, .expectedHeadsChanged:
            invalidRecoveryState(intent)
        }
    }

    private func invalidRecoveryState(
        _ intent: V3ImmutableTransactionRecoveryIntent
    ) -> V3ImmutableTransactionRecoveryError {
        .invalidRecoveryState(operationID: intent.operationID.rawValue)
    }
}

/// Internal control flow for a recoverable intent whose candidate manifest was
/// never staged. No immutable manifest could have been published in this case.
private struct V3DeviceWrappedMissingStagedManifest: Error {}
