import CryptoKit
import Foundation

fileprivate struct V3ContentRecoveryEntries: Sendable {
    let stagedData: [V3EntryObjectKey: Data]
    let availableEntries: [V3EncryptedEntry]
    let entriesToPublish: [V3EntryObjectKey: V3EncryptedEntry]
}

/// Selected, bounded ciphertext only, not authenticated authority or approval.
/// Early outcomes use the same locally owned cleanup paths as ordinary recovery.
enum V3ContentTransactionRecoveryPreparation: Sendable {
    case finished(V3ImmutableTransactionRecoveryOutcome)
    case ready(V3ContentTransactionRecoveryState)
}

struct V3ContentTransactionRecoveryState: Sendable {
    let intent: V3ImmutableTransactionRecoveryIntent
    let anchorData: Data
    let currentCheckpoint: V3ManifestCheckpoint
    let candidateCheckpoint: V3ManifestCheckpoint
    fileprivate let intentData: Data
    fileprivate let manifest: (data: Data, published: Bool, stagedData: Data?)
    fileprivate let entries: V3ContentRecoveryEntries

    var manifestData: Data { manifest.data }
    var availableEntries: [V3EncryptedEntry] { entries.availableEntries }
    var alreadyCommitted: Bool { currentCheckpoint == candidateCheckpoint }
}

/// Reconstructs one locally anchored content publication with an explicit profile validator.
///
/// Synchronized transaction files never authorize recovery. The device-local
/// anchor selects one exact intent; the candidate HMAC, unchanged authority,
/// entry objects, current checkpoint, and vault key are revalidated before any
/// publication or checkpoint replacement resumes.
struct V3ContentTransactionRecoverer<Validator: V3ContentTransactionValidating>: Sendable {
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let validator: Validator

    init(
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits,
        validator: Validator
    ) {
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.cache = cache
        self.limits = limits
        self.validator = validator
    }

    func recover(
        vaultID: String,
        vaultKey: Data,
        expectedAnchor: Data? = nil
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        switch try prepare(vaultID: vaultID, expectedAnchor: expectedAnchor) {
        case .finished(let outcome): return outcome
        case .ready(let state): return try recover(state, vaultKey: vaultKey)
        }
    }

    /// No private operation or checkpoint advance. Incomplete locally owned work
    /// is abandoned using the established kernel cleanup, never provider scanning.
    func prepare(
        vaultID: String,
        expectedAnchor: Data? = nil
    ) throws -> V3ContentTransactionRecoveryPreparation {
        guard isValidV3UUID(vaultID) else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }
        try validator.requireAvailable(vaultID: vaultID)
        guard
            let anchorData = try recoveryAnchorStore.loadRecoveryAnchor(
                vaultID: vaultID
            )
        else {
            guard expectedAnchor == nil else {
                throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID)
            }
            return .finished(.nothingToRecover)
        }
        // A workflow that routed by one locally pinned intent must not resume
        // a different reservation after that routing decision, even before the
        // prepared/no-intent cleanup path. Existing direct callers remain valid.
        guard expectedAnchor == nil || expectedAnchor == anchorData else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: vaultID)
        }
        guard
            anchorData.count <= 1_024,
            let anchor = try? V3ImmutableTransactionRecoveryAnchor(
                canonicalBytes: anchorData
            ), anchor.vaultID == vaultID
        else {
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
            try validator.requireAvailable(vaultID: vaultID)
            try recoveryAnchorStore.replaceRecoveryAnchor(
                nil,
                expectedAnchor: anchorData,
                vaultID: vaultID
            )
            return .finished(.abandoned(operationID: anchor.operationID))
        }
        guard case .available(let intentData) = intentRead,
            intentData.count <= V3ImmutableTransactionRecoveryIntent.maximumBytes,
            Data(SHA256.hash(data: intentData)) == anchor.intentDigest,
            let intent = try? V3ImmutableTransactionRecoveryIntent(
                canonicalBytes: intentData
            ),
            intent.operationID == anchor.operationID,
            intent.vaultID == vaultID
        else {
            throw V3ImmutableTransactionRecoveryError.invalidIntent(
                operationID: anchor.operationID.rawValue
            )
        }
        try validator.validateRecoveryIntent(intent)
        return try prepare(intent, intentData: intentData, anchorData: anchorData)
    }

    private func prepare(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data
    ) throws -> V3ContentTransactionRecoveryPreparation {
        guard
            let checkpointData = try checkpointStore.loadCheckpoint(
                vaultID: intent.vaultID
            ),
            checkpointData.count <= 1_024,
            let currentCheckpoint = try? V3ManifestCheckpoint(
                canonicalBytes: checkpointData
            ), currentCheckpoint.vaultID == intent.vaultID
        else {
            throw V3ImmutableTransactionRecoveryError.checkpointUnavailable(
                vaultID: intent.vaultID
            )
        }
        let candidateCheckpoint = try V3ManifestCheckpoint(
            vaultID: intent.vaultID,
            envelopeDigest: intent.candidateManifestDigest
        )
        guard
            currentCheckpoint == intent.expectedCheckpoint
                || currentCheckpoint == candidateCheckpoint
        else {
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedEntries(intent),
                stagedManifest: try availableStagedManifest(intent)
            )
            return .finished(.abandoned(operationID: intent.operationID))
        }

        let manifest: (data: Data, published: Bool, stagedData: Data?)
        do {
            manifest = try recoveryManifest(
                intent,
                checkpointAlreadyAdvanced: currentCheckpoint
                    == candidateCheckpoint
            )
        } catch is V3ContentMissingStagedManifest {
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedEntries(intent),
                stagedManifest: nil
            )
            return .finished(.abandoned(operationID: intent.operationID))
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
            return .finished(.abandoned(operationID: intent.operationID))
        }

        try validator.requireAvailable(vaultID: intent.vaultID)
        try requireState(checkpoint: currentCheckpoint, anchorData: anchorData)
        return .ready(.init(
            intent: intent, anchorData: anchorData, currentCheckpoint: currentCheckpoint,
            candidateCheckpoint: candidateCheckpoint, intentData: intentData,
            manifest: manifest, entries: entries
        ))
    }

    private func recover(
        _ state: V3ContentTransactionRecoveryState, vaultKey: Data
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        let intent = state.intent
        let intentData = state.intentData
        let anchorData = state.anchorData
        let currentCheckpoint = state.currentCheckpoint
        let candidateCheckpoint = state.candidateCheckpoint
        let manifest = state.manifest
        let entries = state.entries
        let candidateKeyID: V3VaultKeyID
        do {
            candidateKeyID = try validator.keyID(manifestData: manifest.data)
        } catch {
            throw invalidRecoveryState(intent)
        }
        guard
            (try? V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: intent.vaultID
            )) == candidateKeyID
        else {
            throw V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
                keyID: candidateKeyID.rawValue
            )
        }

        let input = try validator.recoveryInput(
            intent: intent, manifestData: manifest.data, stagedEntries: entries.availableEntries)
        let validated: Validator.Validated
        do {
            validated = try validator.validate(
                input, vaultKey: vaultKey,
                alreadyCommitted: currentCheckpoint == candidateCheckpoint)
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        } catch {
            throw invalidRecoveryState(intent)
        }

        if currentCheckpoint == candidateCheckpoint {
            try requireState(checkpoint: candidateCheckpoint, anchorData: anchorData)
            try validator.recheck(
                input, validated: validated, vaultKey: vaultKey, alreadyCommitted: true)
            do {
                try validator.validatePublishedEntries(validated)
                try validator.validatePublishedManifest(validated)
            } catch let error as V3ImmutableTransactionError {
                throw recoveryError(for: error, intent: intent)
            }
            try requireState(checkpoint: candidateCheckpoint, anchorData: anchorData)
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

        guard
            try checkpointStore.loadCheckpoint(vaultID: intent.vaultID)
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
            try requireState(checkpoint: intent.expectedCheckpoint, anchorData: anchorData)
            try validator.recheck(
                input, validated: validated, vaultKey: vaultKey, alreadyCommitted: false)
            try requireState(checkpoint: intent.expectedCheckpoint, anchorData: anchorData)
            try objectStore.publishStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        do {
            try validator.validatePublishedEntries(validated)
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        }
        if !manifest.published {
            try requireState(checkpoint: intent.expectedCheckpoint, anchorData: anchorData)
            try validator.recheck(
                input, validated: validated, vaultKey: vaultKey, alreadyCommitted: false)
            try requireState(checkpoint: intent.expectedCheckpoint, anchorData: anchorData)
            try validator.validatePublishedEntries(validated)
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
        try requireState(checkpoint: intent.expectedCheckpoint, anchorData: anchorData)
        try validator.recheck(
            input, validated: validated, vaultKey: vaultKey, alreadyCommitted: false)
        try requireState(checkpoint: intent.expectedCheckpoint, anchorData: anchorData)
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
        case .available(let data):
            guard
                data.count <= limits.maximumManifestBytes,
                Data(SHA256.hash(data: data))
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
                throw V3ContentMissingStagedManifest()
            }
            return (staged, false, staged)
        }
    }

    private func recoveryEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        manifestAlreadyPublished: Bool
    ) throws -> V3ContentRecoveryEntries? {
        guard intent.stagedEntries.count <= limits.maximumReferencedEntryObjects else {
            throw invalidRecoveryState(intent)
        }
        var total = 0
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
            case .available(let data):
                guard data.count <= limits.maximumEntryBytes,
                      Data(SHA256.hash(data: data)) == key.digest else {
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
            guard data.count <= limits.maximumEntryBytes,
                  data.count <= limits.maximumTotalEntryBytes - total
            else { throw invalidRecoveryState(intent) }
            total += data.count
            guard let encrypted = try? V3EntryCipher().parse(data)
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
        return V3ContentRecoveryEntries(
            stagedData: stagedData,
            availableEntries: available,
            entriesToPublish: toPublish
        )
    }

    private func availableStagedEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent
    ) throws -> [V3EntryObjectKey: Data] {
        guard intent.stagedEntries.count <= limits.maximumReferencedEntryObjects else {
            throw invalidRecoveryState(intent)
        }
        var total = 0
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
                guard data.count <= limits.maximumTotalEntryBytes - total else {
                    throw invalidRecoveryState(intent)
                }
                total += data.count
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
        case .available(let data):
            guard data.count <= limits.maximumEntryBytes,
                  Data(SHA256.hash(data: data)) == key.digest else {
                throw
                    V3ImmutableTransactionRecoveryError
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
        case .available(let data):
            guard
                data.count <= limits.maximumManifestBytes,
                Data(SHA256.hash(data: data))
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
        try validator.requireAvailable(vaultID: intent.vaultID)
        guard try recoveryAnchorStore.loadRecoveryAnchor(vaultID: intent.vaultID) == anchorData
        else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(vaultID: intent.vaultID)
        }
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
        try validator.requireAvailable(vaultID: intent.vaultID)
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

    private func requireState(checkpoint: V3ManifestCheckpoint, anchorData: Data) throws {
        guard
            try checkpointStore.loadCheckpoint(vaultID: checkpoint.vaultID)
                == checkpoint.canonicalBytes,
            try recoveryAnchorStore.loadRecoveryAnchor(vaultID: checkpoint.vaultID) == anchorData
        else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
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
private struct V3ContentMissingStagedManifest: Error {}
