import CryptoKit
import Foundation

struct V3DeviceWrappedEnrollmentRecoveryResult: Equatable, Sendable {
    let outcome: V3ImmutableTransactionRecoveryOutcome
    let trustedCheckpoint: V3DeviceWrappedTrustedCheckpoint?
    let vaultKey: Data?
}

/// Reconstructs one locally anchored key-rotating enrollment publication.
///
/// The exact device-local anchor authorizes only the immutable candidate that
/// passed the fresh ceremony gate before publication began. Recovery reopens
/// the old and new owner wrappers, authenticates both key epochs, and proves a
/// complete plaintext-preserving reseal before resuming any shared write.
struct V3DeviceWrappedEnrollmentTransitionRecoverer: Sendable {
    private struct RecoveryEntries {
        let stagedData: [V3EntryObjectKey: Data]
        let available: [V3EncryptedEntry]
        let toPublish: [V3EntryObjectKey: V3EncryptedEntry]
    }

    private let objectStore: any V3TransactionArtifactStore
    private let repositoryObserver: any V3DeviceWrappedRepositoryObserving
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let validator: V3DeviceWrappedEnrollmentTransitionValidator
    private let usageValidator: V3DeviceWrappedRepositoryUsageValidator
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()

    init(
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits
    ) {
        self.repositoryObserver = repositoryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.cache = cache
        self.limits = limits
        validator = V3DeviceWrappedEnrollmentTransitionValidator(
            limits: limits
        )
        usageValidator = V3DeviceWrappedRepositoryUsageValidator(
            limits: limits
        )
    }

    func recover(
        vaultID: String,
        expectedTranscriptDigest: Data,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String,
        afterCheckpointAdvance:
            V3DeviceWrappedEnrollmentCommitHandler = { _, _ in }
    ) throws -> V3DeviceWrappedEnrollmentRecoveryResult {
        guard isValidV3UUID(vaultID),
              expectedTranscriptDigest.count == 32,
              localIdentity.vaultID == vaultID,
              !unwrapReason.isEmpty
        else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }
        guard let anchorData = try recoveryAnchorStore.loadRecoveryAnchor(
            vaultID: vaultID
        ) else {
            return recoveryResult(.nothingToRecover)
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
            return recoveryResult(
                .abandoned(operationID: anchor.operationID)
            )
        }
        guard case let .available(intentData) = intentRead,
              Data(SHA256.hash(data: intentData)) == anchor.intentDigest,
              let intent = try? V3ImmutableTransactionRecoveryIntent(
                  canonicalBytes: intentData
              ),
              intent.operationID == anchor.operationID,
              intent.kind == .enrollDevice,
              intent.vaultID == vaultID,
              intent.enrollmentTranscriptDigest
                == expectedTranscriptDigest,
              intent.expectedHeads
                == [intent.expectedCheckpoint.envelopeDigest],
              intent.stagedEntries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3ImmutableTransactionRecoveryError.invalidIntent(
                operationID: anchor.operationID.rawValue
            )
        }
        return try recover(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            localIdentity: localIdentity,
            unwrapReason: unwrapReason,
            afterCheckpointAdvance: afterCheckpointAdvance
        )
    }

    private func recover(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String,
        afterCheckpointAdvance:
            V3DeviceWrappedEnrollmentCommitHandler
    ) throws -> V3DeviceWrappedEnrollmentRecoveryResult {
        let currentCheckpoint = try loadCheckpoint(vaultID: intent.vaultID)
        let candidateCheckpoint = try V3ManifestCheckpoint(
            vaultID: intent.vaultID,
            envelopeDigest: intent.candidateManifestDigest
        )
        guard currentCheckpoint == intent.expectedCheckpoint
                || currentCheckpoint == candidateCheckpoint
        else {
            try cleanupAvailableArtifacts(
                intent,
                intentData: intentData,
                anchorData: anchorData
            )
            return recoveryResult(
                .abandoned(operationID: intent.operationID)
            )
        }

        guard let manifest = try recoveryManifest(
            intent,
            checkpointAlreadyAdvanced: currentCheckpoint
                == candidateCheckpoint
        ) else {
            try cleanupAvailableArtifacts(
                intent,
                intentData: intentData,
                anchorData: anchorData
            )
            return recoveryResult(
                .abandoned(operationID: intent.operationID)
            )
        }
        let parent = try loadParent(
            intent.expectedCheckpoint,
            operationID: intent.operationID
        )
        let entries = try recoveryEntries(
            intent,
            manifestAlreadyPublished: manifest.published
        )
        guard let entries else {
            if manifest.published {
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            }
            try cleanupAvailableArtifacts(
                intent,
                intentData: intentData,
                anchorData: anchorData
            )
            return recoveryResult(
                .abandoned(operationID: intent.operationID)
            )
        }
        let candidateEnvelope: V3DeviceWrappedManifestEnvelope
        do {
            candidateEnvelope = try envelopeCodec.parse(manifest.data)
        } catch {
            throw invalidRecoveryState(intent)
        }
        let currentVaultKey: Data
        let nextVaultKey: Data
        do {
            currentVaultKey = try openVaultKey(
                parent.envelope,
                identity: localIdentity,
                reason: unwrapReason
            )
            nextVaultKey = try openVaultKey(
                candidateEnvelope,
                identity: localIdentity,
                reason: unwrapReason
            )
        } catch V3DeviceWrappedEnrollmentValidationError
                    .authenticationCancelled {
            throw V3DeviceWrappedEnrollmentValidationError
                .authenticationCancelled
        } catch {
            throw invalidRecoveryState(intent)
        }
        let currentEntries = try loadCurrentEntries(
            parent.envelope,
            operationID: intent.operationID
        )
        let candidate = V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: intent.expectedCheckpoint,
            body: candidateEnvelope.body,
            manifestData: manifest.data,
            manifestDigest: intent.candidateManifestDigest,
            stagedEntries: entries.available,
            transcriptDigest: Data(repeating: 0, count: 32)
        )
        let validated: V3DeviceWrappedValidatedEnrollmentTransition
        do {
            validated = try validator.validateAnchored(
                candidate,
                parent: parent,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                expectedOwner: localIdentity.publicIdentity
            )
        } catch {
            throw invalidRecoveryState(intent)
        }

        do {
            let observation = try repositoryObserver.observeRepository(
                vaultID: intent.vaultID,
                vaultKeys: [currentVaultKey, nextVaultKey]
            )
            let observedState = try usageValidator.validatedState(
                observation,
                vaultID: intent.vaultID
            )
            guard observedState.checkpoint == currentCheckpoint else {
                throw V3ImmutableTransactionError.expectedHeadsChanged
            }
            try usageValidator.requireRecoveryPublicationState(
                observation,
                expectedParentDigest:
                    intent.expectedCheckpoint.envelopeDigest,
                candidateDigest: intent.candidateManifestDigest,
                candidateAlreadyPublished: manifest.published
            )
            try usageValidator.requireProjectedUsage(
                observation,
                candidateManifestDigest: intent.candidateManifestDigest,
                candidateManifestBytes: manifest.data.count,
                candidateEntries: validated.stagedEntries
            )
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        }

        if currentCheckpoint == candidateCheckpoint {
            do {
                try validatePublishedEntries(validated.stagedEntries)
                try validatePublishedManifest(
                    manifest.data,
                    digest: intent.candidateManifestDigest
                )
            } catch let error as V3ImmutableTransactionError {
                throw recoveryError(for: error, intent: intent)
            }
            let trusted = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: candidateCheckpoint,
                envelope: validated.candidate
            )
            try afterCheckpointAdvance(trusted, nextVaultKey)
            try cleanup(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: entries.stagedData,
                stagedManifest: manifest.stagedData
            )
            try? cache.store(manifest.data, for: candidateCheckpoint)
            return V3DeviceWrappedEnrollmentRecoveryResult(
                outcome: .alreadyCompleted(operationID: intent.operationID),
                trustedCheckpoint: trusted,
                vaultKey: nextVaultKey
            )
        }

        try requireExactCheckpoint(intent.expectedCheckpoint)
        for key in entries.toPublish.keys.sorted(
            by: entryObjectKeyPrecedes
        ) {
            guard let entry = entries.toPublish[key] else {
                preconditionFailure("Recoverable staging must retain bytes.")
            }
            try objectStore.publishStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        do {
            try validatePublishedEntries(validated.stagedEntries)
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
            try validatePublishedManifest(
                manifest.data,
                digest: intent.candidateManifestDigest
            )
        } catch let error as V3ImmutableTransactionError {
            throw recoveryError(for: error, intent: intent)
        }
        try checkpointStore.replaceCheckpoint(
            candidateCheckpoint.canonicalBytes,
            expectedCheckpoint: intent.expectedCheckpoint.canonicalBytes,
            vaultID: intent.vaultID
        )
        let trusted = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: candidateCheckpoint,
            envelope: validated.candidate
        )
        try afterCheckpointAdvance(trusted, nextVaultKey)
        try cleanup(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            stagedEntries: entries.stagedData,
            stagedManifest: manifest.stagedData
        )
        try? cache.store(manifest.data, for: candidateCheckpoint)
        return V3DeviceWrappedEnrollmentRecoveryResult(
            outcome: .completed(operationID: intent.operationID),
            trustedCheckpoint: trusted,
            vaultKey: nextVaultKey
        )
    }

    private func loadCheckpoint(
        vaultID: String
    ) throws -> V3ManifestCheckpoint {
        guard let data = try checkpointStore.loadCheckpoint(
            vaultID: vaultID
        ), let checkpoint = try? V3ManifestCheckpoint(
            canonicalBytes: data
        ), checkpoint.vaultID == vaultID else {
            throw V3ImmutableTransactionRecoveryError.checkpointUnavailable(
                vaultID: vaultID
            )
        }
        return checkpoint
    }

    private func requireExactCheckpoint(
        _ expected: V3ManifestCheckpoint
    ) throws {
        guard try checkpointStore.loadCheckpoint(vaultID: expected.vaultID)
                == expected.canonicalBytes
        else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
    }

    private func loadParent(
        _ checkpoint: V3ManifestCheckpoint,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        let data: Data
        if case let .available(cached) = try? cache.load(for: checkpoint) {
            data = cached
        } else {
            switch try objectStore.readManifest(
                digest: checkpoint.envelopeDigest,
                maximumBytes: limits.maximumManifestBytes
            ) {
            case let .available(available):
                data = available
            case .unavailable:
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            case .invalid, .tooLarge:
                throw V3ImmutableTransactionRecoveryError
                    .invalidRecoveryState(
                        operationID: operationID.rawValue
                    )
            }
        }
        guard Data(SHA256.hash(data: data)) == checkpoint.envelopeDigest,
              let envelope = try? envelopeCodec.parse(data),
              envelope.body.vaultID == checkpoint.vaultID
        else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryState(
                operationID: operationID.rawValue
            )
        }
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: envelope
        )
    }

    private func loadCurrentEntries(
        _ parent: V3DeviceWrappedManifestEnvelope,
        operationID: VaultTransactionOperationID
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        guard parent.body.entries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw invalidRecoveryState(operationID)
        }
        var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var totalBytes = 0
        for entry in parent.body.entries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32 else {
                throw invalidRecoveryState(operationID)
            }
            let data: Data
            switch try objectStore.readEntry(
                entryID: entry.entryID,
                digest: digest,
                maximumBytes: limits.maximumEntryBytes
            ) {
            case let .available(available):
                data = available
            case .unavailable:
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            case .invalid, .tooLarge:
                throw invalidRecoveryState(operationID)
            }
            guard Data(SHA256.hash(data: data)) == digest,
                  data.count <= limits.maximumTotalEntryBytes - totalBytes,
                  let encrypted = try? entryCipher.parse(data)
            else {
                throw invalidRecoveryState(operationID)
            }
            totalBytes += data.count
            let key = V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            )
            guard result.updateValue(encrypted, forKey: key) == nil else {
                throw invalidRecoveryState(operationID)
            }
        }
        return result
    }

    private func openVaultKey(
        _ envelope: V3DeviceWrappedManifestEnvelope,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        reason: String
    ) throws -> Data {
        let deviceID = identity.publicIdentity.deviceID
        guard identity.vaultID == envelope.body.vaultID,
              let device = envelope.body.devices.first(where: {
                  $0.identity.deviceID == deviceID
              }),
              device.identity == identity.publicIdentity,
              device.role == .owner,
              device.status == .active,
              let wrapped = envelope.body.wrappedKeys.first(where: {
                  $0.recipientDeviceID == deviceID
              }),
              let context = try? V3VaultKeyHPKEContext(
                  vaultID: envelope.body.vaultID,
                  keyID: envelope.body.keyID,
                  authorityTransitionID:
                    envelope.body.authorityTransitionID,
                  recipientDeviceID: deviceID
              )
        else {
            throw V3DeviceWrappedEnrollmentValidationError
                .localWrapperInvalid
        }
        let key: Data
        do {
            key = try identity.unwrapDeviceWrappedVaultKey(
                wrapped.wrappedKey,
                context: context,
                reason: reason
            )
        } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
            throw V3DeviceWrappedEnrollmentValidationError
                .authenticationCancelled
        } catch {
            throw V3DeviceWrappedEnrollmentValidationError
                .localWrapperInvalid
        }
        guard key.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: key,
                  vaultID: envelope.body.vaultID
              )) == envelope.body.keyID
        else {
            throw V3DeviceWrappedEnrollmentValidationError
                .localWrapperInvalid
        }
        return key
    }

    private func recoveryManifest(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        checkpointAlreadyAdvanced: Bool
    ) throws -> (data: Data, published: Bool, stagedData: Data?)? {
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
                return nil
            }
            return (staged, false, staged)
        }
    }

    private func recoveryEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        manifestAlreadyPublished: Bool
    ) throws -> RecoveryEntries? {
        var stagedData: [V3EntryObjectKey: Data] = [:]
        var available: [V3EncryptedEntry] = []
        var toPublish: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var totalBytes = 0
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
            guard data.count
                    <= limits.maximumTotalEntryBytes - totalBytes,
                  let encrypted = try? entryCipher.parse(data)
            else {
                throw invalidRecoveryState(intent)
            }
            totalBytes += data.count
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
        return RecoveryEntries(
            stagedData: stagedData,
            available: available,
            toPublish: toPublish
        )
    }

    private func validatePublishedEntries(
        _ entries: [V3EntryObjectKey: V3EncryptedEntry]
    ) throws {
        var totalBytes = 0
        for key in entries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let entry = entries[key] else {
                preconditionFailure("Validated entries must retain bytes.")
            }
            switch try objectStore.readEntry(
                entryID: key.entryID,
                digest: key.digest,
                maximumBytes: limits.maximumEntryBytes
            ) {
            case let .available(data):
                guard data == entry.canonicalBytes,
                      data.count
                        <= limits.maximumTotalEntryBytes - totalBytes
                else {
                    throw V3ImmutableTransactionError
                        .referencedEntryInvalid(
                            entryID: key.entryID,
                            digest: Base64URL.encode(key.digest)
                        )
                }
                totalBytes += data.count
            case .unavailable:
                throw V3ImmutableTransactionError
                    .referencedEntryUnavailable(
                        entryID: key.entryID,
                        digest: Base64URL.encode(key.digest)
                    )
            case .invalid, .tooLarge:
                throw V3ImmutableTransactionError.referencedEntryInvalid(
                    entryID: key.entryID,
                    digest: Base64URL.encode(key.digest)
                )
            }
        }
    }

    private func validatePublishedManifest(
        _ expected: Data,
        digest: Data
    ) throws {
        switch try objectStore.readManifest(
            digest: digest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case let .available(data) where data == expected:
            return
        case .unavailable:
            throw V3ImmutableTransactionError.publishedManifestUnavailable(
                digest: Base64URL.encode(digest)
            )
        case .available, .invalid, .tooLarge:
            throw V3ImmutableTransactionError.publishedManifestInvalid(
                digest: Base64URL.encode(digest)
            )
        }
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
                throw invalidRecoveryState(operationID)
            }
            return data
        case .unavailable:
            return nil
        case .invalid, .tooLarge:
            throw invalidRecoveryState(operationID)
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

    private func cleanupAvailableArtifacts(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data
    ) throws {
        var staged: [V3EntryObjectKey: Data] = [:]
        for intended in intent.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: intended.entryID,
                digest: intended.digest
            )
            if let data = try availableStagedEntry(
                key,
                operationID: intent.operationID
            ) {
                staged[key] = data
            }
        }
        try cleanup(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            stagedEntries: staged,
            stagedManifest: try availableStagedManifest(intent)
        )
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
                preconditionFailure("Available staging must retain bytes.")
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

    private func recoveryResult(
        _ outcome: V3ImmutableTransactionRecoveryOutcome
    ) -> V3DeviceWrappedEnrollmentRecoveryResult {
        V3DeviceWrappedEnrollmentRecoveryResult(
            outcome: outcome,
            trustedCheckpoint: nil,
            vaultKey: nil
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
        invalidRecoveryState(intent.operationID)
    }

    private func invalidRecoveryState(
        _ operationID: VaultTransactionOperationID
    ) -> V3ImmutableTransactionRecoveryError {
        .invalidRecoveryState(operationID: operationID.rawValue)
    }
}
