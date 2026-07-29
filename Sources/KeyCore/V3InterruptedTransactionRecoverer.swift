import CryptoKit
import Foundation

private struct V3RecoveryEntryValidation {
    let availableStagedEntries: [V3EntryObjectKey: Data]
    let entriesToPublish: [V3EntryObjectKey: V3EncryptedEntry]
    let entrySizes: [V3EntryObjectKey: Int]
}

/// Reconstructs and resolves one device-local interrupted publication.
///
/// Shared transaction artifacts have no authority by themselves. Recovery
/// begins only from the exact device-local anchor, then re-authenticates every
/// candidate and entry before it can publish or advance a checkpoint.
struct V3InterruptedTransactionRecoverer: Sendable {
    private let ancestryObserver: any V3ManifestAncestryObserving
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let authenticator: V3ManifestAuthenticator
    private let reconciler: V3ManifestReconciler
    private let limits: V3ManifestRepositoryLimits
    private let validator: V3ImmutableTransactionValidator

    init(
        ancestryObserver: any V3ManifestAncestryObserving,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        authenticator: V3ManifestAuthenticator,
        reconciler: V3ManifestReconciler,
        validator: V3ImmutableTransactionValidator,
        limits: V3ManifestRepositoryLimits
    ) {
        self.ancestryObserver = ancestryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.authenticator = authenticator
        self.reconciler = reconciler
        self.validator = validator
        self.limits = limits
    }

    /// Recovers at most one locally anchored operation for `vaultID`.
    ///
    /// Multiple shared intents are deliberately not ordered or selected:
    /// synchronized operations can represent concurrent branches, and lexical
    /// operation-ID order is not authority.
    func recover(
        vaultID: String,
        availableVaultKeys: [Data]
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
        let intentResult = try objectStore.readRecoveryIntent(
            operationID: anchor.operationID,
            maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes
        )
        if case .unavailable = intentResult {
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
        guard case let .available(intentData) = intentResult,
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
        return try recover(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            availableVaultKeys: availableVaultKeys
        )
    }

    private func recover(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        availableVaultKeys: [Data]
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
        if currentCheckpoint == candidateCheckpoint {
            let candidateData = try requirePublishedRecoveryManifest(intent)
            let observation = try ancestryObserver.observeAncestry()
            let expectedProof = try recoveryProof(
                for: intent,
                from: observation.proof
            )
            let candidate = try verifyRecoveryCandidate(
                candidateData,
                intent: intent,
                proof: expectedProof,
                availableVaultKeys: availableVaultKeys
            )
            guard try validateRecoveryEntries(
                intent,
                candidate: candidate,
                availableVaultKeys: availableVaultKeys
            ) != nil else {
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            }
            try cleanupRecoveryArtifacts(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedRecoveryEntries(intent),
                stagedManifestData: try availableStagedRecoveryManifest(intent)
            )
            return .alreadyCompleted(operationID: intent.operationID)
        }

        guard currentCheckpoint == intent.expectedCheckpoint else {
            try cleanupRecoveryArtifacts(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedRecoveryEntries(intent),
                stagedManifestData: try availableStagedRecoveryManifest(intent)
            )
            return .abandoned(operationID: intent.operationID)
        }

        let observation = try ancestryObserver.observeAncestry()
        let expectedProof = try recoveryProof(
            for: intent,
            from: observation.proof
        )
        let expectedState = try validator.validatedState(for: expectedProof)

        let publishedManifestResult = try objectStore.readManifest(
            digest: intent.candidateManifestDigest,
            maximumBytes: limits.maximumManifestBytes
        )
        let candidateData: Data
        let manifestAlreadyPublished: Bool
        switch publishedManifestResult {
        case let .available(data):
            candidateData = data
            manifestAlreadyPublished = true
        case .unavailable:
            let observedState = try validator.validatedState(
                for: observation.proof
            )
            guard observedState == expectedState else {
                try cleanupRecoveryArtifacts(
                    intent,
                    intentData: intentData,
                    anchorData: anchorData,
                    stagedEntries:
                        try availableStagedRecoveryEntries(intent),
                    stagedManifestData:
                        try availableStagedRecoveryManifest(intent)
                )
                return .abandoned(operationID: intent.operationID)
            }
            guard let staged = try availableStagedRecoveryManifest(
                intent
            ) else {
                try cleanupRecoveryArtifacts(
                    intent,
                    intentData: intentData,
                    anchorData: anchorData,
                    stagedEntries:
                        try availableStagedRecoveryEntries(intent),
                    stagedManifestData: nil
                )
                return .abandoned(operationID: intent.operationID)
            }
            candidateData = staged
            manifestAlreadyPublished = false
        case .invalid, .tooLarge:
            throw invalidRecoveryState(for: intent)
        }

        guard Data(SHA256.hash(data: candidateData))
                == intent.candidateManifestDigest
        else {
            throw invalidRecoveryState(for: intent)
        }
        let candidate = try verifyRecoveryCandidate(
            candidateData,
            intent: intent,
            proof: expectedProof,
            availableVaultKeys: availableVaultKeys
        )
        let reconciliation = try reconciler.reconcile(expectedProof)
        try validator.requirePermittedCandidate(
            candidate,
            reconciliation: reconciliation
        )

        guard let recoveryEntries = try validateRecoveryEntries(
            intent,
            candidate: candidate,
            availableVaultKeys: availableVaultKeys
        ) else {
            if manifestAlreadyPublished {
                throw V3ImmutableTransactionRecoveryError
                    .transactionDirectoryUnavailable
            }
            try cleanupRecoveryArtifacts(
                intent,
                intentData: intentData,
                anchorData: anchorData,
                stagedEntries: try availableStagedRecoveryEntries(intent),
                stagedManifestData: try availableStagedRecoveryManifest(intent)
            )
            return .abandoned(operationID: intent.operationID)
        }
        if !manifestAlreadyPublished {
            try validator.requireProjectedRepositoryUsage(
                observation,
                candidate: candidate,
                candidateEntrySizes: recoveryEntries.entrySizes
            )
            for key in recoveryEntries.entriesToPublish.keys.sorted(
                by: entryObjectKeyPrecedes
            ) {
                guard let entry = recoveryEntries.entriesToPublish[key] else {
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
            for entry in candidate.envelope.content.manifest.entries {
                _ = try validator.validatePublishedEntry(
                    entry,
                    vaultID: intent.vaultID
                )
            }
            try objectStore.publishStagedManifest(
                candidateData,
                digest: intent.candidateManifestDigest,
                operationID: intent.operationID
            )
        }
        try validator.validatePublishedManifest(candidate)

        try checkpointStore.replaceCheckpoint(
            candidateCheckpoint.canonicalBytes,
            expectedCheckpoint: intent.expectedCheckpoint.canonicalBytes,
            vaultID: intent.vaultID
        )
        try cleanupRecoveryArtifacts(
            intent,
            intentData: intentData,
            anchorData: anchorData,
            stagedEntries: recoveryEntries.availableStagedEntries,
            stagedManifestData: manifestAlreadyPublished
                ? try availableStagedRecoveryManifest(intent)
                : candidateData
        )
        return .completed(operationID: intent.operationID)
    }

    private func recoveryProof(
        for intent: V3ImmutableTransactionRecoveryIntent,
        from observed: V3ManifestAncestryProof
    ) throws -> V3ManifestAncestryProof {
        var manifestsByDigest: [Data: V3VerifiedManifest] = [:]
        for manifest in observed.manifests {
            guard manifestsByDigest.updateValue(
                manifest,
                forKey: manifest.envelopeDigest
            ) == nil else {
                throw invalidRecoveryState(for: intent)
            }
        }
        let heads = try intent.expectedHeads.map { digest in
            guard let head = manifestsByDigest[digest],
                  head.envelope.content.manifest.vaultID == intent.vaultID
            else {
                throw invalidRecoveryState(for: intent)
            }
            return head
        }
        let proof = V3ManifestAncestryProof(
            checkpoint: intent.expectedCheckpoint,
            manifests: observed.manifests,
            heads: heads
        )
        _ = try validator.validatedState(for: proof)
        return proof
    }

    private func verifyRecoveryCandidate(
        _ data: Data,
        intent: V3ImmutableTransactionRecoveryIntent,
        proof: V3ManifestAncestryProof,
        availableVaultKeys: [Data]
    ) throws -> V3VerifiedManifest {
        let parsed: V3ManifestEnvelope
        do {
            parsed = try authenticator.parse(data)
        } catch {
            throw invalidRecoveryState(for: intent)
        }
        guard parsed.content.manifest.vaultID == intent.vaultID,
              Data(SHA256.hash(data: data))
                == intent.candidateManifestDigest
        else {
            throw invalidRecoveryState(for: intent)
        }
        let vaultKey = try recoveryVaultKey(
            for: parsed.content.manifest.keyID,
            vaultID: intent.vaultID,
            availableVaultKeys: availableVaultKeys
        )
        do {
            let candidate = try authenticator.verify(
                data,
                vaultKey: vaultKey,
                trustAnchor: .verifiedParents(proof.heads)
            )
            guard candidate.envelopeDigest
                    == intent.candidateManifestDigest
            else {
                throw invalidRecoveryState(for: intent)
            }
            return candidate
        } catch let error as V3ImmutableTransactionRecoveryError {
            throw error
        } catch {
            throw invalidRecoveryState(for: intent)
        }
    }

    private func recoveryVaultKey(
        for keyID: V3VaultKeyID,
        vaultID: String,
        availableVaultKeys: [Data]
    ) throws -> Data {
        for key in availableVaultKeys {
            if (try? V3VaultKeyID.derive(
                vaultKey: key,
                vaultID: vaultID
            )) == keyID {
                return key
            }
        }
        throw V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
            keyID: keyID.rawValue
        )
    }

    private func validateRecoveryEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        candidate: V3VerifiedManifest,
        availableVaultKeys: [Data]
    ) throws -> V3RecoveryEntryValidation? {
        let body = candidate.envelope.content.manifest
        let vaultKey = try recoveryVaultKey(
            for: body.keyID,
            vaultID: intent.vaultID,
            availableVaultKeys: availableVaultKeys
        )
        var candidateEntries: [V3EntryObjectKey: V3ManifestEntry] = [:]
        for entry in body.entries {
            let key = try entryObjectKey(entry)
            guard candidateEntries.updateValue(entry, forKey: key) == nil else {
                throw invalidRecoveryState(for: intent)
            }
        }

        var stagedObjects: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var availableStagedData: [V3EntryObjectKey: Data] = [:]
        var entriesToPublish: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var entrySizes: [V3EntryObjectKey: Int] = [:]
        let intendedKeys = Set(intent.stagedEntries.map {
            V3EntryObjectKey(entryID: $0.entryID, digest: $0.digest)
        })
        guard intendedKeys.count == intent.stagedEntries.count,
              intendedKeys.allSatisfy({ candidateEntries[$0] != nil })
        else {
            throw invalidRecoveryState(for: intent)
        }

        for recoveryEntry in intent.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: recoveryEntry.entryID,
                digest: recoveryEntry.digest
            )
            let stagedResult = try objectStore.readStagedEntry(
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID,
                maximumBytes: limits.maximumEntryBytes
            )
            switch stagedResult {
            case let .available(data):
                guard Data(SHA256.hash(data: data)) == key.digest,
                      let parsed = try? validator.parseEncryptedEntry(data)
                else {
                    throw invalidRecoveryState(for: intent)
                }
                stagedObjects[key] = parsed
                availableStagedData[key] = data
            case .unavailable:
                break
            case .invalid, .tooLarge:
                throw invalidRecoveryState(for: intent)
            }

            let publishedResult = try objectStore.readEntry(
                entryID: key.entryID,
                digest: key.digest,
                maximumBytes: limits.maximumEntryBytes
            )
            switch publishedResult {
            case .available:
                guard let manifestEntry = candidateEntries[key] else {
                    throw invalidRecoveryState(for: intent)
                }
                entrySizes[key] = try validator.validatePublishedEntry(
                    manifestEntry,
                    vaultID: intent.vaultID
                )
            case .unavailable:
                guard let staged = stagedObjects[key] else {
                    return nil
                }
                entriesToPublish[key] = staged
                entrySizes[key] = staged.canonicalBytes.count
            case .invalid, .tooLarge:
                throw invalidRecoveryState(for: intent)
            }
        }

        do {
            let validated = try validator.validateStagedEntries(
                Array(stagedObjects.values),
                candidate: candidate,
                vaultKey: vaultKey
            )
            guard validated.count == stagedObjects.count else {
                throw invalidRecoveryState(for: intent)
            }
        } catch let error as V3ImmutableTransactionRecoveryError {
            throw error
        } catch {
            throw invalidRecoveryState(for: intent)
        }

        for (key, manifestEntry) in candidateEntries
        where !intendedKeys.contains(key) {
            let result = try objectStore.readEntry(
                entryID: key.entryID,
                digest: key.digest,
                maximumBytes: limits.maximumEntryBytes
            )
            switch result {
            case .available:
                entrySizes[key] = try validator.validatePublishedEntry(
                    manifestEntry,
                    vaultID: intent.vaultID
                )
            case .unavailable:
                return nil
            case .invalid, .tooLarge:
                throw invalidRecoveryState(for: intent)
            }
        }

        guard entrySizes.count == candidateEntries.count else {
            throw invalidRecoveryState(for: intent)
        }
        return V3RecoveryEntryValidation(
            availableStagedEntries: availableStagedData,
            entriesToPublish: entriesToPublish,
            entrySizes: entrySizes
        )
    }

    private func availableStagedRecoveryEntries(
        _ intent: V3ImmutableTransactionRecoveryIntent
    ) throws -> [V3EntryObjectKey: Data] {
        var result: [V3EntryObjectKey: Data] = [:]
        for entry in intent.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: entry.entryID,
                digest: entry.digest
            )
            switch try objectStore.readStagedEntry(
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID,
                maximumBytes: limits.maximumEntryBytes
            ) {
            case let .available(data):
                guard Data(SHA256.hash(data: data)) == key.digest else {
                    throw invalidRecoveryState(for: intent)
                }
                result[key] = data
            case .unavailable:
                continue
            case .invalid, .tooLarge:
                throw invalidRecoveryState(for: intent)
            }
        }
        return result
    }

    private func availableStagedRecoveryManifest(
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
                throw invalidRecoveryState(for: intent)
            }
            return data
        case .unavailable:
            return nil
        case .invalid, .tooLarge:
            throw invalidRecoveryState(for: intent)
        }
    }

    private func requirePublishedRecoveryManifest(
        _ intent: V3ImmutableTransactionRecoveryIntent
    ) throws -> Data {
        switch try objectStore.readManifest(
            digest: intent.candidateManifestDigest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case let .available(data):
            guard Data(SHA256.hash(data: data))
                    == intent.candidateManifestDigest
            else {
                throw invalidRecoveryState(for: intent)
            }
            return data
        case .unavailable:
            throw V3ImmutableTransactionRecoveryError
                .transactionDirectoryUnavailable
        case .invalid, .tooLarge:
            throw invalidRecoveryState(for: intent)
        }
    }

    private func cleanupRecoveryArtifacts(
        _ intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        stagedEntries: [V3EntryObjectKey: Data],
        stagedManifestData: Data?
    ) throws {
        for key in stagedEntries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let data = stagedEntries[key] else {
                preconditionFailure(
                    "Available recovery staging must retain its bytes."
                )
            }
            try objectStore.removeStagedEntry(
                data,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        if let stagedManifestData {
            try objectStore.removeStagedManifest(
                stagedManifestData,
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

    private func invalidRecoveryState(
        for intent: V3ImmutableTransactionRecoveryIntent
    ) -> V3ImmutableTransactionRecoveryError {
        .invalidRecoveryState(operationID: intent.operationID.rawValue)
    }
}
