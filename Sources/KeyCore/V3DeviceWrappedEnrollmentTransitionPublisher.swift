import CryptoKit
import Foundation

private struct V3DeviceWrappedNoopEnrollmentPublicationObserver:
    V3ImmutableTransactionPhaseObserving
{
    func didReach(
        _: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

/// Durably publishes one validated key-rotating enrollment transition.
///
/// A device-local anchor is installed only after the fresh ceremony, owner
/// authorization, complete plaintext-preserving reseal, and local owner
/// wrapper have all been verified. Recovery may therefore finish that exact
/// immutable candidate after invitation expiry, but synchronized transaction
/// files alone can never authorize a roster or key-epoch change.
struct V3DeviceWrappedEnrollmentTransitionPublisher: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let repositoryObserver: any V3DeviceWrappedRepositoryObserving
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let phaseObserver: any V3ImmutableTransactionPhaseObserving
    private let validator: V3DeviceWrappedEnrollmentTransitionValidator
    private let usageValidator: V3DeviceWrappedRepositoryUsageValidator
    private let recoverer: V3DeviceWrappedEnrollmentTransitionRecoverer

    init(
        mutationOwner: any VaultTransactionMutationOwning,
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3ImmutableTransactionPhaseObserving =
            V3DeviceWrappedNoopEnrollmentPublicationObserver()
    ) {
        self.mutationOwner = mutationOwner
        self.repositoryObserver = repositoryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.cache = cache
        self.limits = limits
        self.phaseObserver = phaseObserver
        validator = V3DeviceWrappedEnrollmentTransitionValidator(
            limits: limits
        )
        usageValidator = V3DeviceWrappedRepositoryUsageValidator(
            limits: limits
        )
        recoverer = V3DeviceWrappedEnrollmentTransitionRecoverer(
            repositoryObserver: repositoryObserver,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            cache: cache,
            limits: limits
        )
    }

    func publish(
        _ candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        state: V3EnrollmentCeremonyState,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        at unixTime: UInt64,
        unwrapReason: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        try mutationOwner.perform(.enrollDevice) { context in
            try publish(
                candidate,
                parent: parent,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                state: state,
                localIdentity: localIdentity,
                at: unixTime,
                unwrapReason: unwrapReason,
                operationID: context.operationID
            )
        }
    }

    func recoverInterruptedTransaction(
        vaultID: String,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String
    ) throws -> V3DeviceWrappedEnrollmentRecoveryResult {
        try mutationOwner.perform(.recoverInterruptedTransaction) { _ in
            try recoverer.recover(
                vaultID: vaultID,
                localIdentity: localIdentity,
                unwrapReason: unwrapReason
            )
        }
    }

    private func publish(
        _ candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        state: V3EnrollmentCeremonyState,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        at unixTime: UInt64,
        unwrapReason: String,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        let vaultID = candidate.expectedCheckpoint.vaultID
        try requireNoInterruptedTransaction(vaultID: vaultID)
        try requireExactCheckpoint(candidate.expectedCheckpoint)

        let validated = try validator.validate(
            candidate,
            parent: parent,
            currentEntries: currentEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            state: state,
            localIdentity: localIdentity,
            at: unixTime,
            unwrapReason: unwrapReason
        )
        let initialObservation = try repositoryObserver.observeRepository(
            vaultID: vaultID,
            vaultKeys: [currentVaultKey, nextVaultKey]
        )
        let expectedState = try usageValidator.validatedState(
            initialObservation,
            vaultID: vaultID
        )
        guard expectedState.checkpoint == candidate.expectedCheckpoint,
              expectedState.heads
                == [candidate.expectedCheckpoint.envelopeDigest]
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        try usageValidator.requireProjectedUsage(
            initialObservation,
            candidateManifestDigest: candidate.manifestDigest,
            candidateManifestBytes: candidate.manifestData.count,
            candidateEntries: validated.stagedEntries
        )
        let orderedKeys = validated.stagedEntries.keys.sorted(
            by: entryObjectKeyPrecedes
        )
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: .enrollDevice,
            vaultID: vaultID,
            expectedCheckpoint: candidate.expectedCheckpoint,
            expectedHeads: [candidate.expectedCheckpoint.envelopeDigest],
            candidateManifestDigest: candidate.manifestDigest,
            stagedEntries: orderedKeys.map {
                V3ImmutableTransactionRecoveryEntry(
                    entryID: $0.entryID,
                    digest: $0.digest
                )
            }
        )
        let intentData = intent.canonicalBytes
        let intentDigest = Data(SHA256.hash(data: intentData))
        let preparedAnchor = try V3ImmutableTransactionRecoveryAnchor(
            operationID: operationID,
            vaultID: vaultID,
            intentDigest: intentDigest,
            phase: .prepared
        )
        let preparedAnchorData = preparedAnchor.canonicalBytes
        try recoveryAnchorStore.replaceRecoveryAnchor(
            preparedAnchorData,
            expectedAnchor: nil,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .recoveryAnchorPrepared,
            operationID: operationID
        )

        try objectStore.persistRecoveryIntent(
            intentData,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .recoveryIntentPersisted,
            operationID: operationID
        )
        let recoverableAnchor = try V3ImmutableTransactionRecoveryAnchor(
            operationID: operationID,
            vaultID: vaultID,
            intentDigest: intentDigest,
            phase: .recoverable
        )
        let recoverableAnchorData = recoverableAnchor.canonicalBytes
        try recoveryAnchorStore.replaceRecoveryAnchor(
            recoverableAnchorData,
            expectedAnchor: preparedAnchorData,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .recoveryArmed,
            operationID: operationID
        )

        for (index, key) in orderedKeys.enumerated() {
            guard let entry = validated.stagedEntries[key] else {
                preconditionFailure("Validated staging must retain bytes.")
            }
            try objectStore.stageEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID
            )
            try phaseObserver.didReach(
                .entryStaged(index: index),
                operationID: operationID
            )
        }
        try objectStore.stageManifest(
            candidate.manifestData,
            digest: candidate.manifestDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestStaged,
            operationID: operationID
        )

        do {
            try requireExactCheckpoint(candidate.expectedCheckpoint)
            _ = try validator.validateAnchored(
                candidate,
                parent: parent,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                expectedOwner: localIdentity.publicIdentity
            )
            try validateStagedObjects(
                validated.stagedEntries,
                operationID: operationID
            )
            let recheckedObservation = try repositoryObserver
                .observeRepository(
                    vaultID: vaultID,
                    vaultKeys: [currentVaultKey, nextVaultKey]
                )
            guard try usageValidator.validatedState(
                recheckedObservation,
                vaultID: vaultID
            ) == expectedState else {
                throw V3ImmutableTransactionError.expectedHeadsChanged
            }
            try usageValidator.requireProjectedUsage(
                recheckedObservation,
                candidateManifestDigest: candidate.manifestDigest,
                candidateManifestBytes: candidate.manifestData.count,
                candidateEntries: validated.stagedEntries
            )
        } catch {
            try? cleanup(
                intent,
                intentData: intentData,
                anchorData: recoverableAnchorData,
                stagedEntries: stagedData(validated.stagedEntries),
                stagedManifest: candidate.manifestData
            )
            throw error
        }
        try phaseObserver.didReach(
            .repositoryStateRechecked,
            operationID: operationID
        )

        for (index, key) in orderedKeys.enumerated() {
            guard let entry = validated.stagedEntries[key] else {
                preconditionFailure("Validated staging must retain bytes.")
            }
            try objectStore.publishStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID
            )
            try phaseObserver.didReach(
                .entryPublished(index: index),
                operationID: operationID
            )
        }
        try validatePublishedEntries(validated.stagedEntries)
        try phaseObserver.didReach(
            .publishedEntriesValidated,
            operationID: operationID
        )

        try objectStore.publishStagedManifest(
            candidate.manifestData,
            digest: candidate.manifestDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestPublished,
            operationID: operationID
        )
        try validatePublishedManifest(
            candidate.manifestData,
            digest: candidate.manifestDigest
        )
        try phaseObserver.didReach(
            .publishedManifestValidated,
            operationID: operationID
        )

        let checkpoint = try V3ManifestCheckpoint(
            vaultID: vaultID,
            envelopeDigest: candidate.manifestDigest
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: candidate.expectedCheckpoint.canonicalBytes,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .checkpointAdvanced,
            operationID: operationID
        )

        if (try? cleanup(
            intent,
            intentData: intentData,
            anchorData: recoverableAnchorData,
            stagedEntries: stagedData(validated.stagedEntries),
            stagedManifest: candidate.manifestData
        )) != nil {
            try? cache.store(candidate.manifestData, for: checkpoint)
            try phaseObserver.didReach(
                .cleanupCompleted,
                operationID: operationID
            )
        }
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: validated.candidate
        )
    }

    private func requireNoInterruptedTransaction(vaultID: String) throws {
        guard let data = try recoveryAnchorStore.loadRecoveryAnchor(
            vaultID: vaultID
        ) else {
            return
        }
        guard let anchor = try? V3ImmutableTransactionRecoveryAnchor(
            canonicalBytes: data
        ), anchor.vaultID == vaultID else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }
        throw V3ImmutableTransactionRecoveryError
            .interruptedTransactionPending(
                operationID: anchor.operationID.rawValue
            )
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

    private func validateStagedObjects(
        _ entries: [V3EntryObjectKey: V3EncryptedEntry],
        operationID: VaultTransactionOperationID
    ) throws {
        for key in entries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let entry = entries[key] else {
                preconditionFailure("Validated staging must retain bytes.")
            }
            guard case let .available(data) = try objectStore.readStagedEntry(
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID,
                maximumBytes: limits.maximumEntryBytes
            ), data == entry.canonicalBytes else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
        }
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

    private func stagedData(
        _ entries: [V3EntryObjectKey: V3EncryptedEntry]
    ) -> [V3EntryObjectKey: Data] {
        entries.mapValues(\.canonicalBytes)
    }
}
