import CryptoKit
import Foundation

typealias V3DeviceWrappedKeyRotationCommitHandler = @Sendable (
    _ checkpoint: V3DeviceWrappedTrustedCheckpoint,
    _ vaultKey: Data
) throws -> Void

struct V3DeviceWrappedNoopKeyRotationPublicationObserver:
    V3ImmutableTransactionPhaseObserving
{
    func didReach(
        _: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

/// Publishes an already-authorized device-roster key rotation.
///
/// Enrollment and revocation keep their own authorization and membership
/// validators. This type owns only their identical durable transaction: bind
/// an exact candidate to a local recovery anchor, stage and revalidate every
/// object, publish immutable bytes, then advance the checkpoint last.
struct V3DeviceWrappedKeyRotationTransitionPublisher: Sendable {
    private let repositoryObserver: any V3DeviceWrappedRepositoryObserving
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let phaseObserver: any V3ImmutableTransactionPhaseObserving
    private let usageValidator: V3DeviceWrappedRepositoryUsageValidator

    init(
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3ImmutableTransactionPhaseObserving =
            V3DeviceWrappedNoopKeyRotationPublicationObserver()
    ) {
        self.repositoryObserver = repositoryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.cache = cache
        self.limits = limits
        self.phaseObserver = phaseObserver
        usageValidator = V3DeviceWrappedRepositoryUsageValidator(
            limits: limits
        )
    }

    func publish(
        kind: VaultTransactionMutationKind,
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestData: Data,
        manifestDigest: Data,
        currentVaultKey: Data,
        nextVaultKey: Data,
        enrollmentTranscriptDigest: Data?,
        operationID: VaultTransactionOperationID,
        validate: () throws -> V3DeviceWrappedValidatedKeyRotation,
        revalidate: () throws -> V3DeviceWrappedValidatedKeyRotation,
        afterCheckpointAdvance:
            V3DeviceWrappedKeyRotationCommitHandler = { _, _ in }
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard kind == .enrollDevice || kind == .revokeDevice,
              (kind == .enrollDevice)
                == (enrollmentTranscriptDigest != nil)
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        let vaultID = expectedCheckpoint.vaultID
        try requireNoInterruptedTransaction(vaultID: vaultID)
        try requireExactCheckpoint(expectedCheckpoint)

        let validated = try validate()
        try requireExactValidatedCandidate(
            validated,
            expectedCheckpoint: expectedCheckpoint,
            manifestData: manifestData,
            manifestDigest: manifestDigest
        )
        let initialObservation = try repositoryObserver.observeRepository(
            vaultID: vaultID,
            vaultKeys: [currentVaultKey, nextVaultKey]
        )
        let expectedState = try usageValidator.validatedState(
            initialObservation,
            vaultID: vaultID
        )
        guard expectedState.checkpoint == expectedCheckpoint,
              expectedState.heads == [expectedCheckpoint.envelopeDigest]
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        try usageValidator.requireProjectedUsage(
            initialObservation,
            candidateManifestDigest: manifestDigest,
            candidateManifestBytes: manifestData.count,
            candidateEntries: validated.stagedEntries
        )
        let orderedKeys = validated.stagedEntries.keys.sorted(
            by: entryObjectKeyPrecedes
        )
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: kind,
            vaultID: vaultID,
            expectedCheckpoint: expectedCheckpoint,
            expectedHeads: [expectedCheckpoint.envelopeDigest],
            candidateManifestDigest: manifestDigest,
            stagedEntries: orderedKeys.map {
                V3ImmutableTransactionRecoveryEntry(
                    entryID: $0.entryID,
                    digest: $0.digest
                )
            },
            enrollmentTranscriptDigest: enrollmentTranscriptDigest
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
            manifestData,
            digest: manifestDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestStaged,
            operationID: operationID
        )

        do {
            try requireExactCheckpoint(expectedCheckpoint)
            let revalidated = try revalidate()
            guard revalidated == validated else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
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
                candidateManifestDigest: manifestDigest,
                candidateManifestBytes: manifestData.count,
                candidateEntries: validated.stagedEntries
            )
        } catch {
            try? cleanup(
                intent,
                intentData: intentData,
                anchorData: recoverableAnchorData,
                stagedEntries: stagedData(validated.stagedEntries),
                stagedManifest: manifestData
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
            manifestData,
            digest: manifestDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestPublished,
            operationID: operationID
        )
        try validatePublishedManifest(
            manifestData,
            digest: manifestDigest
        )
        try phaseObserver.didReach(
            .publishedManifestValidated,
            operationID: operationID
        )

        let checkpoint = try V3ManifestCheckpoint(
            vaultID: vaultID,
            envelopeDigest: manifestDigest
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: expectedCheckpoint.canonicalBytes,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .checkpointAdvanced,
            operationID: operationID
        )

        let trusted = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: validated.candidate
        )
        try afterCheckpointAdvance(trusted, nextVaultKey)

        if (try? cleanup(
            intent,
            intentData: intentData,
            anchorData: recoverableAnchorData,
            stagedEntries: stagedData(validated.stagedEntries),
            stagedManifest: manifestData
        )) != nil {
            try? cache.store(manifestData, for: checkpoint)
            try phaseObserver.didReach(
                .cleanupCompleted,
                operationID: operationID
            )
        }
        return trusted
    }

    private func requireExactValidatedCandidate(
        _ validated: V3DeviceWrappedValidatedKeyRotation,
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestData: Data,
        manifestDigest: Data
    ) throws {
        guard validated.manifestDigest == manifestDigest,
              validated.candidate.canonicalBytes == manifestData,
              validated.parent.body.vaultID == expectedCheckpoint.vaultID,
              Data(SHA256.hash(data: validated.parent.canonicalBytes))
                == expectedCheckpoint.envelopeDigest
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
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
