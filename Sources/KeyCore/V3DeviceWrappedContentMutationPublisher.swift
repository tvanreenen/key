import CryptoKit
import Foundation

private struct V3DeviceWrappedNoopTransactionPhaseObserver:
    V3ImmutableTransactionPhaseObserving
{
    func didReach(
        _: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

/// Durably publishes one already-planned permanent-profile content mutation.
///
/// The helper mutation owner supplies serialization and the operation ID. The
/// publisher writes an anchored recovery intent before staging anything,
/// publishes entries before the manifest, and advances only the exact expected
/// device-local checkpoint after every immutable object reopens exactly.
/// Directory-wide history bounds and branch reconciliation remain the
/// responsibility of the higher-level multi-device mutation service.
struct V3DeviceWrappedContentMutationPublisher: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let validator: V3DeviceWrappedTransactionValidator
    private let recoverer: V3DeviceWrappedInterruptedTransactionRecoverer
    private let limits: V3ManifestRepositoryLimits
    private let phaseObserver: any V3ImmutableTransactionPhaseObserving

    init(
        mutationOwner: any VaultTransactionMutationOwning,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3ImmutableTransactionPhaseObserving =
            V3DeviceWrappedNoopTransactionPhaseObserver()
    ) {
        self.mutationOwner = mutationOwner
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
        recoverer = V3DeviceWrappedInterruptedTransactionRecoverer(
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            cache: cache,
            limits: limits
        )
        self.phaseObserver = phaseObserver
    }

    func publish(
        _ candidate: V3DeviceWrappedContentMutationCandidate,
        vaultKey: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        try mutationOwner.perform(candidate.kind) { context in
            try publish(
                candidate,
                vaultKey: vaultKey,
                operationID: context.operationID
            )
        }
    }

    func recoverInterruptedTransaction(
        vaultID: String,
        vaultKey: Data
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        try mutationOwner.perform(.recoverInterruptedTransaction) { _ in
            try recoverer.recover(
                vaultID: vaultID,
                vaultKey: vaultKey
            )
        }
    }

    private func publish(
        _ candidate: V3DeviceWrappedContentMutationCandidate,
        vaultKey: Data,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        let vaultID = candidate.expectedCheckpoint.vaultID
        try requireNoInterruptedTransaction(vaultID: vaultID)
        try requireExactCheckpoint(candidate.expectedCheckpoint)

        let validated = try validator.validate(
            manifestData: candidate.manifestData,
            manifestDigest: candidate.manifestDigest,
            expectedCheckpoint: candidate.expectedCheckpoint,
            kind: candidate.kind,
            stagedEntries: candidate.stagedEntries,
            vaultKey: vaultKey
        )
        guard validated.envelope.body == candidate.body else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        let orderedKeys = validated.stagedEntries.keys.sorted(
            by: entryObjectKeyPrecedes
        )
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: candidate.kind,
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
        let armedAnchor = try V3ImmutableTransactionRecoveryAnchor(
            operationID: operationID,
            vaultID: vaultID,
            intentDigest: intentDigest,
            phase: .recoverable
        )
        let armedAnchorData = armedAnchor.canonicalBytes
        try recoveryAnchorStore.replaceRecoveryAnchor(
            armedAnchorData,
            expectedAnchor: preparedAnchorData,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .recoveryArmed,
            operationID: operationID
        )

        for (index, key) in orderedKeys.enumerated() {
            guard let entry = validated.stagedEntries[key] else {
                preconditionFailure("A staged entry must retain its bytes.")
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
            _ = try validator.validate(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                expectedCheckpoint: candidate.expectedCheckpoint,
                kind: candidate.kind,
                stagedEntries: candidate.stagedEntries,
                vaultKey: vaultKey
            )
            try validator.validateStagedObjects(
                validated,
                operationID: operationID
            )
        } catch {
            try? removeRecoveryArtifacts(
                intent: intent,
                intentData: intentData,
                anchorData: armedAnchorData,
                stagedEntries: validated.stagedEntries,
                manifestData: candidate.manifestData
            )
            throw error
        }
        try phaseObserver.didReach(
            .repositoryStateRechecked,
            operationID: operationID
        )

        for (index, key) in orderedKeys.enumerated() {
            guard let entry = validated.stagedEntries[key] else {
                preconditionFailure("A staged entry must retain its bytes.")
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
        try validator.validatePublishedEntries(validated.envelope)
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
        try validator.validatePublishedManifest(validated)
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

        if (try? removeRecoveryArtifacts(
            intent: intent,
            intentData: intentData,
            anchorData: armedAnchorData,
            stagedEntries: validated.stagedEntries,
            manifestData: candidate.manifestData
        )) != nil {
            try? cache.store(candidate.manifestData, for: checkpoint)
            try phaseObserver.didReach(
                .cleanupCompleted,
                operationID: operationID
            )
        }
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: validated.envelope
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

    private func removeRecoveryArtifacts(
        intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        stagedEntries: [V3EntryObjectKey: V3EncryptedEntry],
        manifestData: Data
    ) throws {
        for key in stagedEntries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let entry = stagedEntries[key] else {
                preconditionFailure("A staged entry must retain its bytes.")
            }
            try objectStore.removeStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        try objectStore.removeStagedManifest(
            manifestData,
            digest: intent.candidateManifestDigest,
            operationID: intent.operationID
        )
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
}
