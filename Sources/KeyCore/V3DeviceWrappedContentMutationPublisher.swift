import Foundation

protocol V3DeviceWrappedContentMutationPublishing: Sendable {
    func publish(_ candidate: V3DeviceWrappedContentMutationCandidate, vaultKey: Data) throws
        -> V3DeviceWrappedTrustedCheckpoint
    func recoverInterruptedTransaction(vaultID: String, vaultKey: Data) throws
        -> V3ImmutableTransactionRecoveryOutcome
}

/// Explicit permanent-profile facade; the durability kernel never selects a profile.
struct V3DeviceWrappedContentMutationPublisher: V3DeviceWrappedContentMutationPublishing {
    private let publisher: V3ContentTransactionPublisher<V3DeviceWrappedTransactionValidator>
    private let limits: V3ManifestRepositoryLimits
    init(
        mutationOwner: any VaultTransactionMutationOwning,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3ImmutableTransactionPhaseObserving =
            V3NoopContentTransactionPhaseObserver()
    ) {
        self.limits = limits
        publisher = V3ContentTransactionPublisher(
            mutationOwner: mutationOwner, objectStore: objectStore,
            checkpointStore: checkpointStore, recoveryAnchorStore: recoveryAnchorStore,
            cache: cache,
            validator: V3DeviceWrappedTransactionValidator(
                objectStore: objectStore, cache: cache, limits: limits),
            limits: limits, phaseObserver: phaseObserver)
    }
    func publish(_ candidate: V3DeviceWrappedContentMutationCandidate, vaultKey: Data) throws
        -> V3DeviceWrappedTrustedCheckpoint
    {
        guard candidate.manifestData.count <= limits.maximumManifestBytes,
            try V3DeviceWrappedManifestEnvelopeCodec().parse(candidate.manifestData).body
                == candidate.body
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        let validated = try publisher.publish(
            V3ContentTransactionInput(
                kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
                manifestData: candidate.manifestData, manifestDigest: candidate.manifestDigest,
                stagedEntries: candidate.stagedEntries), vaultKey: vaultKey)
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: candidate.expectedCheckpoint.vaultID,
                envelopeDigest: candidate.manifestDigest),
            envelope: validated.envelope)
    }
    func recoverInterruptedTransaction(vaultID: String, vaultKey: Data) throws
        -> V3ImmutableTransactionRecoveryOutcome
    {
        try publisher.recoverInterruptedTransaction(vaultID: vaultID, vaultKey: vaultKey)
    }
}
