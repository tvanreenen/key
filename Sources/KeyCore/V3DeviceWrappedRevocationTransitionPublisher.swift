import Foundation

typealias V3DeviceWrappedRevocationCommitHandler =
    V3DeviceWrappedKeyRotationCommitHandler

/// Applies the exact reviewed revocation policy before delegating the common
/// immutable key-rotation transaction to its shared publisher.
struct V3DeviceWrappedRevocationTransitionPublisher: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let validator: V3DeviceWrappedRevocationTransitionValidator
    private let publisher: V3DeviceWrappedKeyRotationTransitionPublisher

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
            V3DeviceWrappedNoopKeyRotationPublicationObserver()
    ) {
        self.mutationOwner = mutationOwner
        validator = V3DeviceWrappedRevocationTransitionValidator(
            limits: limits
        )
        publisher = V3DeviceWrappedKeyRotationTransitionPublisher(
            repositoryObserver: repositoryObserver,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            cache: cache,
            limits: limits,
            phaseObserver: phaseObserver
        )
    }

    func publish(
        _ candidate: V3DeviceWrappedRevocationTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String,
        afterCheckpointAdvance: @escaping
            V3DeviceWrappedRevocationCommitHandler = { _, _ in }
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        try mutationOwner.perform(.revokeDevice) { context in
            try publisher.publish(
                kind: .revokeDevice,
                expectedCheckpoint: candidate.plan.expectedCheckpoint,
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                enrollmentTranscriptDigest: nil,
                operationID: context.operationID,
                validate: {
                    keyRotation(try validator.validate(
                        candidate,
                        parent: parent,
                        currentEntries: currentEntries,
                        currentVaultKey: currentVaultKey,
                        nextVaultKey: nextVaultKey,
                        localIdentity: localIdentity,
                        unwrapReason: unwrapReason
                    ))
                },
                revalidate: {
                    keyRotation(try validator.validateAnchored(
                        candidate,
                        parent: parent,
                        currentEntries: currentEntries,
                        currentVaultKey: currentVaultKey,
                        nextVaultKey: nextVaultKey,
                        expectedOwner: localIdentity.publicIdentity
                    ))
                },
                afterCheckpointAdvance: afterCheckpointAdvance
            )
        }
    }

    private func keyRotation(
        _ validated: V3DeviceWrappedValidatedRevocationTransition
    ) -> V3DeviceWrappedValidatedKeyRotation {
        V3DeviceWrappedValidatedKeyRotation(
            parent: validated.parent,
            candidate: validated.candidate,
            manifestDigest: validated.manifestDigest,
            stagedEntries: validated.stagedEntries
        )
    }
}
