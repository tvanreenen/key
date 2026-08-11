import Foundation

typealias V3DeviceWrappedEnrollmentCommitHandler =
    V3DeviceWrappedKeyRotationCommitHandler

/// Applies enrollment-specific authorization before delegating the common
/// immutable key-rotation transaction to its shared publisher.
struct V3DeviceWrappedEnrollmentTransitionPublisher: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let validator: V3DeviceWrappedEnrollmentTransitionValidator
    private let publisher: V3DeviceWrappedKeyRotationTransitionPublisher
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
            V3DeviceWrappedNoopKeyRotationPublicationObserver()
    ) {
        self.mutationOwner = mutationOwner
        validator = V3DeviceWrappedEnrollmentTransitionValidator(
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
        unwrapReason: String,
        afterCheckpointAdvance: @escaping
            V3DeviceWrappedEnrollmentCommitHandler = { _, _ in }
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        try mutationOwner.perform(.enrollDevice) { context in
            try publisher.publish(
                kind: .enrollDevice,
                expectedCheckpoint: candidate.expectedCheckpoint,
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                enrollmentTranscriptDigest: candidate.transcriptDigest,
                operationID: context.operationID,
                validate: {
                    keyRotation(try validator.validate(
                        candidate,
                        parent: parent,
                        currentEntries: currentEntries,
                        currentVaultKey: currentVaultKey,
                        nextVaultKey: nextVaultKey,
                        state: state,
                        localIdentity: localIdentity,
                        at: unixTime,
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

    func recoverInterruptedTransaction(
        vaultID: String,
        expectedTranscriptDigest: Data,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String,
        afterCheckpointAdvance: @escaping
            V3DeviceWrappedEnrollmentCommitHandler = { _, _ in }
    ) throws -> V3DeviceWrappedEnrollmentRecoveryResult {
        try mutationOwner.perform(.recoverInterruptedTransaction) { _ in
            try recoverer.recover(
                vaultID: vaultID,
                expectedTranscriptDigest: expectedTranscriptDigest,
                localIdentity: localIdentity,
                unwrapReason: unwrapReason,
                afterCheckpointAdvance: afterCheckpointAdvance
            )
        }
    }

    private func keyRotation(
        _ validated: V3DeviceWrappedValidatedEnrollmentTransition
    ) -> V3DeviceWrappedValidatedKeyRotation {
        V3DeviceWrappedValidatedKeyRotation(
            parent: validated.parent,
            candidate: validated.candidate,
            manifestDigest: validated.manifestDigest,
            stagedEntries: validated.stagedEntries
        )
    }
}
