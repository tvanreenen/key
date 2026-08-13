import Foundation

typealias V3DeviceWrappedEnrollmentRecoveryResult =
    V3DeviceWrappedKeyRotationRecoveryResult

/// Supplies enrollment's ceremony binding and roster policy to the shared
/// device-roster key-rotation recovery engine.
struct V3DeviceWrappedEnrollmentTransitionRecoverer: Sendable {
    private let recoverer: V3DeviceWrappedKeyRotationTransitionRecoverer
    private let validator: V3DeviceWrappedEnrollmentTransitionValidator

    init(
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits
    ) {
        recoverer = V3DeviceWrappedKeyRotationTransitionRecoverer(
            repositoryObserver: repositoryObserver,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            cache: cache,
            limits: limits
        )
        validator = V3DeviceWrappedEnrollmentTransitionValidator(
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
        guard expectedTranscriptDigest.count == 32 else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }
        do {
            return try recoverer.recover(
                vaultID: vaultID,
                kind: .enrollDevice,
                localIdentity: localIdentity,
                unwrapReason: unwrapReason,
                validateIntent: {
                    $0.enrollmentTranscriptDigest
                        == expectedTranscriptDigest
                },
                validate: { context in
                    let candidate =
                        V3DeviceWrappedEnrollmentTransitionCandidate(
                            expectedCheckpoint:
                                context.intent.expectedCheckpoint,
                            body: context.candidate.body,
                            manifestData: context.manifestData,
                            manifestDigest:
                                context.intent.candidateManifestDigest,
                            stagedEntries: context.stagedEntries,
                            transcriptDigest: expectedTranscriptDigest
                        )
                    let validated = try validator.validateAnchored(
                        candidate,
                        parent: context.parent,
                        currentEntries: context.currentEntries,
                        currentVaultKey: context.currentVaultKey,
                        nextVaultKey: context.nextVaultKey,
                        expectedOwner: localIdentity.publicIdentity
                    )
                    return V3DeviceWrappedValidatedKeyRotation(
                        parent: validated.parent,
                        candidate: validated.candidate,
                        manifestDigest: validated.manifestDigest,
                        stagedEntries: validated.stagedEntries
                    )
                },
                afterCheckpointAdvance: afterCheckpointAdvance
            )
        } catch V3DeviceWrappedKeyRotationRecoveryValidationError
                    .authenticationCancelled {
            throw V3DeviceWrappedEnrollmentValidationError
                .authenticationCancelled
        }
    }
}
