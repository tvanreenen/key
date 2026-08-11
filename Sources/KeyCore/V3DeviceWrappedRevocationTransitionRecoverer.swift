import Foundation

typealias V3DeviceWrappedRevocationRecoveryResult =
    V3DeviceWrappedKeyRotationRecoveryResult

/// Supplies revocation's exact one-device roster policy to the shared
/// device-roster key-rotation recovery engine.
struct V3DeviceWrappedRevocationTransitionRecoverer: Sendable {
    private let recoverer: V3DeviceWrappedKeyRotationTransitionRecoverer
    private let validator: V3DeviceWrappedRevocationTransitionValidator
    private let planner = V3DeviceWrappedRevocationPlanner()

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
        validator = V3DeviceWrappedRevocationTransitionValidator(
            limits: limits
        )
    }

    func recover(
        vaultID: String,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String,
        afterCheckpointAdvance:
            V3DeviceWrappedRevocationCommitHandler = { _, _ in }
    ) throws -> V3DeviceWrappedRevocationRecoveryResult {
        do {
            return try recoverer.recover(
                vaultID: vaultID,
                kind: .revokeDevice,
                localIdentity: localIdentity,
                unwrapReason: unwrapReason,
                validateIntent: {
                    $0.enrollmentTranscriptDigest == nil
                },
                validate: { context in
                    let plan = try recoveryPlan(
                        context,
                        authorizingOwner: localIdentity.publicIdentity
                    )
                    let candidate =
                        V3DeviceWrappedRevocationTransitionCandidate(
                            plan: plan,
                            body: context.candidate.body,
                            manifestData: context.manifestData,
                            manifestDigest:
                                context.intent.candidateManifestDigest,
                            stagedEntries: context.stagedEntries
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
            throw V3DeviceWrappedRevocationValidationError
                .authenticationCancelled
        }
    }

    private func recoveryPlan(
        _ context: V3DeviceWrappedKeyRotationRecoveryContext,
        authorizingOwner: V3EnrollmentDeviceIdentity
    ) throws -> V3DeviceWrappedRevocationPlan {
        let candidateByID = Dictionary(
            grouping: context.candidate.body.devices,
            by: { $0.identity.deviceID }
        )
        let revoked = context.parent.envelope.body.devices.filter { parent in
            guard parent.status == .active,
                  let matches = candidateByID[parent.identity.deviceID],
                  matches.count == 1,
                  let candidate = matches.first
            else {
                return false
            }
            return candidate.identity == parent.identity
                && candidate.role == parent.role
                && candidate.status == .revoked
        }
        guard revoked.count == 1, let device = revoked.first else {
            throw V3DeviceWrappedRevocationValidationError.invalidPlan
        }
        do {
            return try planner.plan(
                from: context.parent,
                authorizingDeviceID: authorizingOwner.deviceID,
                revoking: device.identity.deviceID
            )
        } catch {
            throw V3DeviceWrappedRevocationValidationError.invalidPlan
        }
    }
}
