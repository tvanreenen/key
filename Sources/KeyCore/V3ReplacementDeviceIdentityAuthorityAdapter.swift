import Foundation

/// Supplies replacement cleanup with the same conflict-aware authority view
/// used by ordinary catch-up, without advancing the checkpoint.
///
/// A checkpoint that already proves the identity revoked is sufficient. When
/// the checkpoint still lists it active, the adapter authenticates the full
/// same-epoch observation and all owner-authorized direct key transitions
/// before allowing the classifier to select one exact revocation proof.
struct V3ReplacementDeviceIdentityAuthorityAdapter:
    V3ReplacementDeviceIdentityAuthorityClassifying,
    Sendable
{
    private let vaultID: String
    private let stateManager: any V3DeviceWrappedCatchUpStateManaging
    private let contentSteps:
        any V3DeviceWrappedSameEpochCatchUpStepServicing
    private let keyTransitionDiscovery:
        any V3DeviceWrappedKeyTransitionDiscovering
    private let classifier = V3ReplacementDeviceIdentityClassifier()

    init(
        vaultID: String,
        stateManager: any V3DeviceWrappedCatchUpStateManaging,
        contentSteps:
            any V3DeviceWrappedSameEpochCatchUpStepServicing,
        keyTransitionDiscovery:
            any V3DeviceWrappedKeyTransitionDiscovering
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.stateManager = stateManager
        self.contentSteps = contentSteps
        self.keyTransitionDiscovery = keyTransitionDiscovery
    }

    func classifyCurrentAuthority(
        for target: V3EnrollmentDeviceIdentityDeletionTarget
    ) throws -> V3ReplacementDeviceIdentityClassification {
        guard target.vaultID == vaultID else {
            throw V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        }

        return try stateManager.withCatchUpSession {
            let trusted = try stateManager.authenticatedCheckpoint(
                reason: "Unlock version 3 vault to verify this Mac was revoked before replacing it."
            )
            let checkpointClassification = try classifier.classify(
                target,
                at: trusted
            )
            guard case .active = checkpointClassification else {
                return checkpointClassification
            }

            let vaultKey = try stateManager.loadVaultKey(
                keyID: trusted.envelope.body.keyID
            )
            let content = try contentSteps.inspect(
                trusted: trusted,
                vaultKey: vaultKey
            )
            let keyTransition = try keyTransitionDiscovery.discover(
                from: trusted,
                currentVaultKey: vaultKey
            )
            return try classifier.classify(
                target,
                from: trusted,
                content: content,
                keyTransition: keyTransition,
                currentVaultKey: vaultKey
            )
        }
    }
}
