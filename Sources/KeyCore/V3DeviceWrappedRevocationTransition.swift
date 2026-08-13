import Foundation

enum V3DeviceWrappedRevocationTransitionError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidPlan
    case invalidTrustedCheckpoint
    case invalidCurrentVaultKey
    case invalidNextVaultKey
    case invalidOwner
    case incompleteEntrySnapshot
    case invalidEntry
    case invalidCandidate

    var errorDescription: String? {
        switch self {
        case .invalidPlan:
            "Device revocation no longer matches the exact reviewed roster."
        case .invalidTrustedCheckpoint:
            "Device revocation requires the exact authenticated checkpoint."
        case .invalidCurrentVaultKey:
            "The current in-memory vault key does not authenticate the revocation parent."
        case .invalidNextVaultKey:
            "Device revocation requires a distinct new 32-byte vault key."
        case .invalidOwner:
            "Device revocation must be signed by the active reviewing device."
        case .incompleteEntrySnapshot:
            "Device revocation requires every entry in the current authenticated snapshot."
        case .invalidEntry:
            "A current entry could not be authenticated and re-encrypted for revocation."
        case .invalidCandidate:
            "The key-rotating revocation candidate is invalid."
        }
    }
}

/// One complete, still-unpublished permanent-profile revocation.
///
/// The candidate retains the exact reviewed plan while containing only
/// encrypted entry objects and wrappers for devices that remain active.
struct V3DeviceWrappedRevocationTransitionCandidate:
    Equatable,
    Sendable
{
    let plan: V3DeviceWrappedRevocationPlan
    let body: V3DeviceWrappedManifestBody
    let manifestData: Data
    let manifestDigest: Data
    let stagedEntries: [V3EncryptedEntry]
}

/// Converts an exact reviewed revocation plan into a key-rotating candidate.
///
/// Durable publication, checkpoint compare-and-swap, retry recovery, CLI
/// confirmation, and remaining-device catch-up stay outside this constructor.
struct V3DeviceWrappedRevocationTransitionBuilder: Sendable {
    private let planner = V3DeviceWrappedRevocationPlanner()
    private let keyRotationBuilder = V3DeviceWrappedKeyRotationBuilder()

    func build(
        from base: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        plan: V3DeviceWrappedRevocationPlan,
        currentVaultKey: Data,
        nextVaultKey: Data,
        authorityTransitionID: String,
        owner: any V3EnrollmentMessageSigning,
        authorizationReason: String
    ) throws -> V3DeviceWrappedRevocationTransitionCandidate {
        let reviewedPlan: V3DeviceWrappedRevocationPlan
        do {
            reviewedPlan = try planner.plan(
                from: base,
                authorizingDeviceID:
                    plan.authorizingDevice.identity.deviceID,
                revoking: plan.revokedDevice.identity.deviceID
            )
        } catch {
            throw V3DeviceWrappedRevocationTransitionError.invalidPlan
        }
        guard reviewedPlan == plan,
              owner.publicIdentity == plan.authorizingDevice.identity,
              owner.vaultID == plan.expectedCheckpoint.vaultID
        else {
            throw V3DeviceWrappedRevocationTransitionError.invalidPlan
        }

        let rotation: V3DeviceWrappedKeyRotationCandidate
        do {
            rotation = try keyRotationBuilder.build(
                from: base,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                authorityTransitionID: authorityTransitionID,
                resultingDevices: plan.resultingDevices,
                owner: owner,
                authorizationReason: authorizationReason
            )
        } catch let error as V3DeviceWrappedKeyRotationError {
            throw revocationError(for: error)
        }
        guard rotation.expectedCheckpoint == plan.expectedCheckpoint else {
            throw V3DeviceWrappedRevocationTransitionError.invalidPlan
        }
        return V3DeviceWrappedRevocationTransitionCandidate(
            plan: plan,
            body: rotation.body,
            manifestData: rotation.manifestData,
            manifestDigest: rotation.manifestDigest,
            stagedEntries: rotation.stagedEntries
        )
    }

    private func revocationError(
        for error: V3DeviceWrappedKeyRotationError
    ) -> V3DeviceWrappedRevocationTransitionError {
        switch error {
        case .invalidTrustedCheckpoint:
            .invalidTrustedCheckpoint
        case .invalidCurrentVaultKey:
            .invalidCurrentVaultKey
        case .invalidNextVaultKey:
            .invalidNextVaultKey
        case .invalidOwner:
            .invalidOwner
        case .incompleteEntrySnapshot:
            .incompleteEntrySnapshot
        case .invalidEntry:
            .invalidEntry
        case .invalidCandidate:
            .invalidCandidate
        }
    }
}
