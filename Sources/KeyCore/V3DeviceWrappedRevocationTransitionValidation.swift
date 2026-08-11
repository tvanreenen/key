import Foundation

enum V3DeviceWrappedRevocationValidationError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidPlan
    case invalidTrustedCheckpoint
    case invalidCurrentVaultKey
    case invalidNextVaultKey
    case invalidTransition
    case invalidOwnerAuthorization
    case authenticationCancelled
    case localWrapperInvalid
    case invalidCurrentEntry
    case invalidStagedEntry
    case objectTooLarge

    var errorDescription: String? {
        switch self {
        case .invalidPlan:
            "The revocation no longer matches the exact reviewed device and checkpoint."
        case .invalidTrustedCheckpoint:
            "The revocation does not extend the exact authenticated checkpoint."
        case .invalidCurrentVaultKey:
            "The current vault key does not authenticate the revocation parent."
        case .invalidNextVaultKey:
            "The rotated vault key does not authenticate the revocation candidate."
        case .invalidTransition:
            "The candidate is not exactly one key-rotating device revocation."
        case .invalidOwnerAuthorization:
            "The revocation lacks the reviewed active-owner authorization."
        case .authenticationCancelled:
            "Device authentication was cancelled while checking the owner's new vault-key wrapper."
        case .localWrapperInvalid:
            "The approving owner cannot open its new vault-key wrapper."
        case .invalidCurrentEntry:
            "A current entry does not match the authenticated parent snapshot."
        case .invalidStagedEntry:
            "A re-encrypted entry does not match the complete revocation snapshot."
        case .objectTooLarge:
            "The revocation transition exceeds a repository resource limit."
        }
    }
}

struct V3DeviceWrappedValidatedRevocationTransition: Sendable {
    let plan: V3DeviceWrappedRevocationPlan
    let parent: V3DeviceWrappedManifestEnvelope
    let candidate: V3DeviceWrappedManifestEnvelope
    let manifestDigest: Data
    let stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
}

/// Independently proves one complete owner-authorized revocation transition.
///
/// The builder grants no authority. This validator reconstructs the reviewed
/// roster decision, authenticates both key epochs and the parent-owner
/// signature, compares every old and new plaintext, and opens the approving
/// owner's wrapper before durable publication may begin.
struct V3DeviceWrappedRevocationTransitionValidator: Sendable {
    private let planner = V3DeviceWrappedRevocationPlanner()
    private let keyRotationValidator: V3DeviceWrappedKeyRotationValidator

    init(limits: V3ManifestRepositoryLimits = .standard) {
        keyRotationValidator = V3DeviceWrappedKeyRotationValidator(
            limits: limits
        )
    }

    func validate(
        _ transition: V3DeviceWrappedRevocationTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        unwrapReason: String
    ) throws -> V3DeviceWrappedValidatedRevocationTransition {
        guard localIdentity.vaultID == parent.checkpoint.vaultID else {
            throw V3DeviceWrappedRevocationValidationError.invalidPlan
        }
        let validated = try validateAnchored(
            transition,
            parent: parent,
            currentEntries: currentEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            expectedOwner: localIdentity.publicIdentity
        )
        do {
            try keyRotationValidator.validateLocalWrapper(
                validated.candidate,
                identity: localIdentity,
                nextVaultKey: nextVaultKey,
                reason: unwrapReason
            )
        } catch let error as V3DeviceWrappedKeyRotationValidationError {
            throw revocationError(for: error)
        }
        return validated
    }

    /// Revalidates the exact immutable revocation after its local recovery
    /// anchor is durable, without prompting the approving owner a second time.
    func validateAnchored(
        _ transition: V3DeviceWrappedRevocationTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        expectedOwner: V3EnrollmentDeviceIdentity
    ) throws -> V3DeviceWrappedValidatedRevocationTransition {
        let reviewedPlan: V3DeviceWrappedRevocationPlan
        do {
            reviewedPlan = try planner.plan(
                from: parent,
                authorizingDeviceID:
                    transition.plan.authorizingOwner.identity.deviceID,
                revoking: transition.plan.revokedDevice.identity.deviceID
            )
        } catch {
            throw V3DeviceWrappedRevocationValidationError.invalidPlan
        }
        guard reviewedPlan == transition.plan,
              expectedOwner == reviewedPlan.authorizingOwner.identity
        else {
            throw V3DeviceWrappedRevocationValidationError.invalidPlan
        }

        let rotation: V3DeviceWrappedValidatedKeyRotation
        do {
            rotation = try keyRotationValidator.validate(
                transition.keyRotationValidationInput,
                parent: parent,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                expectedOwner: expectedOwner
            ) { authenticatedParent, authenticatedCandidate in
                guard authenticatedCandidate.body.keyID
                        != authenticatedParent.body.keyID,
                      authenticatedCandidate.body.authorityTransitionID
                        != authenticatedParent.body.authorityTransitionID,
                      authenticatedCandidate.body.devices
                        == reviewedPlan.resultingDevices
                else {
                    throw V3DeviceWrappedRevocationValidationError
                        .invalidTransition
                }
            }
        } catch let error as V3DeviceWrappedKeyRotationValidationError {
            throw revocationError(for: error)
        }
        return V3DeviceWrappedValidatedRevocationTransition(
            plan: reviewedPlan,
            parent: rotation.parent,
            candidate: rotation.candidate,
            manifestDigest: rotation.manifestDigest,
            stagedEntries: rotation.stagedEntries
        )
    }

    private func revocationError(
        for error: V3DeviceWrappedKeyRotationValidationError
    ) -> V3DeviceWrappedRevocationValidationError {
        switch error {
        case .invalidTrustedCheckpoint:
            .invalidTrustedCheckpoint
        case .invalidCurrentVaultKey:
            .invalidCurrentVaultKey
        case .invalidNextVaultKey:
            .invalidNextVaultKey
        case .invalidTransition:
            .invalidTransition
        case .invalidOwnerAuthorization:
            .invalidOwnerAuthorization
        case .authenticationCancelled:
            .authenticationCancelled
        case .localWrapperInvalid:
            .localWrapperInvalid
        case .invalidCurrentEntry:
            .invalidCurrentEntry
        case .invalidStagedEntry:
            .invalidStagedEntry
        case .objectTooLarge:
            .objectTooLarge
        }
    }
}
