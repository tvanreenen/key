import CryptoKit
import Foundation

enum V3ReplacementDeviceIdentityClassificationError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidAuthority
    case conflictingAuthority
    case identityMismatch
    case upgradeRequired

    var errorDescription: String? {
        switch self {
        case .invalidAuthority:
            "The replacement check is not bound to authenticated vault authority."
        case .conflictingAuthority:
            "The vault has competing authenticated transitions. Resolve the security conflict before replacing this device."
        case .identityMismatch:
            "The local device identity does not match the authenticated vault roster."
        case .upgradeRequired:
            "The authenticated vault transition requires a newer version of Key."
        }
    }
}

/// The exact authority observation used to classify a residual local identity.
///
/// A trusted checkpoint can directly prove any roster status. A revoked Mac
/// cannot open the rotated key, so its terminal proof is instead the exact
/// direct child signed by another active device that revokes this identity.
enum V3ReplacementDeviceIdentityAuthority: Equatable, Sendable {
    case trustedCheckpoint(manifestDigest: Data)
    case ownerAuthorizedRevocation(
        parentCheckpoint: V3ManifestCheckpoint,
        manifestDigest: Data,
        authorizingDevice: V3EnrollmentDeviceIdentity
    )
}

/// A read-only decision about whether one exact local identity may enter the
/// later replacement workflow. Nothing here deletes keys or changes trust.
enum V3ReplacementDeviceIdentityClassification: Equatable, Sendable {
    case noLocalIdentity
    case active(
        V3EnrollmentDeviceIdentityDeletionTarget,
        authority: V3ReplacementDeviceIdentityAuthority
    )
    case revoked(
        V3EnrollmentDeviceIdentityDeletionTarget,
        authority: V3ReplacementDeviceIdentityAuthority
    )
    case unrecognized(
        V3EnrollmentDeviceIdentityDeletionTarget,
        authority: V3ReplacementDeviceIdentityAuthority
    )
}

/// Compares the exact public identity captured for retry-safe deletion with
/// authenticated device authority.
///
/// Unknown identities remain explicit instead of being treated as stale. An
/// equal device ID with different public identity fields is a security error,
/// not an invitation to replace local state.
struct V3ReplacementDeviceIdentityClassifier: Sendable {
    func classify(
        _ target: V3EnrollmentDeviceIdentityDeletionTarget?,
        at trusted: V3DeviceWrappedTrustedCheckpoint
    ) throws -> V3ReplacementDeviceIdentityClassification {
        guard let target else {
            return .noLocalIdentity
        }
        try validate(trusted, for: target)
        let authority = V3ReplacementDeviceIdentityAuthority
            .trustedCheckpoint(
                manifestDigest: trusted.checkpoint.envelopeDigest
            )
        return try classify(
            target,
            devices: trusted.envelope.body.devices,
            authority: authority
        )
    }

    /// Applies one conflict-aware catch-up observation to the classification.
    ///
    /// The authority planner must select one unique key transition before its
    /// owner authorization is inspected. Competing content and key authority
    /// therefore cannot be reduced to whichever provider object was supplied
    /// first. Only an exact revocation of this active local identity changes
    /// the result from active to revoked.
    func classify(
        _ target: V3EnrollmentDeviceIdentityDeletionTarget?,
        from parent: V3DeviceWrappedTrustedCheckpoint,
        content: V3DeviceWrappedCatchUpPlan,
        keyTransition: V3DeviceWrappedKeyTransitionDiscoveryOutcome,
        currentVaultKey: Data
    ) throws -> V3ReplacementDeviceIdentityClassification {
        guard let target else {
            return .noLocalIdentity
        }
        try validate(parent, for: target)
        let parentClassification = try classify(
            target,
            devices: parent.envelope.body.devices,
            authority: .trustedCheckpoint(
                manifestDigest: parent.checkpoint.envelopeDigest
            )
        )
        let action: V3DeviceWrappedCatchUpAction
        do {
            action = try V3DeviceWrappedCatchUpAuthorityPlanner().plan(
                content: content,
                keyTransition: keyTransition
            )
        } catch {
            throw V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        }
        let manifestData: Data
        let manifestDigest: Data
        switch action {
        case let .advanceKey(data, digest):
            manifestData = data
            manifestDigest = digest
        case .securityConflict:
            throw V3ReplacementDeviceIdentityClassificationError
                .conflictingAuthority
        case .upToDate, .advanceContent, .contentConflict:
            return parentClassification
        }

        let transition: V3DeviceWrappedOwnerAuthorizedKeyTransition
        let validator = V3DeviceWrappedEnrollmentTransitionValidator()
        do {
            transition = try validator.preflightOwnerAuthorizedKeyTransition(
                manifestData: manifestData,
                manifestDigest: manifestDigest,
                parent: parent,
                currentVaultKey: currentVaultKey
            )
        } catch let error as V3DeviceWrappedUnlockError {
            if case .unsupportedProfileVersion = error,
               (try? validator.isOwnerAuthorizedDirectChildEnvelope(
                   manifestData: manifestData,
                   manifestDigest: manifestDigest,
                   parent: parent,
                   currentVaultKey: currentVaultKey
               )) == true
            {
                throw V3ReplacementDeviceIdentityClassificationError
                    .upgradeRequired
            }
            throw V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        } catch {
            throw V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        }
        guard case let .active(activeTarget, _) = parentClassification,
              case let .revocation(plan) = transition.kind,
              plan.revokedDevice.identity == activeTarget.identity
        else {
            return parentClassification
        }

        guard plan.expectedCheckpoint == parent.checkpoint,
              plan.authorizingDevice.identity
                == transition.authorizingDevice,
              plan.authorizingDevice.status == .active,
              plan.revokedDevice.status == .active,
              plan.resultingDevices == transition.candidate.body.devices,
              transition.candidate.body.devices.contains(where: {
                  $0.identity == activeTarget.identity
                      && $0.status == .revoked
              })
        else {
            throw V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        }

        return .revoked(
            activeTarget,
            authority: .ownerAuthorizedRevocation(
                parentCheckpoint: parent.checkpoint,
                manifestDigest: transition.manifestDigest,
                authorizingDevice: transition.authorizingDevice
            )
        )
    }

    private func classify(
        _ target: V3EnrollmentDeviceIdentityDeletionTarget,
        devices: [V3DeviceWrappedManifestDevice],
        authority: V3ReplacementDeviceIdentityAuthority
    ) throws -> V3ReplacementDeviceIdentityClassification {
        guard let device = devices.first(where: {
            $0.identity.deviceID == target.identity.deviceID
        }) else {
            return .unrecognized(target, authority: authority)
        }
        guard device.identity == target.identity else {
            throw V3ReplacementDeviceIdentityClassificationError
                .identityMismatch
        }
        switch device.status {
        case .active:
            return .active(target, authority: authority)
        case .revoked:
            return .revoked(target, authority: authority)
        }
    }

    private func validate(
        _ trusted: V3DeviceWrappedTrustedCheckpoint,
        for target: V3EnrollmentDeviceIdentityDeletionTarget
    ) throws {
        let manifestData = trusted.envelope.canonicalBytes
        guard target.vaultID == trusted.checkpoint.vaultID,
              trusted.checkpoint.vaultID
                == trusted.envelope.body.vaultID,
              trusted.checkpoint.envelopeDigest
                == Data(SHA256.hash(data: manifestData)),
              (try? V3DeviceWrappedManifestEnvelopeCodec().parse(
                  manifestData
              )) == trusted.envelope
        else {
            throw V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        }
    }
}
