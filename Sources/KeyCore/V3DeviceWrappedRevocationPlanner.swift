import CryptoKit
import Foundation

enum V3DeviceWrappedRevocationPlanningError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidTrustedCheckpoint
    case invalidAuthorizingOwner
    case deviceNotFound
    case deviceAlreadyRevoked
    case cannotRevokeAuthorizingDevice
    case lastActiveOwner

    var errorDescription: String? {
        switch self {
        case .invalidTrustedCheckpoint:
            "Device revocation requires the exact authenticated checkpoint."
        case .invalidAuthorizingOwner:
            "Device revocation must be authorized by an active owner."
        case .deviceNotFound:
            "The selected device is not enrolled in this vault."
        case .deviceAlreadyRevoked:
            "The selected device is already revoked."
        case .cannotRevokeAuthorizingDevice:
            "Use another active owner to revoke this Mac."
        case .lastActiveOwner:
            "The vault must retain at least one active owner."
        }
    }
}

/// One reviewable roster decision made before generating or exposing a new
/// vault key.
///
/// The plan preserves the complete historical roster, marks exactly one
/// active device revoked, and binds every later cryptographic and publication
/// step to the exact authenticated checkpoint reviewed by the owner.
struct V3DeviceWrappedRevocationPlan: Equatable, Sendable {
    let expectedCheckpoint: V3ManifestCheckpoint
    let authorizingOwner: V3DeviceWrappedManifestDevice
    let revokedDevice: V3DeviceWrappedManifestDevice
    let resultingDevices: [V3DeviceWrappedManifestDevice]

    var remainingActiveDevices: [V3DeviceWrappedManifestDevice] {
        resultingDevices.filter { $0.status == .active }
    }
}

/// Pure membership planning for one owner-authorized revocation.
///
/// Key generation, entry resealing, HPKE wrapping, signing, publication,
/// checkpoint movement, and retry recovery remain separate responsibilities.
/// A later builder consumes this plan and must revalidate its exact checkpoint
/// before constructing the key-rotating transition.
struct V3DeviceWrappedRevocationPlanner: Sendable {
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()

    func plan(
        from base: V3DeviceWrappedTrustedCheckpoint,
        authorizingDeviceID: String,
        revoking revokedDeviceID: String
    ) throws -> V3DeviceWrappedRevocationPlan {
        let envelope = try validate(base)
        guard let authorizingOwner = envelope.body.devices.first(where: {
            $0.identity.deviceID == authorizingDeviceID
                && $0.role == .owner
                && $0.status == .active
        }) else {
            throw V3DeviceWrappedRevocationPlanningError
                .invalidAuthorizingOwner
        }
        guard let revokedDevice = envelope.body.devices.first(where: {
            $0.identity.deviceID == revokedDeviceID
        }) else {
            throw V3DeviceWrappedRevocationPlanningError.deviceNotFound
        }
        guard revokedDevice.status == .active else {
            throw V3DeviceWrappedRevocationPlanningError
                .deviceAlreadyRevoked
        }

        let resultingDevices = envelope.body.devices.map { device in
            guard device.identity.deviceID == revokedDeviceID else {
                return device
            }
            return V3DeviceWrappedManifestDevice(
                identity: device.identity,
                role: device.role,
                status: .revoked
            )
        }
        guard resultingDevices.contains(where: {
            $0.role == .owner && $0.status == .active
        }) else {
            throw V3DeviceWrappedRevocationPlanningError.lastActiveOwner
        }
        guard authorizingDeviceID != revokedDeviceID else {
            // The publishing Mac must remain able to validate and recover the
            // new epoch. A future explicit leave/handoff flow can safely own
            // the different local cleanup semantics of self-removal.
            throw V3DeviceWrappedRevocationPlanningError
                .cannotRevokeAuthorizingDevice
        }

        return V3DeviceWrappedRevocationPlan(
            expectedCheckpoint: base.checkpoint,
            authorizingOwner: authorizingOwner,
            revokedDevice: revokedDevice,
            resultingDevices: resultingDevices
        )
    }

    private func validate(
        _ base: V3DeviceWrappedTrustedCheckpoint
    ) throws -> V3DeviceWrappedManifestEnvelope {
        guard base.checkpoint.vaultID == base.envelope.body.vaultID,
              base.checkpoint.envelopeDigest
                == Data(SHA256.hash(data: base.envelope.canonicalBytes)),
              let reparsed = try? envelopeCodec.parse(
                  base.envelope.canonicalBytes
              ),
              reparsed == base.envelope
        else {
            throw V3DeviceWrappedRevocationPlanningError
                .invalidTrustedCheckpoint
        }
        return reparsed
    }
}
