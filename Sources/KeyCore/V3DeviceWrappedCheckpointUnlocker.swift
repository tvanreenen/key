import CryptoKit
import Foundation

enum V3DeviceWrappedUnlockError: Error, Equatable, LocalizedError {
    case invalidManifest
    case unsupportedEnvelopeVersion(UInt64)
    case unsupportedProfileVersion(UInt64)
    case checkpointMismatch
    case deviceIdentityMismatch
    case deviceNotEnrolled
    case deviceRevoked
    case wrapperMissing
    case authenticationCancelled
    case keyUnwrapFailed
    case authenticationFailed

    var errorDescription: String? {
        switch self {
        case .invalidManifest:
            "The permanent version 3 checkpoint manifest is invalid."
        case let .unsupportedEnvelopeVersion(version):
            "Manifest envelope version \(version) requires a newer version of Key."
        case let .unsupportedProfileVersion(version):
            "Device-wrapped vault profile version \(version) requires a newer version of Key."
        case .checkpointMismatch:
            "The permanent version 3 manifest does not match this device's trusted checkpoint."
        case .deviceIdentityMismatch:
            "This Mac's recorded Secure Enclave identity does not match the trusted vault."
        case .deviceNotEnrolled:
            "This Mac is not enrolled in the trusted vault."
        case .deviceRevoked:
            "This Mac has been revoked from the trusted vault."
        case .wrapperMissing:
            "The trusted vault has no current key wrapper for this Mac."
        case .authenticationCancelled:
            "Device authentication was cancelled or is not currently available."
        case .keyUnwrapFailed:
            "This Mac could not open its current vault-key wrapper."
        case .authenticationFailed:
            "The permanent version 3 checkpoint manifest failed authentication."
        }
    }
}

protocol V3DeviceWrappedVaultKeyUnwrapping: Sendable {
    var vaultID: String { get }
    var publicIdentity: V3EnrollmentDeviceIdentity { get }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data
}

/// Opens only the exact manifest selected by the device-local checkpoint and
/// installs its authenticated key into the non-persistent helper session.
struct V3DeviceWrappedCheckpointUnlocker: Sendable {
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()

    func unlock(
        checkpoint: V3ManifestCheckpoint,
        manifestData: Data,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        session: V3DeviceWrappedVaultKeySessionStore,
        reason: String,
        validateBeforeSessionInstall: () throws -> Void = {}
    ) throws -> V3DeviceWrappedManifestEnvelope {
        guard !manifestData.isEmpty,
              manifestData.count
                <= V3ManifestRepositoryLimits.standard.maximumManifestBytes
        else {
            throw V3DeviceWrappedUnlockError.invalidManifest
        }
        guard Data(SHA256.hash(data: manifestData))
                == checkpoint.envelopeDigest
        else {
            throw V3DeviceWrappedUnlockError.checkpointMismatch
        }

        let envelope = try envelopeCodec.parse(manifestData)
        guard envelope.body.vaultID == checkpoint.vaultID else {
            throw V3DeviceWrappedUnlockError.checkpointMismatch
        }
        guard identity.vaultID == checkpoint.vaultID else {
            throw V3DeviceWrappedUnlockError.deviceIdentityMismatch
        }

        let deviceID = identity.publicIdentity.deviceID
        guard let rosterDevice = envelope.body.devices.first(where: {
            $0.identity.deviceID == deviceID
        }) else {
            throw V3DeviceWrappedUnlockError.deviceNotEnrolled
        }
        guard rosterDevice.identity == identity.publicIdentity else {
            throw V3DeviceWrappedUnlockError.deviceIdentityMismatch
        }
        guard rosterDevice.status == .active else {
            throw V3DeviceWrappedUnlockError.deviceRevoked
        }
        guard let wrappedKey = envelope.body.wrappedKeys.first(where: {
            $0.recipientDeviceID == deviceID
        }) else {
            throw V3DeviceWrappedUnlockError.wrapperMissing
        }

        let context: V3VaultKeyHPKEContext
        do {
            context = try V3VaultKeyHPKEContext(
                vaultID: envelope.body.vaultID,
                keyID: envelope.body.keyID,
                authorityTransitionID: envelope.body.authorityTransitionID,
                recipientDeviceID: deviceID
            )
        } catch {
            throw V3DeviceWrappedUnlockError.invalidManifest
        }

        let vaultKey: Data
        do {
            vaultKey = try identity.unwrapDeviceWrappedVaultKey(
                wrappedKey.wrappedKey,
                context: context,
                reason: reason
            )
        } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
            throw V3DeviceWrappedUnlockError.authenticationCancelled
        } catch {
            throw V3DeviceWrappedUnlockError.keyUnwrapFailed
        }
        guard (try? V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: envelope.body.vaultID
        )) == envelope.body.keyID else {
            throw V3DeviceWrappedUnlockError.authenticationFailed
        }
        guard (try? V3ManifestAuthenticator.isValidAuthenticationTag(
            envelope.authenticationTag,
            canonicalContent: envelope.canonicalContentBytes,
            vaultID: envelope.body.vaultID,
            vaultKey: vaultKey
        )) == true else {
            throw V3DeviceWrappedUnlockError.authenticationFailed
        }

        try validateBeforeSessionInstall()
        do {
            try session.install(
                vaultKey,
                vaultID: envelope.body.vaultID,
                keyID: envelope.body.keyID
            )
        } catch {
            throw V3DeviceWrappedUnlockError.authenticationFailed
        }
        return envelope
    }
}
