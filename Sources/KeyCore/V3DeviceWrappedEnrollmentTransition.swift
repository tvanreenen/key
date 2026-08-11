import CryptoKit
import Foundation

/// Derives a stable RFC 9562 version-8 UUID from the complete enrollment
/// transcript. The identifier is authenticated by the manifest, included in
/// every HPKE wrapper context, and lets a joining Mac prove that synchronized
/// approval bytes belong to the exact comparison it accepted.
func v3EnrollmentAuthorityTransitionID(
    transcriptDigest: Data
) throws -> String {
    guard transcriptDigest.count == 32 else {
        throw V3DeviceWrappedEnrollmentTransitionError.invalidCeremony
    }
    var bytes = Array(transcriptDigest.prefix(16))
    bytes[6] = (bytes[6] & 0x0f) | 0x80
    bytes[8] = (bytes[8] & 0x3f) | 0x80
    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    return [
        String(hex.prefix(8)),
        String(hex.dropFirst(8).prefix(4)),
        String(hex.dropFirst(12).prefix(4)),
        String(hex.dropFirst(16).prefix(4)),
        String(hex.dropFirst(20)),
    ].joined(separator: "-")
}

enum V3DeviceWrappedEnrollmentTransitionError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidCeremony
    case invalidTrustedCheckpoint
    case invalidCurrentVaultKey
    case invalidNextVaultKey
    case invalidOwner
    case joiningIdentityConflict
    case incompleteEntrySnapshot
    case invalidEntry
    case invalidCandidate

    var errorDescription: String? {
        switch self {
        case .invalidCeremony:
            "Permanent enrollment requires the exact compared device ceremony."
        case .invalidTrustedCheckpoint:
            "Permanent enrollment requires the exact authenticated checkpoint."
        case .invalidCurrentVaultKey:
            "The current in-memory vault key does not match the authenticated checkpoint."
        case .invalidNextVaultKey:
            "Permanent enrollment requires a distinct new 32-byte vault key."
        case .invalidOwner:
            "Permanent enrollment must be authorized by the active inviting owner."
        case .joiningIdentityConflict:
            "The joining identity is already enrolled or reuses an existing device key."
        case .incompleteEntrySnapshot:
            "Permanent enrollment requires every entry in the current authenticated snapshot."
        case .invalidEntry:
            "A current entry could not be authenticated and re-encrypted for the new vault key."
        case .invalidCandidate:
            "The permanent key-rotating enrollment candidate is invalid."
        }
    }
}

/// One complete, still-unpublished permanent-profile roster addition.
///
/// The raw current and next vault keys are intentionally absent. The helper
/// owns their in-memory lifetime while a later transaction layer publishes
/// these newly encrypted entry objects and the owner-authorized manifest.
struct V3DeviceWrappedEnrollmentTransitionCandidate: Equatable, Sendable {
    let expectedCheckpoint: V3ManifestCheckpoint
    let body: V3DeviceWrappedManifestBody
    let manifestData: Data
    let manifestDigest: Data
    let stagedEntries: [V3EncryptedEntry]
    let transcriptDigest: Data
}

/// Pure cryptographic construction for one permanent-profile enrollment.
///
/// Provider reads, key generation, durable publication, checkpoint movement,
/// retry state, and joining-device adoption remain separate responsibilities.
struct V3DeviceWrappedEnrollmentTransitionBuilder: Sendable {
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let keyRotationBuilder = V3DeviceWrappedKeyRotationBuilder()
    private let messageAuthenticator = V3EnrollmentMessageAuthenticator()

    func build(
        from base: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        state: V3EnrollmentCeremonyState,
        currentVaultKey: Data,
        nextVaultKey: Data,
        authorityTransitionID: String,
        owner: any V3EnrollmentMessageSigning,
        at unixTime: UInt64,
        authorizationReason: String
    ) throws -> V3DeviceWrappedEnrollmentTransitionCandidate {
        let transcript = try validate(
            base: base,
            state: state,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            authorityTransitionID: authorityTransitionID,
            owner: owner,
            at: unixTime,
            authorizationReason: authorizationReason
        )

        let devices = try resultingDevices(
            parent: base.envelope.body.devices,
            joining: transcript.joinRequest.joiningDevice,
            role: transcript.invitation.invitedRole
        )
        let rotation: V3DeviceWrappedKeyRotationCandidate
        do {
            rotation = try keyRotationBuilder.build(
                from: base,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                authorityTransitionID: authorityTransitionID,
                resultingDevices: devices,
                owner: owner,
                authorizationReason: authorizationReason
            )
        } catch let error as V3DeviceWrappedKeyRotationError {
            throw enrollmentError(for: error)
        }
        return V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: rotation.expectedCheckpoint,
            body: rotation.body,
            manifestData: rotation.manifestData,
            manifestDigest: rotation.manifestDigest,
            stagedEntries: rotation.stagedEntries,
            transcriptDigest: transcript.digest
        )
    }

    private func validate(
        base: V3DeviceWrappedTrustedCheckpoint,
        state: V3EnrollmentCeremonyState,
        currentVaultKey: Data,
        nextVaultKey: Data,
        authorityTransitionID: String,
        owner: any V3EnrollmentMessageSigning,
        at unixTime: UInt64,
        authorizationReason: String
    ) throws -> V3EnrollmentTranscript {
        let baseBody = base.envelope.body
        guard let reparsed = try? envelopeCodec.parse(
                  base.envelope.canonicalBytes
              ),
              reparsed == base.envelope,
              base.checkpoint.vaultID == baseBody.vaultID,
              base.checkpoint.envelopeDigest
                == Data(SHA256.hash(data: base.envelope.canonicalBytes))
        else {
            throw V3DeviceWrappedEnrollmentTransitionError
                .invalidTrustedCheckpoint
        }
        guard currentVaultKey.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: currentVaultKey,
                  vaultID: baseBody.vaultID
              )) == baseBody.keyID
        else {
            throw V3DeviceWrappedEnrollmentTransitionError
                .invalidCurrentVaultKey
        }
        guard (try? V3ManifestAuthenticator.isValidAuthenticationTag(
            base.envelope.authenticationTag,
            canonicalContent: base.envelope.canonicalContentBytes,
            vaultID: baseBody.vaultID,
            vaultKey: currentVaultKey
        )) == true else {
            throw V3DeviceWrappedEnrollmentTransitionError
                .invalidTrustedCheckpoint
        }
        guard nextVaultKey.count == 32,
              nextVaultKey != currentVaultKey,
              (try? V3VaultKeyID.derive(
                  vaultKey: nextVaultKey,
                  vaultID: baseBody.vaultID
              )) != baseBody.keyID,
              isValidV3UUID(authorityTransitionID),
              authorityTransitionID != baseBody.authorityTransitionID
        else {
            throw V3DeviceWrappedEnrollmentTransitionError.invalidNextVaultKey
        }
        guard !authorizationReason.isEmpty,
              state.role == .inviter,
              state.phase == .awaitingComparison,
              let signedJoinRequest = state.signedJoinRequest,
              let transcript = state.transcript,
              transcript.invitation.vaultID == baseBody.vaultID,
              transcript.invitation.parentManifestDigest
                == base.checkpoint.envelopeDigest,
              transcript.invitation.invitingDevice == owner.publicIdentity,
              owner.vaultID == baseBody.vaultID,
              let parentOwner = baseBody.devices.first(where: {
                  $0.identity.deviceID == owner.publicIdentity.deviceID
              }),
              parentOwner.identity == owner.publicIdentity,
              parentOwner.role == .owner,
              parentOwner.status == .active
        else {
            throw V3DeviceWrappedEnrollmentTransitionError.invalidOwner
        }
        do {
            _ = try messageAuthenticator.verify(state.signedInvitation)
            _ = try messageAuthenticator.verify(signedJoinRequest)
            try transcript.invitation.requireUnexpired(at: unixTime)
        } catch {
            if error as? V3EnrollmentProtocolError == .expired {
                throw V3EnrollmentProtocolError.expired
            }
            throw V3DeviceWrappedEnrollmentTransitionError.invalidCeremony
        }
        return transcript
    }

    private func resultingDevices(
        parent: [V3DeviceWrappedManifestDevice],
        joining: V3EnrollmentDeviceIdentity,
        role: V3DeviceRole
    ) throws -> [V3DeviceWrappedManifestDevice] {
        guard !parent.contains(where: {
            $0.identity.deviceID == joining.deviceID
        }), parent.allSatisfy({ device in
            let identity = device.identity
            return identity.signingPublicKey != joining.signingPublicKey
                && identity.wrappingPublicKey != joining.wrappingPublicKey
                && identity.signingPublicKey != joining.wrappingPublicKey
                && identity.wrappingPublicKey != joining.signingPublicKey
        }) else {
            throw V3DeviceWrappedEnrollmentTransitionError
                .joiningIdentityConflict
        }
        return (parent + [V3DeviceWrappedManifestDevice(
            identity: joining,
            role: role,
            status: .active
        )]).sorted {
            Data($0.identity.deviceID.utf8).lexicographicallyPrecedes(
                Data($1.identity.deviceID.utf8)
            )
        }
    }

    private func enrollmentError(
        for error: V3DeviceWrappedKeyRotationError
    ) -> V3DeviceWrappedEnrollmentTransitionError {
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
