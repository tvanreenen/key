import CryptoKit
import Foundation
internal import JSONCanonicalization

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
    private static let envelopeFormat = "key-vault-manifest-envelope"
    private static let envelopeVersion: UInt64 = 3
    private static let authenticationAlgorithm =
        "HKDF-SHA256+HMAC-SHA256"
    private static let authorizationAlgorithm = "P-256-ECDSA-SHA256"

    private let entryCipher = V3EntryCipher()
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let hpke = V3VaultKeyHPKE()
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

        let baseBody = base.envelope.body
        let nextKeyID = try V3VaultKeyID.derive(
            vaultKey: nextVaultKey,
            vaultID: baseBody.vaultID
        )
        let devices = try resultingDevices(
            parent: baseBody.devices,
            joining: transcript.joinRequest.joiningDevice,
            role: transcript.invitation.invitedRole
        )
        let wrappedKeys: [V3DeviceWrappedManifestKey] = try devices.compactMap {
            device -> V3DeviceWrappedManifestKey? in
            guard device.status == .active else {
                return nil
            }
            let context = try V3VaultKeyHPKEContext(
                vaultID: baseBody.vaultID,
                keyID: nextKeyID,
                authorityTransitionID: authorityTransitionID,
                recipientDeviceID: device.identity.deviceID
            )
            return try V3DeviceWrappedManifestKey(
                recipientDeviceID: device.identity.deviceID,
                wrappedKey: hpke.wrap(
                    vaultKey: nextVaultKey,
                    recipientPublicKey: device.identity.wrappingPublicKey,
                    context: context
                )
            )
        }
        let resealed = try resealEntries(
            baseBody.entries,
            currentEntries: currentEntries,
            vaultID: baseBody.vaultID,
            nextKeyID: nextKeyID,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey
        )
        let body: V3DeviceWrappedManifestBody
        do {
            body = try V3DeviceWrappedManifestBody(
                vaultID: baseBody.vaultID,
                keyID: nextKeyID,
                authorityTransitionID: authorityTransitionID,
                devices: devices,
                wrappedKeys: wrappedKeys,
                entries: resealed.map(\.manifestEntry)
            )
        } catch {
            throw V3DeviceWrappedEnrollmentTransitionError.invalidCandidate
        }

        let content = CanonicalJSONValue.object([
            (
                "parents",
                .array([.string(Base64URL.encode(
                    base.checkpoint.envelopeDigest
                ))])
            ),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let authenticationTag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: body.vaultID,
            vaultKey: nextVaultKey
        )
        let authorizationInput = V3ManifestAuthenticator.authenticationInput(
            for: canonicalContent
        )
        let signature: Data
        do {
            signature = try V3P256Signature.canonicalize(
                owner.signature(
                    for: authorizationInput,
                    reason: authorizationReason
                )
            )
        } catch {
            throw V3DeviceWrappedEnrollmentTransitionError.invalidOwner
        }
        let authorization = V3ManifestAuthorization(
            signerDeviceID: owner.publicIdentity.deviceID,
            signature: Base64URL.encode(signature)
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string(Self.envelopeFormat)),
            ("version", .integer(Self.envelopeVersion)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string(Self.authenticationAlgorithm)),
                ("tag", .string(Base64URL.encode(authenticationTag))),
            ])),
            ("authorizations", .array([
                .object([
                    ("algorithm", .string(Self.authorizationAlgorithm)),
                    ("signerDeviceID", .string(authorization.signerDeviceID)),
                    ("signature", .string(authorization.signature)),
                ]),
            ])),
        ]))
        try validateCandidate(
            manifestData,
            expectedBody: body,
            expectedParent: base.checkpoint.envelopeDigest,
            ownerIdentity: owner.publicIdentity,
            authorizationInput: authorizationInput,
            nextVaultKey: nextVaultKey
        )
        return V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: base.checkpoint,
            body: body,
            manifestData: manifestData,
            manifestDigest: Data(SHA256.hash(data: manifestData)),
            stagedEntries: resealed.map(\.encryptedEntry),
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

    private func resealEntries(
        _ manifestEntries: [V3ManifestEntry],
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        vaultID: String,
        nextKeyID: V3VaultKeyID,
        currentVaultKey: Data,
        nextVaultKey: Data
    ) throws -> [ResealedEntry] {
        var expected = Set<V3EntryObjectKey>()
        for entry in manifestEntries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32 else {
                throw V3DeviceWrappedEnrollmentTransitionError.invalidEntry
            }
            expected.insert(V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            ))
        }
        guard Set(currentEntries.keys) == expected else {
            throw V3DeviceWrappedEnrollmentTransitionError
                .incompleteEntrySnapshot
        }

        var result: [ResealedEntry] = []
        result.reserveCapacity(manifestEntries.count)
        for entry in manifestEntries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), let encrypted = currentEntries[V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            )] else {
                throw V3DeviceWrappedEnrollmentTransitionError
                    .incompleteEntrySnapshot
            }
            do {
                let plaintext = try entryCipher.openTrusted(
                    encrypted.canonicalBytes,
                    vaultID: vaultID,
                    manifestEntry: entry,
                    vaultKey: currentVaultKey
                )
                let resealed = try entryCipher.seal(
                    plaintext,
                    context: V3EntryAuthenticationContext(
                        vaultID: vaultID,
                        entryID: entry.entryID,
                        name: entry.name,
                        type: entry.type,
                        keyID: nextKeyID,
                        revision: entry.revision
                    ),
                    vaultKey: nextVaultKey
                )
                result.append(ResealedEntry(
                    manifestEntry: V3ManifestEntry(
                        entryID: entry.entryID,
                        name: entry.name,
                        type: entry.type,
                        revision: entry.revision,
                        keyID: nextKeyID,
                        ciphertextDigest: resealed.ciphertextDigest
                    ),
                    encryptedEntry: resealed
                ))
            } catch {
                throw V3DeviceWrappedEnrollmentTransitionError.invalidEntry
            }
        }
        return result.sorted {
            v3ManifestEntryPrecedes($0.manifestEntry, $1.manifestEntry)
        }
    }

    private func validateCandidate(
        _ manifestData: Data,
        expectedBody: V3DeviceWrappedManifestBody,
        expectedParent: Data,
        ownerIdentity: V3EnrollmentDeviceIdentity,
        authorizationInput: Data,
        nextVaultKey: Data
    ) throws {
        do {
            let parsed = try envelopeCodec.parse(manifestData)
            guard parsed.parents == [expectedParent],
                  parsed.body == expectedBody,
                  parsed.authorizations.count == 1,
                  parsed.authorizations[0].signerDeviceID
                    == ownerIdentity.deviceID,
                  (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                      parsed.authenticationTag,
                      canonicalContent: parsed.canonicalContentBytes,
                      vaultID: expectedBody.vaultID,
                      vaultKey: nextVaultKey
                  )) == true,
                  let signatureBytes = Base64URL.decodeCanonical(
                      parsed.authorizations[0].signature
                  ),
                  V3P256Signature.isCanonical(signatureBytes)
            else {
                throw V3DeviceWrappedEnrollmentTransitionError.invalidCandidate
            }
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: ownerIdentity.signingPublicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: signatureBytes
            )
            guard publicKey.isValidSignature(
                signature,
                for: SHA256.hash(data: authorizationInput)
            ) else {
                throw V3DeviceWrappedEnrollmentTransitionError.invalidCandidate
            }
        } catch let error as V3DeviceWrappedEnrollmentTransitionError {
            throw error
        } catch {
            throw V3DeviceWrappedEnrollmentTransitionError.invalidCandidate
        }
    }
}

private struct ResealedEntry: Sendable {
    let manifestEntry: V3ManifestEntry
    let encryptedEntry: V3EncryptedEntry
}
