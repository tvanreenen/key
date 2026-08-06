import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3EnrollmentOwnerTransitionError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidCeremony
    case parentMismatch
    case inviterIdentityMismatch
    case joiningIdentityConflict
    case invalidVaultKey
    case invalidAuthorization

    var errorDescription: String? {
        switch self {
        case .invalidCeremony:
            "Owner approval requires one complete authenticated enrollment transcript."
        case .parentMismatch:
            "The enrollment invitation no longer names the exact trusted vault head."
        case .inviterIdentityMismatch:
            "The approving Secure Enclave identity does not match the inviting device."
        case .joiningIdentityConflict:
            "The joining identity is already enrolled or reuses an existing device key."
        case .invalidVaultKey:
            "The enrollment vault key does not match the trusted parent manifest."
        case .invalidAuthorization:
            "The owner-authorized enrollment transition could not be created."
        }
    }
}

struct V3EnrollmentOwnerTransitionCandidate: Equatable, Sendable {
    let manifestData: Data
    let verifiedManifest: V3VerifiedManifest
    let transcriptDigest: Data
    let approval: V3EnrollmentPreparedOwnerApproval
}

/// Small device-local retry record for one exact owner approval.
///
/// It retains only the randomized wrapped-key outputs and owner signature,
/// not the vault key or the potentially large manifest body. The candidate is
/// reconstructed from the exact authenticated parent and transcript.
struct V3EnrollmentPreparedOwnerApproval: Equatable, Sendable {
    static let maximumBytes = 16 * 1_024

    let transcriptDigest: Data
    let wrappedKeys: [V3WrappedKey]
    let authorization: V3ManifestAuthorization
    let candidateManifestDigest: Data

    init(
        transcriptDigest: Data,
        wrappedKeys: [V3WrappedKey],
        authorization: V3ManifestAuthorization,
        candidateManifestDigest: Data
    ) throws {
        guard transcriptDigest.count == 32,
            (1 ... 2).contains(wrappedKeys.count),
            wrappedKeys.map(\.deviceID)
                == wrappedKeys.map(\.deviceID)
                .sorted(by: enrollmentUTF8Precedes),
            Set(wrappedKeys.map(\.deviceID)).count == wrappedKeys.count,
            wrappedKeys.allSatisfy({ wrappedKey in
                guard
                    let bytes = Base64URL.decodeCanonical(
                        wrappedKey.ciphertext
                    )
                else {
                    return false
                }
                return
                    (try? V3EnrollmentWrappedVaultKeyCiphertext(
                        combinedBytes: bytes
                    )) != nil
            }),
            Base64URL.decodeCanonical(authorization.signerDeviceID)?
                .count == 32,
            Base64URL.decodeCanonical(authorization.signature)?.count
                == 64,
            candidateManifestDigest.count == 32
        else {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        self.transcriptDigest = transcriptDigest
        self.wrappedKeys = wrappedKeys
        self.authorization = authorization
        self.candidateManifestDigest = candidateManifestDigest
    }

    init(canonicalBytes: Data) throws {
        let value: CanonicalJSONValue
        do {
            value = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        guard canonicalBytes.count <= Self.maximumBytes,
            CanonicalJSON.encode(value) == canonicalBytes,
            let object = value.objectValue,
            Set(object.map(\.0))
                == Set([
                    "authorization", "candidateManifestDigest", "format",
                    "transcriptDigest", "version", "wrappedKeys",
                ]),
            ownerApprovalString("format", in: object)
                == "key-vault-enrollment-owner-approval",
            ownerApprovalInteger("version", in: object) == 1,
            let transcriptDigest = ownerApprovalData(
                "transcriptDigest",
                in: object
            ),
            let candidateManifestDigest = ownerApprovalData(
                "candidateManifestDigest",
                in: object
            ),
            let wrappedValues = ownerApprovalMember(
                "wrappedKeys",
                in: object
            )?.arrayValue,
            let authorizationValue = ownerApprovalMember(
                "authorization",
                in: object
            )?.objectValue,
            let signerDeviceID = ownerApprovalString(
                "signerDeviceID",
                in: authorizationValue
            ),
            let signature = ownerApprovalString(
                "signature",
                in: authorizationValue
            ),
            ownerApprovalString("algorithm", in: authorizationValue)
                == "P-256-ECDSA-SHA256"
        else {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        let wrappedKeys = try wrappedValues.map { value in
            guard let wrapped = value.objectValue,
                Set(wrapped.map(\.0))
                    == Set(["algorithm", "ciphertext", "deviceID"]),
                ownerApprovalString("algorithm", in: wrapped)
                    == "p256-ecies-x963-sha256-aes-gcm",
                let deviceID = ownerApprovalString(
                    "deviceID",
                    in: wrapped
                ),
                let ciphertext = ownerApprovalString(
                    "ciphertext",
                    in: wrapped
                )
            else {
                throw V3EnrollmentOwnerTransitionError.invalidAuthorization
            }
            return V3WrappedKey(
                deviceID: deviceID,
                ciphertext: ciphertext
            )
        }
        try self.init(
            transcriptDigest: transcriptDigest,
            wrappedKeys: wrappedKeys,
            authorization: V3ManifestAuthorization(
                signerDeviceID: signerDeviceID,
                signature: signature
            ),
            candidateManifestDigest: candidateManifestDigest
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-enrollment-owner-approval")),
                ("version", .integer(1)),
                (
                    "transcriptDigest",
                    .string(Base64URL.encode(transcriptDigest))
                ),
                (
                    "wrappedKeys",
                    .array(wrappedKeys.map(enrollmentWrappedKeyValue))
                ),
                (
                    "authorization",
                    enrollmentAuthorizationValue(authorization)
                ),
                (
                    "candidateManifestDigest",
                    .string(Base64URL.encode(candidateManifestDigest))
                ),
            ]))
    }
}

/// Pure construction of one owner-approved membership addition from an exact
/// vault head and independently compared enrollment transcript.
struct V3EnrollmentOwnerTransitionBuilder: Sendable {
    private let wrapper: any V3EnrollmentVaultKeyWrapping
    private let authenticator: V3ManifestAuthenticator
    private let messageAuthenticator: V3EnrollmentMessageAuthenticator

    init(
        wrapper: any V3EnrollmentVaultKeyWrapping =
            V3EnrollmentVaultKeyWrapper(),
        authenticator: V3ManifestAuthenticator = V3ManifestAuthenticator(),
        messageAuthenticator: V3EnrollmentMessageAuthenticator =
            V3EnrollmentMessageAuthenticator()
    ) {
        self.wrapper = wrapper
        self.authenticator = authenticator
        self.messageAuthenticator = messageAuthenticator
    }

    func build(
        state: V3EnrollmentCeremonyState,
        parent: V3VerifiedManifest,
        vaultKey: Data,
        inviterIdentity: any V3EnrollmentMessageSigning,
        authorizationReason: String
    ) throws -> V3EnrollmentOwnerTransitionCandidate {
        guard state.role == .inviter,
            state.phase == .awaitingComparison,
            let signedJoinRequest = state.signedJoinRequest,
            let transcript = state.transcript,
            !authorizationReason.isEmpty
        else {
            throw V3EnrollmentOwnerTransitionError.invalidCeremony
        }
        _ = try messageAuthenticator.verify(state.signedInvitation)
        _ = try messageAuthenticator.verify(signedJoinRequest)

        let invitation = transcript.invitation
        let joinRequest = transcript.joinRequest
        let parentBody = parent.envelope.content.manifest
        guard invitation.vaultID == parentBody.vaultID,
            invitation.parentManifestDigest == parent.envelopeDigest
        else {
            throw V3EnrollmentOwnerTransitionError.parentMismatch
        }
        guard inviterIdentity.vaultID == invitation.vaultID,
            inviterIdentity.publicIdentity == invitation.invitingDevice
        else {
            throw V3EnrollmentOwnerTransitionError
                .inviterIdentityMismatch
        }
        guard vaultKey.count == 32,
            (try? V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: parentBody.vaultID
            )) == parentBody.keyID
        else {
            throw V3EnrollmentOwnerTransitionError.invalidVaultKey
        }

        let joiningDevice = enrollmentTransitionDevice(
            joinRequest.joiningDevice,
            role: invitation.invitedRole
        )
        let devices: [V3ManifestDevice]
        let identitiesToWrap: [V3EnrollmentDeviceIdentity]
        switch parentBody.mode {
        case .local:
            guard parentBody.devices.isEmpty,
                  parentBody.wrappedKeys.isEmpty
            else {
                throw V3EnrollmentOwnerTransitionError.parentMismatch
            }
            devices = [
                enrollmentTransitionDevice(
                    invitation.invitingDevice,
                    role: .owner
                ),
                joiningDevice,
            ].sorted {
                enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
            }
            identitiesToWrap = [
                invitation.invitingDevice,
                joinRequest.joiningDevice,
            ]
        case .shared:
            guard let inviter = parentBody.devices.first(where: {
                $0.deviceID == invitation.invitingDevice.deviceID
            }),
                  inviter.role == .owner,
                  inviter.status == .active,
                  invitation.invitingDevice.matchesManifestDevice(inviter)
            else {
                throw V3EnrollmentOwnerTransitionError
                    .inviterIdentityMismatch
            }
            guard !parentBody.devices.contains(where: {
                $0.deviceID == joiningDevice.deviceID
            }),
            joinRequest.joiningDevice.usesDistinctKeys(
                from: parentBody.devices
            ) else {
                throw V3EnrollmentOwnerTransitionError
                    .joiningIdentityConflict
            }
            devices = (parentBody.devices + [joiningDevice]).sorted {
                enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
            }
            identitiesToWrap = [joinRequest.joiningDevice]
        }
        let newWrappedKeys = try identitiesToWrap.map { identity in
            let context = try V3EnrollmentVaultKeyWrapContext(
                vaultID: parentBody.vaultID,
                keyID: parentBody.keyID,
                recipientDeviceID: identity.deviceID,
                transcriptDigest: transcript.digest
            )
            let ciphertext = try wrapper.wrap(
                vaultKey: vaultKey,
                recipientPublicKey: identity.wrappingPublicKey,
                context: context
            )
            _ = try V3EnrollmentWrappedVaultKeyCiphertext(
                combinedBytes: ciphertext
            )
            return V3WrappedKey(
                deviceID: identity.deviceID,
                ciphertext: Base64URL.encode(ciphertext)
            )
        }.sorted {
            enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
        }
        let wrappedKeys = (
            parentBody.mode == .local
                ? newWrappedKeys
                : parentBody.wrappedKeys + newWrappedKeys
        ).sorted {
            enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
        }
        let body = V3ManifestBody(
            vaultID: parentBody.vaultID,
            mode: .shared,
            keyID: parentBody.keyID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: parentBody.entries
        )
        let content = enrollmentManifestContentValue(
            parentDigest: parent.envelopeDigest,
            body: body
        )
        let canonicalContent = CanonicalJSON.encode(content)
        let authenticationTag =
            try V3ManifestAuthenticator
            .authenticationTag(
                canonicalContent: canonicalContent,
                vaultID: body.vaultID,
                vaultKey: vaultKey
            )
        let manifestInput = V3ManifestAuthenticator.authenticationInput(
            for: canonicalContent
        )
        // The first local-to-shared transition retains its released
        // transcript-specific signature convention. Later shared authority
        // changes use the ordinary manifest authorization convention.
        let authorizationInput = parentBody.mode == .local
            ? Data(SHA256.hash(data: manifestInput))
            : manifestInput
        let authorizationSignature: Data
        do {
            authorizationSignature = try V3P256Signature.canonicalize(
                inviterIdentity.signature(
                    for: authorizationInput,
                    reason: authorizationReason
                )
            )
        } catch {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        let authorization = V3ManifestAuthorization(
            signerDeviceID: invitation.invitingDevice.deviceID,
            signature: Base64URL.encode(authorizationSignature)
        )
        let manifestData = CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-manifest-envelope")),
                ("version", .integer(3)),
                ("content", content),
                (
                    "authentication",
                    .object([
                        (
                            "algorithm",
                            .string("HKDF-SHA256+HMAC-SHA256")
                        ),
                        ("tag", .string(Base64URL.encode(authenticationTag))),
                    ])
                ),
                (
                    "authorizations",
                    .array([enrollmentAuthorizationValue(authorization)])
                ),
            ]))
        let verified = try authenticator.verifyOwnerApprovedEnrollment(
            manifestData,
            vaultKey: vaultKey,
            parent: parent,
            transcript: transcript
        )
        let approval = try V3EnrollmentPreparedOwnerApproval(
            transcriptDigest: transcript.digest,
            wrappedKeys: newWrappedKeys,
            authorization: authorization,
            candidateManifestDigest: verified.envelopeDigest
        )
        return V3EnrollmentOwnerTransitionCandidate(
            manifestData: manifestData,
            verifiedManifest: verified,
            transcriptDigest: transcript.digest,
            approval: approval
        )
    }

    /// Reconstructs the exact randomized candidate after a retry or restart.
    /// No Secure Enclave signature or fresh wrapping randomness is requested.
    func rebuild(
        state: V3EnrollmentCeremonyState,
        parent: V3VerifiedManifest,
        vaultKey: Data,
        approval: V3EnrollmentPreparedOwnerApproval
    ) throws -> V3EnrollmentOwnerTransitionCandidate {
        guard state.role == .inviter,
            state.phase == .publishingApproval,
            let signedJoinRequest = state.signedJoinRequest,
            let transcript = state.transcript,
            transcript.digest == approval.transcriptDigest
        else {
            throw V3EnrollmentOwnerTransitionError.invalidCeremony
        }
        _ = try messageAuthenticator.verify(state.signedInvitation)
        _ = try messageAuthenticator.verify(signedJoinRequest)
        let invitation = transcript.invitation
        let joinRequest = transcript.joinRequest
        let parentBody = parent.envelope.content.manifest
        guard invitation.vaultID == parentBody.vaultID,
            invitation.parentManifestDigest == parent.envelopeDigest,
            vaultKey.count == 32,
            (try? V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: parentBody.vaultID
            )) == parentBody.keyID
        else {
            throw V3EnrollmentOwnerTransitionError.parentMismatch
        }

        let joiningDevice = enrollmentTransitionDevice(
            joinRequest.joiningDevice,
            role: invitation.invitedRole
        )
        let devices: [V3ManifestDevice]
        let expectedWrappedDeviceIDs: [String]
        let wrappedKeys: [V3WrappedKey]
        switch parentBody.mode {
        case .local:
            guard parentBody.devices.isEmpty,
                  parentBody.wrappedKeys.isEmpty
            else {
                throw V3EnrollmentOwnerTransitionError.parentMismatch
            }
            devices = [
                enrollmentTransitionDevice(
                    invitation.invitingDevice,
                    role: .owner
                ),
                joiningDevice,
            ].sorted {
                enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
            }
            expectedWrappedDeviceIDs = devices.map(\.deviceID)
            wrappedKeys = approval.wrappedKeys
        case .shared:
            guard let inviter = parentBody.devices.first(where: {
                $0.deviceID == invitation.invitingDevice.deviceID
            }),
                  inviter.role == .owner,
                  inviter.status == .active,
                  invitation.invitingDevice.matchesManifestDevice(inviter)
            else {
                throw V3EnrollmentOwnerTransitionError.parentMismatch
            }
            guard !parentBody.devices.contains(where: {
                $0.deviceID == joiningDevice.deviceID
            }),
            joinRequest.joiningDevice.usesDistinctKeys(
                from: parentBody.devices
            ) else {
                throw V3EnrollmentOwnerTransitionError
                    .joiningIdentityConflict
            }
            devices = (parentBody.devices + [joiningDevice]).sorted {
                enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
            }
            expectedWrappedDeviceIDs = [joiningDevice.deviceID]
            wrappedKeys = (
                parentBody.wrappedKeys + approval.wrappedKeys
            ).sorted {
                enrollmentUTF8Precedes($0.deviceID, $1.deviceID)
            }
        }
        guard
            approval.wrappedKeys.map(\.deviceID)
                == expectedWrappedDeviceIDs,
            approval.authorization.signerDeviceID
                == invitation.invitingDevice.deviceID
        else {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        let body = V3ManifestBody(
            vaultID: parentBody.vaultID,
            mode: .shared,
            keyID: parentBody.keyID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: parentBody.entries
        )
        let content = enrollmentManifestContentValue(
            parentDigest: parent.envelopeDigest,
            body: body
        )
        let canonicalContent = CanonicalJSON.encode(content)
        let authenticationTag =
            try V3ManifestAuthenticator
            .authenticationTag(
                canonicalContent: canonicalContent,
                vaultID: body.vaultID,
                vaultKey: vaultKey
            )
        let manifestData = CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-manifest-envelope")),
                ("version", .integer(3)),
                ("content", content),
                (
                    "authentication",
                    .object([
                        (
                            "algorithm",
                            .string("HKDF-SHA256+HMAC-SHA256")
                        ),
                        ("tag", .string(Base64URL.encode(authenticationTag))),
                    ])
                ),
                (
                    "authorizations",
                    .array([
                        enrollmentAuthorizationValue(
                            approval.authorization
                        )
                    ])
                ),
            ]))
        guard
            Data(SHA256.hash(data: manifestData))
                == approval.candidateManifestDigest
        else {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        let verified = try authenticator.verifyOwnerApprovedEnrollment(
            manifestData,
            vaultKey: vaultKey,
            parent: parent,
            transcript: transcript
        )
        return V3EnrollmentOwnerTransitionCandidate(
            manifestData: manifestData,
            verifiedManifest: verified,
            transcriptDigest: transcript.digest,
            approval: approval
        )
    }
}

private func enrollmentTransitionDevice(
    _ identity: V3EnrollmentDeviceIdentity,
    role: V3DeviceRole
) -> V3ManifestDevice {
    V3ManifestDevice(
        deviceID: identity.deviceID,
        displayName: identity.displayName,
        role: role,
        status: .active,
        signingPublicKey: V3DevicePublicKey(
            value: Base64URL.encode(identity.signingPublicKey)
        ),
        wrappingPublicKey: V3DevicePublicKey(
            value: Base64URL.encode(identity.wrappingPublicKey)
        )
    )
}

private func enrollmentManifestContentValue(
    parentDigest: Data,
    body: V3ManifestBody
) -> CanonicalJSONValue {
    .object([
        (
            "parents",
            .array([.string(Base64URL.encode(parentDigest))])
        ),
        (
            "manifest",
            .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(body.vaultID)),
                ("mode", .string(body.mode.rawValue)),
                ("keyID", .string(body.keyID.rawValue)),
                (
                    "devices",
                    .array(body.devices.map(enrollmentManifestDeviceValue))
                ),
                (
                    "wrappedKeys",
                    .array(
                        body.wrappedKeys.map {
                            .object([
                                ("deviceID", .string($0.deviceID)),
                                (
                                    "algorithm",
                                    .string(
                                        "p256-ecies-x963-sha256-aes-gcm"
                                    )
                                ),
                                ("ciphertext", .string($0.ciphertext)),
                            ])
                        })
                ),
                (
                    "entries",
                    .array(
                        body.entries.map {
                            .object([
                                ("entryID", .string($0.entryID)),
                                ("name", .string($0.name)),
                                ("type", .string($0.type.rawValue)),
                                ("revision", .integer($0.revision)),
                                ("keyID", .string($0.keyID.rawValue)),
                                (
                                    "ciphertextDigest",
                                    .string($0.ciphertextDigest)
                                ),
                            ])
                        })
                ),
            ])
        ),
    ])
}

private func enrollmentManifestDeviceValue(
    _ device: V3ManifestDevice
) -> CanonicalJSONValue {
    .object([
        ("deviceID", .string(device.deviceID)),
        ("displayName", .string(device.displayName)),
        ("role", .string(device.role.rawValue)),
        ("status", .string(device.status.rawValue)),
        (
            "signingPublicKey",
            .object([
                ("algorithm", .string("P-256-ECDSA")),
                ("encoding", .string("x963")),
                ("value", .string(device.signingPublicKey.value)),
            ])
        ),
        (
            "wrappingPublicKey",
            .object([
                ("algorithm", .string("P-256-ECDH")),
                ("encoding", .string("x963")),
                ("value", .string(device.wrappingPublicKey.value)),
            ])
        ),
    ])
}

private func enrollmentWrappedKeyValue(
    _ wrappedKey: V3WrappedKey
) -> CanonicalJSONValue {
    .object([
        ("deviceID", .string(wrappedKey.deviceID)),
        (
            "algorithm",
            .string("p256-ecies-x963-sha256-aes-gcm")
        ),
        ("ciphertext", .string(wrappedKey.ciphertext)),
    ])
}

private func enrollmentAuthorizationValue(
    _ authorization: V3ManifestAuthorization
) -> CanonicalJSONValue {
    .object([
        ("algorithm", .string("P-256-ECDSA-SHA256")),
        ("signerDeviceID", .string(authorization.signerDeviceID)),
        ("signature", .string(authorization.signature)),
    ])
}

private func ownerApprovalMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func ownerApprovalString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    ownerApprovalMember(name, in: object)?.stringValue
}

private func ownerApprovalInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    ownerApprovalMember(name, in: object)?.integerValue
}

private func ownerApprovalData(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> Data? {
    guard let encoded = ownerApprovalString(name, in: object),
        let data = Base64URL.decodeCanonical(encoded),
        data.count == 32
    else {
        return nil
    }
    return data
}

private func enrollmentUTF8Precedes(
    _ lhs: String,
    _ rhs: String
) -> Bool {
    Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
}
