import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3EnrollmentAuthenticationError: Error, Equatable, LocalizedError {
    case invalidFormat
    case unsupportedVersion(UInt64)
    case vaultMismatch
    case signerMismatch
    case invalidSignature

    var errorDescription: String? {
        switch self {
        case .invalidFormat:
            "The signed version 3 device-enrollment message is invalid."
        case .unsupportedVersion(let version):
            "Signed device-enrollment message version \(version) requires a newer version of Key."
        case .vaultMismatch:
            "The device enrollment identity belongs to a different vault."
        case .signerMismatch:
            "The device signing this enrollment message does not match the enclosed identity."
        case .invalidSignature:
            "The device-enrollment message signature is invalid."
        }
    }
}

struct V3EnrollmentMessageAuthentication: Equatable, Sendable {
    let signerDeviceID: String
    let signature: Data

    init(signerDeviceID: String, signature: Data) throws {
        guard let signerID = Base64URL.decodeCanonical(signerDeviceID),
            signerID.count == 32,
            signature.count == 64
        else {
            throw V3EnrollmentAuthenticationError.invalidFormat
        }
        self.signerDeviceID = signerDeviceID
        self.signature = signature
    }

    var canonicalValue: CanonicalJSONValue {
        .object([
            ("algorithm", .string("P-256-ECDSA-SHA256")),
            ("signerDeviceID", .string(signerDeviceID)),
            ("signature", .string(Base64URL.encode(signature))),
        ])
    }
}

struct V3SignedEnrollmentInvitation: Equatable, Sendable {
    static let maximumBytes = 24 * 1_024

    let invitation: V3EnrollmentInvitation
    let authentication: V3EnrollmentMessageAuthentication

    init(
        invitation: V3EnrollmentInvitation,
        authentication: V3EnrollmentMessageAuthentication
    ) {
        self.invitation = invitation
        self.authentication = authentication
    }

    init(canonicalBytes: Data) throws {
        let root = try parseSignedEnrollmentEnvelope(
            canonicalBytes,
            maximumBytes: Self.maximumBytes,
            fields: ["authentication", "format", "invitation", "version"],
            format: "key-vault-enrollment-signed-invitation"
        )
        guard
            let invitationValue = signedEnrollmentMember(
                "invitation",
                in: root
            ),
            let authenticationValue = signedEnrollmentMember(
                "authentication",
                in: root
            )
        else {
            throw V3EnrollmentAuthenticationError.invalidFormat
        }
        invitation = try V3EnrollmentInvitation(
            canonicalBytes: CanonicalJSON.encode(invitationValue)
        )
        authentication = try decodeEnrollmentAuthentication(
            authenticationValue
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-enrollment-signed-invitation")),
                ("version", .integer(1)),
                ("invitation", invitation.canonicalValue),
                ("authentication", authentication.canonicalValue),
            ]))
    }
}

struct V3SignedEnrollmentJoinRequest: Equatable, Sendable {
    static let maximumBytes = 24 * 1_024

    let joinRequest: V3EnrollmentJoinRequest
    let authentication: V3EnrollmentMessageAuthentication

    init(
        joinRequest: V3EnrollmentJoinRequest,
        authentication: V3EnrollmentMessageAuthentication
    ) {
        self.joinRequest = joinRequest
        self.authentication = authentication
    }

    init(canonicalBytes: Data) throws {
        let root = try parseSignedEnrollmentEnvelope(
            canonicalBytes,
            maximumBytes: Self.maximumBytes,
            fields: ["authentication", "format", "joinRequest", "version"],
            format: "key-vault-enrollment-signed-join-request"
        )
        guard
            let joinRequestValue = signedEnrollmentMember(
                "joinRequest",
                in: root
            ),
            let authenticationValue = signedEnrollmentMember(
                "authentication",
                in: root
            )
        else {
            throw V3EnrollmentAuthenticationError.invalidFormat
        }
        joinRequest = try V3EnrollmentJoinRequest(
            canonicalBytes: CanonicalJSON.encode(joinRequestValue)
        )
        authentication = try decodeEnrollmentAuthentication(
            authenticationValue
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                (
                    "format",
                    .string("key-vault-enrollment-signed-join-request")
                ),
                ("version", .integer(1)),
                ("joinRequest", joinRequest.canonicalValue),
                ("authentication", authentication.canonicalValue),
            ]))
    }
}

struct V3VerifiedEnrollmentInvitation: Equatable, Sendable {
    let signedInvitation: V3SignedEnrollmentInvitation

    fileprivate init(signedInvitation: V3SignedEnrollmentInvitation) {
        self.signedInvitation = signedInvitation
    }

    var invitation: V3EnrollmentInvitation {
        signedInvitation.invitation
    }
}

struct V3VerifiedEnrollmentJoinRequest: Equatable, Sendable {
    let signedJoinRequest: V3SignedEnrollmentJoinRequest

    fileprivate init(signedJoinRequest: V3SignedEnrollmentJoinRequest) {
        self.signedJoinRequest = signedJoinRequest
    }

    var joinRequest: V3EnrollmentJoinRequest {
        signedJoinRequest.joinRequest
    }
}

protocol V3EnrollmentMessageSigning: Sendable {
    var vaultID: String { get }
    var publicIdentity: V3EnrollmentDeviceIdentity { get }

    func signature(
        for input: Data,
        reason: String
    ) throws -> Data
}

struct V3EnrollmentMessageAuthenticator: Sendable {
    private static let invitationDomain = Data(
        "work.tvr.key/v3/enrollment-signed-invitation/v1".utf8
    )
    private static let joinRequestDomain = Data(
        "work.tvr.key/v3/enrollment-signed-join-request/v1".utf8
    )

    func sign(
        _ invitation: V3EnrollmentInvitation,
        using signer: any V3EnrollmentMessageSigning,
        reason: String
    ) throws -> V3SignedEnrollmentInvitation {
        guard signer.vaultID == invitation.vaultID else {
            throw V3EnrollmentAuthenticationError.vaultMismatch
        }
        guard signer.publicIdentity == invitation.invitingDevice else {
            throw V3EnrollmentAuthenticationError.signerMismatch
        }
        let signature = try canonicalSignature(
            from: signer,
            input: Self.signatureInput(
                domain: Self.invitationDomain,
                message: invitation.canonicalBytes
            ),
            reason: reason
        )
        let signed = V3SignedEnrollmentInvitation(
            invitation: invitation,
            authentication: try V3EnrollmentMessageAuthentication(
                signerDeviceID: signer.publicIdentity.deviceID,
                signature: signature
            )
        )
        _ = try verify(signed)
        return signed
    }

    func sign(
        _ joinRequest: V3EnrollmentJoinRequest,
        answering verifiedInvitation: V3VerifiedEnrollmentInvitation,
        using signer: any V3EnrollmentMessageSigning,
        reason: String
    ) throws -> V3SignedEnrollmentJoinRequest {
        let invitation = verifiedInvitation.invitation
        guard signer.vaultID == invitation.vaultID else {
            throw V3EnrollmentAuthenticationError.vaultMismatch
        }
        guard joinRequest.invitationDigest == invitation.digest else {
            throw V3EnrollmentProtocolError.invitationMismatch
        }
        guard signer.publicIdentity == joinRequest.joiningDevice else {
            throw V3EnrollmentAuthenticationError.signerMismatch
        }
        let signature = try canonicalSignature(
            from: signer,
            input: Self.signatureInput(
                domain: Self.joinRequestDomain,
                message: joinRequest.canonicalBytes
            ),
            reason: reason
        )
        let signed = V3SignedEnrollmentJoinRequest(
            joinRequest: joinRequest,
            authentication: try V3EnrollmentMessageAuthentication(
                signerDeviceID: signer.publicIdentity.deviceID,
                signature: signature
            )
        )
        _ = try verify(signed)
        return signed
    }

    func verify(
        _ signed: V3SignedEnrollmentInvitation
    ) throws -> V3VerifiedEnrollmentInvitation {
        try verify(
            authentication: signed.authentication,
            identity: signed.invitation.invitingDevice,
            input: Self.signatureInput(
                domain: Self.invitationDomain,
                message: signed.invitation.canonicalBytes
            )
        )
        return V3VerifiedEnrollmentInvitation(signedInvitation: signed)
    }

    func verify(
        _ signed: V3SignedEnrollmentJoinRequest
    ) throws -> V3VerifiedEnrollmentJoinRequest {
        try verify(
            authentication: signed.authentication,
            identity: signed.joinRequest.joiningDevice,
            input: Self.signatureInput(
                domain: Self.joinRequestDomain,
                message: signed.joinRequest.canonicalBytes
            )
        )
        return V3VerifiedEnrollmentJoinRequest(signedJoinRequest: signed)
    }

    private func verify(
        authentication: V3EnrollmentMessageAuthentication,
        identity: V3EnrollmentDeviceIdentity,
        input: Data
    ) throws {
        guard authentication.signerDeviceID == identity.deviceID else {
            throw V3EnrollmentAuthenticationError.signerMismatch
        }
        guard V3P256Signature.isCanonical(authentication.signature) else {
            throw V3EnrollmentAuthenticationError.invalidSignature
        }
        do {
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: identity.signingPublicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: authentication.signature
            )
            guard publicKey.isValidSignature(signature, for: input) else {
                throw V3EnrollmentAuthenticationError.invalidSignature
            }
        } catch let error as V3EnrollmentAuthenticationError {
            throw error
        } catch {
            throw V3EnrollmentAuthenticationError.invalidSignature
        }
    }

    private func canonicalSignature(
        from signer: any V3EnrollmentMessageSigning,
        input: Data,
        reason: String
    ) throws -> Data {
        let rawSignature = try signer.signature(
            for: input,
            reason: reason
        )
        do {
            return try V3P256Signature.canonicalize(rawSignature)
        } catch {
            throw V3EnrollmentAuthenticationError.invalidSignature
        }
    }

    private static func signatureInput(
        domain: Data,
        message: Data
    ) -> Data {
        var input = domain
        input.append(0)
        input.append(message)
        return input
    }
}

private func parseSignedEnrollmentEnvelope(
    _ canonicalBytes: Data,
    maximumBytes: Int,
    fields: Set<String>,
    format: String
) throws -> [(String, CanonicalJSONValue)] {
    guard canonicalBytes.count <= maximumBytes else {
        throw V3EnrollmentAuthenticationError.invalidFormat
    }
    let value: CanonicalJSONValue
    do {
        value = try CanonicalJSON.parse(canonicalBytes)
    } catch {
        throw V3EnrollmentAuthenticationError.invalidFormat
    }
    guard CanonicalJSON.encode(value) == canonicalBytes,
        let object = value.objectValue,
        signedEnrollmentString("format", in: object) == format,
        let version = signedEnrollmentInteger("version", in: object)
    else {
        throw V3EnrollmentAuthenticationError.invalidFormat
    }
    if version > 1 {
        throw V3EnrollmentAuthenticationError.unsupportedVersion(version)
    }
    guard version == 1, Set(object.map(\.0)) == fields else {
        throw V3EnrollmentAuthenticationError.invalidFormat
    }
    return object
}

private func decodeEnrollmentAuthentication(
    _ value: CanonicalJSONValue
) throws -> V3EnrollmentMessageAuthentication {
    guard let object = value.objectValue,
        Set(object.map(\.0))
            == Set(["algorithm", "signature", "signerDeviceID"]),
        signedEnrollmentString("algorithm", in: object)
            == "P-256-ECDSA-SHA256",
        let signerDeviceID = signedEnrollmentString(
            "signerDeviceID",
            in: object
        ),
        let signatureValue = signedEnrollmentString("signature", in: object),
        let signature = Base64URL.decodeCanonical(signatureValue)
    else {
        throw V3EnrollmentAuthenticationError.invalidFormat
    }
    return try V3EnrollmentMessageAuthentication(
        signerDeviceID: signerDeviceID,
        signature: signature
    )
}

private func signedEnrollmentMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func signedEnrollmentString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    signedEnrollmentMember(name, in: object)?.stringValue
}

private func signedEnrollmentInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    signedEnrollmentMember(name, in: object)?.integerValue
}
