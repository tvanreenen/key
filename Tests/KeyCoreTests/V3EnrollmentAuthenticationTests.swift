import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3EnrollmentAuthenticationTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"

    @Test
    func canonicalizationAlwaysPreservesSignatureValidity() throws {
        let signer = try makeSigner(
            name: "Office Mac",
            signingScalar: 0x11,
            wrappingScalar: 0x12
        )
        let invitation = try makeInvitation(identity: signer.publicIdentity)
        let authenticator = V3EnrollmentMessageAuthenticator()
        let verified = try authenticator.verify(authenticator.sign(
            invitation,
            using: signer,
            reason: "Create the enrollment invitation"
        ))
        let joiner = try makeSigner(
            name: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        let request = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0xB1, count: 32)
        )

        for _ in 0..<512 {
            _ = try authenticator.sign(
                invitation,
                using: signer,
                reason: "Exercise canonical enrollment signatures"
            )
            _ = try authenticator.sign(
                request,
                answering: verified,
                using: joiner,
                reason: "Exercise canonical join signatures"
            )

            let input = Data("canonical manifest authorization".utf8)
            let raw = try signer.privateKey.signature(for: input)
            let canonical = try V3P256Signature.canonicalize(
                raw.rawRepresentation
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: canonical
            )
            let digest = SHA256.hash(data: input)
            #expect(signer.privateKey.publicKey.isValidSignature(
                signature,
                for: digest
            ))
        }
    }

    @Test
    func signedMessagesRoundTripAndVerifyExactParticipants() throws {
        let inviter = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let joiner = try makeSigner(
            name: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        let invitation = try makeInvitation(identity: inviter.publicIdentity)
        let joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0xB1, count: 32)
        )
        let authenticator = V3EnrollmentMessageAuthenticator()

        let signedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Approve invitation"
        )
        let parsedInvitation = try V3SignedEnrollmentInvitation(
            canonicalBytes: signedInvitation.canonicalBytes
        )
        let verifiedInvitation = try authenticator.verify(parsedInvitation)
        #expect(
            verifiedInvitation.invitation == invitation
        )

        let signedJoinRequest = try authenticator.sign(
            joinRequest,
            answering: verifiedInvitation,
            using: joiner,
            reason: "Approve join request"
        )
        let parsedJoinRequest = try V3SignedEnrollmentJoinRequest(
            canonicalBytes: signedJoinRequest.canonicalBytes
        )
        #expect(
            try authenticator.verify(parsedJoinRequest).joinRequest
                == joinRequest
        )

        let firstTranscript = try V3EnrollmentTranscript(
            invitation: signedInvitation.invitation,
            joinRequest: signedJoinRequest.joinRequest
        )
        let secondSignedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Approve invitation again"
        )
        let secondTranscript = try V3EnrollmentTranscript(
            invitation: secondSignedInvitation.invitation,
            joinRequest: signedJoinRequest.joinRequest
        )
        #expect(firstTranscript.digest == secondTranscript.digest)
    }

    @Test
    func signingRejectsAnIdentityScopedToAnotherVault() throws {
        let otherVaultID = "028f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        let inviter = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let wrongVaultInvitation = try V3EnrollmentInvitation(
            vaultID: otherVaultID,
            parentManifestDigest: Data(repeating: 0x91, count: 32),
            invitingDevice: inviter.publicIdentity,
            nonce: Data(repeating: 0xA1, count: 32),
            expiresAt: 1_900_000_000
        )
        let authenticator = V3EnrollmentMessageAuthenticator()

        #expect(throws: V3EnrollmentAuthenticationError.vaultMismatch) {
            try authenticator.sign(
                wrongVaultInvitation,
                using: inviter,
                reason: "Sign for another vault"
            )
        }

        let invitation = try makeInvitation(identity: inviter.publicIdentity)
        let verifiedInvitation = try authenticator.verify(
            authenticator.sign(
                invitation,
                using: inviter,
                reason: "Approve invitation"
            )
        )
        let wrongVaultJoiner = try makeSigner(
            vaultID: otherVaultID,
            name: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        let joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: wrongVaultJoiner.publicIdentity,
            nonce: Data(repeating: 0xB1, count: 32)
        )

        #expect(throws: V3EnrollmentAuthenticationError.vaultMismatch) {
            try authenticator.sign(
                joinRequest,
                answering: verifiedInvitation,
                using: wrongVaultJoiner,
                reason: "Join another vault"
            )
        }
    }

    @Test
    func joinSigningRequiresTheExactVerifiedInvitation() throws {
        let inviter = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let joiner = try makeSigner(
            name: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        let invitation = try makeInvitation(identity: inviter.publicIdentity)
        let authenticator = V3EnrollmentMessageAuthenticator()
        let verifiedInvitation = try authenticator.verify(
            authenticator.sign(
                invitation,
                using: inviter,
                reason: "Approve invitation"
            )
        )
        let joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: Data(repeating: 0x92, count: 32),
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0xB1, count: 32)
        )

        #expect(throws: V3EnrollmentProtocolError.invitationMismatch) {
            try authenticator.sign(
                joinRequest,
                answering: verifiedInvitation,
                using: joiner,
                reason: "Answer wrong invitation"
            )
        }
    }

    @Test
    func signingRequiresTheExactEnclosedIdentity() throws {
        let inviter = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let other = try makeSigner(
            name: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        let invitation = try makeInvitation(identity: inviter.publicIdentity)

        #expect(throws: V3EnrollmentAuthenticationError.signerMismatch) {
            try V3EnrollmentMessageAuthenticator().sign(
                invitation,
                using: other,
                reason: "Wrong signer"
            )
        }
    }

    @Test
    func verificationRejectsSubstitutionWrongSignerAndHighS() throws {
        let inviter = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let invitation = try makeInvitation(identity: inviter.publicIdentity)
        let authenticator = V3EnrollmentMessageAuthenticator()
        let signed = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Approve invitation"
        )

        let substitutedInvitation = try V3EnrollmentInvitation(
            vaultID: Self.vaultID,
            parentManifestDigest: Data(repeating: 0x92, count: 32),
            invitingDevice: inviter.publicIdentity,
            nonce: Data(repeating: 0xA1, count: 32),
            expiresAt: 1_900_000_000
        )
        #expect(throws: V3EnrollmentAuthenticationError.invalidSignature) {
            try authenticator.verify(
                V3SignedEnrollmentInvitation(
                    invitation: substitutedInvitation,
                    authentication: signed.authentication
                )
            )
        }

        let other = try makeSigner(
            name: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        let wrongSigner = try V3EnrollmentMessageAuthentication(
            signerDeviceID: other.publicIdentity.deviceID,
            signature: signed.authentication.signature
        )
        #expect(throws: V3EnrollmentAuthenticationError.signerMismatch) {
            try authenticator.verify(
                V3SignedEnrollmentInvitation(
                    invitation: invitation,
                    authentication: wrongSigner
                )
            )
        }

        let highS = try V3EnrollmentMessageAuthentication(
            signerDeviceID: inviter.publicIdentity.deviceID,
            signature: highSSignature(
                fromLowS: signed.authentication.signature
            )
        )
        #expect(throws: V3EnrollmentAuthenticationError.invalidSignature) {
            try authenticator.verify(
                V3SignedEnrollmentInvitation(
                    invitation: invitation,
                    authentication: highS
                )
            )
        }
    }

    @Test
    func invitationSignatureCannotAuthenticateAJoinRequest() throws {
        let signer = try makeSigner(
            name: "One Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let invitation = try makeInvitation(identity: signer.publicIdentity)
        let authenticator = V3EnrollmentMessageAuthenticator()
        let signedInvitation = try authenticator.sign(
            invitation,
            using: signer,
            reason: "Approve invitation"
        )
        let joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: signer.publicIdentity,
            nonce: Data(repeating: 0xB1, count: 32)
        )
        let reusedAuthentication = try V3EnrollmentMessageAuthentication(
            signerDeviceID: signer.publicIdentity.deviceID,
            signature: signedInvitation.authentication.signature
        )

        #expect(throws: V3EnrollmentAuthenticationError.invalidSignature) {
            try authenticator.verify(
                V3SignedEnrollmentJoinRequest(
                    joinRequest: joinRequest,
                    authentication: reusedAuthentication
                )
            )
        }
    }

    @Test
    func envelopeParserRejectsNoncanonicalExtendedAndMalformedBytes() throws {
        let signer = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let signed = try V3EnrollmentMessageAuthenticator().sign(
            makeInvitation(identity: signer.publicIdentity),
            using: signer,
            reason: "Approve invitation"
        )

        var spaced = Data("{ ".utf8)
        spaced.append(signed.canonicalBytes.dropFirst())
        #expect(throws: V3EnrollmentAuthenticationError.invalidFormat) {
            try V3SignedEnrollmentInvitation(canonicalBytes: spaced)
        }

        let extended = replacing(
            signed.canonicalBytes,
            "\"version\":2",
            with: "\"extra\":true,\"version\":2"
        )
        #expect(throws: V3EnrollmentAuthenticationError.invalidFormat) {
            try V3SignedEnrollmentInvitation(canonicalBytes: extended)
        }

        let malformedSignature = replacing(
            signed.canonicalBytes,
            Base64URL.encode(signed.authentication.signature),
            with: Base64URL.encode(Data(repeating: 0xA5, count: 63))
        )
        #expect(throws: V3EnrollmentAuthenticationError.invalidFormat) {
            try V3SignedEnrollmentInvitation(
                canonicalBytes: malformedSignature
            )
        }

        #expect(throws: V3EnrollmentAuthenticationError.invalidFormat) {
            try V3SignedEnrollmentInvitation(
                canonicalBytes: Data(
                    repeating: 0x41,
                    count: V3SignedEnrollmentInvitation.maximumBytes + 1
                )
            )
        }
    }

    @Test
    func canonicalFutureEnvelopeVersionRequiresAnUpgrade() throws {
        let signer = try makeSigner(
            name: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let signed = try V3EnrollmentMessageAuthenticator().sign(
            makeInvitation(identity: signer.publicIdentity),
            using: signer,
            reason: "Approve invitation"
        )
        let futureSchema = replacing(
            signed.canonicalBytes,
            "\"format\":\"key-vault-enrollment-signed-invitation\",\"invitation\":",
            with:
                "\"format\":\"key-vault-enrollment-signed-invitation\",\"futureField\":true,\"invitation\":"
        )
        let futureVersion = replacingLast(
            futureSchema,
            "\"version\":2}",
            with: "\"version\":3}"
        )

        #expect(
            throws: V3EnrollmentAuthenticationError.unsupportedVersion(3)
        ) {
            try V3SignedEnrollmentInvitation(canonicalBytes: futureVersion)
        }
    }

    private func makeInvitation(
        identity: V3EnrollmentDeviceIdentity
    ) throws -> V3EnrollmentInvitation {
        try V3EnrollmentInvitation(
            vaultID: Self.vaultID,
            parentManifestDigest: Data(repeating: 0x91, count: 32),
            invitingDevice: identity,
            nonce: Data(repeating: 0xA1, count: 32),
            expiresAt: 1_900_000_000
        )
    }

    private func makeSigner(
        vaultID: String = Self.vaultID,
        name: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws -> SoftwareEnrollmentSigner {
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: privateKeyBytes(signingScalar)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: privateKeyBytes(wrappingScalar)
        )
        return SoftwareEnrollmentSigner(
            vaultID: vaultID,
            publicIdentity: try V3EnrollmentDeviceIdentity(
                displayName: name,
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey:
                    wrappingKey.publicKey.x963Representation
            ),
            privateKey: signingKey
        )
    }

    private func privateKeyBytes(_ scalar: UInt8) -> Data {
        Data(SHA256.hash(data: Data([scalar])))
    }

    private func replacing(
        _ data: Data,
        _ original: String,
        with replacement: String
    ) -> Data {
        Data(
            String(decoding: data, as: UTF8.self)
                .replacingOccurrences(of: original, with: replacement)
                .utf8
        )
    }

    private func replacingLast(
        _ data: Data,
        _ original: String,
        with replacement: String
    ) -> Data {
        var value = String(decoding: data, as: UTF8.self)
        if let range = value.range(of: original, options: .backwards) {
            value.replaceSubrange(range, with: replacement)
        }
        return Data(value.utf8)
    }

    private func highSSignature(fromLowS signature: Data) -> Data {
        let order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
        ]
        let bytes = Array(signature)
        let s = Array(bytes[32..<64])
        var highS = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for index in stride(from: 31, through: 0, by: -1) {
            let difference = Int(order[index]) - Int(s[index]) - borrow
            if difference < 0 {
                highS[index] = UInt8(difference + 256)
                borrow = 1
            } else {
                highS[index] = UInt8(difference)
                borrow = 0
            }
        }
        return Data(bytes[0..<32] + highS)
    }
}

private struct SoftwareEnrollmentSigner:
    V3EnrollmentMessageSigning,
    Sendable
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let privateKey: P256.Signing.PrivateKey

    func signature(for input: Data, reason _: String) throws -> Data {
        try privateKey.signature(for: input).rawRepresentation
    }
}
