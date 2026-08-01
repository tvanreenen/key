import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3EnrollmentProtocolTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let alternateVaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"

    @Test
    func canonicalMessagesRoundTripAndProduceStableTranscriptVector() throws {
        let invitation = try makeInvitation()
        let joinRequest = try makeJoinRequest(invitation: invitation)

        #expect(
            try V3EnrollmentInvitation(
                canonicalBytes: invitation.canonicalBytes
            ) == invitation
        )
        #expect(
            try V3EnrollmentJoinRequest(
                canonicalBytes: joinRequest.canonicalBytes
            ) == joinRequest
        )

        let transcript = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: joinRequest
        )
        #expect(transcript.comparisonCode == "7a93-fed2-728e-38ad-d125")
        #expect(
            Base64URL.encode(transcript.digest)
                == "epP-0nKOOK3RJUbdQ4lX_GyMOhBMh8537Ve3BSrryqg"
        )
    }

    @Test
    func transcriptBindsVaultHeadRoleExpiryNoncesAndBothDeviceKeys() throws {
        let invitation = try makeInvitation()
        let joinRequest = try makeJoinRequest(invitation: invitation)
        let baseline = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: joinRequest
        ).digest

        let changedInvitations = [
            try makeInvitation(vaultID: Self.alternateVaultID),
            try makeInvitation(parentManifestDigest: Data(repeating: 0xA1, count: 32)),
            try makeInvitation(invitedRole: .owner),
            try makeInvitation(nonce: Data(repeating: 0xA2, count: 32)),
            try makeInvitation(expiresAt: 1_900_000_001),
            try makeInvitation(
                invitingDevice: makeIdentity(
                    name: "Office Mac",
                    signingScalar: 5,
                    wrappingScalar: 2
                )
            ),
            try makeInvitation(
                invitingDevice: makeIdentity(
                    name: "Office Mac",
                    signingScalar: 1,
                    wrappingScalar: 6
                )
            ),
        ]
        for changedInvitation in changedInvitations {
            let changedRequest = try makeJoinRequest(
                invitation: changedInvitation
            )
            let changed = try V3EnrollmentTranscript(
                invitation: changedInvitation,
                joinRequest: changedRequest
            )
            #expect(changed.digest != baseline)
        }

        let changedRequests = [
            try makeJoinRequest(
                invitation: invitation,
                nonce: Data(repeating: 0xB2, count: 32)
            ),
            try makeJoinRequest(
                invitation: invitation,
                joiningDevice: makeIdentity(
                    name: "Travel Mac",
                    signingScalar: 7,
                    wrappingScalar: 4
                )
            ),
            try makeJoinRequest(
                invitation: invitation,
                joiningDevice: makeIdentity(
                    name: "Travel Mac",
                    signingScalar: 3,
                    wrappingScalar: 8
                )
            ),
        ]
        for changedRequest in changedRequests {
            let changed = try V3EnrollmentTranscript(
                invitation: invitation,
                joinRequest: changedRequest
            )
            #expect(changed.digest != baseline)
        }
    }

    @Test
    func transcriptRejectsWrongInvitationSelfEnrollmentAndKeyReuse() throws {
        let invitation = try makeInvitation()
        let joinRequest = try makeJoinRequest(invitation: invitation)
        let wrongRequest = try V3EnrollmentJoinRequest(
            invitationDigest: Data(repeating: 0xFF, count: 32),
            joiningDevice: joinRequest.joiningDevice,
            nonce: joinRequest.nonce
        )
        #expect(throws: V3EnrollmentProtocolError.invitationMismatch) {
            try V3EnrollmentTranscript(
                invitation: invitation,
                joinRequest: wrongRequest
            )
        }

        let selfRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: invitation.invitingDevice,
            nonce: Data(repeating: 0xB1, count: 32)
        )
        #expect(throws: V3EnrollmentProtocolError.sameDevice) {
            try V3EnrollmentTranscript(
                invitation: invitation,
                joinRequest: selfRequest
            )
        }

        let reusedKeyDevice = try makeIdentity(
            name: "Travel Mac",
            signingScalar: 1,
            wrappingScalar: 4
        )
        let reusedKeyRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: reusedKeyDevice,
            nonce: Data(repeating: 0xB1, count: 32)
        )
        #expect(throws: V3EnrollmentProtocolError.publicKeyReuse) {
            try V3EnrollmentTranscript(
                invitation: invitation,
                joinRequest: reusedKeyRequest
            )
        }
    }

    @Test
    func invitationExpiryHasAnExactBoundary() throws {
        let invitation = try makeInvitation(expiresAt: 1_900_000_000)

        try invitation.requireUnexpired(at: 1_900_000_000)
        #expect(throws: V3EnrollmentProtocolError.expired) {
            try invitation.requireUnexpired(at: 1_900_000_001)
        }
    }

    @Test
    func unsupportedVersionsRequireAnUpgradeWithoutLookingCorrupt() throws {
        let invitation = try makeInvitation()
        #expect(
            String(decoding: invitation.canonicalBytes, as: UTF8.self)
                .contains("\"vaultFormatVersion\":3")
        )

        let futureVaultFormat = replacing(
            invitation.canonicalBytes,
            "\"vaultFormatVersion\":3",
            with: "\"vaultFormatVersion\":4"
        )
        #expect(
            Data(SHA256.hash(data: futureVaultFormat)) != invitation.digest
        )
        #expect(
            throws:
                V3EnrollmentProtocolError.unsupportedVaultFormatVersion(4)
        ) {
            try V3EnrollmentInvitation(canonicalBytes: futureVaultFormat)
        }

        let malformedFutureVaultFormat = replacing(
            futureVaultFormat,
            Self.vaultID,
            with: "not-a-canonical-vault-id"
        )
        #expect(throws: V3EnrollmentProtocolError.invalidFormat) {
            try V3EnrollmentInvitation(
                canonicalBytes: malformedFutureVaultFormat
            )
        }

        let futureInvitationVersion = replacing(
            invitation.canonicalBytes,
            "\"version\":1",
            with: "\"version\":2"
        )
        let futureInvitationMessage = replacing(
            futureInvitationVersion,
            "\"format\":\"key-vault-enrollment-invitation\",",
            with:
                "\"format\":\"key-vault-enrollment-invitation\",\"futureField\":true,"
        )
        #expect(
            throws: V3EnrollmentProtocolError.unsupportedMessageVersion(2)
        ) {
            try V3EnrollmentInvitation(
                canonicalBytes: futureInvitationMessage
            )
        }

        let joinRequest = try makeJoinRequest(invitation: invitation)
        let futureJoinVersion = replacing(
            joinRequest.canonicalBytes,
            "\"version\":1",
            with: "\"version\":2"
        )
        let futureJoinMessage = replacing(
            futureJoinVersion,
            "\"format\":\"key-vault-enrollment-join-request\",",
            with:
                "\"format\":\"key-vault-enrollment-join-request\",\"futureField\":true,"
        )
        #expect(
            throws: V3EnrollmentProtocolError.unsupportedMessageVersion(2)
        ) {
            try V3EnrollmentJoinRequest(canonicalBytes: futureJoinMessage)
        }

        #expect(
            throws:
                V3EnrollmentProtocolError.unsupportedVaultFormatVersion(4)
        ) {
            try V3EnrollmentInvitation(
                vaultID: Self.vaultID,
                vaultFormatVersion: 4,
                parentManifestDigest: Data(repeating: 0x91, count: 32),
                invitingDevice: makeIdentity(
                    name: "Office Mac",
                    signingScalar: 1,
                    wrappingScalar: 2
                ),
                invitedRole: .member,
                nonce: Data(repeating: 0xA1, count: 32),
                expiresAt: 1_900_000_000
            )
        }
    }

    @Test
    func parsersRejectNoncanonicalUnknownAndMalformedMessages() throws {
        let invitation = try makeInvitation()
        var spacedInvitation = Data("{ ".utf8)
        spacedInvitation.append(invitation.canonicalBytes.dropFirst())
        #expect(throws: V3EnrollmentProtocolError.invalidFormat) {
            try V3EnrollmentInvitation(canonicalBytes: spacedInvitation)
        }

        let unknownInvitation = replacing(
            invitation.canonicalBytes,
            "\"version\":1",
            with: "\"unknown\":true,\"version\":1"
        )
        #expect(throws: V3EnrollmentProtocolError.invalidFormat) {
            try V3EnrollmentInvitation(canonicalBytes: unknownInvitation)
        }

        let invalidOlderMessage = replacing(
            invitation.canonicalBytes,
            "\"version\":1",
            with: "\"version\":0"
        )
        #expect(throws: V3EnrollmentProtocolError.invalidFormat) {
            try V3EnrollmentInvitation(canonicalBytes: invalidOlderMessage)
        }

        let joinRequest = try makeJoinRequest(invitation: invitation)
        let malformedNonce = replacing(
            joinRequest.canonicalBytes,
            Base64URL.encode(joinRequest.nonce),
            with: Base64URL.encode(Data(repeating: 0xB1, count: 31))
        )
        #expect(throws: V3EnrollmentProtocolError.invalidFormat) {
            try V3EnrollmentJoinRequest(canonicalBytes: malformedNonce)
        }

        let substitutedID = replacing(
            invitation.canonicalBytes,
            invitation.invitingDevice.deviceID,
            with: String(repeating: "A", count: 43)
        )
        #expect(throws: V3EnrollmentProtocolError.invalidDeviceIdentity) {
            try V3EnrollmentInvitation(canonicalBytes: substitutedID)
        }
    }

    private func makeInvitation(
        vaultID: String = Self.vaultID,
        parentManifestDigest: Data = Data(repeating: 0x91, count: 32),
        invitingDevice: V3EnrollmentDeviceIdentity? = nil,
        invitedRole: V3DeviceRole = .member,
        nonce: Data = Data(repeating: 0xA1, count: 32),
        expiresAt: UInt64 = 1_900_000_000
    ) throws -> V3EnrollmentInvitation {
        try V3EnrollmentInvitation(
            vaultID: vaultID,
            parentManifestDigest: parentManifestDigest,
            invitingDevice: invitingDevice
                ?? makeIdentity(
                    name: "Office Mac",
                    signingScalar: 1,
                    wrappingScalar: 2
                ),
            invitedRole: invitedRole,
            nonce: nonce,
            expiresAt: expiresAt
        )
    }

    private func makeJoinRequest(
        invitation: V3EnrollmentInvitation,
        joiningDevice: V3EnrollmentDeviceIdentity? = nil,
        nonce: Data = Data(repeating: 0xB1, count: 32)
    ) throws -> V3EnrollmentJoinRequest {
        try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiningDevice
                ?? makeIdentity(
                    name: "Travel Mac",
                    signingScalar: 3,
                    wrappingScalar: 4
                ),
            nonce: nonce
        )
    }

    private func makeIdentity(
        name: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws -> V3EnrollmentDeviceIdentity {
        var signingBytes = Data(repeating: 0, count: 32)
        signingBytes[31] = signingScalar
        var wrappingBytes = Data(repeating: 0, count: 32)
        wrappingBytes[31] = wrappingScalar
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: signingBytes
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: wrappingBytes
        )
        return try V3EnrollmentDeviceIdentity(
            displayName: name,
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    private func replacing(
        _ data: Data,
        _ original: String,
        with replacement: String
    ) -> Data {
        let string = String(decoding: data, as: UTF8.self)
        return Data(
            string.replacingOccurrences(
                of: original,
                with: replacement
            ).utf8)
    }
}
