import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3ReplacementEnrollmentIntentTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94c3"

    @Test
    func trustedRevocationReviewIsCanonicalAndContainsNoPrivateKeys()
        throws
    {
        let identity = try Self.identity(
            name: "Revoked Mac",
            signing: 0x11,
            wrapping: 0x12
        )
        let signingSecret = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let wrappingSecret = Data([0xFA, 0xCE, 0xCA, 0xFE])
        let target = try Self.target(
            identity,
            signingSecret: signingSecret,
            wrappingSecret: wrappingSecret
        )
        let checkpoint = try Self.checkpoint(byte: 0x21)
        let review = try V3ReplacementEnrollmentReview(
            classification: .revoked(
                target,
                authority: .trustedCheckpoint(checkpoint)
            )
        )

        let decoded = try V3ReplacementEnrollmentReview(
            canonicalBytes: review.canonicalBytes
        )

        #expect(decoded == review)
        #expect(decoded.expectedCheckpoint == checkpoint)
        #expect(decoded.digest == Data(SHA256.hash(
            data: review.canonicalBytes
        )))
        #expect(!review.canonicalBytes.contains(signingSecret))
        #expect(!review.canonicalBytes.contains(wrappingSecret))
        #expect(
            !String(decoding: review.canonicalBytes, as: UTF8.self)
                .contains(Base64URL.encode(signingSecret))
        )
        #expect(
            !String(decoding: review.canonicalBytes, as: UTF8.self)
                .contains(Base64URL.encode(wrappingSecret))
        )
    }

    @Test
    func ownerAuthorizedRevocationReviewRetainsExactEvidence() throws {
        let revoked = try Self.identity(
            name: "Revoked Mac",
            signing: 0x21,
            wrapping: 0x22
        )
        let owner = try Self.identity(
            name: "Owner Mac",
            signing: 0x31,
            wrapping: 0x32
        )
        let target = try Self.target(revoked)
        let parent = try Self.checkpoint(byte: 0x41)
        let manifestDigest = Data(repeating: 0x51, count: 32)
        let review = try V3ReplacementEnrollmentReview(
            classification: .revoked(
                target,
                authority: .ownerAuthorizedRevocation(
                    parentCheckpoint: parent,
                    manifestDigest: manifestDigest,
                    authorizingDevice: owner
                )
            )
        )

        let decoded = try V3ReplacementEnrollmentReview(
            canonicalBytes: review.canonicalBytes
        )

        #expect(decoded == review)
        #expect(decoded.expectedCheckpoint == parent)
        #expect(
            decoded.authority == .ownerAuthorizedRevocation(
                parentCheckpoint: parent,
                manifestDigest: manifestDigest,
                authorizingDevice: owner
            )
        )
    }

    @Test
    func reviewRefusesAnythingExceptAnAuthenticatedRevocation() throws {
        let identity = try Self.identity(
            name: "Active Mac",
            signing: 0x61,
            wrapping: 0x62
        )
        let target = try Self.target(identity)
        let authority = V3ReplacementDeviceIdentityAuthority
            .trustedCheckpoint(try Self.checkpoint(byte: 0x63))

        for classification in [
            V3ReplacementDeviceIdentityClassification.noLocalIdentity,
            .active(target, authority: authority),
            .unrecognized(target, authority: authority),
        ] {
            #expect(
                throws: V3ReplacementEnrollmentIntentError.invalidReview
            ) {
                _ = try V3ReplacementEnrollmentReview(
                    classification: classification
                )
            }
        }
    }

    @Test
    func reviewRejectsMismatchedVaultAndSelfAuthorizedRevocation() throws {
        let identity = try Self.identity(
            name: "Revoked Mac",
            signing: 0x71,
            wrapping: 0x72
        )
        let target = try Self.target(identity)
        let otherCheckpoint = try V3ManifestCheckpoint(
            vaultID: "028f4d38-7d5a-7b20-b0f1-97d6e96c94c3",
            envelopeDigest: Data(repeating: 0x73, count: 32)
        )

        #expect(
            throws: V3ReplacementEnrollmentIntentError.invalidReview
        ) {
            _ = try V3ReplacementEnrollmentReview(
                target: target,
                authority: .trustedCheckpoint(otherCheckpoint)
            )
        }
        #expect(
            throws: V3ReplacementEnrollmentIntentError.invalidReview
        ) {
            _ = try V3ReplacementEnrollmentReview(
                target: target,
                authority: .ownerAuthorizedRevocation(
                    parentCheckpoint: try Self.checkpoint(byte: 0x74),
                    manifestDigest: Data(repeating: 0x75, count: 32),
                    authorizingDevice: identity
                )
            )
        }
    }

    @Test
    func intentRoundTripsAndOnlyAdvancesInCleanupOrder() throws {
        let review = try Self.review()
        let prepared = V3ReplacementEnrollmentIntent(review: review)
        let identityDeleted = try prepared.advanced(
            to: .identityDeleted
        )
        let checkpointDeleted = try identityDeleted.advanced(
            to: .checkpointDeleted
        )

        #expect(
            try V3ReplacementEnrollmentIntent(
                canonicalBytes: prepared.canonicalBytes
            ) == prepared
        )
        #expect(identityDeleted.phase == .identityDeleted)
        #expect(checkpointDeleted.phase == .checkpointDeleted)
        #expect(checkpointDeleted.review == review)
        #expect(
            throws: V3ReplacementEnrollmentIntentError
                .invalidPhaseTransition
        ) {
            _ = try prepared.advanced(to: .checkpointDeleted)
        }
        #expect(
            throws: V3ReplacementEnrollmentIntentError
                .invalidPhaseTransition
        ) {
            _ = try identityDeleted.advanced(to: .prepared)
        }
        #expect(
            throws: V3ReplacementEnrollmentIntentError
                .invalidPhaseTransition
        ) {
            _ = try checkpointDeleted.advanced(to: .checkpointDeleted)
        }
    }

    @Test
    func noncanonicalReviewAndIntentAreRejected() throws {
        let review = try Self.review()
        var reviewBytes = review.canonicalBytes
        reviewBytes.append(0x20)
        #expect(
            throws: V3ReplacementEnrollmentIntentError.invalidReview
        ) {
            _ = try V3ReplacementEnrollmentReview(
                canonicalBytes: reviewBytes
            )
        }

        var intentBytes = V3ReplacementEnrollmentIntent(
            review: review
        ).canonicalBytes
        intentBytes.append(0x0A)
        #expect(
            throws: V3ReplacementEnrollmentIntentError.invalidIntent
        ) {
            _ = try V3ReplacementEnrollmentIntent(
                canonicalBytes: intentBytes
            )
        }
    }

    private static func review() throws -> V3ReplacementEnrollmentReview {
        let identity = try Self.identity(
            name: "Revoked Mac",
            signing: 0x81,
            wrapping: 0x82
        )
        return try V3ReplacementEnrollmentReview(
            classification: .revoked(
                try Self.target(identity),
                authority: .trustedCheckpoint(
                    try Self.checkpoint(byte: 0x83)
                )
            )
        )
    }

    private static func checkpoint(byte: UInt8) throws
        -> V3ManifestCheckpoint
    {
        try V3ManifestCheckpoint(
            vaultID: vaultID,
            envelopeDigest: Data(repeating: byte, count: 32)
        )
    }

    private static func target(
        _ identity: V3EnrollmentDeviceIdentity,
        signingSecret: Data = Data([0x01]),
        wrappingSecret: Data = Data([0x02])
    ) throws -> V3EnrollmentDeviceIdentityDeletionTarget {
        let record = try V3EnrollmentDeviceKeyRecord(
            vaultID: vaultID,
            identity: identity,
            signingKeyRepresentation: signingSecret,
            wrappingKeyRepresentation: wrappingSecret
        )
        return try V3EnrollmentDeviceIdentityDeletionTarget(
            recordData: record.canonicalBytes
        )
    }

    private static func identity(
        name: String,
        signing: UInt8,
        wrapping: UInt8
    ) throws -> V3EnrollmentDeviceIdentity {
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: scalar(signing)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: scalar(wrapping)
        )
        return try V3EnrollmentDeviceIdentity(
            displayName: name,
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(SHA256.hash(data: Data([value])))
    }
}
