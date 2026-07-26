import CryptoKit
import Foundation
import Testing
@testable import KeyCore

struct V3ManifestAuthenticationTests {
    @Test
    func manifestAuthenticationMatchesIndependentHKDFAndHMACVector() throws {
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: Data("{}".utf8),
            vaultID: Fixture.vaultID,
            vaultKey: Fixture.vaultKey
        )

        #expect(tag.hex == "c6723b1c5ac2944e59c3179df901b9f316947dcee71beb9ad40581c1df3e0f14")
    }

    @Test
    func localGenesisAuthenticatesWithExplicitVaultTrustAnchor() throws {
        let fixture = Fixture()
        let envelope = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )

        let verified = try V3ManifestAuthenticator().verify(
            envelope,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
        )

        #expect(verified.envelope.content.manifest.vaultID == Fixture.vaultID)
        #expect(verified.envelope.content.manifest.entries.first?.name == "email/personal")
        #expect(verified.envelopeDigest == Data(SHA256.hash(data: envelope)))
    }

    @Test
    func localGenesisRejectsWrongKeyAndUntrustedVaultIdentity() throws {
        let fixture = Fixture()
        let envelope = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )

        #expect(throws: V3ManifestError.authenticationFailed) {
            try V3ManifestAuthenticator().verify(
                envelope,
                vaultKey: Data(repeating: 0xAA, count: 32),
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }
        #expect(throws: V3ManifestError.parentMismatch) {
            try V3ManifestAuthenticator().verify(
                envelope,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4")
            )
        }
    }

    @Test
    func parserRejectsNonCanonicalDuplicateUnknownAndFutureJSON() throws {
        let fixture = Fixture()
        let canonical = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        var spaced = Data("{ ".utf8)
        spaced.append(canonical.dropFirst())

        #expect(throws: V3ManifestError.nonCanonicalJSON) {
            _ = try V3ManifestAuthenticator().parse(spaced)
        }
        #expect(throws: V3ManifestError.duplicateProperty) {
            try V3ManifestAuthenticator().parse(
                Data("{\"format\":\"key-vault-manifest-envelope\",\"format\":\"key-vault-manifest-envelope\",\"version\":3}".utf8)
            )
        }
        #expect(throws: V3ManifestError.invalidStructure("$")) {
            try V3ManifestAuthenticator().parse(
                Data("{\"bogus\":true,\"format\":\"key-vault-manifest-envelope\",\"version\":3}".utf8)
            )
        }
        #expect(throws: V3ManifestError.unsupportedVersion(4)) {
            try V3ManifestAuthenticator().parse(
                Data("{\"format\":\"key-vault-manifest-envelope\",\"version\":4}".utf8)
            )
        }
        #expect(throws: V3ManifestError.invalidEncoding) {
            var bom = Data([0xEF, 0xBB, 0xBF])
            bom.append(canonical)
            _ = try V3ManifestAuthenticator().parse(bom)
        }
    }

    @Test
    func changingAnyManifestBodyFieldWithoutRetaggingIsRejected() throws {
        let fixture = Fixture()
        let envelope = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let replacements = [
            ("format", "\"format\":\"key-vault-manifest\"", "\"format\":\"key-vault-other\""),
            ("version", "\"version\":3,\"wrappedKeys\"", "\"version\":4,\"wrappedKeys\""),
            ("vaultID", Fixture.vaultID, "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"),
            ("mode", "\"mode\":\"local\"", "\"mode\":\"shared\""),
            ("generation", "\"generation\":1,\"keyEpoch\"", "\"generation\":2,\"keyEpoch\""),
            ("keyEpoch", "\"keyEpoch\":1,\"mode\"", "\"keyEpoch\":2,\"mode\""),
            ("deviceID", fixture.deviceID, String(repeating: "A", count: 43)),
            ("displayName", "\"displayName\":\"Laptop\"", "\"displayName\":\"Desktop\""),
            ("role", "\"role\":\"owner\"", "\"role\":\"member\""),
            ("status", "\"status\":\"active\"", "\"status\":\"revoked\""),
            ("signingPublicKey", fixture.signingPublicKeyValue, fixture.alternateSigningPublicKeyValue),
            ("wrappingPublicKey", fixture.wrappingPublicKeyValue, fixture.alternateWrappingPublicKeyValue),
            ("enrolledAtGeneration", "\"enrolledAtGeneration\":0", "\"enrolledAtGeneration\":1"),
            ("wrappedKeyEpoch", "\"ciphertext\":\"AQID\",\"deviceID\"", "\"ciphertext\":\"BAUG\",\"deviceID\""),
            ("entryID", Fixture.entryID, "018f4d39-930c-735d-8d6f-588e9b0a3a49"),
            ("entryName", "\"name\":\"email/personal\"", "\"name\":\"email/work\""),
            ("entryType", "\"type\":\"secret\"", "\"type\":\"totp\""),
            ("entryRevision", "\"revision\":4", "\"revision\":5"),
            ("entryKeyEpoch", "\"keyEpoch\":1,\"name\"", "\"keyEpoch\":0,\"name\""),
            ("ciphertextDigest", Fixture.digest, String(repeating: "B", count: 43))
        ]

        for (field, original, replacement) in replacements {
            let mutated = replacing(envelope, original, with: replacement)
            do {
                _ = try V3ManifestAuthenticator().verify(
                    mutated,
                    vaultKey: Fixture.vaultKey,
                    trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
                )
                Issue.record("Mutation of \(field) was accepted.")
            } catch {
                // Every body-field mutation must fail before authenticated state is returned.
            }
        }
    }

    @Test
    func entryOnlyChildAuthenticatesWithoutOwnerPresence() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                generation: 1,
                entryRevision: 4
            )
        )
        let child = try fixture.envelope(
            content: fixture.content(
                parent: fixture.parentReference(to: parent, generation: 1),
                generation: 2,
                entryRevision: 5
            )
        )

        let verified = try V3ManifestAuthenticator().verify(
            child,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .parent(parent)
        )

        #expect(verified.envelope.content.manifest.generation == 2)
        #expect(verified.envelope.authorizations.isEmpty)
    }

    @Test
    func childMustExtendTheExactTrustedParent() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let otherParent = replacing(parent, Fixture.digest, with: String(repeating: "C", count: 43))
        let child = try fixture.envelope(
            content: fixture.content(
                parent: fixture.parentReference(to: otherParent, generation: 1),
                generation: 2
            )
        )

        #expect(throws: V3ManifestError.parentMismatch) {
            try V3ManifestAuthenticator().verify(
                child,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }
    }

    @Test
    func authorityChangeRequiresActiveParentOwnerSignature() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let candidateContent = fixture.content(
            parent: fixture.parentReference(to: parent, generation: 1),
            generation: 2,
            keyEpoch: 2
        )
        let unsigned = try fixture.envelope(content: candidateContent)

        #expect(throws: V3ManifestError.authorizationRequired) {
            try V3ManifestAuthenticator().verify(
                unsigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let signed = try fixture.envelope(
            content: candidateContent,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)]
        )
        let verified = try V3ManifestAuthenticator().verify(
            signed,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .parent(parent)
        )
        #expect(verified.envelope.content.manifest.keyEpoch == 2)
        #expect(verified.envelope.authorizations.map(\.signerDeviceID) == [fixture.deviceID])
    }

    @Test
    func invalidMemberCandidateAndHighSSignaturesFailClosed() throws {
        let ownerFixture = Fixture()
        let memberParent = try ownerFixture.envelope(
            content: ownerFixture.content(
                parent: .object([("kind", .string("genesis"))]),
                role: .member
            )
        )
        let memberCandidateContent = ownerFixture.content(
            parent: ownerFixture.parentReference(to: memberParent, generation: 1),
            generation: 2,
            keyEpoch: 2,
            role: .member
        )
        let memberSigned = try ownerFixture.envelope(
            content: memberCandidateContent,
            signers: [(ownerFixture.deviceID, ownerFixture.signingPrivateKey)]
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                memberSigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(memberParent)
            )
        }

        let emptyParent = try ownerFixture.envelope(
            content: ownerFixture.content(
                parent: .object([("kind", .string("genesis"))]),
                includeDevice: false
            )
        )
        let introducedContent = ownerFixture.content(
            parent: ownerFixture.parentReference(to: emptyParent, generation: 1),
            generation: 2
        )
        let introducedSigned = try ownerFixture.envelope(
            content: introducedContent,
            signers: [(ownerFixture.deviceID, ownerFixture.signingPrivateKey)]
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                introducedSigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(emptyParent)
            )
        }

        let ownerParent = try ownerFixture.envelope(
            content: ownerFixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let ownerCandidateContent = ownerFixture.content(
            parent: ownerFixture.parentReference(to: ownerParent, generation: 1),
            generation: 2,
            keyEpoch: 2
        )
        let highSSigned = try ownerFixture.envelope(
            content: ownerCandidateContent,
            signers: [(ownerFixture.deviceID, ownerFixture.signingPrivateKey)],
            forceHighS: true
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                highSSigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(ownerParent)
            )
        }
    }

    @Test
    func entryOnlyTransitionRejectsInjectedAuthorization() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let content = fixture.content(
            parent: fixture.parentReference(to: parent, generation: 1),
            generation: 2,
            entryRevision: 5
        )
        let signed = try fixture.envelope(
            content: content,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)]
        )

        #expect(throws: V3ManifestError.unexpectedAuthorization) {
            try V3ManifestAuthenticator().verify(
                signed,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }
    }

    @Test
    func authenticatedSemanticViolationsRemainUntrusted() throws {
        let fixture = Fixture()
        let badName = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                entryName: "../escape"
            )
        )
        #expect(throws: V3ManifestError.semanticViolation("entries.name")) {
            try V3ManifestAuthenticator().verify(
                badName,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }

        let wrongDeviceID = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                deviceID: String(repeating: "A", count: 43)
            )
        )
        #expect(throws: V3ManifestError.semanticViolation("devices.deviceID")) {
            try V3ManifestAuthenticator().verify(
                wrongDeviceID,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }
    }
}

private struct Fixture {
    static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    static let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    static let digest = String(repeating: "A", count: 43)
    static let vaultKey = Data((0..<32).map(UInt8.init))

    let signingPrivateKey = P256.Signing.PrivateKey()
    let wrappingPrivateKey = P256.KeyAgreement.PrivateKey()
    let alternateSigningPrivateKey = P256.Signing.PrivateKey()
    let alternateWrappingPrivateKey = P256.KeyAgreement.PrivateKey()

    var signingPublicKeyValue: String {
        encodeBase64URL(signingPrivateKey.publicKey.x963Representation)
    }

    var wrappingPublicKeyValue: String {
        encodeBase64URL(wrappingPrivateKey.publicKey.x963Representation)
    }

    var alternateSigningPublicKeyValue: String {
        encodeBase64URL(alternateSigningPrivateKey.publicKey.x963Representation)
    }

    var alternateWrappingPublicKeyValue: String {
        encodeBase64URL(alternateWrappingPrivateKey.publicKey.x963Representation)
    }

    var deviceID: String {
        V3ManifestAuthenticator.deviceID(
            signingPublicKey: signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingPrivateKey.publicKey.x963Representation
        )
    }

    func content(
        parent: V3JSONValue,
        generation: UInt64 = 1,
        keyEpoch: UInt64 = 1,
        role: V3DeviceRole = .owner,
        includeDevice: Bool = true,
        deviceID overriddenDeviceID: String? = nil,
        entryName: String = "email/personal",
        entryRevision: UInt64 = 4
    ) -> V3JSONValue {
        .object([
            ("parent", parent),
            ("manifest", manifest(
                generation: generation,
                keyEpoch: keyEpoch,
                role: role,
                includeDevice: includeDevice,
                deviceID: overriddenDeviceID,
                entryName: entryName,
                entryRevision: entryRevision
            ))
        ])
    }

    func manifest(
        generation: UInt64,
        keyEpoch: UInt64,
        role: V3DeviceRole,
        includeDevice: Bool,
        deviceID overriddenDeviceID: String?,
        entryName: String,
        entryRevision: UInt64
    ) -> V3JSONValue {
        let actualDeviceID = overriddenDeviceID ?? deviceID
        let devices: [V3JSONValue] = includeDevice ? [
            .object([
                ("deviceID", .string(actualDeviceID)),
                ("displayName", .string("Laptop")),
                ("role", .string(role.rawValue)),
                ("status", .string("active")),
                ("signingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDSA")),
                    ("encoding", .string("x963")),
                    ("value", .string(signingPublicKeyValue))
                ])),
                ("wrappingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDH")),
                    ("encoding", .string("x963")),
                    ("value", .string(wrappingPublicKeyValue))
                ])),
                ("enrolledAtGeneration", .integer(0))
            ])
        ] : []
        let wrappedKeys: [V3JSONValue] = includeDevice ? [
            .object([
                ("deviceID", .string(actualDeviceID)),
                ("keyEpoch", .integer(keyEpoch)),
                ("algorithm", .string("p256-ecies-x963-sha256-aes-gcm")),
                ("ciphertext", .string("AQID"))
            ])
        ] : []

        return .object([
            ("format", .string("key-vault-manifest")),
            ("version", .integer(3)),
            ("vaultID", .string(Self.vaultID)),
            ("mode", .string("local")),
            ("generation", .integer(generation)),
            ("keyEpoch", .integer(keyEpoch)),
            ("devices", .array(devices)),
            ("wrappedKeys", .array(wrappedKeys)),
            ("entries", .array([
                .object([
                    ("entryID", .string(Self.entryID)),
                    ("name", .string(entryName)),
                    ("type", .string("secret")),
                    ("revision", .integer(entryRevision)),
                    ("keyEpoch", .integer(min(keyEpoch, 1))),
                    ("ciphertextDigest", .string(Self.digest))
                ])
            ]))
        ])
    }

    func parentReference(to envelope: Data, generation: UInt64) -> V3JSONValue {
        .object([
            ("kind", .string("manifest")),
            ("generation", .integer(generation)),
            ("digest", .string(encodeBase64URL(Data(SHA256.hash(data: envelope)))))
        ])
    }

    func envelope(
        content: V3JSONValue,
        signers: [(String, P256.Signing.PrivateKey)] = [],
        forceHighS: Bool = false
    ) throws -> Data {
        let canonicalContent = V3CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: Self.vaultID,
            vaultKey: Self.vaultKey
        )
        let input = V3ManifestAuthenticator.authenticationInput(for: canonicalContent)
        let digest = SHA256.hash(data: input)
        let authorizations = try signers.map { signerID, privateKey -> V3JSONValue in
            let signature = try privateKey.signature(for: digest)
            let lowS = try V3ManifestAuthenticator.canonicalizeP256Signature(signature.rawRepresentation)
            let storedSignature = forceHighS ? highSSignature(fromLowS: lowS) : lowS
            return .object([
                ("algorithm", .string("P-256-ECDSA-SHA256")),
                ("signerDeviceID", .string(signerID)),
                ("signature", .string(encodeBase64URL(storedSignature)))
            ])
        }

        return V3CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("keyEpoch", .integer(manifestKeyEpoch(in: content))),
                ("tag", .string(encodeBase64URL(tag)))
            ])),
            ("authorizations", .array(authorizations))
        ]))
    }

    private func manifestKeyEpoch(in content: V3JSONValue) -> UInt64 {
        guard case let .object(contentMembers) = content,
              case let .object(manifestMembers)? = contentMembers.first(where: { $0.0 == "manifest" })?.1,
              case let .integer(keyEpoch)? = manifestMembers.first(where: { $0.0 == "keyEpoch" })?.1
        else {
            preconditionFailure("Fixture content has no manifest key epoch.")
        }
        return keyEpoch
    }
}

private func encodeBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func replacing(_ data: Data, _ original: String, with replacement: String) -> Data {
    let source = String(decoding: data, as: UTF8.self)
    precondition(source.contains(original), "Fixture does not contain \(original)")
    return Data(source.replacingOccurrences(of: original, with: replacement).utf8)
}

private func highSSignature(fromLowS signature: Data) -> Data {
    let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
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

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
