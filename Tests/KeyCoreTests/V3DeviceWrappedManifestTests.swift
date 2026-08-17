import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedManifestTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let vaultKey = Data(0..<32)

    @Test
    func canonicalBodyRoundTripsWithoutTheAlphaModeSplit() throws {
        let body = try Self.makeBody()

        let decoded = try V3DeviceWrappedManifestCodec().parseCanonicalBody(
            body.canonicalBytes
        )
        let json = String(decoding: body.canonicalBytes, as: UTF8.self)

        #expect(decoded == body)
        #expect(json.contains(#""profile":"device-wrapped""#))
        #expect(json.contains(#""profileVersion":2"#))
        #expect(!json.contains(#""role":"#))
        #expect(json.contains(#""authorityTransitionID":"#))
        #expect(json.contains(#""hpkeSuite":{"aead":2,"kdf":1,"kem":16,"mode":0}"#))
        #expect(!json.contains(#""mode":"local""#))
        #expect(!json.contains(#""mode":"shared""#))
    }

    @Test
    func checkedInSchemasTrackTheShippingRoleFreeCanonicalBody() throws {
        let body = try Self.makeBody()
        let fixture = try #require(
            JSONSerialization.jsonObject(with: body.canonicalBytes)
                as? [String: Any]
        )
        let bodySchema = try Self.schema("v3-manifest-body.schema.json")
        try Self.expectExactObjectSchema(bodySchema, matches: fixture)

        let properties = try #require(
            bodySchema["properties"] as? [String: Any]
        )
        #expect((properties["format"] as? [String: Any])?["const"] as? String
            == V3DeviceWrappedManifestBody.format)
        #expect((properties["version"] as? [String: Any])?["const"] as? Int
            == Int(V3DeviceWrappedManifestBody.version))
        #expect((properties["profile"] as? [String: Any])?["const"] as? String
            == V3DeviceWrappedManifestBody.profile)
        #expect(
            (properties["profileVersion"] as? [String: Any])?["const"] as? Int
                == Int(V3DeviceWrappedManifestBody.profileVersion)
        )
        #expect(properties["mode"] == nil)

        let definitions = try #require(
            bodySchema["$defs"] as? [String: Any]
        )
        let suite = try #require(fixture["hpkeSuite"] as? [String: Any])
        let suiteSchema = try #require(
            definitions["hpkeSuite"] as? [String: Any]
        )
        try Self.expectExactObjectSchema(suiteSchema, matches: suite)
        for field in ["mode", "kem", "kdf", "aead"] {
            let suiteProperties = try #require(
                suiteSchema["properties"] as? [String: Any]
            )
            #expect(
                (suiteProperties[field] as? [String: Any])?["const"] as? Int
                    == suite[field] as? Int
            )
        }

        let devices = try #require(fixture["devices"] as? [[String: Any]])
        let device = try #require(devices.first)
        let deviceSchema = try #require(
            definitions["device"] as? [String: Any]
        )
        try Self.expectExactObjectSchema(deviceSchema, matches: device)
        #expect((deviceSchema["properties"] as? [String: Any])?["role"] == nil)

        let wrappedKeys = try #require(
            fixture["wrappedKeys"] as? [[String: Any]]
        )
        let wrappedKey = try #require(wrappedKeys.first)
        let wrappedKeySchema = try #require(
            definitions["wrappedKey"] as? [String: Any]
        )
        try Self.expectExactObjectSchema(wrappedKeySchema, matches: wrappedKey)

        let entries = try #require(fixture["entries"] as? [[String: Any]])
        let entry = try #require(entries.first)
        let entrySchema = try #require(
            definitions["entry"] as? [String: Any]
        )
        try Self.expectExactObjectSchema(entrySchema, matches: entry)

        let common = try Self.schema("v3-common.schema.json")
        let commonDefinitions = try #require(
            common["$defs"] as? [String: Any]
        )
        #expect(
            (commonDefinitions["hpkeP256EncapsulatedKey"]
                as? [String: Any])?["pattern"] as? String
                == "^[A-Za-z0-9_-]{87}$"
        )
        #expect(
            (commonDefinitions["hpkeAESGCM256WrappedVaultKey"]
                as? [String: Any])?["pattern"] as? String
                == "^[A-Za-z0-9_-]{64}$"
        )

        let genesis = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: body.vaultID,
            authorityTransitionID: body.authorityTransitionID,
            vaultKey: Self.vaultKey,
            ownerIdentity: body.devices[0].identity,
            entries: body.entries
        )
        let envelopeFixture = try #require(
            JSONSerialization.jsonObject(with: genesis.manifestData)
                as? [String: Any]
        )
        let envelopeSchema = try Self.schema(
            "v3-manifest-envelope.schema.json"
        )
        try Self.expectExactObjectSchema(
            envelopeSchema,
            matches: envelopeFixture
        )
        let envelopeDefinitions = try #require(
            envelopeSchema["$defs"] as? [String: Any]
        )
        let content = try #require(
            envelopeFixture["content"] as? [String: Any]
        )
        try Self.expectExactObjectSchema(
            try #require(envelopeDefinitions["content"] as? [String: Any]),
            matches: content
        )
        let authentication = try #require(
            envelopeFixture["authentication"] as? [String: Any]
        )
        try Self.expectExactObjectSchema(
            try #require(
                envelopeDefinitions["authentication"] as? [String: Any]
            ),
            matches: authentication
        )
        let authorizationSchema = try #require(
            envelopeDefinitions["authorization"] as? [String: Any]
        )
        #expect(Set(try #require(
            authorizationSchema["required"] as? [String]
        )) == Set(["algorithm", "signerDeviceID", "signature"]))
    }

    @Test
    func oldAlphaAndUnknownSchemasAreRejected() throws {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        let alphaBody = Data(
            "{\"devices\":[],\"entries\":[],\"format\":\"key-vault-manifest\",\"keyID\":\"\(keyID.rawValue)\",\"mode\":\"local\",\"vaultID\":\"\(Self.vaultID)\",\"version\":3,\"wrappedKeys\":[]}".utf8
        )
        #expect(throws: V3DeviceWrappedManifestError.invalidStructure("$.profile")) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(alphaBody)
        }

        let body = try Self.makeBody()
        let unknown = Self.replacing(
            body.canonicalBytes,
            #""vaultID":"#,
            with: #""unknown":true,"vaultID":"#
        )
        #expect(throws: V3DeviceWrappedManifestError.invalidStructure("$")) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(unknown)
        }
    }

    @Test
    func futureProfileAndSuiteChangesAreFailClosed() throws {
        let body = try Self.makeBody()
        let roleBearingAlpha = Self.replacing(
            body.canonicalBytes,
            #""profileVersion":2"#,
            with: #""profileVersion":1"#
        )
        #expect(
            throws: V3DeviceWrappedManifestError.unsupportedProfileVersion(1)
        ) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(
                roleBearingAlpha
            )
        }

        let future = Self.replacing(
            body.canonicalBytes,
            #""profileVersion":2"#,
            with: #""profileFuture":true,"profileVersion":3"#
        )
        #expect(
            throws: V3DeviceWrappedManifestError.unsupportedProfileVersion(3)
        ) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(future)
        }
        let futureWithDifferentFields = Data(
            #"{"format":"key-vault-manifest","profile":"device-wrapped","profileVersion":3,"version":3}"#.utf8
        )
        #expect(
            throws: V3DeviceWrappedManifestError.unsupportedProfileVersion(3)
        ) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(
                futureWithDifferentFields
            )
        }

        let changedSuite = Self.replacing(
            body.canonicalBytes,
            #""kem":16"#,
            with: #""kem":32"#
        )
        #expect(
            throws: V3DeviceWrappedManifestError.invalidStructure(
                "$.hpkeSuite.kem"
            )
        ) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(changedSuite)
        }
    }

    @Test
    func parserRequiresCanonicalJSONAndExactHPKEFraming() throws {
        let body = try Self.makeBody()
        var nonCanonical = Data("{ ".utf8)
        nonCanonical.append(body.canonicalBytes.dropFirst())
        #expect(throws: V3DeviceWrappedManifestError.nonCanonicalJSON) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(nonCanonical)
        }

        let shortCiphertext = Self.replacing(
            body.canonicalBytes,
            Base64URL.encode(Data(repeating: 0xA5, count: 48)),
            with: Base64URL.encode(Data(repeating: 0xA5, count: 47))
        )
        #expect(throws: V3DeviceWrappedManifestError.invalidStructure(
            "$.wrappedKeys[0].ciphertext"
        )) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(shortCiphertext)
        }
    }

    @Test
    func wrappersCoverExactlyTheActiveRoster() throws {
        let owner = try Self.identity(signingScalar: 1, wrappingScalar: 2)
        let revoked = try Self.identity(signingScalar: 3, wrappingScalar: 4)
        let devices = [
            V3DeviceWrappedManifestDevice(
                identity: owner,
                status: .active
            ),
            V3DeviceWrappedManifestDevice(
                identity: revoked,
                status: .revoked
            ),
        ].sorted { Data($0.identity.deviceID.utf8)
            .lexicographicallyPrecedes(Data($1.identity.deviceID.utf8)) }
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        let ownerWrapper = try Self.wrapper(for: owner)

        _ = try V3DeviceWrappedManifestBody(
            vaultID: Self.vaultID,
            keyID: keyID,
            authorityTransitionID: Self.transitionID,
            devices: devices,
            wrappedKeys: [ownerWrapper],
            entries: []
        )

        #expect(throws: V3DeviceWrappedManifestError.semanticViolation(
            "wrappedKeys.coverage"
        )) {
            try V3DeviceWrappedManifestBody(
                vaultID: Self.vaultID,
                keyID: keyID,
                authorityTransitionID: Self.transitionID,
                devices: devices,
                wrappedKeys: [ownerWrapper, try Self.wrapper(for: revoked)]
                    .sorted { Data($0.recipientDeviceID.utf8)
                        .lexicographicallyPrecedes(
                            Data($1.recipientDeviceID.utf8)
                        ) },
                entries: []
            )
        }
    }

    @Test
    func rosterRequiresAnActiveDeviceAndGloballyDistinctKeys() throws {
        let owner = try Self.identity(signingScalar: 1, wrappingScalar: 2)
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        #expect(throws: V3DeviceWrappedManifestError.semanticViolation(
            "devices.active"
        )) {
            try V3DeviceWrappedManifestBody(
                vaultID: Self.vaultID,
                keyID: keyID,
                authorityTransitionID: Self.transitionID,
                devices: [V3DeviceWrappedManifestDevice(
                    identity: owner,
                    status: .revoked
                )],
                wrappedKeys: [],
                entries: []
            )
        }

        let reused = try V3EnrollmentDeviceIdentity(
            displayName: "Reused Mac",
            signingPublicKey: owner.wrappingPublicKey,
            wrappingPublicKey: try Self.keyAgreementPrivateKey(scalar: 3)
                .publicKey.x963Representation
        )
        let devices = [owner, reused].map {
            V3DeviceWrappedManifestDevice(
                identity: $0,
                status: .active
            )
        }.sorted { Data($0.identity.deviceID.utf8)
            .lexicographicallyPrecedes(Data($1.identity.deviceID.utf8)) }
        #expect(throws: V3DeviceWrappedManifestError.semanticViolation(
            "devices.publicKeyReuse"
        )) {
            try V3DeviceWrappedManifestBody(
                vaultID: Self.vaultID,
                keyID: keyID,
                authorityTransitionID: Self.transitionID,
                devices: devices,
                wrappedKeys: [],
                entries: []
            )
        }
    }

    @Test
    func everyCurrentEntryMustUseTheManifestKey() throws {
        let body = try Self.makeBody()
        let otherKeyID = try V3VaultKeyID.derive(
            vaultKey: Data(repeating: 0xFF, count: 32),
            vaultID: Self.vaultID
        )
        #expect(throws: V3DeviceWrappedManifestError.semanticViolation(
            "entries"
        )) {
            try V3DeviceWrappedManifestBody(
                vaultID: body.vaultID,
                keyID: body.keyID,
                authorityTransitionID: body.authorityTransitionID,
                devices: body.devices,
                wrappedKeys: body.wrappedKeys,
                entries: [V3ManifestEntry(
                    entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5",
                    name: "email/personal",
                    type: .secret,
                    revision: 1,
                    keyID: otherKeyID,
                    ciphertextDigest: Base64URL.encode(
                        Data(repeating: 0x11, count: 32)
                    )
                )]
            )
        }
    }

    private static func makeBody() throws -> V3DeviceWrappedManifestBody {
        let owner = try identity(signingScalar: 1, wrappingScalar: 2)
        return try V3DeviceWrappedManifestBody(
            vaultID: vaultID,
            keyID: V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: vaultID
            ),
            authorityTransitionID: transitionID,
            devices: [V3DeviceWrappedManifestDevice(
                identity: owner,
                status: .active
            )],
            wrappedKeys: [try wrapper(for: owner)],
            entries: [V3ManifestEntry(
                entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5",
                name: "service/example",
                type: .secret,
                revision: 1,
                keyID: V3VaultKeyID.derive(
                    vaultKey: vaultKey,
                    vaultID: vaultID
                ),
                ciphertextDigest: Base64URL.encode(
                    Data(repeating: 0x11, count: 32)
                )
            )]
        )
    }

    private static func schema(_ name: String) throws -> [String: Any] {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(contentsOf: repositoryRoot
            .appendingPathComponent("docs/schemas")
            .appendingPathComponent(name))
        return try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
    }

    private static func expectExactObjectSchema(
        _ schema: [String: Any],
        matches object: [String: Any]
    ) throws {
        let required = try #require(schema["required"] as? [String])
        let properties = try #require(
            schema["properties"] as? [String: Any]
        )
        #expect(schema["additionalProperties"] as? Bool == false)
        #expect(Set(required) == Set(object.keys))
        #expect(Set(properties.keys) == Set(object.keys))
    }

    private static func identity(
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws -> V3EnrollmentDeviceIdentity {
        try V3EnrollmentDeviceIdentity(
            displayName: "Mac \(signingScalar)",
            signingPublicKey: try P256.Signing.PrivateKey(
                rawRepresentation: scalar(signingScalar)
            ).publicKey.x963Representation,
            wrappingPublicKey: try keyAgreementPrivateKey(scalar: wrappingScalar)
                .publicKey.x963Representation
        )
    }

    private static func wrapper(
        for identity: V3EnrollmentDeviceIdentity
    ) throws -> V3DeviceWrappedManifestKey {
        try V3DeviceWrappedManifestKey(
            recipientDeviceID: identity.deviceID,
            wrappedKey: V3HPKEWrappedVaultKey(
                encapsulatedKey: identity.wrappingPublicKey,
                ciphertext: Data(repeating: 0xA5, count: 48)
            )
        )
    }

    private static func keyAgreementPrivateKey(
        scalar: UInt8
    ) throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: self.scalar(scalar))
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }

    private static func replacing(
        _ data: Data,
        _ original: String,
        with replacement: String
    ) -> Data {
        Data(
            String(decoding: data, as: UTF8.self)
                .replacingOccurrences(of: original, with: replacement).utf8
        )
    }
}
