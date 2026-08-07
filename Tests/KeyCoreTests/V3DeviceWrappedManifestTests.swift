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
        #expect(json.contains(#""profileVersion":1"#))
        #expect(json.contains(#""authorityTransitionID":"#))
        #expect(json.contains(#""hpkeSuite":{"aead":2,"kdf":1,"kem":16,"mode":0}"#))
        #expect(!json.contains(#""mode":"local""#))
        #expect(!json.contains(#""mode":"shared""#))
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
        let future = Self.replacing(
            body.canonicalBytes,
            #""profileVersion":1"#,
            with: #""profileFuture":true,"profileVersion":2"#
        )
        #expect(
            throws: V3DeviceWrappedManifestError.unsupportedProfileVersion(2)
        ) {
            try V3DeviceWrappedManifestCodec().parseCanonicalBody(future)
        }
        let futureWithDifferentFields = Data(
            #"{"format":"key-vault-manifest","profile":"device-wrapped","profileVersion":2,"version":3}"#.utf8
        )
        #expect(
            throws: V3DeviceWrappedManifestError.unsupportedProfileVersion(2)
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
                role: .owner,
                status: .active
            ),
            V3DeviceWrappedManifestDevice(
                identity: revoked,
                role: .member,
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
    func rosterRequiresAnActiveOwnerAndGloballyDistinctKeys() throws {
        let owner = try Self.identity(signingScalar: 1, wrappingScalar: 2)
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        #expect(throws: V3DeviceWrappedManifestError.semanticViolation(
            "devices.activeOwner"
        )) {
            try V3DeviceWrappedManifestBody(
                vaultID: Self.vaultID,
                keyID: keyID,
                authorityTransitionID: Self.transitionID,
                devices: [V3DeviceWrappedManifestDevice(
                    identity: owner,
                    role: .owner,
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
                role: .owner,
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
                role: .owner,
                status: .active
            )],
            wrappedKeys: [try wrapper(for: owner)],
            entries: []
        )
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
