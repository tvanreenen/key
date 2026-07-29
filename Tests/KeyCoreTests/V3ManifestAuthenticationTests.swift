import CryptoKit
import Foundation
import JSONCanonicalization
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
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                mode: .local,
                includeDevice: false
            )
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
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                mode: .local,
                includeDevice: false
            )
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
    func parserRejectsNonCanonicalUnknownAndFutureJSON() throws {
        let fixture = Fixture()
        let canonical = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        var spaced = Data("{ ".utf8)
        spaced.append(canonical.dropFirst())

        #expect(throws: V3ManifestError.nonCanonicalJSON) {
            _ = try V3ManifestAuthenticator().parse(spaced)
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
    }

    @Test
    func unreleasedPrototypeMetadataIsNotAVersion3Manifest() {
        let prototypeMetadata = Data(
            #"{"devices":[],"epoch":1,"securityMode":"enclave","vaultID":"prototype-vault","version":1,"wrappedKeys":[]}"#.utf8
        )

        #expect(throws: V3ManifestError.invalidStructure("$.format")) {
            _ = try V3ManifestAuthenticator().parse(prototypeMetadata)
        }
    }

    @Test
    func removedGenerationFieldsAreRejectedAsUnknown() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                mode: .local,
                includeDevice: false
            )
        )
        let bodyWithGeneration = replacing(
            parent,
            "\"format\":\"key-vault-manifest\",\"keyEpoch\"",
            with: "\"format\":\"key-vault-manifest\",\"generation\":1,\"keyEpoch\""
        )
        #expect(throws: V3ManifestError.invalidStructure("$.content.manifest")) {
            _ = try V3ManifestAuthenticator().parse(bodyWithGeneration)
        }

        let child = try fixture.envelope(
            content: fixture.content(parent: fixture.parentReference(to: parent))
        )
        let parentWithGeneration = replacing(
            child,
            ",\"kind\":\"manifest\"",
            with: ",\"generation\":1,\"kind\":\"manifest\""
        )
        #expect(throws: V3ManifestError.invalidStructure("$.content.parent")) {
            _ = try V3ManifestAuthenticator().parse(parentWithGeneration)
        }
    }

    @Test
    func canonicalJSONFailuresMapToManifestErrors() {
        #expect(throws: V3ManifestError.duplicateProperty) {
            _ = try V3ManifestAuthenticator().parse(Data(#"{"a":1,"\u0061":2}"#.utf8))
        }
        #expect(throws: V3ManifestError.invalidEncoding) {
            _ = try V3ManifestAuthenticator().parse(Data([0xEF, 0xBB, 0xBF, 0x7B, 0x7D]))
        }

        let count = 33
        let deeplyNested = String(repeating: "[", count: count)
            + "0"
            + String(repeating: "]", count: count)
        #expect(throws: V3ManifestError.invalidJSON) {
            _ = try V3ManifestAuthenticator().parse(Data(deeplyNested.utf8))
        }
    }

    @Test
    func changingAnyManifestBodyFieldWithoutRetaggingIsRejected() throws {
        let fixture = Fixture()
        let localEnvelope = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                mode: .local,
                includeDevice: false
            )
        )

        #expect(throws: V3ManifestError.invalidStructure("$.content.manifest.format")) {
            let mutated = replacing(
                localEnvelope,
                "\"format\":\"key-vault-manifest\"",
                with: "\"format\":\"key-vault-other\""
            )
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }
        #expect(throws: V3ManifestError.invalidStructure("$.content.manifest.version")) {
            let mutated = replacing(
                localEnvelope,
                "\"version\":3,\"wrappedKeys\"",
                with: "\"version\":4,\"wrappedKeys\""
            )
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }

        let localReplacements = [
            ("entryID", Fixture.entryID, "018f4d39-930c-735d-8d6f-588e9b0a3a49"),
            ("entryName", "\"name\":\"email/personal\"", "\"name\":\"email/work\""),
            ("entryType", "\"type\":\"secret\"", "\"type\":\"totp\""),
            ("entryRevision", "\"revision\":4", "\"revision\":5"),
            ("entryKeyEpoch", "\"keyEpoch\":1,\"name\"", "\"keyEpoch\":0,\"name\""),
            ("ciphertextDigest", Fixture.digest, String(repeating: "E", count: 43))
        ]

        for (_, original, replacement) in localReplacements {
            let mutated = replacing(localEnvelope, original, with: replacement)
            #expect(throws: V3ManifestError.authenticationFailed) {
                _ = try V3ManifestAuthenticator().verify(
                    mutated,
                    vaultKey: Fixture.vaultKey,
                    trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
                )
            }
        }

        let alternateVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
        #expect(throws: V3ManifestError.authenticationFailed) {
            let mutated = replacing(localEnvelope, Fixture.vaultID, with: alternateVaultID)
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: alternateVaultID)
            )
        }

        #expect(throws: V3ManifestError.authenticationFailed) {
            var mutated = replacing(
                localEnvelope,
                "\"keyEpoch\":1,\"mode\"",
                with: "\"keyEpoch\":2,\"mode\""
            )
            mutated = replacing(mutated, "\"keyEpoch\":1,\"tag\"", with: "\"keyEpoch\":2,\"tag\"")
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }

        let parent = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let child = try fixture.envelope(
            content: fixture.content(
                parent: fixture.parentReference(to: parent),
                entryRevision: 5
            )
        )

        let sharedReplacements = [
            ("mode", "\"mode\":\"shared\"", "\"mode\":\"local\""),
            ("deviceID", fixture.deviceID, String(repeating: "A", count: 43)),
            ("displayName", "\"displayName\":\"Laptop\"", "\"displayName\":\"Desktop\""),
            ("role", "\"role\":\"owner\"", "\"role\":\"member\""),
            ("status", "\"status\":\"active\"", "\"status\":\"revoked\""),
            ("signingPublicKey", fixture.signingPublicKeyValue, fixture.alternateSigningPublicKeyValue),
            ("wrappingPublicKey", fixture.wrappingPublicKeyValue, fixture.alternateWrappingPublicKeyValue),
            ("wrappedKeyCiphertext", "\"ciphertext\":\"AQID\",\"deviceID\"", "\"ciphertext\":\"BAUG\",\"deviceID\""),
            (
                "wrappedKeyEpoch",
                "\"deviceID\":\"\(fixture.deviceID)\",\"keyEpoch\":1",
                "\"deviceID\":\"\(fixture.deviceID)\",\"keyEpoch\":0"
            )
        ]

        for (_, original, replacement) in sharedReplacements {
            let mutated = replacing(child, original, with: replacement)
            #expect(throws: V3ManifestError.authenticationFailed) {
                _ = try V3ManifestAuthenticator().verify(
                    mutated,
                    vaultKey: Fixture.vaultKey,
                    trustAnchor: .parent(parent)
                )
            }
        }
    }

    @Test
    func entryOnlyChildAuthenticatesWithoutOwnerPresence() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                entryRevision: 4
            )
        )
        let child = try fixture.envelope(
            content: fixture.content(
                parent: fixture.parentReference(to: parent),
                entryRevision: 5
            )
        )

        let verified = try V3ManifestAuthenticator().verify(
            child,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .parent(parent)
        )

        #expect(verified.envelope.content.manifest.entries.first?.revision == 5)
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
                parent: fixture.parentReference(to: otherParent)
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
            parent: fixture.parentReference(to: parent),
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
                additionalDeviceRole: .member
            )
        )
        let memberCandidateContent = ownerFixture.content(
            parent: ownerFixture.parentReference(to: memberParent),
            keyEpoch: 2,
            additionalDeviceRole: .member
        )
        let memberSigned = try ownerFixture.envelope(
            content: memberCandidateContent,
            signers: [(ownerFixture.alternateDeviceID, ownerFixture.alternateSigningPrivateKey)]
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                memberSigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(memberParent)
            )
        }

        let ownerOnlyParent = try ownerFixture.envelope(
            content: ownerFixture.content(
                parent: .object([("kind", .string("genesis"))])
            )
        )
        let introducedContent = ownerFixture.content(
            parent: ownerFixture.parentReference(to: ownerOnlyParent),
            additionalDeviceRole: .member
        )
        let introducedSigned = try ownerFixture.envelope(
            content: introducedContent,
            signers: [(ownerFixture.alternateDeviceID, ownerFixture.alternateSigningPrivateKey)]
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                introducedSigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(ownerOnlyParent)
            )
        }

        let ownerParent = try ownerFixture.envelope(
            content: ownerFixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let ownerCandidateContent = ownerFixture.content(
            parent: ownerFixture.parentReference(to: ownerParent),
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
            parent: fixture.parentReference(to: parent),
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
    func modeSpecificMembershipAndWrappedKeyStateFailClosed() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let parentReference = fixture.parentReference(to: parent)

        func signedCandidate(_ content: CanonicalJSONValue) throws -> Data {
            try fixture.envelope(
                content: content,
                signers: [(fixture.deviceID, fixture.signingPrivateKey)]
            )
        }

        let localWithDevice = try signedCandidate(fixture.content(
            parent: parentReference,
            mode: .local
        ))
        #expect(throws: V3ManifestError.semanticViolation("devices.localMode")) {
            try V3ManifestAuthenticator().verify(
                localWithDevice,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let localWithWrapper = try signedCandidate(fixture.content(
            parent: parentReference,
            mode: .local,
            includeDevice: false,
            includeWrapper: true
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.localMode")) {
            try V3ManifestAuthenticator().verify(
                localWithWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let ownerless = try signedCandidate(fixture.content(
            parent: parentReference,
            role: .member
        ))
        #expect(throws: V3ManifestError.semanticViolation("devices.activeOwner")) {
            try V3ManifestAuthenticator().verify(
                ownerless,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let missingWrapper = try signedCandidate(fixture.content(
            parent: parentReference,
            includeWrapper: false
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.coverage")) {
            try V3ManifestAuthenticator().verify(
                missingWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let staleWrapper = try signedCandidate(fixture.content(
            parent: parentReference,
            wrapperKeyEpoch: 0
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.keyEpoch")) {
            try V3ManifestAuthenticator().verify(
                staleWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let unknownRecipient = try signedCandidate(fixture.content(
            parent: parentReference,
            wrapperDeviceID: fixture.alternateDeviceID
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.deviceID")) {
            try V3ManifestAuthenticator().verify(
                unknownRecipient,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let revokedWithWrapper = try signedCandidate(fixture.content(
            parent: parentReference,
            role: .member,
            status: .revoked,
            additionalDeviceRole: .owner
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.deviceID")) {
            try V3ManifestAuthenticator().verify(
                revokedWithWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
            )
        }

        let validRevokedMembership = try signedCandidate(fixture.content(
            parent: parentReference,
            role: .member,
            status: .revoked,
            includeWrapper: false,
            additionalDeviceRole: .owner
        ))
        let verified = try V3ManifestAuthenticator().verify(
            validRevokedMembership,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .parent(parent)
        )
        #expect(verified.envelope.content.manifest.devices.count == 2)
        #expect(verified.envelope.content.manifest.wrappedKeys.count == 1)
    }

    @Test
    func authenticatedSemanticViolationsRemainUntrusted() throws {
        let fixture = Fixture()
        let badName = try fixture.envelope(
            content: fixture.content(
                parent: .object([("kind", .string("genesis"))]),
                mode: .local,
                includeDevice: false,
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

        let parent = try fixture.envelope(
            content: fixture.content(parent: .object([("kind", .string("genesis"))]))
        )
        let wrongDeviceIDContent = fixture.content(
            parent: fixture.parentReference(to: parent),
            deviceID: String(repeating: "A", count: 43)
        )
        let wrongDeviceID = try fixture.envelope(
            content: wrongDeviceIDContent,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)]
        )
        #expect(throws: V3ManifestError.semanticViolation("devices.deviceID")) {
            try V3ManifestAuthenticator().verify(
                wrongDeviceID,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .parent(parent)
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

    var alternateDeviceID: String {
        V3ManifestAuthenticator.deviceID(
            signingPublicKey: alternateSigningPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: alternateWrappingPrivateKey.publicKey.x963Representation
        )
    }

    func content(
        parent: CanonicalJSONValue,
        mode: V3VaultMode = .shared,
        keyEpoch: UInt64 = 1,
        role: V3DeviceRole = .owner,
        status: V3DeviceStatus = .active,
        includeDevice: Bool = true,
        includeWrapper: Bool? = nil,
        wrapperKeyEpoch: UInt64? = nil,
        wrapperDeviceID: String? = nil,
        additionalDeviceRole: V3DeviceRole? = nil,
        deviceID overriddenDeviceID: String? = nil,
        entryName: String = "email/personal",
        entryRevision: UInt64 = 4
    ) -> CanonicalJSONValue {
        .object([
            ("parent", parent),
            ("manifest", manifest(
                mode: mode,
                keyEpoch: keyEpoch,
                role: role,
                status: status,
                includeDevice: includeDevice,
                includeWrapper: includeWrapper,
                wrapperKeyEpoch: wrapperKeyEpoch,
                wrapperDeviceID: wrapperDeviceID,
                additionalDeviceRole: additionalDeviceRole,
                deviceID: overriddenDeviceID,
                entryName: entryName,
                entryRevision: entryRevision
            ))
        ])
    }

    func manifest(
        mode: V3VaultMode,
        keyEpoch: UInt64,
        role: V3DeviceRole,
        status: V3DeviceStatus,
        includeDevice: Bool,
        includeWrapper: Bool?,
        wrapperKeyEpoch: UInt64?,
        wrapperDeviceID: String?,
        additionalDeviceRole: V3DeviceRole?,
        deviceID overriddenDeviceID: String?,
        entryName: String,
        entryRevision: UInt64
    ) -> CanonicalJSONValue {
        let actualDeviceID = overriddenDeviceID ?? deviceID
        var deviceRecords: [(String, CanonicalJSONValue)] = []
        if includeDevice {
            let members: [(String, CanonicalJSONValue)] = [
                ("deviceID", .string(actualDeviceID)),
                ("displayName", .string("Laptop")),
                ("role", .string(role.rawValue)),
                ("status", .string(status.rawValue)),
                ("signingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDSA")),
                    ("encoding", .string("x963")),
                    ("value", .string(signingPublicKeyValue))
                ])),
                ("wrappingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDH")),
                    ("encoding", .string("x963")),
                    ("value", .string(wrappingPublicKeyValue))
                ]))
            ]
            deviceRecords.append((actualDeviceID, .object(members)))
        }
        if let additionalDeviceRole {
            deviceRecords.append((alternateDeviceID, .object([
                ("deviceID", .string(alternateDeviceID)),
                ("displayName", .string("Phone")),
                ("role", .string(additionalDeviceRole.rawValue)),
                ("status", .string(V3DeviceStatus.active.rawValue)),
                ("signingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDSA")),
                    ("encoding", .string("x963")),
                    ("value", .string(alternateSigningPublicKeyValue))
                ])),
                ("wrappingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDH")),
                    ("encoding", .string("x963")),
                    ("value", .string(alternateWrappingPublicKeyValue))
                ]))
            ])))
        }
        let devices = deviceRecords
            .sorted { Data($0.0.utf8).lexicographicallyPrecedes(Data($1.0.utf8)) }
            .map(\.1)

        var wrapperRecords: [(UInt64, String, CanonicalJSONValue)] = []
        if includeWrapper ?? includeDevice {
            let actualWrapperDeviceID = wrapperDeviceID ?? actualDeviceID
            let actualWrapperKeyEpoch = wrapperKeyEpoch ?? keyEpoch
            wrapperRecords.append((actualWrapperKeyEpoch, actualWrapperDeviceID, .object([
                ("deviceID", .string(actualWrapperDeviceID)),
                ("keyEpoch", .integer(actualWrapperKeyEpoch)),
                ("algorithm", .string("p256-ecies-x963-sha256-aes-gcm")),
                ("ciphertext", .string("AQID"))
            ])))
        }
        if additionalDeviceRole != nil {
            wrapperRecords.append((keyEpoch, alternateDeviceID, .object([
                ("deviceID", .string(alternateDeviceID)),
                ("keyEpoch", .integer(keyEpoch)),
                ("algorithm", .string("p256-ecies-x963-sha256-aes-gcm")),
                ("ciphertext", .string("BAUG"))
            ])))
        }
        let wrappedKeys = wrapperRecords.sorted {
            $0.0 < $1.0 || ($0.0 == $1.0
                && Data($0.1.utf8).lexicographicallyPrecedes(Data($1.1.utf8)))
        }.map(\.2)

        return .object([
            ("format", .string("key-vault-manifest")),
            ("version", .integer(3)),
            ("vaultID", .string(Self.vaultID)),
            ("mode", .string(mode.rawValue)),
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

    func parentReference(to envelope: Data) -> CanonicalJSONValue {
        .object([
            ("kind", .string("manifest")),
            ("digest", .string(encodeBase64URL(Data(SHA256.hash(data: envelope)))))
        ])
    }

    func envelope(
        content: CanonicalJSONValue,
        signers: [(String, P256.Signing.PrivateKey)] = [],
        forceHighS: Bool = false
    ) throws -> Data {
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: Self.vaultID,
            vaultKey: Self.vaultKey
        )
        let input = V3ManifestAuthenticator.authenticationInput(for: canonicalContent)
        let digest = SHA256.hash(data: input)
        let authorizations = try signers.map { signerID, privateKey -> CanonicalJSONValue in
            let signature = try privateKey.signature(for: digest)
            let lowS = try V3ManifestAuthenticator.canonicalizeP256Signature(signature.rawRepresentation)
            let storedSignature = forceHighS ? highSSignature(fromLowS: lowS) : lowS
            return .object([
                ("algorithm", .string("P-256-ECDSA-SHA256")),
                ("signerDeviceID", .string(signerID)),
                ("signature", .string(encodeBase64URL(storedSignature)))
            ])
        }

        return CanonicalJSON.encode(.object([
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

    private func manifestKeyEpoch(in content: CanonicalJSONValue) -> UInt64 {
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
