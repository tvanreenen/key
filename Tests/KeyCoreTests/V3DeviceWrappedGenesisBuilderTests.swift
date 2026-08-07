import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3DeviceWrappedGenesisBuilderTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let vaultKey = Data(0..<32)

    @Test
    func buildsOneOwnerGenesisWhoseWrapperOpensForThatDevice() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: Self.vaultID,
            authorityTransitionID: Self.transitionID,
            vaultKey: Self.vaultKey,
            ownerIdentity: fixture.identity
        )

        #expect(candidate.body.devices.count == 1)
        #expect(candidate.body.devices[0].identity == fixture.identity)
        #expect(candidate.body.devices[0].role == .owner)
        #expect(candidate.body.devices[0].status == .active)
        #expect(candidate.body.wrappedKeys.count == 1)
        #expect(candidate.body.entries.isEmpty)
        #expect(
            candidate.manifestDigest
                == Data(SHA256.hash(data: candidate.manifestData))
        )

        let context = try V3VaultKeyHPKEContext(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            recipientDeviceID: fixture.identity.deviceID
        )
        #expect(
            try V3VaultKeyHPKE().unwrap(
                candidate.body.wrappedKeys[0].wrappedKey,
                recipientPrivateKey: fixture.wrappingPrivateKey,
                context: context
            ) == Self.vaultKey
        )
    }

    @Test
    func envelopeCarriesCanonicalPermanentBodyAndValidAuthentication() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: Self.vaultID,
            authorityTransitionID: Self.transitionID,
            vaultKey: Self.vaultKey,
            ownerIdentity: fixture.identity
        )
        let root = try #require(
            CanonicalJSON.parse(candidate.manifestData).objectValue
        )
        #expect(CanonicalJSON.encode(.object(root)) == candidate.manifestData)
        #expect(Self.string("format", in: root) == "key-vault-manifest-envelope")
        #expect(Self.integer("version", in: root) == 3)
        #expect(Self.member("authorizations", in: root)?.arrayValue?.isEmpty == true)

        let content = try #require(Self.member("content", in: root))
        let contentObject = try #require(content.objectValue)
        let manifestValue = try #require(
            Self.member("manifest", in: contentObject)
        )
        #expect(
            try V3DeviceWrappedManifestCodec().decodeBody(manifestValue)
                == candidate.body
        )

        let authentication = try #require(
            Self.member("authentication", in: root)?.objectValue
        )
        let encodedTag = try #require(Self.string("tag", in: authentication))
        let suppliedTag = try #require(Base64URL.decodeCanonical(encodedTag))
        let expectedTag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: CanonicalJSON.encode(content),
            vaultID: Self.vaultID,
            vaultKey: Self.vaultKey
        )
        #expect(suppliedTag == expectedTag)
    }

    @Test
    func wrongDeviceAndContextCannotOpenGenesisWrapper() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: Self.vaultID,
            authorityTransitionID: Self.transitionID,
            vaultKey: Self.vaultKey,
            ownerIdentity: fixture.identity
        )
        let otherWrappingKey = P256.KeyAgreement.PrivateKey()
        let context = try V3VaultKeyHPKEContext(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            recipientDeviceID: fixture.identity.deviceID
        )
        #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
            try V3VaultKeyHPKE().unwrap(
                candidate.body.wrappedKeys[0].wrappedKey,
                recipientPrivateKey: otherWrappingKey,
                context: context
            )
        }
        let wrongContext = try V3VaultKeyHPKEContext(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID:
                "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5",
            recipientDeviceID: fixture.identity.deviceID
        )
        #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
            try V3VaultKeyHPKE().unwrap(
                candidate.body.wrappedKeys[0].wrappedKey,
                recipientPrivateKey: fixture.wrappingPrivateKey,
                context: wrongContext
            )
        }
    }

    @Test
    func rejectsInvalidVaultKeyBeforeProducingAWrapper() throws {
        let fixture = try Self.fixture()
        #expect(throws: V3DeviceWrappedGenesisError.invalidVaultKey) {
            try V3DeviceWrappedGenesisBuilder().build(
                vaultID: Self.vaultID,
                authorityTransitionID: Self.transitionID,
                vaultKey: Data(repeating: 0, count: 31),
                ownerIdentity: fixture.identity
            )
        }
    }

    private static func fixture() throws -> (
        identity: V3EnrollmentDeviceIdentity,
        wrappingPrivateKey: P256.KeyAgreement.PrivateKey
    ) {
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: scalar(1)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: scalar(2)
        )
        return (
            try V3EnrollmentDeviceIdentity(
                displayName: "Owner Mac",
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey: wrappingKey.publicKey.x963Representation
            ),
            wrappingKey
        )
    }

    private static func member(
        _ name: String,
        in object: [(String, CanonicalJSONValue)]
    ) -> CanonicalJSONValue? {
        object.first(where: { $0.0 == name })?.1
    }

    private static func string(
        _ name: String,
        in object: [(String, CanonicalJSONValue)]
    ) -> String? {
        member(name, in: object)?.stringValue
    }

    private static func integer(
        _ name: String,
        in object: [(String, CanonicalJSONValue)]
    ) -> UInt64? {
        member(name, in: object)?.integerValue
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}
