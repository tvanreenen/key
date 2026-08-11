import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3DeviceWrappedRevocationTransitionTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b3"
    fileprivate static let parentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b4"
    fileprivate static let revocationTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b5"
    fileprivate static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b6"
    fileprivate static let currentKey = Data(0..<32)
    fileprivate static let nextKey = Data(repeating: 0x51, count: 32)

    @Test
    func revocationRotatesTheKeyAndExcludesTheSelectedDevice() throws {
        let fixture = try Fixture()

        let candidate = try V3DeviceWrappedRevocationTransitionBuilder()
            .build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                plan: fixture.plan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )

        #expect(candidate.plan == fixture.plan)
        #expect(candidate.body.keyID != fixture.base.envelope.body.keyID)
        #expect(candidate.body.authorityTransitionID
            == Self.revocationTransitionID)
        #expect(candidate.manifestDigest == Data(SHA256.hash(
            data: candidate.manifestData
        )))
        #expect(candidate.body.devices.first(where: {
            $0.identity.deviceID == fixture.member.identity.deviceID
        })?.status == .revoked)
        #expect(candidate.body.wrappedKeys.map(\.recipientDeviceID) == [
            fixture.owner.identity.deviceID,
        ])

        let ownerWrapper = try #require(candidate.body.wrappedKeys.first)
        let context = try V3VaultKeyHPKEContext(
            vaultID: Self.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: Self.revocationTransitionID,
            recipientDeviceID: fixture.owner.identity.deviceID
        )
        #expect(try V3VaultKeyHPKE().unwrap(
            ownerWrapper.wrappedKey,
            recipientPrivateKey: fixture.owner.wrappingPrivateKey,
            context: context
        ) == Self.nextKey)

        let oldEntry = try #require(fixture.base.envelope.body.entries.first)
        let newEntry = try #require(candidate.body.entries.first)
        let staged = try #require(candidate.stagedEntries.first)
        #expect(newEntry.entryID == oldEntry.entryID)
        #expect(newEntry.name == oldEntry.name)
        #expect(newEntry.type == oldEntry.type)
        #expect(newEntry.revision == oldEntry.revision)
        #expect(newEntry.keyID == candidate.body.keyID)
        #expect(newEntry.ciphertextDigest != oldEntry.ciphertextDigest)
        #expect(try V3EntryCipher().openTrusted(
            staged.canonicalBytes,
            vaultID: Self.vaultID,
            manifestEntry: newEntry,
            vaultKey: Self.nextKey
        ) == "correct horse battery staple")
        #expect(throws: V3EncryptedEntryError.self) {
            try V3EntryCipher().openTrusted(
                staged.canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: newEntry,
                vaultKey: Self.currentKey
            )
        }

        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            candidate.manifestData
        )
        let authorization = try #require(envelope.authorizations.first)
        let signatureBytes = try #require(Base64URL.decodeCanonical(
            authorization.signature
        ))
        let signature = try P256.Signing.ECDSASignature(
            rawRepresentation: signatureBytes
        )
        #expect(fixture.owner.signingPrivateKey.publicKey.isValidSignature(
            signature,
            for: SHA256.hash(data:
                V3ManifestAuthenticator.authenticationInput(
                    for: envelope.canonicalContentBytes
                )
            )
        ))
    }

    @Test
    func refusesAPlanThatNoLongerMatchesTheCheckpoint() throws {
        let fixture = try Fixture()
        let alteredPlan = V3DeviceWrappedRevocationPlan(
            expectedCheckpoint: fixture.plan.expectedCheckpoint,
            authorizingOwner: fixture.plan.authorizingOwner,
            revokedDevice: fixture.plan.authorizingOwner,
            resultingDevices: fixture.plan.resultingDevices
        )

        #expect(
            throws: V3DeviceWrappedRevocationTransitionError.invalidPlan
        ) {
            _ = try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                plan: alteredPlan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )
        }
    }

    @Test
    func requiresTheCompleteCurrentSnapshot() throws {
        let fixture = try Fixture()

        #expect(
            throws: V3DeviceWrappedRevocationTransitionError
                .incompleteEntrySnapshot
        ) {
            _ = try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: fixture.base,
                currentEntries: [:],
                plan: fixture.plan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )
        }
    }

    @Test
    func refusesToReuseTheCurrentVaultKey() throws {
        let fixture = try Fixture()

        #expect(
            throws: V3DeviceWrappedRevocationTransitionError
                .invalidNextVaultKey
        ) {
            _ = try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                plan: fixture.plan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.currentKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )
        }
    }
}

private struct RevocationTestDevice: V3EnrollmentMessageSigning {
    let vaultID = V3DeviceWrappedRevocationTransitionTests.vaultID
    let identity: V3EnrollmentDeviceIdentity
    let signingPrivateKey: P256.Signing.PrivateKey
    let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    var publicIdentity: V3EnrollmentDeviceIdentity { identity }

    init(name: String, signing: UInt8, wrapping: UInt8) throws {
        signingPrivateKey = try P256.Signing.PrivateKey(
            rawRepresentation: Self.scalar(signing)
        )
        wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Self.scalar(wrapping)
        )
        identity = try V3EnrollmentDeviceIdentity(
            displayName: name,
            signingPublicKey: signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingPrivateKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingPrivateKey.signature(for: input).rawRepresentation
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}

private struct RevocationTransitionFixture {
    let owner: RevocationTestDevice
    let member: RevocationTestDevice
    let base: V3DeviceWrappedTrustedCheckpoint
    let currentEntries: [V3EntryObjectKey: V3EncryptedEntry]
    let plan: V3DeviceWrappedRevocationPlan

    init() throws {
        owner = try RevocationTestDevice(
            name: "Owner Mac",
            signing: 0x11,
            wrapping: 0x12
        )
        member = try RevocationTestDevice(
            name: "Member Mac",
            signing: 0x21,
            wrapping: 0x22
        )
        let keyID = try V3VaultKeyID.derive(
            vaultKey: V3DeviceWrappedRevocationTransitionTests.currentKey,
            vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID
        )
        let encrypted = try V3EntryCipher().seal(
            "correct horse battery staple",
            context: V3EntryAuthenticationContext(
                vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID,
                entryID: V3DeviceWrappedRevocationTransitionTests.entryID,
                name: "account/password",
                type: .secret,
                keyID: keyID,
                revision: 1
            ),
            vaultKey: V3DeviceWrappedRevocationTransitionTests.currentKey
        )
        let devices = [
            V3DeviceWrappedManifestDevice(
                identity: owner.identity,
                role: .owner,
                status: .active
            ),
            V3DeviceWrappedManifestDevice(
                identity: member.identity,
                role: .member,
                status: .active
            ),
        ].sorted {
            Data($0.identity.deviceID.utf8).lexicographicallyPrecedes(
                Data($1.identity.deviceID.utf8)
            )
        }
        let wrappedKeys = try devices.map { device in
            let context = try V3VaultKeyHPKEContext(
                vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID,
                keyID: keyID,
                authorityTransitionID:
                    V3DeviceWrappedRevocationTransitionTests
                        .parentTransitionID,
                recipientDeviceID: device.identity.deviceID
            )
            return try V3DeviceWrappedManifestKey(
                recipientDeviceID: device.identity.deviceID,
                wrappedKey: V3VaultKeyHPKE().wrap(
                    vaultKey:
                        V3DeviceWrappedRevocationTransitionTests.currentKey,
                    recipientPublicKey: device.identity.wrappingPublicKey,
                    context: context
                )
            )
        }
        let body = try V3DeviceWrappedManifestBody(
            vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID,
            keyID: keyID,
            authorityTransitionID:
                V3DeviceWrappedRevocationTransitionTests.parentTransitionID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: [V3ManifestEntry(
                entryID: encrypted.context.entryID,
                name: encrypted.context.name,
                type: encrypted.context.type,
                revision: encrypted.context.revision,
                keyID: encrypted.context.keyID,
                ciphertextDigest: encrypted.ciphertextDigest
            )]
        )
        let content: CanonicalJSONValue = .object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: body.vaultID,
            vaultKey: V3DeviceWrappedRevocationTransitionTests.currentKey
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([])),
        ]))
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            manifestData
        )
        base = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: body.vaultID,
                envelopeDigest: Data(SHA256.hash(data: manifestData))
            ),
            envelope: envelope
        )
        guard let digest = Base64URL.decodeCanonical(
            encrypted.ciphertextDigest
        ) else {
            throw V3DeviceWrappedRevocationTransitionError.invalidEntry
        }
        currentEntries = [V3EntryObjectKey(
            entryID: encrypted.context.entryID,
            digest: digest
        ): encrypted]
        plan = try V3DeviceWrappedRevocationPlanner().plan(
            from: base,
            authorizingDeviceID: owner.identity.deviceID,
            revoking: member.identity.deviceID
        )
    }
}

private typealias Fixture = RevocationTransitionFixture
