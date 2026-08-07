import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedManifestCandidateBuilderTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let sourceID =
        "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let destinationID =
        "018f4d3a-a844-72ad-983e-b09a8fc0e924"
    private static let addedID =
        "018f4d3b-033d-770e-a63c-ddb280e24d1f"
    private static let vaultKey = Data(0..<32)

    @Test
    func addBuildsAnExactParentAndPreservesAuthority() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedManifestCandidateBuilder().add(
            to: fixture.trusted,
            entryID: Self.addedID,
            name: "service/new",
            type: .secret,
            plaintext: "new value",
            vaultKey: Self.vaultKey
        )

        try Self.expectValidCandidate(
            candidate,
            kind: .addEntry,
            base: fixture.trusted
        )
        #expect(candidate.stagedEntries.count == 1)
        let added = try #require(candidate.body.entries.first {
            $0.entryID == Self.addedID
        })
        #expect(added.name == "service/new")
        #expect(added.revision == 1)
        #expect(
            try V3EntryCipher().openTrusted(
                candidate.stagedEntries[0].canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: added,
                vaultKey: Self.vaultKey
            ) == "new value"
        )
    }

    @Test
    func editPreservesIdentityAndAdvancesOnlyItsRevision() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedManifestCandidateBuilder().edit(
            in: fixture.trusted,
            name: "service/source",
            type: .totp,
            plaintext: "JBSWY3DPEHPK3PXP",
            vaultKey: Self.vaultKey
        )

        try Self.expectValidCandidate(
            candidate,
            kind: .editEntry,
            base: fixture.trusted
        )
        let edited = try #require(candidate.body.entries.first {
            $0.entryID == Self.sourceID
        })
        #expect(edited.name == "service/source")
        #expect(edited.type == .totp)
        #expect(edited.revision == 5)
        #expect(candidate.body.entries.first {
            $0.entryID == Self.destinationID
        } == fixture.destination.manifestEntry)
    }

    @Test
    func copyResealsUnderANewIdentityAndCanReplaceTheDestination() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedManifestCandidateBuilder().copy(
            in: fixture.trusted,
            sourceName: "service/source",
            sourceData: fixture.source.encrypted.canonicalBytes,
            destinationEntryID: Self.addedID,
            destinationName: "service/destination",
            overwrite: true,
            vaultKey: Self.vaultKey
        )

        try Self.expectValidCandidate(
            candidate,
            kind: .copyEntry,
            base: fixture.trusted
        )
        #expect(candidate.body.entries.count == 2)
        #expect(!candidate.body.entries.contains {
            $0.entryID == Self.destinationID
        })
        let copied = try #require(candidate.body.entries.first {
            $0.entryID == Self.addedID
        })
        #expect(copied.name == "service/destination")
        #expect(copied.type == .secret)
        #expect(copied.revision == 1)
        #expect(
            try V3EntryCipher().openTrusted(
                candidate.stagedEntries[0].canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: copied,
                vaultKey: Self.vaultKey
            ) == "source value"
        )
    }

    @Test
    func movePreservesSourceIdentityAndCanReplaceTheDestination() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedManifestCandidateBuilder().move(
            in: fixture.trusted,
            sourceName: "service/source",
            sourceData: fixture.source.encrypted.canonicalBytes,
            destinationName: "service/destination",
            overwrite: true,
            vaultKey: Self.vaultKey
        )

        try Self.expectValidCandidate(
            candidate,
            kind: .moveEntry,
            base: fixture.trusted
        )
        #expect(candidate.body.entries.count == 1)
        let moved = try #require(candidate.body.entries.first)
        #expect(moved.entryID == Self.sourceID)
        #expect(moved.name == "service/destination")
        #expect(moved.revision == 5)
        #expect(
            try V3EntryCipher().openTrusted(
                candidate.stagedEntries[0].canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: moved,
                vaultKey: Self.vaultKey
            ) == "source value"
        )
    }

    @Test
    func removePublishesNoEntryObject() throws {
        let fixture = try Self.fixture()
        let candidate = try V3DeviceWrappedManifestCandidateBuilder().remove(
            from: fixture.trusted,
            name: "service/source",
            vaultKey: Self.vaultKey
        )

        try Self.expectValidCandidate(
            candidate,
            kind: .removeEntry,
            base: fixture.trusted
        )
        #expect(candidate.stagedEntries.isEmpty)
        #expect(candidate.body.entries == [fixture.destination.manifestEntry])
    }

    @Test
    func refusesOverwriteAndIdentityCollisionsBeforeBuilding() throws {
        let fixture = try Self.fixture()
        let builder = V3DeviceWrappedManifestCandidateBuilder()

        #expect(throws: V3DeviceWrappedContentMutationError.entryExists) {
            _ = try builder.copy(
                in: fixture.trusted,
                sourceName: "service/source",
                sourceData: fixture.source.encrypted.canonicalBytes,
                destinationEntryID: Self.addedID,
                destinationName: "service/destination",
                overwrite: false,
                vaultKey: Self.vaultKey
            )
        }
        #expect(throws: V3DeviceWrappedContentMutationError.invalidEntryID) {
            _ = try builder.copy(
                in: fixture.trusted,
                sourceName: "service/source",
                sourceData: fixture.source.encrypted.canonicalBytes,
                destinationEntryID: Self.destinationID,
                destinationName: "service/copied",
                overwrite: false,
                vaultKey: Self.vaultKey
            )
        }
    }

    @Test
    func rejectsWrongAuthorityKeyAndSubstitutedSourceBytes() throws {
        let fixture = try Self.fixture()
        let builder = V3DeviceWrappedManifestCandidateBuilder()

        #expect(throws: V3DeviceWrappedContentMutationError.invalidVaultKey) {
            _ = try builder.remove(
                from: fixture.trusted,
                name: "service/source",
                vaultKey: Data(repeating: 0xFF, count: 32)
            )
        }
        #expect(throws: V3EncryptedEntryError.digestMismatch) {
            _ = try builder.move(
                in: fixture.trusted,
                sourceName: "service/source",
                sourceData: fixture.destination.encrypted.canonicalBytes,
                destinationName: "service/moved",
                overwrite: false,
                vaultKey: Self.vaultKey
            )
        }

        let wrongCheckpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 0xAA, count: 32)
        )
        #expect(
            throws:
                V3DeviceWrappedContentMutationError.invalidTrustedCheckpoint
        ) {
            _ = try builder.remove(
                from: V3DeviceWrappedTrustedCheckpoint(
                    checkpoint: wrongCheckpoint,
                    envelope: fixture.trusted.envelope
                ),
                name: "service/source",
                vaultKey: Self.vaultKey
            )
        }

        let envelope = fixture.trusted.envelope
        let inconsistentEnvelope = V3DeviceWrappedManifestEnvelope(
            parents: [Data(repeating: 0xBB, count: 32)],
            body: envelope.body,
            authenticationTag: envelope.authenticationTag,
            authorizations: envelope.authorizations,
            canonicalBytes: envelope.canonicalBytes,
            canonicalContentBytes: envelope.canonicalContentBytes
        )
        #expect(
            throws:
                V3DeviceWrappedContentMutationError.invalidTrustedCheckpoint
        ) {
            _ = try builder.remove(
                from: V3DeviceWrappedTrustedCheckpoint(
                    checkpoint: fixture.trusted.checkpoint,
                    envelope: inconsistentEnvelope
                ),
                name: "service/source",
                vaultKey: Self.vaultKey
            )
        }
    }

    private struct EntryFixture {
        let encrypted: V3EncryptedEntry
        let manifestEntry: V3ManifestEntry
    }

    private struct Fixture {
        let trusted: V3DeviceWrappedTrustedCheckpoint
        let source: EntryFixture
        let destination: EntryFixture
    }

    private static func fixture() throws -> Fixture {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        let source = try entry(
            id: sourceID,
            name: "service/source",
            plaintext: "source value",
            revision: 4,
            keyID: keyID
        )
        let destination = try entry(
            id: destinationID,
            name: "service/destination",
            plaintext: "destination value",
            revision: 2,
            keyID: keyID
        )
        let owner = try identity()
        let genesis = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: vaultID,
            authorityTransitionID: transitionID,
            vaultKey: vaultKey,
            ownerIdentity: owner,
            entries: [source.manifestEntry, destination.manifestEntry]
                .sorted(by: v3ManifestEntryPrecedes)
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: vaultID,
            envelopeDigest: genesis.manifestDigest
        )
        return Fixture(
            trusted: V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    genesis.manifestData
                )
            ),
            source: source,
            destination: destination
        )
    }

    private static func entry(
        id: String,
        name: String,
        plaintext: String,
        revision: UInt64,
        keyID: V3VaultKeyID
    ) throws -> EntryFixture {
        let encrypted = try V3EntryCipher().seal(
            plaintext,
            context: V3EntryAuthenticationContext(
                vaultID: vaultID,
                entryID: id,
                name: name,
                type: .secret,
                keyID: keyID,
                revision: revision
            ),
            vaultKey: vaultKey
        )
        return EntryFixture(
            encrypted: encrypted,
            manifestEntry: V3ManifestEntry(
                entryID: id,
                name: name,
                type: .secret,
                revision: revision,
                keyID: keyID,
                ciphertextDigest: encrypted.ciphertextDigest
            )
        )
    }

    private static func identity() throws -> V3EnrollmentDeviceIdentity {
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: scalar(1)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: scalar(2)
        )
        return try V3EnrollmentDeviceIdentity(
            displayName: "Owner Mac",
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    private static func expectValidCandidate(
        _ candidate: V3DeviceWrappedContentMutationCandidate,
        kind: VaultTransactionMutationKind,
        base: V3DeviceWrappedTrustedCheckpoint
    ) throws {
        #expect(candidate.kind == kind)
        #expect(candidate.expectedCheckpoint == base.checkpoint)
        #expect(candidate.manifestDigest == Data(SHA256.hash(
            data: candidate.manifestData
        )))

        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            candidate.manifestData
        )
        #expect(envelope.parents == [base.checkpoint.envelopeDigest])
        #expect(envelope.body == candidate.body)
        #expect(envelope.authorizations.isEmpty)
        #expect(envelope.body.keyID == base.envelope.body.keyID)
        #expect(
            envelope.body.authorityTransitionID
                == base.envelope.body.authorityTransitionID
        )
        #expect(envelope.body.devices == base.envelope.body.devices)
        #expect(envelope.body.wrappedKeys == base.envelope.body.wrappedKeys)
        #expect(try V3ManifestAuthenticator.isValidAuthenticationTag(
            envelope.authenticationTag,
            canonicalContent: envelope.canonicalContentBytes,
            vaultID: vaultID,
            vaultKey: vaultKey
        ))
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}
