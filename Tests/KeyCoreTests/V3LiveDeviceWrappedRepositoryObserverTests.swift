import CryptoKit
import Foundation
import Testing
import JSONCanonicalization

@testable import KeyCore

@Suite(.serialized)
struct V3LiveDeviceWrappedRepositoryObserverTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c54b3"
    private static let genesisTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c54b4"
    private static let enrollmentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c54b5"
    private static let firstEntryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c54b6"
    private static let secondEntryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c54b7"
    private static let seedOperationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c54b8"
    )
    private static let childOperationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c54b9"
    )
    private static let currentKey = Data(0..<32)
    private static let nextKey = Data(repeating: 0x51, count: 32)
    private static let approvalTime: UInt64 = 4_102_444_800

    @Test
    func discoversAnAuthenticatedContentDescendant() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let child = try V3DeviceWrappedManifestCandidateBuilder().add(
            to: fixture.base,
            entryID: Self.secondEntryID,
            name: "second/password",
            type: .secret,
            plaintext: "another secret",
            vaultKey: Self.currentKey
        )
        try fixture.publish(child)

        let observed = try fixture.observer.observeRepository(
            vaultID: Self.vaultID,
            vaultKeys: [Self.currentKey]
        )

        #expect(observed.heads == [child.manifestDigest])
        #expect(observed.parentsByManifestDigest[child.manifestDigest]
            == [fixture.base.checkpoint.envelopeDigest])
        #expect(observed.resourceUsage.manifestObjectCount == 2)
        #expect(observed.resourceUsage.maximumHistoryDepth == 1)
        #expect(observed.resourceUsage.referencedEntryObjectCount == 2)
    }

    @Test
    func observesFromAnExplicitAuthenticatedCheckpoint() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let child = try V3DeviceWrappedManifestCandidateBuilder().add(
            to: fixture.base,
            entryID: Self.secondEntryID,
            name: "second/password",
            type: .secret,
            plaintext: "another secret",
            vaultKey: Self.currentKey
        )
        try fixture.publish(child)
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: child.manifestDigest
        )
        let trusted = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                child.manifestData
            )
        )

        let observed = try fixture.observer.observeRepository(
            from: trusted,
            vaultKeys: [Self.currentKey]
        )

        #expect(observed.checkpoint == checkpoint)
        #expect(observed.heads == [child.manifestDigest])
        #expect(observed.parentsByManifestDigest[child.manifestDigest] == [])
    }

    @Test
    func discoversAnOwnerAuthorizedKeyRotation() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let transition = try fixture.enrollmentTransition()
        try fixture.publish(transition)

        let observed = try fixture.observer.observeRepository(
            vaultID: Self.vaultID,
            vaultKeys: [Self.currentKey, Self.nextKey]
        )

        #expect(observed.heads == [transition.manifestDigest])
        #expect(observed.parentsByManifestDigest[transition.manifestDigest]
            == [fixture.base.checkpoint.envelopeDigest])
        #expect(observed.resourceUsage.referencedEntryObjectCount == 2)
    }

    @Test
    func rejectsAReachableEntryThatHasNotArrived() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let child = try V3DeviceWrappedManifestCandidateBuilder().add(
            to: fixture.base,
            entryID: Self.secondEntryID,
            name: "second/password",
            type: .secret,
            plaintext: "another secret",
            vaultKey: Self.currentKey
        )
        try fixture.publishManifest(
            child.manifestData,
            digest: child.manifestDigest
        )
        let missing = try #require(child.stagedEntries.first)

        #expect(throws: V3ImmutableTransactionError
            .referencedEntryUnavailable(
                entryID: missing.context.entryID,
                digest: missing.ciphertextDigest
            )) {
            _ = try fixture.observer.observeRepository(
                vaultID: Self.vaultID,
                vaultKeys: [Self.currentKey]
            )
        }
    }

    @Test
    func rejectsAnUnsignedReachableKeyRotation() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let transition = try fixture.enrollmentTransition()
        for entry in transition.stagedEntries {
            try fixture.publishEntry(entry)
        }
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            transition.manifestData
        )
        let unsigned = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", .object([
                ("parents", .array(envelope.parents.map {
                    .string(Base64URL.encode($0))
                })),
                ("manifest", envelope.body.canonicalValue),
            ])),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(
                    envelope.authenticationTag
                ))),
            ])),
            ("authorizations", .array([])),
        ]))
        try fixture.publishManifest(
            unsigned,
            digest: Data(SHA256.hash(data: unsigned))
        )

        #expect(throws: V3ImmutableTransactionError.invalidAncestryProof) {
            _ = try fixture.observer.observeRepository(
                vaultID: Self.vaultID,
                vaultKeys: [Self.currentKey, Self.nextKey]
            )
        }
    }

    @Test
    func unrelatedInvalidObjectsConsumeOnlyTheDirectoryBudget() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let unrelated = Data("{}".utf8)
        try fixture.publishManifest(
            unrelated,
            digest: Data(SHA256.hash(data: unrelated))
        )

        let observed = try fixture.observer.observeRepository(
            vaultID: Self.vaultID,
            vaultKeys: [Self.currentKey]
        )

        #expect(observed.heads == [fixture.base.checkpoint.envelopeDigest])
        #expect(observed.resourceUsage.manifestObjectCount == 2)
        #expect(observed.manifestDigests.count == 2)
    }

    @Test
    func substitutedManifestBytesConsumeTheAggregateBudget() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        try fixture.publishSubstitutedManifest(
            Data(repeating: 0x41, count: 9_000),
            namedBy: Data(repeating: 0x71, count: 32)
        )
        try fixture.publishSubstitutedManifest(
            Data(repeating: 0x42, count: 9_000),
            namedBy: Data(repeating: 0x72, count: 32)
        )
        let limits = V3ManifestRepositoryLimits(
            maximumManifestObjects: 8,
            maximumHistoryDepth: 8,
            maximumManifestBytes: 16 * 1_024,
            maximumEntryBytes: 16 * 1_024,
            maximumTotalManifestBytes: 16 * 1_024,
            maximumTotalEntryBytes: 16 * 1_024
        )

        #expect(throws: V3ImmutableTransactionError.objectTooLarge) {
            _ = try fixture.makeObserver(limits: limits).observeRepository(
                vaultID: Self.vaultID,
                vaultKeys: [Self.currentKey]
            )
        }
    }

    private final class Fixture: @unchecked Sendable {
        let rootURL: URL
        let store: V3FilesystemTransactionArtifactStore
        let checkpointStore: ObserverMemoryCheckpointStore
        let cache = ObserverMemoryCheckpointCache()
        let owner: ObserverSoftwareDevice
        let joiner: ObserverSoftwareDevice
        let base: V3DeviceWrappedTrustedCheckpoint
        let currentEntries: [V3EntryObjectKey: V3EncryptedEntry]

        var observer: V3LiveDeviceWrappedRepositoryObserver {
            makeObserver()
        }

        func makeObserver(
            limits: V3ManifestRepositoryLimits = .standard
        ) -> V3LiveDeviceWrappedRepositoryObserver {
            V3LiveDeviceWrappedRepositoryObserver(
                source: store,
                checkpointStore: checkpointStore,
                cache: cache,
                limits: limits
            )
        }

        init() throws {
            rootURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(
                at: rootURL,
                withIntermediateDirectories: true
            )
            store = V3FilesystemTransactionArtifactStore(
                rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
            )
            owner = try ObserverSoftwareDevice(
                vaultID: vaultID,
                displayName: "Owner Mac",
                signingScalar: 0x31,
                wrappingScalar: 0x32
            )
            joiner = try ObserverSoftwareDevice(
                vaultID: vaultID,
                displayName: "Joining Mac",
                signingScalar: 0x41,
                wrappingScalar: 0x42
            )
            let publication = try V3DeviceWrappedGenesisBuilder()
                .buildPublicationCandidate(
                    vaultID: vaultID,
                    authorityTransitionID: genesisTransitionID,
                    entryIDs: [firstEntryID],
                    sourceEntries: [V2MigrationSourceEntry(
                        name: "account/password",
                        type: .secret,
                        plaintext: "correct horse battery staple",
                        sourceData: Data("retained v2 source".utf8)
                    )],
                    vaultKey: currentKey,
                    ownerIdentity: owner.publicIdentity
                )
            for entry in publication.entries {
                let encryptedEntry = entry.encryptedEntry
                let digest = try #require(Base64URL.decodeCanonical(
                    encryptedEntry.ciphertextDigest
                ))
                try store.stageEntry(
                    encryptedEntry.canonicalBytes,
                    entryID: encryptedEntry.context.entryID,
                    digest: digest,
                    operationID: seedOperationID
                )
                try store.publishStagedEntry(
                    encryptedEntry.canonicalBytes,
                    entryID: encryptedEntry.context.entryID,
                    digest: digest,
                    operationID: seedOperationID
                )
            }
            try store.stageManifest(
                publication.genesis.manifestData,
                digest: publication.genesis.manifestDigest,
                operationID: seedOperationID
            )
            try store.publishStagedManifest(
                publication.genesis.manifestData,
                digest: publication.genesis.manifestDigest,
                operationID: seedOperationID
            )
            let checkpoint = try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: publication.genesis.manifestDigest
            )
            checkpointStore = ObserverMemoryCheckpointStore(
                checkpoint: checkpoint
            )
            try cache.store(publication.genesis.manifestData, for: checkpoint)
            base = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    publication.genesis.manifestData
                )
            )
            currentEntries = Dictionary(uniqueKeysWithValues:
                publication.entries.map {
                    (
                        V3EntryObjectKey(
                            entryID: $0.manifestEntry.entryID,
                            digest: $0.digest
                        ),
                        $0.encryptedEntry
                    )
                }
            )
        }

        func enrollmentTransition()
            throws -> V3DeviceWrappedEnrollmentTransitionCandidate
        {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: base,
                currentEntries: currentEntries,
                state: try ceremony(),
                currentVaultKey: currentKey,
                nextVaultKey: nextKey,
                authorityTransitionID: enrollmentTransitionID,
                owner: owner,
                at: approvalTime,
                authorizationReason: "Approve the compared Mac."
            )
        }

        func publish(
            _ candidate: V3DeviceWrappedContentMutationCandidate
        ) throws {
            for entry in candidate.stagedEntries {
                try publishEntry(entry)
            }
            try publishManifest(
                candidate.manifestData,
                digest: candidate.manifestDigest
            )
        }

        func publish(
            _ candidate: V3DeviceWrappedEnrollmentTransitionCandidate
        ) throws {
            for entry in candidate.stagedEntries {
                try publishEntry(entry)
            }
            try publishManifest(
                candidate.manifestData,
                digest: candidate.manifestDigest
            )
        }

        func publishEntry(_ entry: V3EncryptedEntry) throws {
            let digest = try #require(Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ))
            try store.stageEntry(
                entry.canonicalBytes,
                entryID: entry.context.entryID,
                digest: digest,
                operationID: childOperationID
            )
            try store.publishStagedEntry(
                entry.canonicalBytes,
                entryID: entry.context.entryID,
                digest: digest,
                operationID: childOperationID
            )
        }

        func publishManifest(
            _ data: Data,
            digest: Data,
            operationID: VaultTransactionOperationID = childOperationID
        ) throws {
            try store.stageManifest(
                data,
                digest: digest,
                operationID: operationID
            )
            try store.publishStagedManifest(
                data,
                digest: digest,
                operationID: operationID
            )
        }

        func publishSubstitutedManifest(
            _ data: Data,
            namedBy digest: Data
        ) throws {
            let path = rootURL.appendingPathComponent(
                manifestPath(for: digest)
            )
            try data.write(to: path, options: .withoutOverwriting)
        }

        func ceremony() throws -> V3EnrollmentCeremonyState {
            let invitation = try V3EnrollmentInvitation(
                vaultID: vaultID,
                parentManifestDigest: base.checkpoint.envelopeDigest,
                invitingDevice: owner.publicIdentity,
                invitedRole: .member,
                nonce: Data(repeating: 0x61, count: 32),
                expiresAt: approvalTime
            )
            let authenticator = V3EnrollmentMessageAuthenticator()
            let signedInvitation = try authenticator.sign(
                invitation,
                using: owner,
                reason: "Create invitation."
            )
            let request = try V3EnrollmentJoinRequest(
                invitationDigest: invitation.digest,
                joiningDevice: joiner.publicIdentity,
                nonce: Data(repeating: 0x62, count: 32)
            )
            let signedRequest = try authenticator.sign(
                request,
                answering: authenticator.verify(signedInvitation),
                using: joiner,
                reason: "Join vault."
            )
            return try V3EnrollmentCeremonyState(
                vaultID: vaultID,
                invitationDigest: invitation.digest,
                role: .inviter,
                phase: .awaitingComparison,
                signedInvitation: signedInvitation,
                signedJoinRequest: signedRequest
            )
        }

        func removeRoot() {
            try? FileManager.default.removeItem(at: rootURL)
        }
    }
}

private final class ObserverMemoryCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let checkpoint: Data

    init(checkpoint: V3ManifestCheckpoint) {
        self.checkpoint = checkpoint.canonicalBytes
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        checkpoint
    }

    func replaceCheckpoint(
        _: Data,
        expectedCheckpoint _: Data?,
        vaultID _: String
    ) throws {
        throw V3ManifestCheckpointStoreError.conflict
    }
}

private final class ObserverMemoryCheckpointCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var storedCheckpoint: V3ManifestCheckpoint?
    private var storedData: Data?

    func load(
        for checkpoint: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        lock.withLock {
            guard storedCheckpoint == checkpoint, let storedData else {
                return .missing
            }
            return .available(storedData)
        }
    }

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws {
        lock.withLock {
            storedCheckpoint = checkpoint
            storedData = manifestData
        }
    }
}

private struct ObserverSoftwareDevice:
    V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let signingPrivateKey: P256.Signing.PrivateKey
    private let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    init(
        vaultID: String,
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        signingPrivateKey = try P256.Signing.PrivateKey(
            rawRepresentation: observerPrivateKeyBytes(signingScalar)
        )
        wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: observerPrivateKeyBytes(wrappingScalar)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingPrivateKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingPrivateKey.signature(for: input).rawRepresentation
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: wrappingPrivateKey,
            context: context
        )
    }
}

private func observerPrivateKeyBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}
