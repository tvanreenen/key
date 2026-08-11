import CryptoKit
import Foundation
import Testing

@testable import KeyCore

@Suite
struct V3DeviceWrappedVaultMutationServiceTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let sourceID =
        "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let addedID =
        "018f4d3a-a844-72ad-983e-b09a8fc0e924"
    private static let vaultKey = Data(0..<32)
    private static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d3b-033d-770e-a63c-ddb280e24d1f"
    )

    @Test
    func addRecoversThenPublishesFromTheExactAuthenticatedCheckpoint()
        throws
    {
        let fixture = try Fixture()
        let publisher = RecordingPermanentMutationPublisher()
        let factory = RecordingPermanentMutationPublisherFactory(
            publisher: publisher
        )
        let service = fixture.service(
            factory: factory,
            entryID: Self.addedID
        )

        try service.add(
            name: "service/new",
            secret: "new value",
            type: .secret,
            operationID: Self.operationID
        )

        #expect(factory.operationIDs == [Self.operationID])
        #expect(publisher.events == [.recovered, .published])
        let candidate = try #require(publisher.candidate)
        #expect(candidate.kind == .addEntry)
        #expect(candidate.expectedCheckpoint == fixture.trusted.checkpoint)
        #expect(candidate.body.entries.count == 2)
        #expect(candidate.body.devices == fixture.trusted.envelope.body.devices)
        #expect(
            candidate.body.wrappedKeys
                == fixture.trusted.envelope.body.wrappedKeys
        )
        #expect(
            candidate.body.authorityTransitionID
                == fixture.trusted.envelope.body.authorityTransitionID
        )
        let added = try #require(candidate.body.entries.first {
            $0.entryID == Self.addedID
        })
        #expect(added.name == "service/new")
        #expect(added.revision == 1)
        #expect(publisher.publishedVaultKey == Self.vaultKey)
    }

    @Test
    func completedRecoveryReauthenticatesBeforePlanningTheRequestedWrite()
        throws
    {
        let fixture = try Fixture()
        let publisher = RecordingPermanentMutationPublisher(
            recoveryOutcome: .completed(operationID: Self.operationID)
        )
        let factory = RecordingPermanentMutationPublisherFactory(
            publisher: publisher
        )
        let service = fixture.service(
            factory: factory,
            entryID: Self.addedID
        )

        try service.remove(
            name: "service/source",
            operationID: Self.operationID
        )

        #expect(fixture.stateLoader.checkpointLoadCount == 2)
        #expect(fixture.stateLoader.keyLoadCount == 2)
        #expect(publisher.events == [.recovered, .published])
    }

    @Test
    func missingBaseEntryBlocksPublicationAsTemporaryUnavailable() throws {
        let fixture = try Fixture(entryRead: .unavailable)
        let publisher = RecordingPermanentMutationPublisher()
        let service = fixture.service(
            factory: RecordingPermanentMutationPublisherFactory(
                publisher: publisher
            ),
            entryID: Self.addedID
        )

        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try service.remove(
                name: "service/source",
                operationID: Self.operationID
            )
        }
        #expect(publisher.events == [.recovered])
    }

    @Test
    func substitutedBaseEntryBlocksPublicationAsRecoveryRequired() throws {
        let fixture = try Fixture(
            entryRead: .available(Data("substituted".utf8))
        )
        let publisher = RecordingPermanentMutationPublisher()
        let service = fixture.service(
            factory: RecordingPermanentMutationPublisherFactory(
                publisher: publisher
            ),
            entryID: Self.addedID
        )

        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try service.copy(
                source: "service/source",
                destination: "service/copied",
                overwrite: false,
                operationID: Self.operationID
            )
        }
        #expect(publisher.events == [.recovered])
    }

    @Test
    func catchUpFailureStopsBeforeMutationStateIsOpened() throws {
        let fixture = try Fixture()
        let publisher = RecordingPermanentMutationPublisher()
        let factory = RecordingPermanentMutationPublisherFactory(
            publisher: publisher
        )
        let catchUp = RecordingFailedMutationCatchUp()
        let service = fixture.service(
            factory: factory,
            entryID: Self.addedID,
            catchUp: { operationID in try catchUp.run(operationID) }
        )

        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try service.add(
                name: "service/new",
                secret: "new value",
                type: .secret,
                operationID: Self.operationID
            )
        }

        #expect(catchUp.operationIDs == [Self.operationID])
        #expect(fixture.stateLoader.checkpointLoadCount == 0)
        #expect(factory.operationIDs.isEmpty)
        #expect(publisher.events.isEmpty)
    }

    private final class Fixture: @unchecked Sendable {
        let trusted: V3DeviceWrappedTrustedCheckpoint
        let stateLoader: PermanentMutationStateLoader
        let source: PermanentMutationSource

        init(entryRead: V3RepositoryObjectRead? = nil) throws {
            let sourceEntry = V2MigrationSourceEntry(
                name: "service/source",
                type: .secret,
                plaintext: "source value",
                sourceData: Data("legacy source".utf8)
            )
            let publication = try V3DeviceWrappedGenesisBuilder()
                .buildPublicationCandidate(
                    vaultID: V3DeviceWrappedVaultMutationServiceTests.vaultID,
                    authorityTransitionID:
                        V3DeviceWrappedVaultMutationServiceTests.transitionID,
                    entryIDs: [
                        V3DeviceWrappedVaultMutationServiceTests.sourceID,
                    ],
                    sourceEntries: [sourceEntry],
                    vaultKey:
                        V3DeviceWrappedVaultMutationServiceTests.vaultKey,
                    ownerIdentity: try Self.identity()
                )
            let checkpoint = try V3ManifestCheckpoint(
                vaultID: V3DeviceWrappedVaultMutationServiceTests.vaultID,
                envelopeDigest: publication.genesis.manifestDigest
            )
            trusted = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    publication.genesis.manifestData
                )
            )
            stateLoader = PermanentMutationStateLoader(
                trusted: trusted,
                vaultKey: V3DeviceWrappedVaultMutationServiceTests.vaultKey
            )
            let entry = try #require(publication.entries.first)
            source = PermanentMutationSource(
                entryRead: entryRead
                    ?? .available(entry.encryptedEntry.canonicalBytes)
            )
        }

        func service(
            factory: RecordingPermanentMutationPublisherFactory,
            entryID: String,
            catchUp: V3DeviceWrappedVaultMutationService.CatchUp? = nil
        ) -> V3DeviceWrappedVaultMutationService {
            V3DeviceWrappedVaultMutationService(
                stateLoader: stateLoader,
                source: source,
                makePublisher: { operationID in
                    factory.publisher(for: operationID)
                },
                makeEntryID: { entryID },
                catchUp: catchUp
            )
        }

        private static func identity() throws
            -> V3EnrollmentDeviceIdentity
        {
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

        private static func scalar(_ value: UInt8) -> Data {
            Data(repeating: 0, count: 31) + Data([value])
        }
    }
}

private final class RecordingFailedMutationCatchUp: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedOperationIDs: [VaultTransactionOperationID] = []

    var operationIDs: [VaultTransactionOperationID] {
        lock.withLock { recordedOperationIDs }
    }

    func run(
        _ operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedCatchUpCoordinatorOutcome {
        lock.withLock {
            recordedOperationIDs.append(operationID)
        }
        throw V3DeviceWrappedCatchUpError.temporaryUnavailable
    }
}

private final class PermanentMutationStateLoader:
    V3DeviceWrappedMutationStateLoading,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let trusted: V3DeviceWrappedTrustedCheckpoint
    private let vaultKey: Data
    private var checkpointLoads = 0
    private var keyLoads = 0

    init(trusted: V3DeviceWrappedTrustedCheckpoint, vaultKey: Data) {
        self.trusted = trusted
        self.vaultKey = vaultKey
    }

    var checkpointLoadCount: Int {
        lock.withLock { checkpointLoads }
    }

    var keyLoadCount: Int {
        lock.withLock { keyLoads }
    }

    func authenticatedCheckpoint(
        reason _: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        lock.withLock {
            checkpointLoads += 1
        }
        return trusted
    }

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
        lock.withLock {
            keyLoads += 1
        }
        #expect(keyID == trusted.envelope.body.keyID)
        return vaultKey
    }
}

private final class PermanentMutationSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    private let entryRead: V3RepositoryObjectRead

    init(entryRead: V3RepositoryObjectRead) {
        self.entryRead = entryRead
    }

    func manifestDigests(
        maximumCount _: Int
    ) throws -> V3RepositoryDirectoryListing {
        .available(digests: [], objectCount: 0)
    }

    func readManifest(
        digest _: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        .unavailable
    }

    func readEntry(
        entryID _: String,
        digest _: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        entryRead
    }
}

private final class RecordingPermanentMutationPublisherFactory:
    @unchecked Sendable
{
    private let lock = NSLock()
    private let publisherValue: RecordingPermanentMutationPublisher
    private var recordedOperationIDs: [VaultTransactionOperationID] = []

    init(publisher: RecordingPermanentMutationPublisher) {
        publisherValue = publisher
    }

    var operationIDs: [VaultTransactionOperationID] {
        lock.withLock { recordedOperationIDs }
    }

    func publisher(
        for operationID: VaultTransactionOperationID
    ) -> any V3DeviceWrappedContentMutationPublishing {
        lock.withLock {
            recordedOperationIDs.append(operationID)
        }
        return publisherValue
    }
}

private final class RecordingPermanentMutationPublisher:
    V3DeviceWrappedContentMutationPublishing,
    @unchecked Sendable
{
    enum Event: Equatable {
        case recovered
        case published
    }

    private let lock = NSLock()
    private let recoveryOutcome: V3ImmutableTransactionRecoveryOutcome
    private var recordedEvents: [Event] = []
    private var recordedCandidate: V3DeviceWrappedContentMutationCandidate?
    private var recordedVaultKey: Data?

    init(
        recoveryOutcome: V3ImmutableTransactionRecoveryOutcome =
            .nothingToRecover
    ) {
        self.recoveryOutcome = recoveryOutcome
    }

    var events: [Event] {
        lock.withLock { recordedEvents }
    }

    var candidate: V3DeviceWrappedContentMutationCandidate? {
        lock.withLock { recordedCandidate }
    }

    var publishedVaultKey: Data? {
        lock.withLock { recordedVaultKey }
    }

    func publish(
        _ candidate: V3DeviceWrappedContentMutationCandidate,
        vaultKey: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        lock.withLock {
            recordedEvents.append(.published)
            recordedCandidate = candidate
            recordedVaultKey = vaultKey
        }
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: candidate.body.vaultID,
                envelopeDigest: candidate.manifestDigest
            ),
            envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                candidate.manifestData
            )
        )
    }

    func recoverInterruptedTransaction(
        vaultID _: String,
        vaultKey _: Data
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        lock.withLock {
            recordedEvents.append(.recovered)
        }
        return recoveryOutcome
    }
}
