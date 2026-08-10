import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedSameEpochCatchUpServiceTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c84b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c84b4"
    private static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c84b5"
    private static let forkEntryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c84b6"
    private static let vaultKey = Data(0..<32)

    @Test
    func advancesOneAuthenticatedSameEpochPathWithCheckpointCAS() throws {
        let fixture = try Fixture()

        let outcome = try fixture.service.catchUp()

        #expect(outcome == .advanced(fixture.childTrusted))
        #expect(fixture.owner.kinds == [.catchUpVault])
        #expect(fixture.observer.observedKeys == [[Self.vaultKey]])
        #expect(fixture.checkpointStore.checkpoint
            == fixture.childTrusted.checkpoint.canonicalBytes)
        #expect(fixture.checkpointStore.expectedCheckpoints
            == [fixture.base.checkpoint.canonicalBytes])
        #expect(fixture.cache.storedManifest == fixture.child.manifestData)
    }

    @Test
    func preservesMultipleHeadsWithoutChangingLocalTrust() throws {
        let fixture = try Fixture(includeFork: true)

        let outcome = try fixture.service.catchUp()

        #expect(outcome == .multipleHeads(fixture.observation.heads))
        #expect(fixture.checkpointStore.checkpoint
            == fixture.base.checkpoint.canonicalBytes)
        #expect(fixture.checkpointStore.expectedCheckpoints.isEmpty)
        #expect(fixture.cache.storedManifest == nil)
    }

    @Test
    func mapsACheckpointCompareAndSwapLossToRetryableChange() throws {
        let fixture = try Fixture(checkpointConflict: true)

        #expect(throws: V3DeviceWrappedCatchUpError.checkpointChanged) {
            _ = try fixture.service.catchUp()
        }

        #expect(fixture.checkpointStore.checkpoint
            == fixture.base.checkpoint.canonicalBytes)
        #expect(fixture.cache.storedManifest == nil)
    }

    @Test
    func missingHeadAfterObservationDoesNotAdvanceTrust() throws {
        let fixture = try Fixture(manifestRead: .unavailable)

        #expect(throws: V3DeviceWrappedCatchUpError.temporaryUnavailable) {
            _ = try fixture.service.catchUp()
        }

        #expect(fixture.checkpointStore.checkpoint
            == fixture.base.checkpoint.canonicalBytes)
        #expect(fixture.cache.storedManifest == nil)
    }

    @Test
    func substitutedHeadAfterObservationRequiresRecovery() throws {
        let fixture = try Fixture(
            manifestRead: .available(Data("substituted".utf8))
        )

        #expect(throws: V3DeviceWrappedCatchUpError.recoveryRequired) {
            _ = try fixture.service.catchUp()
        }

        #expect(fixture.checkpointStore.checkpoint
            == fixture.base.checkpoint.canonicalBytes)
        #expect(fixture.cache.storedManifest == nil)
    }

    @Test
    func cacheFailureCannotUndoAnAuthenticatedCheckpointAdvance() throws {
        let fixture = try Fixture(cacheFailure: true)

        let outcome = try fixture.service.catchUp()

        #expect(outcome == .advanced(fixture.childTrusted))
        #expect(fixture.checkpointStore.checkpoint
            == fixture.childTrusted.checkpoint.canonicalBytes)
        #expect(fixture.cache.storeAttempts == 1)
    }

    private final class Fixture: @unchecked Sendable {
        let base: V3DeviceWrappedTrustedCheckpoint
        let child: V3DeviceWrappedContentMutationCandidate
        let childTrusted: V3DeviceWrappedTrustedCheckpoint
        let observation: V3DeviceWrappedRepositoryObservation
        let owner = CatchUpRecordingMutationOwner()
        let observer: CatchUpObservationStub
        let checkpointStore: CatchUpCheckpointStore
        let cache: CatchUpCache
        let service: V3DeviceWrappedSameEpochCatchUpService

        init(
            includeFork: Bool = false,
            checkpointConflict: Bool = false,
            manifestRead requestedManifestRead: V3RepositoryObjectRead? = nil,
            cacheFailure: Bool = false
        ) throws {
            let identity = try Self.identity()
            let genesis = try V3DeviceWrappedGenesisBuilder()
                .buildPublicationCandidate(
                    vaultID:
                        V3DeviceWrappedSameEpochCatchUpServiceTests.vaultID,
                    authorityTransitionID:
                        V3DeviceWrappedSameEpochCatchUpServiceTests
                            .transitionID,
                    entryIDs: [],
                    sourceEntries: [],
                    vaultKey:
                        V3DeviceWrappedSameEpochCatchUpServiceTests.vaultKey,
                    ownerIdentity: identity
                ).genesis
            let baseCheckpoint = try V3ManifestCheckpoint(
                vaultID:
                    V3DeviceWrappedSameEpochCatchUpServiceTests.vaultID,
                envelopeDigest: genesis.manifestDigest
            )
            base = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: baseCheckpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    genesis.manifestData
                )
            )
            child = try V3DeviceWrappedManifestCandidateBuilder().add(
                to: base,
                entryID:
                    V3DeviceWrappedSameEpochCatchUpServiceTests.entryID,
                name: "qualification/laptop",
                type: .secret,
                plaintext: "member value",
                vaultKey:
                    V3DeviceWrappedSameEpochCatchUpServiceTests.vaultKey
            )
            let childCheckpoint = try V3ManifestCheckpoint(
                vaultID:
                    V3DeviceWrappedSameEpochCatchUpServiceTests.vaultID,
                envelopeDigest: child.manifestDigest
            )
            childTrusted = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: childCheckpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    child.manifestData
                )
            )

            var parents: [Data: [Data]] = [
                baseCheckpoint.envelopeDigest: [],
                child.manifestDigest: [baseCheckpoint.envelopeDigest],
            ]
            var heads = [child.manifestDigest]
            if includeFork {
                let fork = try V3DeviceWrappedManifestCandidateBuilder().add(
                    to: base,
                    entryID:
                        V3DeviceWrappedSameEpochCatchUpServiceTests
                            .forkEntryID,
                    name: "qualification/desktop",
                    type: .secret,
                    plaintext: "owner value",
                    vaultKey:
                        V3DeviceWrappedSameEpochCatchUpServiceTests.vaultKey
                )
                parents[fork.manifestDigest] = [
                    baseCheckpoint.envelopeDigest,
                ]
                heads.append(fork.manifestDigest)
                heads.sort(by: { $0.lexicographicallyPrecedes($1) })
            }
            let entryObjects = Set(try child.body.entries.map(entryObjectKey))
            observation = V3DeviceWrappedRepositoryObservation(
                checkpoint: baseCheckpoint,
                heads: heads,
                manifestDigests: Set(parents.keys),
                parentsByManifestDigest: parents,
                referencedEntryObjects: entryObjects,
                resourceUsage: V3ManifestRepositoryUsage(
                    manifestObjectCount: parents.count,
                    maximumHistoryDepth: 1,
                    totalManifestBytes:
                        genesis.manifestData.count + child.manifestData.count,
                    referencedEntryObjectCount: entryObjects.count,
                    totalEntryBytes: child.stagedEntries.reduce(0) {
                        $0 + $1.canonicalBytes.count
                    }
                )
            )
            observer = CatchUpObservationStub(observation: observation)
            checkpointStore = CatchUpCheckpointStore(
                checkpoint: baseCheckpoint.canonicalBytes,
                conflictsOnReplace: checkpointConflict
            )
            cache = CatchUpCache(failsOnStore: cacheFailure)
            let manifestRead = requestedManifestRead
                ?? .available(child.manifestData)
            let childManifestEntry = try #require(child.body.entries.first)
            let childEncryptedEntry = try #require(child.stagedEntries.first)
            let source = CatchUpObjectSource(
                manifestRead: manifestRead,
                entries: [
                    try entryObjectKey(childManifestEntry):
                        childEncryptedEntry.canonicalBytes
                ]
            )
            service = V3DeviceWrappedSameEpochCatchUpService(
                vaultID:
                    V3DeviceWrappedSameEpochCatchUpServiceTests.vaultID,
                mutationOwner: owner,
                stateLoader: CatchUpStateLoader(
                    trusted: base,
                    vaultKey:
                        V3DeviceWrappedSameEpochCatchUpServiceTests.vaultKey
                ),
                repositoryObserver: observer,
                source: source,
                checkpointStore: checkpointStore,
                cache: cache
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

private final class CatchUpRecordingMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private let lock = NSLock()
    private(set) var kinds: [VaultTransactionMutationKind] = []

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        lock.lock()
        kinds.append(kind)
        lock.unlock()
        return try mutation(VaultTransactionMutationContext(
            operationID: VaultTransactionOperationID(),
            kind: kind
        ))
    }
}

private struct CatchUpStateLoader: V3DeviceWrappedMutationStateLoading {
    let trusted: V3DeviceWrappedTrustedCheckpoint
    let vaultKey: Data

    func authenticatedCheckpoint(
        reason _: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        trusted
    }

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
        #expect(keyID == trusted.envelope.body.keyID)
        return vaultKey
    }
}

private final class CatchUpObservationStub:
    V3DeviceWrappedRepositoryObserving,
    @unchecked Sendable
{
    let observation: V3DeviceWrappedRepositoryObservation
    private let lock = NSLock()
    private var keys: [[Data]] = []

    init(observation: V3DeviceWrappedRepositoryObservation) {
        self.observation = observation
    }

    var observedKeys: [[Data]] {
        lock.withLock { keys }
    }

    func observeRepository(
        vaultID _: String,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        lock.withLock {
            keys.append(vaultKeys)
        }
        return observation
    }
}

private final class CatchUpCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var value: Data?
    private let conflictsOnReplace: Bool
    private var expected: [Data?] = []

    init(checkpoint: Data?, conflictsOnReplace: Bool) {
        value = checkpoint
        self.conflictsOnReplace = conflictsOnReplace
    }

    var checkpoint: Data? {
        lock.withLock { value }
    }

    var expectedCheckpoints: [Data?] {
        lock.withLock { expected }
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        checkpoint
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID _: String
    ) throws {
        try lock.withLock {
            expected.append(expectedCheckpoint)
            if conflictsOnReplace || value != expectedCheckpoint {
                throw V3ManifestCheckpointStoreError.conflict
            }
            value = checkpoint
        }
    }
}

private final class CatchUpCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let failsOnStore: Bool
    private var manifest: Data?
    private var attempts = 0

    init(failsOnStore: Bool) {
        self.failsOnStore = failsOnStore
    }

    var storedManifest: Data? {
        lock.withLock { manifest }
    }

    var storeAttempts: Int {
        lock.withLock { attempts }
    }

    func load(
        for _: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        .missing
    }

    func store(
        _ manifestData: Data,
        for _: V3ManifestCheckpoint
    ) throws {
        try lock.withLock {
            attempts += 1
            if failsOnStore {
                throw V3CheckpointManifestCacheError.operationFailed(
                    code: EIO
                )
            }
            manifest = manifestData
        }
    }
}

private struct CatchUpObjectSource: V3ImmutableObjectReading {
    let manifestRead: V3RepositoryObjectRead
    let entries: [V3EntryObjectKey: Data]

    func manifestDigests(
        maximumCount _: Int
    ) throws -> V3RepositoryDirectoryListing {
        .invalid
    }

    func readManifest(
        digest _: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        manifestRead
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        guard let data = entries[V3EntryObjectKey(
            entryID: entryID,
            digest: digest
        )] else {
            return .unavailable
        }
        return .available(data)
    }
}
