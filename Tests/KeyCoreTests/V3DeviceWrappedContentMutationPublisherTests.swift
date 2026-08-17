import CryptoKit
import Foundation
import Testing

@testable import KeyCore

private func permanentAvailableData(
    _ read: V3RepositoryObjectRead
) -> Data? {
    guard case let .available(data) = read else {
        return nil
    }
    return data
}

private func permanentIsUnavailable(
    _ read: V3RepositoryObjectRead
) -> Bool {
    if case .unavailable = read {
        return true
    }
    return false
}

struct V3DeviceWrappedContentMutationPublisherTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let sourceID =
        "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let addedID =
        "018f4d3a-a844-72ad-983e-b09a8fc0e924"
    private static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d3b-033d-770e-a63c-ddb280e24d1f"
    )
    private static let seedOperationID = try! VaultTransactionOperationID(
        validating: "018f4d3c-152e-7711-8ea9-8fa684d7353b"
    )
    private static let vaultKey = Data(0..<32)

    @Test
    func publishesEntriesBeforeManifestAndAdvancesCheckpointLast() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let observer = RecordingPermanentPhaseObserver()

        let trusted = try fixture.publisher(
            phaseObserver: observer
        ).publish(fixture.candidate, vaultKey: Self.vaultKey)

        #expect(observer.phases == [
            .recoveryAnchorPrepared,
            .recoveryIntentPersisted,
            .recoveryArmed,
            .entryStaged(index: 0),
            .manifestStaged,
            .repositoryStateRechecked,
            .entryPublished(index: 0),
            .publishedEntriesValidated,
            .manifestPublished,
            .publishedManifestValidated,
            .checkpointAdvanced,
            .cleanupCompleted,
        ])
        #expect(
            fixture.checkpointStore.checkpoint
                == trusted.checkpoint.canonicalBytes
        )
        #expect(trusted.envelope.body == fixture.candidate.body)
        #expect(
            fixture.cache.storedManifest
                == fixture.candidate.manifestData
        )
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(permanentAvailableData(try fixture.store.readManifest(
            digest: fixture.candidate.manifestDigest,
            maximumBytes: 2 * 1_024 * 1_024
        )) == fixture.candidate.manifestData)
        let staged = try #require(fixture.candidate.stagedEntries.first)
        let digest = try #require(Base64URL.decodeCanonical(
            staged.ciphertextDigest
        ))
        #expect(permanentAvailableData(try fixture.store.readEntry(
            entryID: staged.context.entryID,
            digest: digest,
            maximumBytes: 16 * 1_024 * 1_024
        )) == staged.canonicalBytes)
    }

    @Test
    func publicationUsesTheAuthenticatedCachedParentWhenProviderIsEvicted()
        throws
    {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        try FileManager.default.removeItem(
            at: fixture.publishedBaseManifestURL
        )

        let trusted = try fixture.publisher(
            phaseObserver: RecordingPermanentPhaseObserver()
        ).publish(fixture.candidate, vaultKey: Self.vaultKey)

        #expect(trusted.envelope.body == fixture.candidate.body)
        #expect(
            fixture.checkpointStore.checkpoint
                == trusted.checkpoint.canonicalBytes
        )
    }

    @Test
    func cacheFailureFallsBackToTheProviderParent() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }

        let trusted = try fixture.publisher(
            phaseObserver: RecordingPermanentPhaseObserver(),
            cache: PermanentThrowingCheckpointCache()
        ).publish(fixture.candidate, vaultKey: Self.vaultKey)

        #expect(trusted.envelope.body == fixture.candidate.body)
        #expect(
            fixture.checkpointStore.checkpoint
                == trusted.checkpoint.canonicalBytes
        )
    }

    @Test
    func cleanupFailurePreservesParentCacheForOfflineRecovery() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        fixture.anchorStore.failNextRemoval()
        let publisher = fixture.publisher(
            phaseObserver: RecordingPermanentPhaseObserver()
        )

        let trusted = try publisher.publish(
            fixture.candidate,
            vaultKey: Self.vaultKey
        )

        #expect(
            fixture.checkpointStore.checkpoint
                == trusted.checkpoint.canonicalBytes
        )
        #expect(fixture.cache.storedManifest == fixture.baseManifestData)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)
        try FileManager.default.removeItem(
            at: fixture.publishedBaseManifestURL
        )

        let outcome = try publisher.recoverInterruptedTransaction(
            vaultID: Self.vaultID,
            vaultKey: Self.vaultKey
        )

        #expect(outcome == .alreadyCompleted(operationID: Self.operationID))
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(fixture.cache.storedManifest == fixture.candidate.manifestData)
    }

    @Test
    func everyInterruptionRecoversToTheCompleteOldOrNewCheckpoint() throws {
        let cases: [(
            phase: V3ImmutableTransactionPhase,
            expectsNewCheckpoint: Bool
        )] = [
            (.recoveryAnchorPrepared, false),
            (.recoveryIntentPersisted, false),
            (.recoveryArmed, false),
            (.entryStaged(index: 0), false),
            (.manifestStaged, true),
            (.repositoryStateRechecked, true),
            (.entryPublished(index: 0), true),
            (.publishedEntriesValidated, true),
            (.manifestPublished, true),
            (.publishedManifestValidated, true),
            (.checkpointAdvanced, true),
            (.cleanupCompleted, true),
        ]

        for testCase in cases {
            let fixture = try Fixture()
            defer { fixture.removeRoot() }
            let observer = InterruptingPermanentPhaseObserver(
                target: testCase.phase
            )
            let publisher = fixture.publisher(phaseObserver: observer)

            #expect(throws: PermanentPublicationTestError.interrupted) {
                _ = try publisher.publish(
                    fixture.candidate,
                    vaultKey: Self.vaultKey
                )
            }
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                vaultKey: Self.vaultKey
            )

            let expected = testCase.expectsNewCheckpoint
                ? try V3ManifestCheckpoint(
                    vaultID: Self.vaultID,
                    envelopeDigest: fixture.candidate.manifestDigest
                )
                : fixture.base.checkpoint
            #expect(fixture.checkpointStore.checkpoint == expected.canonicalBytes)
            #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
            #expect(fixture.cache.storedManifest == (
                testCase.expectsNewCheckpoint
                    ? fixture.candidate.manifestData
                    : fixture.baseManifestData
            ))
        }
    }

    @Test
    func checkpointChangeBeforePublicationCleansUpWithoutPublishing() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let concurrent = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 0xAA, count: 32)
        )
        let observer = CheckpointChangingPermanentPhaseObserver(
            target: .manifestStaged,
            store: fixture.checkpointStore,
            expected: fixture.base.checkpoint,
            replacement: concurrent
        )

        #expect(throws: V3ImmutableTransactionError.expectedHeadsChanged) {
            _ = try fixture.publisher(
                phaseObserver: observer
            ).publish(fixture.candidate, vaultKey: Self.vaultKey)
        }

        #expect(fixture.checkpointStore.checkpoint == concurrent.canonicalBytes)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(permanentIsUnavailable(try fixture.store.readManifest(
            digest: fixture.candidate.manifestDigest,
            maximumBytes: 2 * 1_024 * 1_024
        )))
    }

    @Test
    func recoveryAbandonsStagingWhenAnotherCheckpointWon() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            phaseObserver: InterruptingPermanentPhaseObserver(
                target: .manifestStaged
            )
        )
        #expect(throws: PermanentPublicationTestError.interrupted) {
            _ = try publisher.publish(
                fixture.candidate,
                vaultKey: Self.vaultKey
            )
        }
        let concurrent = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 0xBB, count: 32)
        )
        try fixture.checkpointStore.replaceCheckpoint(
            concurrent.canonicalBytes,
            expectedCheckpoint: fixture.base.checkpoint.canonicalBytes,
            vaultID: Self.vaultID
        )

        let outcome = try publisher.recoverInterruptedTransaction(
            vaultID: Self.vaultID,
            vaultKey: Self.vaultKey
        )

        #expect(outcome == .abandoned(operationID: Self.operationID))
        #expect(fixture.checkpointStore.checkpoint == concurrent.canonicalBytes)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(permanentIsUnavailable(try fixture.store.readManifest(
            digest: fixture.candidate.manifestDigest,
            maximumBytes: 2 * 1_024 * 1_024
        )))
    }

    @Test
    func recoveryAnchorRejectsACanonicalIntentSubstitution() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            phaseObserver: InterruptingPermanentPhaseObserver(
                target: .recoveryArmed
            )
        )
        #expect(throws: PermanentPublicationTestError.interrupted) {
            _ = try publisher.publish(
                fixture.candidate,
                vaultKey: Self.vaultKey
            )
        }
        guard case let .available(intentData) = try fixture.store
            .readRecoveryIntent(
                operationID: Self.operationID,
                maximumBytes:
                    V3ImmutableTransactionRecoveryIntent.maximumBytes
            )
        else {
            Issue.record("The anchored recovery intent was unavailable.")
            return
        }
        let intent = try V3ImmutableTransactionRecoveryIntent(
            canonicalBytes: intentData
        )
        let substituted = try V3ImmutableTransactionRecoveryIntent(
            operationID: intent.operationID,
            kind: intent.kind,
            vaultID: intent.vaultID,
            expectedCheckpoint: intent.expectedCheckpoint,
            expectedHeads: intent.expectedHeads,
            candidateManifestDigest: Data(repeating: 0xA5, count: 32),
            stagedEntries: intent.stagedEntries,
            enrollmentTranscriptDigest: intent.enrollmentTranscriptDigest
        )
        try substituted.canonicalBytes.write(to: fixture.recoveryIntentURL)

        #expect(
            throws: V3ImmutableTransactionRecoveryError.invalidIntent(
                operationID: Self.operationID.rawValue
            )
        ) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                vaultKey: Self.vaultKey
            )
        }
        #expect(
            fixture.checkpointStore.checkpoint
                == fixture.base.checkpoint.canonicalBytes
        )
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)
        #expect(permanentIsUnavailable(try fixture.store.readManifest(
            digest: fixture.candidate.manifestDigest,
            maximumBytes: 2 * 1_024 * 1_024
        )))
    }

    @Test(arguments: [true, false])
    func substitutedStagingNeverAdvancesTheCheckpoint(
        tamperManifest: Bool
    ) throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            phaseObserver: InterruptingPermanentPhaseObserver(
                target: .manifestStaged
            )
        )
        #expect(throws: PermanentPublicationTestError.interrupted) {
            _ = try publisher.publish(
                fixture.candidate,
                vaultKey: Self.vaultKey
            )
        }
        if tamperManifest {
            try Data("substituted manifest".utf8).write(
                to: fixture.stagedManifestURL
            )
        } else {
            try Data("substituted entry".utf8).write(
                to: fixture.stagedEntryURL
            )
        }

        #expect(throws: V3ImmutableTransactionRecoveryError.self) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                vaultKey: Self.vaultKey
            )
        }
        #expect(
            fixture.checkpointStore.checkpoint
                == fixture.base.checkpoint.canonicalBytes
        )
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)
    }

    @Test
    func recoveryRequiresTheExactCandidateVaultKey() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            phaseObserver: InterruptingPermanentPhaseObserver(
                target: .manifestStaged
            )
        )
        #expect(throws: PermanentPublicationTestError.interrupted) {
            _ = try publisher.publish(
                fixture.candidate,
                vaultKey: Self.vaultKey
            )
        }

        #expect(
            throws: V3ImmutableTransactionRecoveryError.vaultKeyUnavailable(
                keyID: fixture.candidate.body.keyID.rawValue
            )
        ) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                vaultKey: Data(repeating: 0xFF, count: 32)
            )
        }
        #expect(
            fixture.checkpointStore.checkpoint
                == fixture.base.checkpoint.canonicalBytes
        )
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)
    }

    private final class Fixture: @unchecked Sendable {
        let rootURL: URL
        let store: V3FilesystemTransactionArtifactStore
        let checkpointStore: PermanentMemoryCheckpointStore
        let anchorStore = PermanentMemoryRecoveryAnchorStore()
        let cache = PermanentMemoryCheckpointCache()
        let base: V3DeviceWrappedTrustedCheckpoint
        let baseManifestData: Data
        let candidate: V3DeviceWrappedContentMutationCandidate

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
            let keyID = try V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: vaultID
            )
            let source = try V3EntryCipher().seal(
                "source value",
                context: V3EntryAuthenticationContext(
                    vaultID: vaultID,
                    entryID: sourceID,
                    name: "service/source",
                    type: .secret,
                    keyID: keyID,
                    revision: 1
                ),
                vaultKey: vaultKey
            )
            let sourceDigest = try #require(Base64URL.decodeCanonical(
                source.ciphertextDigest
            ))
            let genesis = try V3DeviceWrappedGenesisBuilder().build(
                vaultID: vaultID,
                authorityTransitionID: transitionID,
                vaultKey: vaultKey,
                ownerIdentity: try Self.identity(),
                entries: [V3ManifestEntry(
                    entryID: sourceID,
                    name: "service/source",
                    type: .secret,
                    revision: 1,
                    keyID: keyID,
                    ciphertextDigest: source.ciphertextDigest
                )]
            )
            try store.stageEntry(
                source.canonicalBytes,
                entryID: sourceID,
                digest: sourceDigest,
                operationID: seedOperationID
            )
            try store.publishStagedEntry(
                source.canonicalBytes,
                entryID: sourceID,
                digest: sourceDigest,
                operationID: seedOperationID
            )
            try store.stageManifest(
                genesis.manifestData,
                digest: genesis.manifestDigest,
                operationID: seedOperationID
            )
            try store.publishStagedManifest(
                genesis.manifestData,
                digest: genesis.manifestDigest,
                operationID: seedOperationID
            )
            let checkpoint = try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: genesis.manifestDigest
            )
            checkpointStore = PermanentMemoryCheckpointStore(
                checkpoint: checkpoint
            )
            baseManifestData = genesis.manifestData
            try cache.store(genesis.manifestData, for: checkpoint)
            base = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    genesis.manifestData
                )
            )
            candidate = try V3DeviceWrappedManifestCandidateBuilder().add(
                to: base,
                entryID: addedID,
                name: "service/added",
                type: .secret,
                plaintext: "added value",
                vaultKey: vaultKey
            )
        }

        var stagedManifestURL: URL {
            rootURL.appendingPathComponent(
                ".transactions/\(operationID)/manifests/"
                    + "\(v3LowercaseHex(candidate.manifestDigest)).json"
            )
        }

        var recoveryIntentURL: URL {
            rootURL.appendingPathComponent(
                ".transactions/\(operationID)/intent.json"
            )
        }

        var publishedBaseManifestURL: URL {
            rootURL.appendingPathComponent(
                "manifests/\(v3LowercaseHex(base.checkpoint.envelopeDigest)).json"
            )
        }

        var stagedEntryURL: URL {
            let entry = candidate.stagedEntries[0]
            let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            )!
            return rootURL.appendingPathComponent(
                ".transactions/\(operationID)/entries/"
                    + "\(entry.context.entryID)/"
                    + "\(v3LowercaseHex(digest)).json"
            )
        }

        func publisher(
            phaseObserver: any V3ImmutableTransactionPhaseObserving,
            cache selectedCache: (any V3CheckpointManifestCaching)? = nil
        ) -> V3DeviceWrappedContentMutationPublisher {
            V3DeviceWrappedContentMutationPublisher(
                mutationOwner: VaultTransactionMutationOwner(
                    makeOperationID: { operationID }
                ),
                objectStore: store,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: anchorStore,
                cache: selectedCache ?? cache,
                phaseObserver: phaseObserver
            )
        }

        func removeRoot() {
            try? FileManager.default.removeItem(at: rootURL)
        }

        private static func identity() throws
            -> V3EnrollmentDeviceIdentity
        {
            let signing = try P256.Signing.PrivateKey(
                rawRepresentation: scalar(1)
            )
            let wrapping = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: scalar(2)
            )
            return try V3EnrollmentDeviceIdentity(
                displayName: "Owner Mac",
                signingPublicKey: signing.publicKey.x963Representation,
                wrappingPublicKey: wrapping.publicKey.x963Representation
            )
        }

        private static func scalar(_ value: UInt8) -> Data {
            Data(repeating: 0, count: 31) + Data([value])
        }
    }
}

private struct PermanentThrowingCheckpointCache:
    V3CheckpointManifestCaching
{
    func load(
        for _: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        throw V3CheckpointManifestCacheError.operationFailed(code: 5)
    }

    func store(
        _: Data,
        for _: V3ManifestCheckpoint
    ) throws {
        throw V3CheckpointManifestCacheError.operationFailed(code: 5)
    }
}

private enum PermanentPublicationTestError: Error {
    case interrupted
}

private final class RecordingPermanentPhaseObserver:
    V3ImmutableTransactionPhaseObserving,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var recorded: [V3ImmutableTransactionPhase] = []

    var phases: [V3ImmutableTransactionPhase] {
        lock.withLock { recorded }
    }

    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        lock.withLock { recorded.append(phase) }
    }
}

private final class InterruptingPermanentPhaseObserver:
    V3ImmutableTransactionPhaseObserving,
    @unchecked Sendable
{
    private let target: V3ImmutableTransactionPhase
    private let lock = NSLock()
    private var interrupted = false

    init(target: V3ImmutableTransactionPhase) {
        self.target = target
    }

    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            if !interrupted, phase == target {
                interrupted = true
                throw PermanentPublicationTestError.interrupted
            }
        }
    }
}

private final class CheckpointChangingPermanentPhaseObserver:
    V3ImmutableTransactionPhaseObserving,
    @unchecked Sendable
{
    private let target: V3ImmutableTransactionPhase
    private let store: PermanentMemoryCheckpointStore
    private let expected: V3ManifestCheckpoint
    private let replacement: V3ManifestCheckpoint
    private let lock = NSLock()
    private var changed = false

    init(
        target: V3ImmutableTransactionPhase,
        store: PermanentMemoryCheckpointStore,
        expected: V3ManifestCheckpoint,
        replacement: V3ManifestCheckpoint
    ) {
        self.target = target
        self.store = store
        self.expected = expected
        self.replacement = replacement
    }

    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            guard !changed, phase == target else {
                return
            }
            changed = true
            try store.replaceCheckpoint(
                replacement.canonicalBytes,
                expectedCheckpoint: expected.canonicalBytes,
                vaultID: expected.vaultID
            )
        }
    }
}

private final class PermanentMemoryCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Data?

    init(checkpoint: V3ManifestCheckpoint) {
        stored = checkpoint.canonicalBytes
    }

    var checkpoint: Data? {
        lock.withLock { stored }
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        lock.withLock { stored }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID _: String
    ) throws {
        try lock.withLock {
            guard stored == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            stored = checkpoint
        }
    }
}

private final class PermanentMemoryRecoveryAnchorStore:
    V3ImmutableTransactionRecoveryAnchorStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var anchors: [String: Data] = [:]
    private var shouldFailRemoval = false

    func failNextRemoval() {
        lock.withLock { shouldFailRemoval = true }
    }

    func anchor(vaultID: String) -> Data? {
        lock.withLock { anchors[vaultID] }
    }

    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
        anchor(vaultID: vaultID)
    }

    func replaceRecoveryAnchor(
        _ anchor: Data?,
        expectedAnchor: Data?,
        vaultID: String
    ) throws {
        try lock.withLock {
            guard anchors[vaultID] == expectedAnchor else {
                throw V3ImmutableTransactionRecoveryAnchorError.conflict
            }
            if anchor == nil, shouldFailRemoval {
                shouldFailRemoval = false
                throw PermanentRecoveryAnchorTestError.removalFailed
            }
            anchors[vaultID] = anchor
        }
    }
}

private enum PermanentRecoveryAnchorTestError: Error {
    case removalFailed
}

private final class PermanentMemoryCheckpointCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var storedCheckpoint: V3ManifestCheckpoint?
    private var storedData: Data?

    var storedManifest: Data? {
        lock.withLock { storedData }
    }

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
