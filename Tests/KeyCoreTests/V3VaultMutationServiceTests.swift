import Foundation
import Testing
@testable import KeyCore

@Suite
struct V3VaultMutationServiceTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c5000"
    fileprivate static let initialEntryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c5001"
    fileprivate static let vaultKey = Data((0..<32).map(UInt8.init))

    @Test
    func ordinaryCommandsPublishAuthenticatedImmutableHistory() throws {
        let harness = try MutationHarness(
            entries: [("original", .secret, "one")]
        )
        defer { harness.removeRoot() }

        try harness.runtime.add(
            name: "added",
            secret: "two",
            type: .secret,
            operationID: VaultTransactionOperationID()
        )
        try harness.runtime.edit(
            name: "added",
            secret: "three",
            type: .secret,
            operationID: VaultTransactionOperationID()
        )
        try harness.runtime.copy(
            source: "added",
            destination: "copied",
            overwrite: false,
            operationID: VaultTransactionOperationID()
        )
        try harness.runtime.move(
            source: "copied",
            destination: "moved",
            overwrite: false,
            operationID: VaultTransactionOperationID()
        )
        try harness.runtime.remove(
            name: "original",
            operationID: VaultTransactionOperationID()
        )

        #expect(try harness.runtime.list(allowStale: false) == [
            "added", "moved"
        ])
        #expect(try harness.runtime.read(
            name: "added",
            allowStale: false
        ).plaintext == "three")
        #expect(try harness.runtime.read(
            name: "moved",
            allowStale: false
        ).plaintext == "three")
        #expect(try harness.runtime.status().health == .ready)
    }

    @Test
    func destinationOverwriteRequiresExplicitPolicy() throws {
        let harness = try MutationHarness(entries: [
            ("source", .secret, "source-value"),
            ("destination", .secret, "old-value")
        ])
        defer { harness.removeRoot() }

        #expect(throws: AppError.self) {
            try harness.runtime.copy(
                source: "source",
                destination: "destination",
                overwrite: false,
                operationID: VaultTransactionOperationID()
            )
        }
        #expect(try harness.runtime.read(
            name: "destination",
            allowStale: false
        ).plaintext == "old-value")

        try harness.runtime.copy(
            source: "source",
            destination: "destination",
            overwrite: true,
            operationID: VaultTransactionOperationID()
        )
        #expect(try harness.runtime.read(
            name: "destination",
            allowStale: false
        ).plaintext == "source-value")
    }

    @Test
    func duplicateCannotReplaceItsOwnStableIdentity() throws {
        let harness = try MutationHarness(
            entries: [("source", .secret, "source-value")]
        )
        defer { harness.removeRoot() }

        #expect(throws: AppError.self) {
            try harness.runtime.copy(
                source: "source",
                destination: "source",
                overwrite: true,
                operationID: VaultTransactionOperationID()
            )
        }
        #expect(try harness.runtime.read(
            name: "source",
            allowStale: false
        ).plaintext == "source-value")
    }

    @Test
    func independentHeadsMergeBeforeRequestedWrite() throws {
        let harness = try MutationHarness(
            entries: [("shared", .secret, "base")]
        )
        defer { harness.removeRoot() }
        let parent = harness.genesis
        let original = try #require(
            parent.envelope.content.manifest.entries.first
        )
        let leftEntry = try harness.encryptedEntry(
            entryID: original.entryID,
            name: original.name,
            type: original.type,
            revision: 2,
            plaintext: "left"
        )
        let rightEntry = try harness.encryptedEntry(
            entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c5009",
            name: "remote",
            type: .secret,
            revision: 1,
            plaintext: "right"
        )
        let left = try harness.publishChild(
            parent: parent,
            entries: [harness.manifestEntry(leftEntry)],
            stagedEntries: [leftEntry]
        )
        _ = try harness.publishChild(
            parent: parent,
            entries: [original, harness.manifestEntry(rightEntry)],
            stagedEntries: [rightEntry]
        )
        try harness.select(left)
        harness.failNextRecoveryAnchorRemoval()

        try harness.runtime.add(
            name: "local",
            secret: "after-merge",
            type: .secret,
            operationID: VaultTransactionOperationID()
        )

        #expect(try harness.runtime.list(allowStale: false) == [
            "local", "remote", "shared"
        ])
        #expect(try harness.runtime.read(
            name: "shared",
            allowStale: false
        ).plaintext == "left")
        #expect(try harness.runtime.read(
            name: "remote",
            allowStale: false
        ).plaintext == "right")
    }

    @Test
    func explicitConflictChoicePublishesAdvancingRevision() throws {
        let harness = try MutationHarness(
            entries: [("shared", .secret, "base")]
        )
        defer { harness.removeRoot() }
        let parent = harness.genesis
        let original = try #require(
            parent.envelope.content.manifest.entries.first
        )
        let leftEntry = try harness.encryptedEntry(
            entryID: original.entryID,
            name: original.name,
            type: original.type,
            revision: 2,
            plaintext: "left"
        )
        let rightEntry = try harness.encryptedEntry(
            entryID: original.entryID,
            name: original.name,
            type: original.type,
            revision: 2,
            plaintext: "right"
        )
        let left = try harness.publishChild(
            parent: parent,
            entries: [harness.manifestEntry(leftEntry)],
            stagedEntries: [leftEntry]
        )
        _ = try harness.publishChild(
            parent: parent,
            entries: [harness.manifestEntry(rightEntry)],
            stagedEntries: [rightEntry]
        )
        try harness.select(left)

        let conflict = try #require(harness.runtime.conflicts().first)
        let detail = try harness.runtime.conflict(id: conflict.id)
        let selected = try #require(detail.versions.first(where: {
            !$0.previouslyTrustedOnThisMac
        }))
        try harness.runtime.resolve(
            [VaultConflictResolution(
                conflictID: conflict.id,
                versionID: selected.id
            )],
            operationID: VaultTransactionOperationID()
        )

        #expect(try harness.runtime.status().health == .ready)
        #expect(try harness.runtime.read(
            name: "shared",
            allowStale: false
        ).plaintext == "right")
    }
}

private final class MutationHarness {
    let root: URL
    let runtime: V3VaultRuntime
    let genesis: V3VerifiedManifest
    private let objectStore: V3FilesystemTransactionArtifactStore
    private let checkpointStore: MutationCheckpointStore
    private let recoveryAnchorStore: MutationRecoveryAnchorStore

    init(entries: [(String, SecretEntryType, String)]) throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let rootHandle = try VaultRootDirectoryHandle(opening: root)
        objectStore = V3FilesystemTransactionArtifactStore(
            rootHandle: rootHandle
        )
        checkpointStore = MutationCheckpointStore()
        recoveryAnchorStore = MutationRecoveryAnchorStore()
        let operationID = VaultTransactionOperationID()
        let sourceEntries = entries.map {
            V2MigrationSourceEntry(
                name: $0.0,
                type: $0.1,
                plaintext: $0.2,
                sourceData: Data()
            )
        }
        let entryIDs = entries.indices.map { index in
            if index == 0 {
                return V3VaultMutationServiceTests.initialEntryID
            }
            return String(
                format: "018f4d38-7d5a-7b20-b0f1-97d6e96c%04x",
                0x5001 + index
            )
        }
        let genesisCandidate = try V3LocalGenesisBuilder().build(
            vaultID: V3VaultMutationServiceTests.vaultID,
            entryIDs: entryIDs,
            sourceEntries: sourceEntries,
            vaultKey: V3VaultMutationServiceTests.vaultKey
        )
        for entry in genesisCandidate.entries {
            try objectStore.stageEntry(
                entry.encryptedEntry.canonicalBytes,
                entryID: entry.manifestEntry.entryID,
                digest: entry.digest,
                operationID: operationID
            )
            try objectStore.publishStagedEntry(
                entry.encryptedEntry.canonicalBytes,
                entryID: entry.manifestEntry.entryID,
                digest: entry.digest,
                operationID: operationID
            )
        }
        let manifestDigest = genesisCandidate.verifiedManifest.envelopeDigest
        try objectStore.stageManifest(
            genesisCandidate.manifestData,
            digest: manifestDigest,
            operationID: operationID
        )
        try objectStore.publishStagedManifest(
            genesisCandidate.manifestData,
            digest: manifestDigest,
            operationID: operationID
        )
        let checkpoint = try V3ManifestCheckpoint(
            verifiedManifest: genesisCandidate.verifiedManifest
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: nil,
            vaultID: V3VaultMutationServiceTests.vaultID
        )
        genesis = genesisCandidate.verifiedManifest
        runtime = V3VaultRuntime(
            objectStore: objectStore,
            vaultID: V3VaultMutationServiceTests.vaultID,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            vaultKeyProvider: { _ in
                V3VaultMutationServiceTests.vaultKey
            }
        )
    }

    func failNextRecoveryAnchorRemoval() {
        recoveryAnchorStore.failNextRemoval()
    }

    func removeRoot() {
        try? FileManager.default.removeItem(at: root)
    }

    func encryptedEntry(
        entryID: String,
        name: String,
        type: SecretEntryType,
        revision: UInt64,
        plaintext: String
    ) throws -> V3EncryptedEntry {
        try V3EntryCipher().seal(
            plaintext,
            context: V3EntryAuthenticationContext(
                vaultID: V3VaultMutationServiceTests.vaultID,
                entryID: entryID,
                name: name,
                type: type,
                keyID: genesis.envelope.content.manifest.keyID,
                revision: revision
            ),
            vaultKey: V3VaultMutationServiceTests.vaultKey
        )
    }

    func manifestEntry(
        _ encrypted: V3EncryptedEntry
    ) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: encrypted.context.entryID,
            name: encrypted.context.name,
            type: encrypted.context.type,
            revision: encrypted.context.revision,
            keyID: encrypted.context.keyID,
            ciphertextDigest: encrypted.ciphertextDigest
        )
    }

    func publishChild(
        parent: V3VerifiedManifest,
        entries: [V3ManifestEntry],
        stagedEntries: [V3EncryptedEntry]
    ) throws -> V3VerifiedManifest {
        let parentBody = parent.envelope.content.manifest
        let body = V3ManifestBody(
            vaultID: parentBody.vaultID,
            mode: parentBody.mode,
            keyID: parentBody.keyID,
            devices: parentBody.devices,
            wrappedKeys: parentBody.wrappedKeys,
            entries: entries.sorted(by: v3ManifestEntryPrecedes)
        )
        let candidate = try V3ManifestCandidateBuilder().build(
            content: V3ManifestContent(
                parents: [Base64URL.encode(parent.envelopeDigest)],
                manifest: body
            ),
            vaultKey: V3VaultMutationServiceTests.vaultKey,
            trustAnchor: .verifiedParents([parent])
        )
        let operationID = VaultTransactionOperationID()
        for encrypted in stagedEntries {
            let digest = try #require(Base64URL.decodeCanonical(
                encrypted.ciphertextDigest
            ))
            try objectStore.stageEntry(
                encrypted.canonicalBytes,
                entryID: encrypted.context.entryID,
                digest: digest,
                operationID: operationID
            )
            try objectStore.publishStagedEntry(
                encrypted.canonicalBytes,
                entryID: encrypted.context.entryID,
                digest: digest,
                operationID: operationID
            )
        }
        try objectStore.stageManifest(
            candidate.data,
            digest: candidate.verified.envelopeDigest,
            operationID: operationID
        )
        try objectStore.publishStagedManifest(
            candidate.data,
            digest: candidate.verified.envelopeDigest,
            operationID: operationID
        )
        return candidate.verified
    }

    func select(_ manifest: V3VerifiedManifest) throws {
        let current = try #require(try checkpointStore.loadCheckpoint(
            vaultID: V3VaultMutationServiceTests.vaultID
        ))
        try checkpointStore.replaceCheckpoint(
            V3ManifestCheckpoint(
                verifiedManifest: manifest
            ).canonicalBytes,
            expectedCheckpoint: current,
            vaultID: V3VaultMutationServiceTests.vaultID
        )
    }
}

private final class MutationCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var checkpoints: [String: Data] = [:]

    func loadCheckpoint(vaultID: String) throws -> Data? {
        lock.withLock { checkpoints[vaultID] }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {
        try lock.withLock {
            guard checkpoints[vaultID] == expectedCheckpoint else {
                throw V3ManifestReplayError.unexpectedHead
            }
            checkpoints[vaultID] = checkpoint
        }
    }
}

private final class MutationRecoveryAnchorStore:
    V3ImmutableTransactionRecoveryAnchorStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var anchors: [String: Data] = [:]
    private var shouldFailNextRemoval = false

    func failNextRemoval() {
        lock.withLock {
            shouldFailNextRemoval = true
        }
    }

    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
        lock.withLock { anchors[vaultID] }
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
            if anchor == nil, shouldFailNextRemoval {
                shouldFailNextRemoval = false
                throw V3ImmutableTransactionRecoveryAnchorError.conflict
            }
            anchors[vaultID] = anchor
        }
    }
}
