import CryptoKit
import Foundation
import JSONCanonicalization
import Testing
@testable import KeyCore

struct V3ManifestReplayProtectionTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let otherVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let key = Data(0..<32)

    @Test
    func checkpointHasStrictCanonicalRepresentation() throws {
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            generation: 12,
            envelopeDigest: Data(0..<32)
        )
        let expected = Data(#"{"envelopeDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","format":"key-vault-manifest-checkpoint","generation":12,"vaultID":"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3","version":1}"#.utf8)

        #expect(checkpoint.canonicalBytes == expected)
        #expect(try V3ManifestCheckpoint(canonicalBytes: expected) == checkpoint)

        #expect(throws: V3ManifestReplayError.invalidCheckpoint) {
            _ = try V3ManifestCheckpoint(canonicalBytes: Data((" " + String(decoding: expected, as: UTF8.self)).utf8))
        }
        #expect(throws: V3ManifestReplayError.invalidCheckpoint) {
            _ = try V3ManifestCheckpoint(
                canonicalBytes: Data(
                    String(decoding: expected, as: UTF8.self)
                        .replacingOccurrences(of: #""version":1"#, with: #""version":2"#)
                        .utf8
                )
            )
        }
        #expect(throws: V3ManifestReplayError.invalidCheckpoint) {
            _ = try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                generation: 12,
                envelopeDigest: Data(repeating: 0, count: 31)
            )
        }
    }

    @Test
    func localGenesisBootstrapPersistsAndReopensExactCurrentManifest() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let genesis = try manifestData(generation: 1)

        let trusted = try protector.bootstrapLocalGenesis(
            genesis,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )

        #expect(trusted.checkpoint.generation == 1)
        #expect(trusted.checkpoint.envelopeDigest == Data(SHA256.hash(data: genesis)))
        #expect(store.checkpoint(vaultID: Self.vaultID) == trusted.checkpoint.canonicalBytes)
        #expect(
            try protector.trustCurrent(
                genesis,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            ) == trusted
        )
        #expect(
            try protector.bootstrapLocalGenesis(
                genesis,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            ) == trusted
        )
    }

    @Test
    func exactChildAdvanceReplacesCheckpointAndRejectsParentRollback() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let parent = try manifestData(generation: 1)
        _ = try protector.bootstrapLocalGenesis(
            parent,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )
        let child = try manifestData(
            parent: parentReference(to: parent, generation: 1),
            generation: 2,
            entryName: "email/current"
        )

        let trustedChild = try protector.acceptCommittedChild(
            to: child,
            from: parent,
            expectedVaultID: Self.vaultID,
            trustedParentVaultKey: Self.key,
            candidateVaultKey: Self.key
        )

        #expect(trustedChild.checkpoint.generation == 2)
        #expect(
            try protector.trustCurrent(
                child,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            ) == trustedChild
        )
        #expect(throws: V3ManifestReplayError.rollbackDetected(
            trustedGeneration: 2,
            observedGeneration: 1
        )) {
            _ = try protector.trustCurrent(
                parent,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }
    }

    @Test
    func sameGenerationForkFutureJumpAndWrongVaultAreDistinct() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let genesis = try manifestData(generation: 1)
        _ = try protector.bootstrapLocalGenesis(
            genesis,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )

        let sibling = try manifestData(generation: 1, entryName: "email/fork")
        #expect(throws: V3ManifestReplayError.divergentManifest(generation: 1)) {
            _ = try protector.trustCurrent(
                sibling,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }

        let child = try manifestData(
            parent: parentReference(to: genesis, generation: 1),
            generation: 2
        )
        #expect(throws: V3ManifestReplayError.untrustedAdvance(
            trustedGeneration: 1,
            observedGeneration: 2
        )) {
            _ = try protector.trustCurrent(
                child,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }

        let otherVault = try manifestData(
            generation: 1,
            vaultID: Self.otherVaultID
        )
        #expect(throws: V3ManifestReplayError.vaultMismatch) {
            _ = try protector.trustCurrent(
                otherVault,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }
    }

    @Test
    func failedAuthenticationAndCheckpointConflictLeaveTrustUnchanged() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let parent = try manifestData(generation: 1)
        let trustedParent = try protector.bootstrapLocalGenesis(
            parent,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )
        let wrongKeyChild = try manifestData(
            parent: parentReference(to: parent, generation: 1),
            generation: 2,
            signingKey: Data(repeating: 0xFF, count: 32)
        )

        #expect(throws: V3ManifestError.authenticationFailed) {
            _ = try protector.acceptCommittedChild(
                to: wrongKeyChild,
                from: parent,
                expectedVaultID: Self.vaultID,
                trustedParentVaultKey: Self.key,
                candidateVaultKey: Self.key
            )
        }
        #expect(store.checkpoint(vaultID: Self.vaultID) == trustedParent.checkpoint.canonicalBytes)

        let validChild = try manifestData(
            parent: parentReference(to: parent, generation: 1),
            generation: 2
        )
        store.failNextReplace = true
        #expect(throws: V3ManifestCheckpointStoreError.conflict) {
            _ = try protector.acceptCommittedChild(
                to: validChild,
                from: parent,
                expectedVaultID: Self.vaultID,
                trustedParentVaultKey: Self.key,
                candidateVaultKey: Self.key
            )
        }
        #expect(store.checkpoint(vaultID: Self.vaultID) == trustedParent.checkpoint.canonicalBytes)
    }

    private func manifestData(
        parent: CanonicalJSONValue = .object([("kind", .string("genesis"))]),
        generation: UInt64,
        vaultID: String = V3ManifestReplayProtectionTests.vaultID,
        entryName: String? = nil,
        signingKey: Data = V3ManifestReplayProtectionTests.key
    ) throws -> Data {
        let entries: [CanonicalJSONValue]
        if let entryName {
            entries = [.object([
                ("entryID", .string(Self.entryID)),
                ("name", .string(entryName)),
                ("type", .string("secret")),
                ("revision", .integer(1)),
                ("keyEpoch", .integer(1)),
                ("ciphertextDigest", .string(String(repeating: "A", count: 43)))
            ])]
        } else {
            entries = []
        }

        let content = CanonicalJSONValue.object([
            ("parent", parent),
            ("manifest", .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(vaultID)),
                ("mode", .string("local")),
                ("generation", .integer(generation)),
                ("keyEpoch", .integer(1)),
                ("devices", .array([])),
                ("wrappedKeys", .array([])),
                ("entries", .array(entries))
            ]))
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: vaultID,
            vaultKey: signingKey
        )
        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("keyEpoch", .integer(1)),
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array([]))
        ]))
    }

    private func parentReference(
        to parent: Data,
        generation: UInt64
    ) -> CanonicalJSONValue {
        .object([
            ("kind", .string("manifest")),
            ("generation", .integer(generation)),
            ("digest", .string(Base64URL.encode(Data(SHA256.hash(data: parent)))))
        ])
    }
}

private final class MemoryManifestCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var checkpoints: [String: Data] = [:]
    var failNextReplace = false

    func loadCheckpoint(vaultID: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return checkpoints[vaultID]
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        if failNextReplace {
            failNextReplace = false
            throw V3ManifestCheckpointStoreError.conflict
        }
        guard checkpoints[vaultID] == expectedCheckpoint else {
            throw V3ManifestCheckpointStoreError.conflict
        }
        checkpoints[vaultID] = checkpoint
    }

    func checkpoint(vaultID: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return checkpoints[vaultID]
    }
}
