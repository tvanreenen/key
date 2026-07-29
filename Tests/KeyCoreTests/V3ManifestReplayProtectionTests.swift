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
            envelopeDigest: Data(0..<32)
        )
        let expected = Data(#"{"envelopeDigest":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","format":"key-vault-manifest-checkpoint","vaultID":"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3","version":1}"#.utf8)
        let expectedHead = try V3VaultHead(
            vaultID: Self.vaultID,
            envelopeDigest: Data(0..<32)
        )

        #expect(checkpoint.canonicalBytes == expected)
        #expect(try V3ManifestCheckpoint(canonicalBytes: expected) == checkpoint)
        #expect(checkpoint.head == expectedHead)
        #expect(throws: V3VaultHeadError.invalidVaultID) {
            _ = try V3VaultHead(
                vaultID: "not-a-vault-id",
                envelopeDigest: Data(0..<32)
            )
        }
        #expect(throws: V3VaultHeadError.invalidDigest) {
            _ = try V3VaultHead(
                vaultID: Self.vaultID,
                envelopeDigest: Data(repeating: 0, count: 31)
            )
        }

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
                envelopeDigest: Data(repeating: 0, count: 31)
            )
        }
    }

    @Test
    func localGenesisBootstrapPersistsAndReopensExactCurrentManifest() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let genesis = try manifestData()

        let trusted = try protector.bootstrapLocalGenesis(
            genesis,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )

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
    func exactChildAdvanceReplacesCheckpointAndRejectsUnexpectedPriorHead() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let parent = try manifestData()
        _ = try protector.bootstrapLocalGenesis(
            parent,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )
        let child = try manifestData(
            parents: parentReferences(to: [parent]),
            entryName: "email/current"
        )

        let trustedChild = try protector.acceptCommittedChild(
            to: child,
            from: parent,
            expectedVaultID: Self.vaultID,
            trustedParentVaultKey: Self.key,
            candidateVaultKey: Self.key
        )

        #expect(
            try protector.trustCurrent(
                child,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            ) == trustedChild
        )
        #expect(throws: V3ManifestReplayError.unexpectedHead) {
            _ = try protector.trustCurrent(
                parent,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }
    }

    @Test
    func unexpectedDigestAndWrongVaultAreDistinct() throws {
        let store = MemoryManifestCheckpointStore()
        let protector = V3ManifestReplayProtector(store: store)
        let genesis = try manifestData()
        _ = try protector.bootstrapLocalGenesis(
            genesis,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )

        let sibling = try manifestData(entryName: "email/fork")
        #expect(throws: V3ManifestReplayError.unexpectedHead) {
            _ = try protector.trustCurrent(
                sibling,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }

        let child = try manifestData(
            parents: parentReferences(to: [genesis])
        )
        #expect(throws: V3ManifestReplayError.unexpectedHead) {
            _ = try protector.trustCurrent(
                child,
                expectedVaultID: Self.vaultID,
                vaultKey: Self.key
            )
        }

        let otherVault = try manifestData(
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
        let parent = try manifestData()
        let trustedParent = try protector.bootstrapLocalGenesis(
            parent,
            expectedVaultID: Self.vaultID,
            vaultKey: Self.key
        )
        let wrongKeyChild = try manifestData(
            parents: parentReferences(to: [parent]),
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
            parents: parentReferences(to: [parent])
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

    @Test
    func mergeRejectsAnAuthenticatedParentFromAnotherVault() throws {
        let authenticator = V3ManifestAuthenticator()
        let genesis = try manifestData()
        let otherGenesis = try manifestData(vaultID: Self.otherVaultID)
        let verifiedGenesis = try authenticator.verify(
            genesis,
            vaultKey: Self.key,
            trustAnchor: .localGenesis(vaultID: Self.vaultID)
        )
        let verifiedOtherGenesis = try authenticator.verify(
            otherGenesis,
            vaultKey: Self.key,
            trustAnchor: .localGenesis(vaultID: Self.otherVaultID)
        )
        let candidate = try manifestData(
            parents: parentReferences(to: [genesis, otherGenesis]),
            entryName: "email/merged"
        )

        #expect(throws: V3ManifestError.parentMismatch) {
            _ = try authenticator.verify(
                candidate,
                vaultKey: Self.key,
                trustAnchor: .verifiedParents([verifiedGenesis, verifiedOtherGenesis])
            )
        }
    }

    private func manifestData(
        parents: CanonicalJSONValue = .array([]),
        vaultID: String = V3ManifestReplayProtectionTests.vaultID,
        entryName: String? = nil,
        signingKey: Data = V3ManifestReplayProtectionTests.key
    ) throws -> Data {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: signingKey,
            vaultID: vaultID
        )
        let entries: [CanonicalJSONValue]
        if let entryName {
            entries = [.object([
                ("entryID", .string(Self.entryID)),
                ("name", .string(entryName)),
                ("type", .string("secret")),
                ("revision", .integer(1)),
                ("keyID", .string(keyID.rawValue)),
                ("ciphertextDigest", .string(String(repeating: "A", count: 43)))
            ])]
        } else {
            entries = []
        }

        let content = CanonicalJSONValue.object([
            ("parents", parents),
            ("manifest", .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(vaultID)),
                ("mode", .string("local")),
                ("keyID", .string(keyID.rawValue)),
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
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array([]))
        ]))
    }

    private func parentReferences(to parents: [Data]) -> CanonicalJSONValue {
        let digests = parents
            .map { Data(SHA256.hash(data: $0)) }
            .sorted(by: { $0.lexicographicallyPrecedes($1) })
            .map { CanonicalJSONValue.string(Base64URL.encode($0)) }
        return .array(digests)
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
