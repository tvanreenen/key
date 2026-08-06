import CryptoKit
import Foundation
import JSONCanonicalization
import Testing
@testable import KeyCore

@Suite
struct V3ReadOnlyVaultRuntimeTests {
    @Test
    func readyRuntimeServesStatusListAndExactReads() throws {
        let fixture = try RuntimeFixture()
        let keys = RuntimeKeyProvider(key: fixture.vaultKey)
        let runtime = V3ReadOnlyVaultRuntime(
            source: fixture.source,
            vaultID: fixture.vaultID,
            checkpointStore: FixedRuntimeCheckpointStore(
                checkpoint: fixture.checkpoint.canonicalBytes
            ),
            vaultKeyProvider: keys.load
        )

        try runtime.unlock()
        let status = try runtime.status()
        #expect(status.format == .version3)
        #expect(status.health == .ready)
        #expect(status.entries == .effective(2))
        #expect(try runtime.list(allowStale: false) == [
            "mail/personal",
            "totp/work"
        ])

        let secret = try runtime.read(
            name: "mail/personal",
            allowStale: false
        )
        #expect(secret == VaultReadValue(
            type: .secret,
            plaintext: "correct horse battery staple"
        ))
        #expect(keys.callCount > 0)
    }

    @Test
    func configuredVaultAndCheckpointMustMatchExactly() throws {
        let fixture = try RuntimeFixture()
        let keys = RuntimeKeyProvider(key: fixture.vaultKey)
        let missingCheckpoint = V3ReadOnlyVaultRuntime(
            source: fixture.source,
            vaultID: fixture.vaultID,
            checkpointStore: FixedRuntimeCheckpointStore(checkpoint: nil),
            vaultKeyProvider: keys.load
        )

        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try missingCheckpoint.read(
                name: "mail/personal",
                allowStale: false
            )
        }
        #expect(keys.callCount == 0)

        let otherVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44c9"
        let wrongSelection = V3ReadOnlyVaultRuntime(
            source: fixture.source,
            vaultID: otherVaultID,
            checkpointStore: FixedRuntimeCheckpointStore(
                checkpoint: fixture.checkpoint.canonicalBytes
            ),
            vaultKeyProvider: keys.load
        )
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try wrongSelection.status()
        }
        #expect(keys.callCount == 0)
    }

    @Test
    func missingCheckpointManifestIsTemporarilyUnavailable() throws {
        let fixture = try RuntimeFixture()
        let keys = RuntimeKeyProvider(key: fixture.vaultKey)
        let checkpointStore = TrackingRuntimeCheckpointStore(
            checkpoint: fixture.checkpoint.canonicalBytes
        )
        let response = try serviceResponse(
            source: RuntimeObjectSource(manifests: [:], entries: [:]),
            fixture: fixture,
            checkpointStore: checkpointStore,
            keys: keys
        )

        #expect(response.exitCode == KeyExitCode.temporarilyUnavailable.rawValue)
        #expect(response.errorCode == .vaultIncomplete)
        #expect(response.value == nil)
        #expect(keys.callCount == 0)
        #expect(checkpointStore.replaceCount == 0)
        #expect(checkpointStore.checkpoint == fixture.checkpoint.canonicalBytes)
    }

    @Test
    func malformedCheckpointManifestRequiresRecovery() throws {
        let fixture = try RuntimeFixture()
        let malformed = Data("not-json".utf8)
        let digest = Data(SHA256.hash(data: malformed))
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: fixture.vaultID,
            envelopeDigest: digest
        )
        let keys = RuntimeKeyProvider(key: fixture.vaultKey)
        let checkpointStore = TrackingRuntimeCheckpointStore(
            checkpoint: checkpoint.canonicalBytes
        )
        let response = try serviceResponse(
            source: RuntimeObjectSource(
                manifests: [digest: malformed],
                entries: [:]
            ),
            fixture: fixture,
            checkpointStore: checkpointStore,
            keys: keys
        )

        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorCode == .recoveryRequired)
        #expect(response.value == nil)
        #expect(checkpointStore.replaceCount == 0)
        #expect(checkpointStore.checkpoint == checkpoint.canonicalBytes)
    }

    @Test
    func substitutedCheckpointManifestRequiresRecoveryBeforeKeyAccess() throws {
        let fixture = try RuntimeFixture()
        let keys = RuntimeKeyProvider(key: fixture.vaultKey)
        let checkpointStore = TrackingRuntimeCheckpointStore(
            checkpoint: fixture.checkpoint.canonicalBytes
        )
        let response = try serviceResponse(
            source: RuntimeObjectSource(
                manifests: [
                    fixture.checkpoint.envelopeDigest:
                        fixture.substitutedManifest
                ],
                entries: [:]
            ),
            fixture: fixture,
            checkpointStore: checkpointStore,
            keys: keys
        )

        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorCode == .recoveryRequired)
        #expect(response.value == nil)
        #expect(keys.callCount == 0)
        #expect(checkpointStore.replaceCount == 0)
        #expect(checkpointStore.checkpoint == fixture.checkpoint.canonicalBytes)
    }

    @Test
    func wrongVaultKeyRequiresRecoveryWithoutReleasingPlaintext() throws {
        let fixture = try RuntimeFixture()

        let wrongKeys = RuntimeKeyProvider(
            key: Data(repeating: 0xFF, count: 32)
        )
        let wrongKeyRuntime = V3ReadOnlyVaultRuntime(
            source: fixture.source,
            vaultID: fixture.vaultID,
            checkpointStore: FixedRuntimeCheckpointStore(
                checkpoint: fixture.checkpoint.canonicalBytes
            ),
            vaultKeyProvider: wrongKeys.load
        )
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try wrongKeyRuntime.unlock()
        }
    }

    @Test
    func unlockRequiresACompleteValidRepository() throws {
        let fixture = try RuntimeFixture()
        let checkpointStore = FixedRuntimeCheckpointStore(
            checkpoint: fixture.checkpoint.canonicalBytes
        )
        let unavailableEntryRuntime = V3ReadOnlyVaultRuntime(
            source: RuntimeObjectSource(
                manifests: fixture.source.manifests,
                entries: [:]
            ),
            vaultID: fixture.vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: RuntimeKeyProvider(
                key: fixture.vaultKey
            ).load
        )
        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try unavailableEntryRuntime.unlock()
        }

        var invalidEntries = fixture.source.entries
        let firstEntry = try #require(invalidEntries.keys.first)
        invalidEntries[firstEntry] = Data("invalid entry".utf8)
        let invalidEntryRuntime = V3ReadOnlyVaultRuntime(
            source: RuntimeObjectSource(
                manifests: fixture.source.manifests,
                entries: invalidEntries
            ),
            vaultID: fixture.vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: RuntimeKeyProvider(
                key: fixture.vaultKey
            ).load
        )
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try invalidEntryRuntime.unlock()
        }
    }

    private func serviceResponse(
        source: RuntimeObjectSource,
        fixture: RuntimeFixture,
        checkpointStore: TrackingRuntimeCheckpointStore,
        keys: RuntimeKeyProvider
    ) throws -> KeyServiceResponse {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let runtime = V3ReadOnlyVaultRuntime(
            source: source,
            vaultID: fixture.vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: keys.load
        )
        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: root),
            mutationOwner: VaultTransactionMutationOwner(),
            vaultUXService: runtime,
            vaultReader: runtime,
            configuredVaultID: fixture.vaultID
        )

        let response = handler.handle(.get(
            name: "mail/personal",
            allowStale: false
        ))

        #expect(
            try FileManager.default.contentsOfDirectory(atPath: root.path)
                .isEmpty
        )
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == nil)
        #expect(keyStore.iCloudKeyData == nil)
        return response
    }

    @Test
    func everyMutationIsRejectedBeforeStateOrKeyAccess() throws {
        let fixture = try RuntimeFixture()
        let keys = RuntimeKeyProvider(key: fixture.vaultKey)
        let runtime = V3ReadOnlyVaultRuntime(
            source: fixture.source,
            vaultID: fixture.vaultID,
            checkpointStore: FixedRuntimeCheckpointStore(
                checkpoint: fixture.checkpoint.canonicalBytes
            ),
            vaultKeyProvider: keys.load
        )

        #expect(throws: AppError.self) {
            try runtime.authorizeMutation()
        }
        #expect(throws: AppError.self) {
            try runtime.resolve([])
        }
        #expect(keys.callCount == 0)
    }
}

private struct RuntimeFixture {
    private static let selectedVaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let selectedVaultKey =
        Data((0..<32).map(UInt8.init))

    let vaultID = selectedVaultID
    let vaultKey = selectedVaultKey
    let source: RuntimeObjectSource
    let checkpoint: V3ManifestCheckpoint
    let substitutedManifest: Data

    init() throws {
        let secret = try Self.sealedEntry(
            entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4",
            name: "mail/personal",
            type: .secret,
            plaintext: "correct horse battery staple"
        )
        let totp = try Self.sealedEntry(
            entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5",
            name: "totp/work",
            type: .totp,
            plaintext: "JBSWY3DPEHPK3PXP"
        )
        let manifest = try Self.localManifest(entries: [
            secret.record,
            totp.record
        ])
        substitutedManifest = try Self.localManifest(entries: [])
        let digest = Data(SHA256.hash(data: manifest))
        let verified = try V3ManifestAuthenticator().verify(
            manifest,
            vaultKey: Self.selectedVaultKey,
            trustAnchor: .localGenesis(vaultID: Self.selectedVaultID)
        )
        checkpoint = try V3ManifestCheckpoint(verifiedManifest: verified)
        source = RuntimeObjectSource(
            manifests: [digest: manifest],
            entries: [
                RuntimeEntryKey(
                    entryID: secret.record.entryID,
                    digest: try #require(Base64URL.decodeCanonical(
                        secret.record.ciphertextDigest
                    ))
                ): secret.data,
                RuntimeEntryKey(
                    entryID: totp.record.entryID,
                    digest: try #require(Base64URL.decodeCanonical(
                        totp.record.ciphertextDigest
                    ))
                ): totp.data
            ]
        )
    }

    private static func sealedEntry(
        entryID: String,
        name: String,
        type: SecretEntryType,
        plaintext: String
    ) throws -> (record: V3ManifestEntry, data: Data) {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: selectedVaultKey,
            vaultID: selectedVaultID
        )
        let context = try V3EntryAuthenticationContext(
            vaultID: selectedVaultID,
            entryID: entryID,
            name: name,
            type: type,
            keyID: keyID,
            revision: 1
        )
        let encrypted = try V3EntryCipher().seal(
            plaintext,
            context: context,
            vaultKey: selectedVaultKey
        )
        return (
            V3ManifestEntry(
                entryID: entryID,
                name: name,
                type: type,
                revision: 1,
                keyID: keyID,
                ciphertextDigest: encrypted.ciphertextDigest
            ),
            encrypted.canonicalBytes
        )
    }

    private static func localManifest(
        entries: [V3ManifestEntry]
    ) throws -> Data {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: selectedVaultKey,
            vaultID: selectedVaultID
        )
        let entryValues = entries.map { entry in
            CanonicalJSONValue.object([
                ("entryID", .string(entry.entryID)),
                ("name", .string(entry.name)),
                ("type", .string(entry.type.rawValue)),
                ("revision", .integer(entry.revision)),
                ("keyID", .string(entry.keyID.rawValue)),
                (
                    "ciphertextDigest",
                    .string(entry.ciphertextDigest)
                )
            ])
        }
        let content = CanonicalJSONValue.object([
            ("parents", .array([])),
            ("manifest", .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(selectedVaultID)),
                ("mode", .string("local")),
                ("keyID", .string(keyID.rawValue)),
                ("devices", .array([])),
                ("wrappedKeys", .array([])),
                ("entries", .array(entryValues))
            ]))
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: selectedVaultID,
            vaultKey: selectedVaultKey
        )
        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                (
                    "algorithm",
                    .string("HKDF-SHA256+HMAC-SHA256")
                ),
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array([]))
        ]))
    }
}

private struct RuntimeEntryKey: Hashable, Sendable {
    let entryID: String
    let digest: Data
}

private struct RuntimeObjectSource: V3ImmutableObjectReading {
    let manifests: [Data: Data]
    let entries: [RuntimeEntryKey: Data]

    func manifestDigests(
        maximumCount: Int
    ) throws -> V3RepositoryDirectoryListing {
        guard manifests.count <= maximumCount else {
            return .limitExceeded
        }
        return .available(
            digests: Array(manifests.keys),
            objectCount: manifests.count
        )
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        guard let data = manifests[digest] else {
            return .unavailable
        }
        return data.count <= maximumBytes ? .available(data) : .tooLarge
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        guard let data = entries[RuntimeEntryKey(
            entryID: entryID,
            digest: digest
        )] else {
            return .unavailable
        }
        return data.count <= maximumBytes ? .available(data) : .tooLarge
    }
}

private struct FixedRuntimeCheckpointStore:
    V3ManifestCheckpointStoring
{
    let checkpoint: Data?

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        checkpoint
    }

    func replaceCheckpoint(
        _: Data,
        expectedCheckpoint _: Data?,
        vaultID _: String
    ) throws {
        throw AppError.operationRefused("Read-only test checkpoint store.")
    }
}

private final class TrackingRuntimeCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Data?
    private var replacements = 0

    init(checkpoint: Data?) {
        stored = checkpoint
    }

    var checkpoint: Data? {
        lock.withLock { stored }
    }

    var replaceCount: Int {
        lock.withLock { replacements }
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        lock.withLock { stored }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint _: Data?,
        vaultID _: String
    ) throws {
        lock.withLock {
            replacements += 1
            stored = checkpoint
        }
    }
}

private final class RuntimeKeyProvider: @unchecked Sendable {
    private let lock = NSLock()
    private let key: Data
    private var calls = 0

    init(key: Data) {
        self.key = key
    }

    var callCount: Int {
        lock.withLock { calls }
    }

    func load(reason _: String) throws -> Data {
        lock.withLock {
            calls += 1
            return key
        }
    }
}
