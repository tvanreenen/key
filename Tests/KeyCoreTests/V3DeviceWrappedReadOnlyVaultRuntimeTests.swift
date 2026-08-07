import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedReadOnlyVaultRuntimeTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let vaultKey = Data(0..<32)

    @Test
    func firstReadUnlocksAndLaterReadsReuseOnlyTheMemorySession() throws {
        let fixture = try Self.fixture()

        #expect(
            try fixture.runtime.read(
                name: "mail/personal",
                allowStale: false
            ).plaintext == "correct horse battery staple"
        )
        #expect(
            try fixture.runtime.read(
                name: "mail/personal",
                allowStale: false
            ).plaintext == "correct horse battery staple"
        )
        #expect(fixture.identity.unwrapCount == 1)
        #expect(fixture.identityLoader.loadCount == 1)
    }

    @Test
    func explicitUnlockCarriesListAndStatusThroughTheSameSession() throws {
        let fixture = try Self.fixture()

        try fixture.runtime.unlock()

        #expect(
            try fixture.runtime.list(allowStale: false)
                == ["mail/personal"]
        )
        let status = try fixture.runtime.status()
        #expect(status.health == .ready)
        #expect(status.entryCount == 1)
        #expect(fixture.identity.unwrapCount == 1)
    }

    @Test
    func lockForcesTheNextReadToOpenTheDeviceWrapperAgain() throws {
        let fixture = try Self.fixture()

        _ = try fixture.runtime.read(
            name: "mail/personal",
            allowStale: false
        )
        fixture.unlockRuntime.lock()
        _ = try fixture.runtime.read(
            name: "mail/personal",
            allowStale: false
        )

        #expect(fixture.identity.unwrapCount == 2)
    }

    @Test
    func checkpointAdvanceDuringEntryReadReleasesNoPlaintext() throws {
        let fixture = try Self.fixture()
        fixture.source.onEntryRead = {
            fixture.checkpointStore.checkpoint = try! V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: Data(repeating: 0xA5, count: 32)
            )
        }

        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try fixture.runtime.read(
                name: "mail/personal",
                allowStale: false
            )
        }
    }

    @Test
    func missingEntryIsResolvedOnlyFromTheAuthenticatedManifest() throws {
        let fixture = try Self.fixture()

        #expect(throws: AppError.entryNotFound(
            "Entry 'mail/missing' was not found."
        )) {
            try fixture.runtime.read(
                name: "mail/missing",
                allowStale: false
            )
        }
        #expect(fixture.source.entryReadCount == 0)
    }

    @Test
    func missingReferencedEntryIsIncompleteAndRequiresExplicitStaleList()
        throws
    {
        let fixture = try Self.fixture()
        fixture.source.setEntryResult(.unavailable)

        let status = try fixture.runtime.status()
        #expect(status.health == .incomplete)
        #expect(status.entries == .lastTrusted(1))
        #expect(status.issues.map(\.code) == [.referencedObjectUnavailable])
        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try fixture.runtime.list(allowStale: false)
        }
        #expect(
            try fixture.runtime.list(allowStale: true)
                == ["mail/personal"]
        )
        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try fixture.runtime.read(
                name: "mail/personal",
                allowStale: false
            )
        }
    }

    @Test
    func invalidReferencedEntryRequiresRecoveryForStatusListAndRead()
        throws
    {
        let fixture = try Self.fixture()
        fixture.source.setEntryResult(.available(Data("malformed".utf8)))

        let status = try fixture.runtime.status()
        #expect(status.health == .recoveryRequired)
        #expect(status.entries == .lastTrusted(1))
        #expect(status.issues.map(\.code) == [.invalidReferencedObject])
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try fixture.runtime.list(allowStale: true)
        }
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try fixture.runtime.read(
                name: "mail/personal",
                allowStale: false
            )
        }
    }

    private static func fixture() throws -> PermanentReadFixture {
        let identity = try PermanentReadIdentity(
            vaultID: vaultID,
            signingScalar: 1,
            wrappingScalar: 2
        )
        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        let context = try V3EntryAuthenticationContext(
            vaultID: vaultID,
            entryID: entryID,
            name: "mail/personal",
            type: .secret,
            keyID: keyID,
            revision: 1
        )
        let sealed = try V3EntryCipher().seal(
            "correct horse battery staple",
            context: context,
            vaultKey: vaultKey
        )
        let entry = V3ManifestEntry(
            entryID: entryID,
            name: context.name,
            type: context.type,
            revision: context.revision,
            keyID: context.keyID,
            ciphertextDigest: sealed.ciphertextDigest
        )
        let candidate = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: vaultID,
            authorityTransitionID: transitionID,
            vaultKey: vaultKey,
            ownerIdentity: identity.publicIdentity,
            entries: [entry]
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: vaultID,
            envelopeDigest: candidate.manifestDigest
        )
        let checkpointStore = PermanentReadCheckpointStore(
            checkpoint: checkpoint
        )
        let source = PermanentReadSource(
            manifestData: candidate.manifestData,
            entryData: sealed.canonicalBytes
        )
        let identityLoader = PermanentReadIdentityLoader(identity: identity)
        let unlockRuntime = V3DeviceWrappedVaultUnlockRuntime(
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            source: source,
            cache: PermanentReadCache(),
            identityLoader: identityLoader,
            session: V3DeviceWrappedVaultKeySessionStore()
        )
        return PermanentReadFixture(
            runtime: V3DeviceWrappedReadOnlyVaultRuntime(
                source: source,
                unlockRuntime: unlockRuntime
            ),
            unlockRuntime: unlockRuntime,
            checkpointStore: checkpointStore,
            source: source,
            identityLoader: identityLoader,
            identity: identity
        )
    }
}

private struct PermanentReadFixture {
    let runtime: V3DeviceWrappedReadOnlyVaultRuntime
    let unlockRuntime: V3DeviceWrappedVaultUnlockRuntime
    let checkpointStore: PermanentReadCheckpointStore
    let source: PermanentReadSource
    let identityLoader: PermanentReadIdentityLoader
    let identity: PermanentReadIdentity
}

private final class PermanentReadCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: V3ManifestCheckpoint

    var checkpoint: V3ManifestCheckpoint {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }

    init(checkpoint: V3ManifestCheckpoint) {
        stored = checkpoint
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        lock.withLock { stored.canonicalBytes }
    }

    func replaceCheckpoint(
        _: Data,
        expectedCheckpoint _: Data?,
        vaultID _: String
    ) throws {}
}

private final class PermanentReadSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    let manifestData: Data
    let entryData: Data
    private let lock = NSLock()
    private var reads = 0
    private var entryResult: V3RepositoryObjectRead?
    var onEntryRead: (@Sendable () -> Void)?

    var entryReadCount: Int {
        lock.withLock { reads }
    }

    init(manifestData: Data, entryData: Data) {
        self.manifestData = manifestData
        self.entryData = entryData
    }

    func setEntryResult(_ result: V3RepositoryObjectRead) {
        lock.withLock { entryResult = result }
    }

    func manifestDigests(
        maximumCount _: Int
    ) throws -> V3RepositoryDirectoryListing {
        .invalid
    }

    func readManifest(
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        guard Data(SHA256.hash(data: manifestData)) == digest else {
            return .invalid
        }
        return .available(manifestData)
    }

    func readEntry(
        entryID _: String,
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        let result = lock.withLock {
            reads += 1
            return entryResult
        }
        onEntryRead?()
        if let result {
            return result
        }
        guard Data(SHA256.hash(data: entryData)) == digest else {
            return .invalid
        }
        return .available(entryData)
    }
}

private final class PermanentReadCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    func load(
        for _: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        .missing
    }

    func store(
        _: Data,
        for _: V3ManifestCheckpoint
    ) throws {}
}

private final class PermanentReadIdentityLoader:
    V3DeviceWrappedIdentityLoading,
    @unchecked Sendable
{
    let identity: PermanentReadIdentity
    private let lock = NSLock()
    private var count = 0

    var loadCount: Int {
        lock.withLock { count }
    }

    init(identity: PermanentReadIdentity) {
        self.identity = identity
    }

    func loadDeviceIdentity(
        vaultID _: String,
        reason _: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        lock.withLock { count += 1 }
        return identity
    }
}

private final class PermanentReadIdentity:
    V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let wrappingPrivateKey: P256.KeyAgreement.PrivateKey
    private let lock = NSLock()
    private var count = 0

    var unwrapCount: Int {
        lock.withLock { count }
    }

    init(
        vaultID: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: Self.scalar(signingScalar)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Self.scalar(wrappingScalar)
        )
        wrappingPrivateKey = wrappingKey
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: "Test Mac",
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        lock.withLock { count += 1 }
        return try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: wrappingPrivateKey,
            context: context
        )
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}
