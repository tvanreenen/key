import CryptoKit
import Foundation
import Testing
import JSONCanonicalization

@testable import KeyCore

struct V3DeviceWrappedVaultUnlockRuntimeTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let vaultKey = Data((0..<32).map(UInt8.init))

    @Test
    func cachedCheckpointUnlocksWithoutReadingProvider() throws {
        let fixture = try Self.fixture()
        let cache = TestCheckpointCache(
            lookup: .available(fixture.candidate.manifestData)
        )
        let source = TestManifestSource(result: .unavailable)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: source,
            cache: cache,
            identity: fixture.identity
        )

        let envelope = try runtime.unlock(reason: "Unlock the vault")

        #expect(envelope.body == fixture.candidate.body)
        #expect(source.manifestReadCount == 0)
        #expect(cache.storeCount == 0)
        #expect(
            try runtime.loadVaultKey(keyID: envelope.body.keyID)
                == Self.vaultKey
        )
    }

    @Test
    func cacheMissFallsBackToProviderAndWarmsCache() throws {
        let fixture = try Self.fixture()
        let cache = TestCheckpointCache(lookup: .missing)
        let source = TestManifestSource(
            result: .available(fixture.candidate.manifestData)
        )
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: source,
            cache: cache,
            identity: fixture.identity
        )

        _ = try runtime.unlock(reason: "Unlock the vault")

        #expect(source.manifestReadCount == 1)
        #expect(source.requestedDigest == fixture.checkpoint.envelopeDigest)
        #expect(cache.storedData == fixture.candidate.manifestData)
    }

    @Test
    func unusableCacheAlsoFallsBackToProvider() throws {
        let fixture = try Self.fixture()
        let source = TestManifestSource(
            result: .available(fixture.candidate.manifestData)
        )
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: source,
            cache: TestCheckpointCache(lookup: .unusable),
            identity: fixture.identity
        )

        _ = try runtime.unlock(reason: "Unlock the vault")

        #expect(source.manifestReadCount == 1)
    }

    @Test
    func missingProviderBytesAreTemporaryUnavailable() throws {
        let fixture = try Self.fixture()
        let identityLoader = TestIdentityLoader(identity: fixture.identity)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(result: .unavailable),
            cache: TestCheckpointCache(lookup: .missing),
            identityLoader: identityLoader
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError
                .temporaryUnavailable
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(identityLoader.loadCount == 0)
    }

    @Test(arguments: [
        V3RepositoryObjectRead.invalid,
        V3RepositoryObjectRead.tooLarge,
    ])
    func invalidProviderBytesRequireRecovery(
        result: V3RepositoryObjectRead
    ) throws {
        let fixture = try Self.fixture()
        let identityLoader = TestIdentityLoader(identity: fixture.identity)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(result: result),
            cache: TestCheckpointCache(lookup: .missing),
            identityLoader: identityLoader
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(identityLoader.loadCount == 0)
    }

    @Test
    func substitutedCheckpointManifestRequiresRecovery() throws {
        let fixture = try Self.fixture()
        let substituted = Data("substituted".utf8)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(result: .available(substituted)),
            cache: TestCheckpointCache(lookup: .missing),
            identity: fixture.identity
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(fixture.identity.unwrapCount == 0)
    }

    @Test
    func missingLocalIdentityRequiresRecovery() throws {
        let fixture = try Self.fixture()
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(
                result: .available(fixture.candidate.manifestData)
            ),
            cache: TestCheckpointCache(lookup: .missing),
            identityLoader: TestIdentityLoader(identity: nil)
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
    }

    @Test
    func releasedAlphaManifestIsReportedAsLegacyProfile() throws {
        let identity = try RuntimeTestUnwrapper(
            vaultID: Self.vaultID,
            signingScalar: 1,
            wrappingScalar: 2
        )
        let alpha = try V3LocalGenesisBuilder().build(
            vaultID: Self.vaultID,
            entryIDs: [],
            sourceEntries: [],
            vaultKey: Self.vaultKey
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: alpha.manifestData))
        )
        let identityLoader = TestIdentityLoader(identity: nil)
        let runtime = Self.runtime(
            checkpoint: checkpoint,
            source: TestManifestSource(
                result: .available(alpha.manifestData)
            ),
            cache: TestCheckpointCache(lookup: .missing),
            identityLoader: identityLoader
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError
                .legacyAlphaProfile
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(identity.unwrapCount == 0)
        #expect(identityLoader.loadCount == 0)
    }

    @Test
    func futurePermanentProfileRequiresAnUpgrade() throws {
        let fixture = try Self.fixture()
        let futureData = try Self.profileManifest(
            fixture.candidate.manifestData,
            version: 3
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: futureData))
        )
        let runtime = Self.runtime(
            checkpoint: checkpoint,
            source: TestManifestSource(result: .available(futureData)),
            cache: TestCheckpointCache(lookup: .missing),
            identity: fixture.identity
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.upgradeRequired
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(fixture.identity.unwrapCount == 0)
    }

    @Test
    func retiredPermanentProfileRequiresResetOrRemigration() throws {
        let fixture = try Self.fixture()
        let retiredData = try Self.profileManifest(
            fixture.candidate.manifestData,
            version: 1
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: retiredData))
        )
        let runtime = Self.runtime(
            checkpoint: checkpoint,
            source: TestManifestSource(result: .available(retiredData)),
            cache: TestCheckpointCache(lookup: .missing),
            identity: fixture.identity
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError
                .legacyAlphaProfile
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(fixture.identity.unwrapCount == 0)
    }

    @Test
    func revokedDeviceReceivesAnExplicitOutcome() throws {
        let revoked = try RuntimeTestUnwrapper(
            vaultID: Self.vaultID,
            signingScalar: 1,
            wrappingScalar: 2
        )
        let active = try RuntimeTestUnwrapper(
            vaultID: Self.vaultID,
            signingScalar: 3,
            wrappingScalar: 4
        )
        let manifestData = try Self.manifest(
            devices: [
                V3DeviceWrappedManifestDevice(
                    identity: revoked.publicIdentity,
                    status: .revoked
                ),
                V3DeviceWrappedManifestDevice(
                    identity: active.publicIdentity,
                    status: .active
                ),
            ].sorted { $0.identity.deviceID < $1.identity.deviceID },
            activeRecipients: [active]
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: manifestData))
        )
        let runtime = Self.runtime(
            checkpoint: checkpoint,
            source: TestManifestSource(result: .available(manifestData)),
            cache: TestCheckpointCache(lookup: .missing),
            identity: revoked
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.deviceRevoked
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(revoked.unwrapCount == 0)
    }

    @Test
    func failedExplicitUnlockClearsPreviouslyResidentKey() throws {
        let fixture = try Self.fixture()
        let session = V3DeviceWrappedVaultKeySessionStore()
        let cache = TestCheckpointCache(
            lookup: .available(fixture.candidate.manifestData)
        )
        let source = TestManifestSource(result: .unavailable)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: source,
            cache: cache,
            identity: fixture.identity,
            session: session
        )
        _ = try runtime.unlock(reason: "Unlock the vault")
        cache.lookup = .missing

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError
                .temporaryUnavailable
        ) {
            try runtime.unlock(reason: "Unlock the vault again")
        }
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try runtime.loadVaultKey(keyID: fixture.candidate.body.keyID)
        }
    }

    @Test
    func cacheWriteFailureDoesNotUndoAuthenticatedUnlock() throws {
        let fixture = try Self.fixture()
        let cache = TestCheckpointCache(
            lookup: .missing,
            storeError: TestError.failed
        )
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(
                result: .available(fixture.candidate.manifestData)
            ),
            cache: cache,
            identity: fixture.identity
        )

        let envelope = try runtime.unlock(reason: "Unlock the vault")

        #expect(
            try runtime.loadVaultKey(keyID: envelope.body.keyID)
                == Self.vaultKey
        )
    }

    @Test
    func changedCheckpointPreventsSessionCommitAndCacheWrite() throws {
        let fixture = try Self.fixture()
        let identity = BlockingRuntimeUnwrapper(base: fixture.identity)
        let checkpointStore = TestCheckpointStore(
            checkpoint: fixture.checkpoint
        )
        let cache = TestCheckpointCache(lookup: .missing)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            checkpointStore: checkpointStore,
            source: TestManifestSource(
                result: .available(fixture.candidate.manifestData)
            ),
            cache: cache,
            identityLoader: TestIdentityLoader(identity: identity)
        )
        let unlockResult = TestResultBox<V3DeviceWrappedManifestEnvelope>()
        let didUnlock = DispatchSemaphore(value: 0)
        Task.detached {
            unlockResult.store(Result {
                try runtime.unlock(reason: "Unlock the vault")
            })
            didUnlock.signal()
        }
        #expect(identity.didBegin.wait(timeout: .now() + 1) == .success)
        checkpointStore.checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 9, count: 32)
        )

        identity.mayContinue.signal()
        #expect(didUnlock.wait(timeout: .now() + 1) == .success)
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError
                .checkpointChanged
        ) {
            try #require(unlockResult.value).get()
        }
        #expect(cache.storeCount == 0)
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try runtime.loadVaultKey(
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    @Test
    func cancelledDeviceAuthenticationLeavesTheRuntimeLocked() throws {
        let fixture = try Self.fixture()
        let identity = AuthenticationCancellingRuntimeUnwrapper(
            base: fixture.identity
        )
        let cache = TestCheckpointCache(lookup: .missing)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(
                result: .available(fixture.candidate.manifestData)
            ),
            cache: cache,
            identityLoader: TestIdentityLoader(identity: identity)
        )

        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try runtime.unlock(reason: "Unlock the vault")
        }
        #expect(cache.storeCount == 0)
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try runtime.loadVaultKey(
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    @Test
    func lockWaitsForInFlightUnlockAndThenClearsItsKey() throws {
        let fixture = try Self.fixture()
        let identity = BlockingRuntimeUnwrapper(base: fixture.identity)
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(
                result: .available(fixture.candidate.manifestData)
            ),
            cache: TestCheckpointCache(lookup: .missing),
            identityLoader: TestIdentityLoader(identity: identity)
        )
        let unlockResult = TestResultBox<V3DeviceWrappedManifestEnvelope>()
        let didUnlock = DispatchSemaphore(value: 0)
        Task.detached {
            unlockResult.store(Result {
                try runtime.unlock(reason: "Unlock the vault")
            })
            didUnlock.signal()
        }
        #expect(identity.didBegin.wait(timeout: .now() + 1) == .success)
        let didLock = DispatchSemaphore(value: 0)
        let lockTask = Task.detached {
            runtime.lock()
            didLock.signal()
        }

        #expect(didLock.wait(timeout: .now() + 0.01) == .timedOut)
        identity.mayContinue.signal()
        #expect(didUnlock.wait(timeout: .now() + 1) == .success)
        #expect(didLock.wait(timeout: .now() + 1) == .success)
        _ = lockTask
        _ = try #require(unlockResult.value).get()
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try runtime.loadVaultKey(
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    @Test
    func lockWaitsForCompleteCatchUpSessionAndThenClearsItsKey() throws {
        let fixture = try Self.fixture()
        let runtime = Self.runtime(
            checkpoint: fixture.checkpoint,
            source: TestManifestSource(
                result: .available(fixture.candidate.manifestData)
            ),
            cache: TestCheckpointCache(lookup: .missing),
            identity: fixture.identity
        )
        _ = try runtime.unlock(reason: "Unlock before catch-up")
        let didBeginCatchUp = DispatchSemaphore(value: 0)
        let mayFinishCatchUp = DispatchSemaphore(value: 0)
        let didFinishCatchUp = DispatchSemaphore(value: 0)
        let catchUpResult = TestResultBox<Void>()
        Task.detached {
            catchUpResult.store(Result {
                try runtime.withCatchUpSession {
                    didBeginCatchUp.signal()
                    mayFinishCatchUp.wait()
                    _ = try runtime.authenticatedCheckpoint(
                        reason: "Continue catch-up"
                    )
                }
            })
            didFinishCatchUp.signal()
        }
        #expect(didBeginCatchUp.wait(timeout: .now() + 1) == .success)
        let didLock = DispatchSemaphore(value: 0)
        let lockTask = Task.detached {
            runtime.lock()
            didLock.signal()
        }

        #expect(didLock.wait(timeout: .now() + 0.01) == .timedOut)
        mayFinishCatchUp.signal()
        #expect(didFinishCatchUp.wait(timeout: .now() + 1) == .success)
        #expect(didLock.wait(timeout: .now() + 1) == .success)
        _ = lockTask
        _ = try #require(catchUpResult.value).get()
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try runtime.loadVaultKey(
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    private static func fixture() throws -> (
        identity: RuntimeTestUnwrapper,
        candidate: V3DeviceWrappedGenesisCandidate,
        checkpoint: V3ManifestCheckpoint
    ) {
        let identity = try RuntimeTestUnwrapper(
            vaultID: vaultID,
            signingScalar: 1,
            wrappingScalar: 2
        )
        let candidate = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: vaultID,
            authorityTransitionID: transitionID,
            vaultKey: vaultKey,
            ownerIdentity: identity.publicIdentity
        )
        return (
            identity,
            candidate,
            try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: candidate.manifestDigest
            )
        )
    }

    private static func profileManifest(
        _ manifestData: Data,
        version: UInt64
    ) throws -> Data {
        let root = try #require(
            CanonicalJSON.parse(manifestData).objectValue
        )
        let content = try #require(
            root.first(where: { $0.0 == "content" })?.1.objectValue
        )
        let body = try #require(
            content.first(where: { $0.0 == "manifest" })?.1.objectValue
        )
        let versionedBody = body.map { name, value in
            name == "profileVersion"
                ? (name, CanonicalJSONValue.integer(version))
                : (name, value)
        }
        let versionedContent = content.map { name, value in
            name == "manifest"
                ? (name, CanonicalJSONValue.object(versionedBody))
                : (name, value)
        }
        return CanonicalJSON.encode(.object(root.map { name, value in
            name == "content"
                ? (name, CanonicalJSONValue.object(versionedContent))
                : (name, value)
        }))
    }

    private static func manifest(
        devices: [V3DeviceWrappedManifestDevice],
        activeRecipients: [RuntimeTestUnwrapper]
    ) throws -> Data {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        var wrappedKeys: [V3DeviceWrappedManifestKey] = []
        for recipient in activeRecipients.sorted(by: {
            $0.publicIdentity.deviceID < $1.publicIdentity.deviceID
        }) {
            let context = try V3VaultKeyHPKEContext(
                vaultID: vaultID,
                keyID: keyID,
                authorityTransitionID: transitionID,
                recipientDeviceID: recipient.publicIdentity.deviceID
            )
            wrappedKeys.append(try V3DeviceWrappedManifestKey(
                recipientDeviceID: recipient.publicIdentity.deviceID,
                wrappedKey: V3VaultKeyHPKE().wrap(
                    vaultKey: vaultKey,
                    recipientPublicKey:
                        recipient.publicIdentity.wrappingPublicKey,
                    context: context
                )
            ))
        }
        let body = try V3DeviceWrappedManifestBody(
            vaultID: vaultID,
            keyID: keyID,
            authorityTransitionID: transitionID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: []
        )
        let content = CanonicalJSONValue.object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: CanonicalJSON.encode(content),
            vaultID: vaultID,
            vaultKey: vaultKey
        )
        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([])),
        ]))
    }

    private static func runtime(
        checkpoint: V3ManifestCheckpoint,
        checkpointStore: TestCheckpointStore? = nil,
        source: TestManifestSource,
        cache: TestCheckpointCache,
        identity: RuntimeTestUnwrapper,
        session: V3DeviceWrappedVaultKeySessionStore =
            V3DeviceWrappedVaultKeySessionStore()
    ) -> V3DeviceWrappedVaultUnlockRuntime {
        runtime(
            checkpoint: checkpoint,
            checkpointStore: checkpointStore,
            source: source,
            cache: cache,
            identityLoader: TestIdentityLoader(identity: identity),
            session: session
        )
    }

    private static func runtime(
        checkpoint: V3ManifestCheckpoint,
        checkpointStore: TestCheckpointStore? = nil,
        source: TestManifestSource,
        cache: TestCheckpointCache,
        identityLoader: TestIdentityLoader,
        session: V3DeviceWrappedVaultKeySessionStore =
            V3DeviceWrappedVaultKeySessionStore()
    ) -> V3DeviceWrappedVaultUnlockRuntime {
        V3DeviceWrappedVaultUnlockRuntime(
            vaultID: vaultID,
            checkpointStore: checkpointStore
                ?? TestCheckpointStore(checkpoint: checkpoint),
            source: source,
            cache: cache,
            identityLoader: identityLoader,
            session: session
        )
    }
}

private enum TestError: Error {
    case failed
}

private final class TestResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Result<Value, Error>?

    var value: Result<Value, Error>? {
        lock.withLock { stored }
    }

    func store(_ result: Result<Value, Error>) {
        lock.withLock { stored = result }
    }
}

private final class TestCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var state: V3ManifestCheckpoint

    var checkpoint: V3ManifestCheckpoint {
        get { lock.withLock { state } }
        set { lock.withLock { state = newValue } }
    }

    init(checkpoint: V3ManifestCheckpoint) {
        state = checkpoint
    }

    func loadCheckpoint(vaultID: String) throws -> Data? {
        checkpoint.canonicalBytes
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {}
}

private final class TestManifestSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    let result: V3RepositoryObjectRead
    private let lock = NSLock()
    private var readCount = 0
    private var digest: Data?

    var manifestReadCount: Int {
        lock.withLock { readCount }
    }

    var requestedDigest: Data? {
        lock.withLock { digest }
    }

    init(result: V3RepositoryObjectRead) {
        self.result = result
    }

    func manifestDigests(
        maximumCount: Int
    ) throws -> V3RepositoryDirectoryListing {
        .invalid
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            readCount += 1
            self.digest = digest
        }
        return result
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        .invalid
    }
}

private final class TestCheckpointCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var state: V3CheckpointManifestCacheLookup
    private var stored: Data?
    private var stores = 0
    private let storeError: Error?

    var lookup: V3CheckpointManifestCacheLookup {
        get { lock.withLock { state } }
        set { lock.withLock { state = newValue } }
    }

    var storedData: Data? {
        lock.withLock { stored }
    }

    var storeCount: Int {
        lock.withLock { stores }
    }

    init(
        lookup: V3CheckpointManifestCacheLookup,
        storeError: Error? = nil
    ) {
        state = lookup
        self.storeError = storeError
    }

    func load(
        for checkpoint: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        lookup
    }

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws {
        try lock.withLock {
            stores += 1
            if let storeError {
                throw storeError
            }
            stored = manifestData
        }
    }
}

private final class TestIdentityLoader:
    V3DeviceWrappedIdentityLoading,
    @unchecked Sendable
{
    let identity: (any V3DeviceWrappedVaultKeyUnwrapping)?
    private let lock = NSLock()
    private var count = 0

    var loadCount: Int {
        lock.withLock { count }
    }

    init(identity: (any V3DeviceWrappedVaultKeyUnwrapping)?) {
        self.identity = identity
    }

    func loadDeviceIdentity(
        vaultID: String,
        reason: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        lock.withLock { count += 1 }
        return identity
    }
}

private final class BlockingRuntimeUnwrapper:
    V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
{
    let base: RuntimeTestUnwrapper
    let didBegin = DispatchSemaphore(value: 0)
    let mayContinue = DispatchSemaphore(value: 0)

    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity {
        base.publicIdentity
    }

    init(base: RuntimeTestUnwrapper) {
        self.base = base
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data {
        didBegin.signal()
        mayContinue.wait()
        return try base.unwrapDeviceWrappedVaultKey(
            wrappedKey,
            context: context,
            reason: reason
        )
    }
}

private final class AuthenticationCancellingRuntimeUnwrapper:
    V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
{
    let base: RuntimeTestUnwrapper

    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity {
        base.publicIdentity
    }

    init(base: RuntimeTestUnwrapper) {
        self.base = base
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data {
        throw V3EnrollmentDeviceIdentityStoreError
            .authenticationCancelled
    }
}

private final class RuntimeTestUnwrapper:
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
            displayName: "Test Mac \(signingScalar)",
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
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
