import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedKeyTransitionCatchUpServiceTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b3"
    private static let genesisTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b4"
    private static let enrollmentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b5"
    private static let currentKey = Data(0..<32)
    private static let nextKey = Data(repeating: 0x71, count: 32)
    private static let approvalTime: UInt64 = 4_102_444_800

    @Test
    func commitsCheckpointBeforeReplacingTheResidentKey() throws {
        let fixture = try Fixture()

        let trusted = try fixture.service.advance(
            manifestData: fixture.candidate.manifestData,
            manifestDigest: fixture.candidate.manifestDigest
        )

        #expect(trusted == fixture.candidateTrusted)
        #expect(fixture.owner.kinds == [.catchUpVault])
        #expect(fixture.checkpointStore.checkpoint
            == fixture.candidateTrusted.checkpoint.canonicalBytes)
        #expect(fixture.checkpointStore.expectedCheckpoints
            == [fixture.parent.checkpoint.canonicalBytes])
        #expect(try fixture.session.load(
            vaultID: Self.vaultID,
            keyID: fixture.candidate.body.keyID
        ) == Self.nextKey)
        #expect(fixture.cache.storedManifest
            == fixture.candidate.manifestData)
    }

    @Test
    func checkpointChangeDuringUnwrapCannotCommitTheNewSession() throws {
        let fixture = try Fixture(changeCheckpointDuringUnwrap: true)

        #expect(throws: V3DeviceWrappedCatchUpError.checkpointChanged) {
            _ = try fixture.service.advance(
                manifestData: fixture.candidate.manifestData,
                manifestDigest: fixture.candidate.manifestDigest
            )
        }

        #expect(fixture.checkpointStore.checkpoint
            == Data("concurrent checkpoint".utf8))
        #expect(try fixture.session.load(
            vaultID: Self.vaultID,
            keyID: fixture.parent.envelope.body.keyID
        ) == Self.currentKey)
        #expect(fixture.cache.storedManifest == nil)
    }

    @Test
    func cancellationChangesNeitherCheckpointNorSession() throws {
        let fixture = try Fixture(unwrapError: .authenticationCancelled)

        #expect(
            throws: V3DeviceWrappedCatchUpError.authenticationCancelled
        ) {
            _ = try fixture.service.advance(
                manifestData: fixture.candidate.manifestData,
                manifestDigest: fixture.candidate.manifestDigest
            )
        }

        #expect(fixture.checkpointStore.checkpoint
            == fixture.parent.checkpoint.canonicalBytes)
        #expect(fixture.checkpointStore.expectedCheckpoints.isEmpty)
        #expect(try fixture.session.load(
            vaultID: Self.vaultID,
            keyID: fixture.parent.envelope.body.keyID
        ) == Self.currentKey)
    }

    @Test
    func cacheFailureCannotUndoTheCheckpointOrSessionAdvance() throws {
        let fixture = try Fixture(cacheFailure: true)

        let trusted = try fixture.service.advance(
            manifestData: fixture.candidate.manifestData,
            manifestDigest: fixture.candidate.manifestDigest
        )

        #expect(trusted == fixture.candidateTrusted)
        #expect(fixture.checkpointStore.checkpoint
            == fixture.candidateTrusted.checkpoint.canonicalBytes)
        #expect(try fixture.session.load(
            vaultID: Self.vaultID,
            keyID: fixture.candidate.body.keyID
        ) == Self.nextKey)
        #expect(fixture.cache.storeAttempts == 1)
    }

    @Test
    func explicitLockWaitsForCatchUpAndThenClearsTheNewKey() throws {
        let fixture = try Fixture(blockDuringUnwrap: true)
        let advanceResult = KeyTransitionCatchUpResultBox<
            V3DeviceWrappedTrustedCheckpoint
        >()
        let didAdvance = DispatchSemaphore(value: 0)
        Task.detached {
            advanceResult.store(Result {
                try fixture.service.advance(
                    manifestData: fixture.candidate.manifestData,
                    manifestDigest: fixture.candidate.manifestDigest
                )
            })
            didAdvance.signal()
        }
        let unwrapDidBegin = try #require(fixture.unwrapDidBegin)
        let unwrapMayContinue = try #require(fixture.unwrapMayContinue)
        #expect(unwrapDidBegin.wait(timeout: .now() + 1) == .success)

        let didLock = DispatchSemaphore(value: 0)
        Task.detached {
            fixture.unlockRuntime.lock()
            didLock.signal()
        }
        #expect(didLock.wait(timeout: .now() + 0.01) == .timedOut)

        unwrapMayContinue.signal()
        #expect(didAdvance.wait(timeout: .now() + 1) == .success)
        _ = try #require(advanceResult.value).get()
        #expect(didLock.wait(timeout: .now() + 1) == .success)
        #expect(
            throws: V3DeviceWrappedVaultUnlockRuntimeError.locked
        ) {
            try fixture.unlockRuntime.loadVaultKey(
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    private final class Fixture: @unchecked Sendable {
        let parent: V3DeviceWrappedTrustedCheckpoint
        let candidate: V3DeviceWrappedEnrollmentTransitionCandidate
        let candidateTrusted: V3DeviceWrappedTrustedCheckpoint
        let owner = KeyTransitionCatchUpMutationOwner()
        let checkpointStore: KeyTransitionCatchUpCheckpointStore
        let cache: KeyTransitionCatchUpCache
        let session = V3DeviceWrappedVaultKeySessionStore()
        let unlockRuntime: V3DeviceWrappedVaultUnlockRuntime
        let service: V3DeviceWrappedKeyTransitionCatchUpService
        let unwrapDidBegin: DispatchSemaphore?
        let unwrapMayContinue: DispatchSemaphore?

        init(
            changeCheckpointDuringUnwrap: Bool = false,
            unwrapError: V3EnrollmentDeviceIdentityStoreError? = nil,
            cacheFailure: Bool = false,
            blockDuringUnwrap: Bool = false
        ) throws {
            let ownerDevice = try KeyTransitionCatchUpDevice(
                displayName: "Owner Mac",
                signingScalar: 0x11,
                wrappingScalar: 0x12
            )
            let joiningDevice = try KeyTransitionCatchUpDevice(
                displayName: "Joining Mac",
                signingScalar: 0x21,
                wrappingScalar: 0x22
            )
            let genesis = try V3DeviceWrappedGenesisBuilder()
                .buildPublicationCandidate(
                    vaultID:
                        V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID,
                    authorityTransitionID:
                        V3DeviceWrappedKeyTransitionCatchUpServiceTests
                            .genesisTransitionID,
                    entryIDs: [],
                    sourceEntries: [],
                    vaultKey:
                        V3DeviceWrappedKeyTransitionCatchUpServiceTests
                            .currentKey,
                    ownerIdentity: ownerDevice.publicIdentity
                ).genesis
            let parentCheckpoint = try V3ManifestCheckpoint(
                vaultID:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID,
                envelopeDigest: genesis.manifestDigest
            )
            parent = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: parentCheckpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    genesis.manifestData
                )
            )
            let state = try Self.ceremony(
                parent: parent,
                owner: ownerDevice,
                joiner: joiningDevice
            )
            candidate = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: parent,
                currentEntries: [:],
                state: state,
                currentVaultKey:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.currentKey,
                nextVaultKey:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.nextKey,
                authorityTransitionID:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests
                        .enrollmentTransitionID,
                owner: ownerDevice,
                at: V3DeviceWrappedKeyTransitionCatchUpServiceTests
                    .approvalTime,
                authorizationReason: "Approve the compared Mac."
            )
            let nextCheckpoint = try V3ManifestCheckpoint(
                vaultID:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID,
                envelopeDigest: candidate.manifestDigest
            )
            candidateTrusted = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: nextCheckpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    candidate.manifestData
                )
            )

            checkpointStore = KeyTransitionCatchUpCheckpointStore(
                checkpoint: parent.checkpoint.canonicalBytes
            )
            cache = KeyTransitionCatchUpCache(
                loadData: genesis.manifestData,
                failsOnStore: cacheFailure
            )
            try session.install(
                V3DeviceWrappedKeyTransitionCatchUpServiceTests.currentKey,
                vaultID:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID,
                keyID: parent.envelope.body.keyID
            )
            let didBegin: DispatchSemaphore?
            let mayContinue: DispatchSemaphore?
            if blockDuringUnwrap {
                didBegin = DispatchSemaphore(value: 0)
                mayContinue = DispatchSemaphore(value: 0)
            } else {
                didBegin = nil
                mayContinue = nil
            }
            unwrapDidBegin = didBegin
            unwrapMayContinue = mayContinue
            let localCheckpointStore = checkpointStore
            let beforeUnwrap: @Sendable () -> Void
            beforeUnwrap = {
                if changeCheckpointDuringUnwrap {
                    localCheckpointStore.forceCheckpoint(
                        Data("concurrent checkpoint".utf8)
                    )
                }
                didBegin?.signal()
                mayContinue?.wait()
            }
            let identity = KeyTransitionCatchUpIdentity(
                device: ownerDevice,
                error: unwrapError,
                beforeUnwrap: beforeUnwrap
            )
            let source = KeyTransitionCatchUpObjectSource(
                manifests: [
                    parent.checkpoint.envelopeDigest: genesis.manifestData,
                ]
            )
            unlockRuntime = V3DeviceWrappedVaultUnlockRuntime(
                vaultID:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID,
                checkpointStore: checkpointStore,
                source: source,
                cache: cache,
                identityLoader: KeyTransitionCatchUpIdentityLoader(),
                session: session
            )
            service = V3DeviceWrappedKeyTransitionCatchUpService(
                vaultID:
                    V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID,
                mutationOwner: owner,
                stateManager: unlockRuntime,
                source: source,
                cache: cache,
                loadIdentity: { _, _ in identity }
            )
        }

        private static func ceremony(
            parent: V3DeviceWrappedTrustedCheckpoint,
            owner: KeyTransitionCatchUpDevice,
            joiner: KeyTransitionCatchUpDevice
        ) throws -> V3EnrollmentCeremonyState {
            let invitation = try V3EnrollmentInvitation(
                vaultID: parent.checkpoint.vaultID,
                parentManifestDigest: parent.checkpoint.envelopeDigest,
                invitingDevice: owner.publicIdentity,
                invitedRole: .member,
                nonce: Data(repeating: 0x41, count: 32),
                expiresAt: V3DeviceWrappedKeyTransitionCatchUpServiceTests
                    .approvalTime
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
                nonce: Data(repeating: 0x42, count: 32)
            )
            let signedRequest = try authenticator.sign(
                request,
                answering: authenticator.verify(signedInvitation),
                using: joiner,
                reason: "Join vault."
            )
            return try V3EnrollmentCeremonyState(
                vaultID: invitation.vaultID,
                invitationDigest: invitation.digest,
                role: .inviter,
                phase: .awaitingComparison,
                signedInvitation: signedInvitation,
                signedJoinRequest: signedRequest
            )
        }
    }
}

private struct KeyTransitionCatchUpDevice:
    V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
{
    let vaultID =
        V3DeviceWrappedKeyTransitionCatchUpServiceTests.vaultID
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let signingKey: P256.Signing.PrivateKey
    private let wrappingKey: P256.KeyAgreement.PrivateKey

    init(
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: signingScalar, count: 32)
        )
        wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: wrappingScalar, count: 32)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingKey.signature(for: input).rawRepresentation
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: wrappingKey,
            context: context
        )
    }
}

private final class KeyTransitionCatchUpIdentity:
    V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
{
    private let device: KeyTransitionCatchUpDevice
    private let error: V3EnrollmentDeviceIdentityStoreError?
    private let beforeUnwrap: @Sendable () -> Void

    init(
        device: KeyTransitionCatchUpDevice,
        error: V3EnrollmentDeviceIdentityStoreError?,
        beforeUnwrap: @escaping @Sendable () -> Void
    ) {
        self.device = device
        self.error = error
        self.beforeUnwrap = beforeUnwrap
    }

    var vaultID: String { device.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { device.publicIdentity }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data {
        beforeUnwrap()
        if let error {
            throw error
        }
        return try device.unwrapDeviceWrappedVaultKey(
            wrappedKey,
            context: context,
            reason: reason
        )
    }
}

private final class KeyTransitionCatchUpMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var recordedKinds: [VaultTransactionMutationKind] = []

    var kinds: [VaultTransactionMutationKind] {
        lock.withLock { recordedKinds }
    }

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        lock.withLock {
            recordedKinds.append(kind)
        }
        return try mutation(VaultTransactionMutationContext(
            operationID: VaultTransactionOperationID(),
            kind: kind
        ))
    }
}

private final class KeyTransitionCatchUpCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var value: Data?
    private var expected: [Data?] = []

    init(checkpoint: Data?) {
        value = checkpoint
    }

    var checkpoint: Data? { lock.withLock { value } }
    var expectedCheckpoints: [Data?] { lock.withLock { expected } }

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
            guard value == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            value = checkpoint
        }
    }

    func forceCheckpoint(_ checkpoint: Data) {
        lock.withLock {
            value = checkpoint
        }
    }
}

private final class KeyTransitionCatchUpCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let loadData: Data
    private let failsOnStore: Bool
    private var manifest: Data?
    private var attempts = 0

    init(loadData: Data, failsOnStore: Bool) {
        self.loadData = loadData
        self.failsOnStore = failsOnStore
    }

    var storedManifest: Data? { lock.withLock { manifest } }
    var storeAttempts: Int { lock.withLock { attempts } }

    func load(
        for _: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        .available(loadData)
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

private struct KeyTransitionCatchUpIdentityLoader:
    V3DeviceWrappedIdentityLoading
{
    func loadDeviceIdentity(
        vaultID _: String,
        reason _: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        nil
    }
}

private final class KeyTransitionCatchUpObjectSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    private let manifests: [Data: Data]

    init(manifests: [Data: Data]) {
        self.manifests = manifests
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
        guard let data = manifests[digest] else {
            return .unavailable
        }
        return .available(data)
    }

    func readEntry(
        entryID _: String,
        digest _: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        .unavailable
    }
}

private final class KeyTransitionCatchUpResultBox<Value>:
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Result<Value, Error>?

    var value: Result<Value, Error>? {
        lock.withLock { stored }
    }

    func store(_ result: Result<Value, Error>) {
        lock.withLock { stored = result }
    }
}
