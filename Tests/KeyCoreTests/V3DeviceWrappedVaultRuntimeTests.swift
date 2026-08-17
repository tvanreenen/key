import CryptoKit
import Foundation
import Testing
@testable import KeyCore

@Suite
struct V3DeviceWrappedVaultRuntimeTests {
    @Test
    func mapsMissingProviderBytesToTemporaryUnavailable() throws {
        let runtime = makeRuntime(failure: .temporaryUnavailable)
        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try runtime.unlock()
        }
    }

    @Test
    func mapsInvalidTrustedStateToRecoveryRequired() throws {
        let runtime = makeRuntime(failure: .recoveryRequired)
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try runtime.unlock()
        }
    }

    @Test
    func preservesMissingDeviceIdentityGuidance() throws {
        let runtime = makeRuntime(failure: .deviceIdentityUnavailable)
        do {
            try runtime.unlock()
            Issue.record("Expected the missing device identity to be refused.")
        } catch let error as VaultUXServiceError {
            #expect(error == .deviceIdentityUnavailable)
            #expect(error.localizedDescription.contains("surviving enrolled Mac"))
            #expect(error.localizedDescription.contains("permanently inaccessible"))
        }
    }

    @Test
    func preservesRevokedDeviceGuidance() throws {
        let runtime = makeRuntime(failure: .deviceRevoked)
        do {
            try runtime.unlock()
            Issue.record("Expected the revoked device to be refused.")
        } catch let error as VaultUXServiceError {
            #expect(error == .deviceRevoked)
            #expect(error.localizedDescription.contains("revoked"))
            #expect(error.localizedDescription.contains("replacement device"))
        }
    }

    @Test
    func refusesTheReplacedAlphaProfileExplicitly() throws {
        let runtime = makeRuntime(failure: .legacyAlphaProfile)
        do {
            try runtime.unlock()
            Issue.record("Expected the replaced alpha profile to be refused.")
        } catch let error as AppError {
            #expect(error.serviceErrorCode == .operationRefused)
            #expect(error.localizedDescription.contains("retired prerelease"))
            #expect(error.localizedDescription.contains("retained version 2 source"))
        }
    }

    @Test
    func mapsCancelledUserPresenceToAuthenticationFailure() throws {
        let runtime = makeRuntime(failure: .locked)
        do {
            try runtime.unlock()
            Issue.record("Expected cancelled authentication to stay locked.")
        } catch let error as AppError {
            #expect(error.serviceErrorCode == .authenticationFailed)
        }
    }

    @Test
    func reportsAndClearsThePermanentInMemorySession() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let session = V3DeviceWrappedVaultKeySessionStore(now: { now })
        let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        let vaultKey = Data(repeating: 19, count: 32)
        try session.install(
            vaultKey,
            vaultID: vaultID,
            keyID: V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: vaultID
            )
        )
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: PermanentRuntimeStub(failure: nil),
            session: session,
            lockSession: {
                session.invalidate()
            }
        )

        let unlocked = runtime.sessionStatus(at: now)
        #expect(unlocked.isUnlocked)
        #expect(unlocked.sessionExpiresAt == now.addingTimeInterval(15 * 60))

        runtime.lock()

        #expect(!runtime.sessionStatus(at: now).isUnlocked)
        #expect(!session.hasResidentKey)
    }

    @Test
    func lockWaitsForInFlightUnlockAndClearsItsInstalledKey() throws {
        let session = V3DeviceWrappedVaultKeySessionStore()
        let coordinatedRuntime = BlockingPermanentRuntimeStub(
            session: session
        )
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: coordinatedRuntime,
            session: session,
            lockSession: {
                coordinatedRuntime.lock()
            }
        )
        let unlockFinished = DispatchSemaphore(value: 0)
        let lockFinished = DispatchSemaphore(value: 0)

        DispatchQueue.global().async {
            try? runtime.unlock()
            unlockFinished.signal()
        }
        #expect(
            coordinatedRuntime.didBeginUnlock.wait(timeout: .now() + 1)
                == .success
        )

        DispatchQueue.global().async {
            runtime.lock()
            lockFinished.signal()
        }
        #expect(
            coordinatedRuntime.didBeginLock.wait(timeout: .now() + 1)
                == .success
        )
        #expect(lockFinished.wait(timeout: .now()) == .timedOut)

        coordinatedRuntime.mayFinishUnlock.signal()
        #expect(unlockFinished.wait(timeout: .now() + 1) == .success)
        #expect(lockFinished.wait(timeout: .now() + 1) == .success)
        #expect(!session.hasResidentKey)
    }

    @Test
    func catchUpFailureStopsAReadBeforePlaintextIsOpened() throws {
        let inner = RecordingPermanentRuntimeStub()
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: inner,
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                throw V3DeviceWrappedCatchUpError.recoveryRequired
            },
            lockSession: {}
        )

        #expect(throws: VaultUXServiceError.recoveryRequired) {
            _ = try runtime.read(name: "account/password", allowStale: false)
        }
        #expect(inner.readCount == 0)
    }

    @Test
    func revokedCatchUpStopsAReadWithExplicitGuidance() throws {
        let inner = RecordingPermanentRuntimeStub()
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: inner,
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                throw V3DeviceWrappedCatchUpError.deviceRevoked
            },
            lockSession: {}
        )

        #expect(throws: VaultUXServiceError.deviceRevoked) {
            _ = try runtime.read(name: "account/password", allowStale: false)
        }
        #expect(inner.readCount == 0)
    }

    @Test
    func revokedCatchUpStopsStatusWithExplicitGuidance() throws {
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: RecordingPermanentRuntimeStub(),
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                throw V3DeviceWrappedCatchUpError.deviceRevoked
            },
            lockSession: {}
        )

        #expect(throws: VaultUXServiceError.deviceRevoked) {
            _ = try runtime.status()
        }
    }

    @Test
    func explicitStaleReadCanUseTheLastTrustedCheckpointDuringDelay() throws {
        let inner = RecordingPermanentRuntimeStub()
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: inner,
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                throw V3DeviceWrappedCatchUpError.temporaryUnavailable
            },
            lockSession: {}
        )

        let value = try runtime.read(
            name: "account/password",
            allowStale: true
        )

        #expect(value.plaintext == "last trusted value")
        #expect(inner.readCount == 1)
    }

    @Test
    func successfulCatchUpCompletesUnlockWithoutASecondUnwrap() throws {
        let inner = RecordingPermanentRuntimeStub()
        let trusted = try Self.trustedCheckpoint()
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: inner,
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                .current(
                    trusted,
                    progress: V3DeviceWrappedCatchUpProgress(
                        contentManifestCount: 0,
                        keyEpochCount: 0
                    )
                )
            },
            lockSession: {}
        )

        try runtime.unlock()

        #expect(inner.unlockCount == 0)
    }

    @Test
    func statusExplainsAuthenticatedCatchUpContentConflict() throws {
        let trusted = try Self.trustedCheckpoint()
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: RecordingPermanentRuntimeStub(),
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                .contentConflict(
                    trusted,
                    manifestDigests: [Data(repeating: 0x31, count: 32)],
                    progress: V3DeviceWrappedCatchUpProgress(
                        contentManifestCount: 1,
                        keyEpochCount: 0
                    )
                )
            },
            lockSession: {}
        )

        let status = try runtime.status()

        #expect(status.health == .contentConflicted)
        #expect(status.entries.basis == .lastTrusted)
        #expect(status.issues.map(\.code) == [.ambiguousHistory])
    }

    @Test
    func statusExplainsAuthenticatedCatchUpSecurityConflict() throws {
        let trusted = try Self.trustedCheckpoint()
        let runtime = V3DeviceWrappedVaultRuntime(
            runtime: RecordingPermanentRuntimeStub(),
            session: V3DeviceWrappedVaultKeySessionStore(),
            catchUp: {
                .securityConflict(
                    trusted,
                    manifestDigests: [Data(repeating: 0x32, count: 32)],
                    progress: V3DeviceWrappedCatchUpProgress(
                        contentManifestCount: 0,
                        keyEpochCount: 1
                    )
                )
            },
            lockSession: {}
        )

        let status = try runtime.status()

        #expect(status.health == .securityConflicted)
        #expect(status.entries.basis == .lastTrusted)
        #expect(status.issues.map(\.code) == [.authorityDiverged])
    }

    private static func trustedCheckpoint() throws
        -> V3DeviceWrappedTrustedCheckpoint
    {
        let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x21, count: 32)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x22, count: 32)
        )
        let identity = try V3EnrollmentDeviceIdentity(
            displayName: "Runtime Mac",
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
        let genesis = try V3DeviceWrappedGenesisBuilder()
            .buildPublicationCandidate(
                vaultID: vaultID,
                authorityTransitionID:
                    "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4",
                entryIDs: [],
                sourceEntries: [],
                vaultKey: Data(repeating: 0x23, count: 32),
                ownerIdentity: identity
            ).genesis
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: genesis.manifestDigest
            ),
            envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                genesis.manifestData
            )
        )
    }

    private func makeRuntime(
        failure: V3DeviceWrappedVaultUnlockRuntimeError
    ) -> V3DeviceWrappedVaultRuntime {
        V3DeviceWrappedVaultRuntime(
            runtime: PermanentRuntimeStub(failure: failure),
            session: V3DeviceWrappedVaultKeySessionStore(),
            lockSession: {}
        )
    }
}

private final class RecordingPermanentRuntimeStub:
    VaultReadServicing,
    VaultUXServicing,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var reads = 0
    private var unlocks = 0

    var readCount: Int {
        lock.withLock { reads }
    }

    var unlockCount: Int {
        lock.withLock { unlocks }
    }

    func unlock() throws {
        lock.withLock {
            unlocks += 1
        }
    }

    func read(name _: String, allowStale _: Bool) throws -> VaultReadValue {
        lock.withLock {
            reads += 1
        }
        return VaultReadValue(type: .secret, plaintext: "last trusted value")
    }

    func list(allowStale _: Bool) throws -> [String] { [] }

    func status() throws -> VaultStatus {
        VaultStatus(format: .version3, health: .ready, entries: .effective(0))
    }

    func authorizeRead(name _: String, allowStale _: Bool) throws {}
    func authorizeMutation() throws {}
    func conflicts() throws -> [VaultConflictSummary] { [] }

    func conflict(id _: String) throws -> VaultConflictDetail {
        throw VaultUXServiceError.conflictNotFound
    }

    func conflictValue(id _: String, versionID _: String) throws -> String {
        throw VaultUXServiceError.conflictVersionNotFound
    }

    func resolve(_: [VaultConflictResolution]) throws {}
}

private final class BlockingPermanentRuntimeStub:
    VaultReadServicing,
    VaultUXServicing,
    @unchecked Sendable
{
    let didBeginUnlock = DispatchSemaphore(value: 0)
    let didBeginLock = DispatchSemaphore(value: 0)
    let mayFinishUnlock = DispatchSemaphore(value: 0)

    private let coordinationLock = NSLock()
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private let vaultKey = Data(repeating: 23, count: 32)

    init(session: V3DeviceWrappedVaultKeySessionStore) {
        self.session = session
    }

    func unlock() throws {
        coordinationLock.lock()
        defer { coordinationLock.unlock() }
        didBeginUnlock.signal()
        mayFinishUnlock.wait()
        try session.install(
            vaultKey,
            vaultID: vaultID,
            keyID: V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: vaultID
            )
        )
    }

    func lock() {
        didBeginLock.signal()
        coordinationLock.lock()
        session.invalidate()
        coordinationLock.unlock()
    }

    func read(name _: String, allowStale _: Bool) throws -> VaultReadValue {
        VaultReadValue(type: .secret, plaintext: "value")
    }

    func list(allowStale _: Bool) throws -> [String] { [] }

    func status() throws -> VaultStatus {
        VaultStatus(
            format: .version3,
            health: .ready,
            entries: .effective(0)
        )
    }

    func authorizeRead(name _: String, allowStale _: Bool) throws {}

    func authorizeMutation() throws {
        throw AppError.operationRefused("Writes are not enabled.")
    }

    func conflicts() throws -> [VaultConflictSummary] { [] }

    func conflict(id _: String) throws -> VaultConflictDetail {
        throw VaultUXServiceError.conflictNotFound
    }

    func conflictValue(id _: String, versionID _: String) throws -> String {
        throw VaultUXServiceError.conflictVersionNotFound
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw AppError.operationRefused("Writes are not enabled.")
    }
}

private struct PermanentRuntimeStub:
    VaultReadServicing,
    VaultUXServicing,
    @unchecked Sendable
{
    let failure: V3DeviceWrappedVaultUnlockRuntimeError?

    func unlock() throws {
        if let failure { throw failure }
    }

    func read(name _: String, allowStale _: Bool) throws -> VaultReadValue {
        if let failure { throw failure }
        return VaultReadValue(type: .secret, plaintext: "value")
    }

    func list(allowStale _: Bool) throws -> [String] {
        if let failure { throw failure }
        return []
    }

    func status() throws -> VaultStatus {
        if let failure { throw failure }
        return VaultStatus(
            format: .version3,
            health: .ready,
            entries: .effective(0)
        )
    }

    func authorizeRead(name _: String, allowStale _: Bool) throws {
        if let failure { throw failure }
    }

    func authorizeMutation() throws {
        throw AppError.operationRefused("Writes are not enabled.")
    }

    func conflicts() throws -> [VaultConflictSummary] { [] }

    func conflict(id _: String) throws -> VaultConflictDetail {
        throw VaultUXServiceError.conflictNotFound
    }

    func conflictValue(id _: String, versionID _: String) throws -> String {
        throw VaultUXServiceError.conflictVersionNotFound
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw AppError.operationRefused("Writes are not enabled.")
    }
}
