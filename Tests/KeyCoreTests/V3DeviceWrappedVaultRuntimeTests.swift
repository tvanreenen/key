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
    func refusesTheReplacedAlphaProfileExplicitly() throws {
        let runtime = makeRuntime(failure: .legacyAlphaProfile)
        do {
            try runtime.unlock()
            Issue.record("Expected the replaced alpha profile to be refused.")
        } catch let error as AppError {
            #expect(error.serviceErrorCode == .operationRefused)
            #expect(error.localizedDescription.contains("replaced prerelease"))
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
