import Foundation

enum V3DeviceWrappedVaultKeySessionError: Error, Equatable {
    case invalidKey
    case unavailable
}

/// The only owner of a plaintext permanent-profile vault key after unwrap.
///
/// This store has no persistent backing. Lock, idle expiry, helper restart,
/// runtime replacement, or process termination discards its sole key value.
final class V3DeviceWrappedVaultKeySessionStore: @unchecked Sendable {
    private struct State {
        var vaultID: String?
        var keyID: V3VaultKeyID?
        var key: Data?
        var deadline: ContinuousClock.Instant?
    }

    private let inactivityTimeout: Duration
    private let clock = ContinuousClock()
    private let lock = NSLock()
    private var state = State()
    private var expirationTask: Task<Void, Never>?
    private var expirationGeneration: UInt64 = 0

    init(
        inactivityTimeout: Duration = .seconds(15 * 60)
    ) {
        precondition(inactivityTimeout > .zero)
        self.inactivityTimeout = inactivityTimeout
    }

    deinit {
        expirationTask?.cancel()
    }

    func install(
        _ key: Data,
        vaultID: String,
        keyID: V3VaultKeyID
    ) throws {
        guard key.count == 32,
              (try? V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID))
                == keyID
        else {
            throw V3DeviceWrappedVaultKeySessionError.invalidKey
        }
        lock.lock()
        defer { lock.unlock() }
        state = State(
            vaultID: vaultID,
            keyID: keyID,
            key: key,
            deadline: nil
        )
        scheduleExpirationLocked(from: clock.now)
    }

    func load(vaultID: String, keyID: V3VaultKeyID) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        let current = clock.now
        guard let deadline = state.deadline,
              current < deadline,
              state.vaultID == vaultID,
              state.keyID == keyID,
              let key = state.key
        else {
            clearLocked()
            throw V3DeviceWrappedVaultKeySessionError.unavailable
        }
        scheduleExpirationLocked(from: current)
        return key
    }

    func invalidate() {
        lock.lock()
        clearLocked()
        lock.unlock()
    }

    /// Test and diagnostic visibility into whether key bytes are still held.
    /// Unlike `load`, this does not perform lazy expiration.
    var hasResidentKey: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state.key != nil
    }

    private func scheduleExpirationLocked(
        from now: ContinuousClock.Instant
    ) {
        expirationTask?.cancel()
        expirationGeneration += 1
        let generation = expirationGeneration
        let deadline = now.advanced(by: inactivityTimeout)
        state.deadline = deadline
        let clock = self.clock
        expirationTask = Task { [weak self] in
            do {
                try await clock.sleep(until: deadline)
            } catch {
                return
            }
            self?.expireIfCurrent(
                generation: generation,
                deadline: deadline
            )
        }
    }

    private func expireIfCurrent(
        generation: UInt64,
        deadline: ContinuousClock.Instant
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard expirationGeneration == generation,
              state.deadline == deadline,
              clock.now >= deadline
        else {
            return
        }
        state = State()
        expirationTask = nil
    }

    private func clearLocked() {
        expirationTask?.cancel()
        expirationTask = nil
        expirationGeneration += 1
        state = State()
    }
}
