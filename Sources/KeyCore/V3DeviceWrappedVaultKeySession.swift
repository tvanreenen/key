import Foundation

enum V3DeviceWrappedVaultKeySessionError: Error, Equatable {
    case invalidKey
    case unavailable
}

/// The in-memory owner of a plaintext Mac-bound vault key after unwrap.
/// Both permanent and recovery-capable profiles bind it to an exact vault/key ID.
///
/// This store has no persistent backing. Lock, idle expiry, helper restart,
/// runtime replacement, or process termination discards its sole key value.
final class V3DeviceWrappedVaultKeySessionStore: @unchecked Sendable {
    /// Process-local race guard only, never evidence of authentication or consent.
    struct AuthenticationTicket: Sendable {
        fileprivate let storeID: UUID
        fileprivate let generation: UInt64
    }

    private struct State {
        var vaultID: String?
        var keyID: V3VaultKeyID?
        var key: Data?
        var deadline: ContinuousClock.Instant?
        var expiresAt: Date?
    }

    private let inactivityTimeout: Duration
    private let inactivityTimeoutSeconds: TimeInterval
    private let clock = ContinuousClock()
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private let storeID = UUID()
    private var authenticationGeneration: UInt64 = 0
    private var state = State()
    private var expirationTask: Task<Void, Never>?
    private var expirationGeneration: UInt64 = 0

    init(
        inactivityTimeout: Duration = .seconds(15 * 60),
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        precondition(inactivityTimeout > .zero)
        self.inactivityTimeout = inactivityTimeout
        let components = inactivityTimeout.components
        inactivityTimeoutSeconds =
            TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
        self.now = now
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
        authenticationGeneration += 1
        state = State(
            vaultID: vaultID,
            keyID: keyID,
            key: key,
            deadline: nil,
            expiresAt: nil
        )
        scheduleExpirationLocked(
            from: clock.now,
            wallTime: now()
        )
    }

    /// Capture before authentication UI. Status polling of a locked session does
    /// not cancel it; explicit lock, actual expiry or key replacement does.
    func beginAuthentication() -> AuthenticationTicket {
        lock.lock()
        defer { lock.unlock() }
        if let deadline = state.deadline, clock.now >= deadline {
            clearLocked()
        }
        return AuthenticationTicket(storeID: storeID, generation: authenticationGeneration)
    }

    func requireCurrent(_ ticket: AuthenticationTicket) throws {
        lock.lock()
        defer { lock.unlock() }
        try requireTicketLocked(ticket)
    }

    /// Install a newly authenticated key without undoing a lock during the UI.
    /// The caller must authenticate exact committed authority before invoking it.
    @discardableResult
    func install(
        _ key: Data, vaultID: String, keyID: V3VaultKeyID,
        authenticationTicket: AuthenticationTicket
    ) throws -> AuthenticationTicket {
        guard key.count == 32,
            (try? V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID)) == keyID
        else { throw V3DeviceWrappedVaultKeySessionError.invalidKey }
        lock.lock()
        defer { lock.unlock() }
        try requireTicketLocked(authenticationTicket)
        authenticationGeneration += 1
        state = State(vaultID: vaultID, keyID: keyID, key: key, deadline: nil, expiresAt: nil)
        scheduleExpirationLocked(from: clock.now, wallTime: now())
        return AuthenticationTicket(storeID: storeID, generation: authenticationGeneration)
    }

    private func requireTicketLocked(_ ticket: AuthenticationTicket) throws {
        if let deadline = state.deadline, clock.now >= deadline { clearLocked() }
        guard ticket.storeID == storeID, ticket.generation == authenticationGeneration else {
            throw V3DeviceWrappedVaultKeySessionError.unavailable
        }
    }

    /// Switch a committed key epoch only while the exact prior session is still
    /// live. A lock/expiry during publication must not be undone by installation.
    func replace(
        _ key: Data,
        vaultID: String,
        keyID: V3VaultKeyID,
        expectedKeyID: V3VaultKeyID
    ) throws {
        guard key.count == 32,
            (try? V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID))
                == keyID
        else {
            throw V3DeviceWrappedVaultKeySessionError.invalidKey
        }
        lock.lock()
        defer { lock.unlock() }
        let current = clock.now
        guard let deadline = state.deadline, current < deadline else {
            clearLocked()
            throw V3DeviceWrappedVaultKeySessionError.unavailable
        }
        guard state.vaultID == vaultID,
            state.keyID == expectedKeyID,
            state.key != nil
        else {
            throw V3DeviceWrappedVaultKeySessionError.unavailable
        }
        state.keyID = keyID
        state.key = key
        authenticationGeneration += 1
        scheduleExpirationLocked(from: current, wallTime: now())
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
        scheduleExpirationLocked(
            from: current,
            wallTime: now()
        )
        return key
    }

    func invalidate() {
        lock.lock()
        authenticationGeneration += 1
        clearLocked()
        lock.unlock()
    }

    func sessionStatus(at date: Date? = nil) -> KeyHelperStatus {
        lock.lock()
        defer { lock.unlock() }
        let observedDate = date ?? now()
        guard let deadline = state.deadline,
            clock.now < deadline,
            let expiresAt = state.expiresAt,
            observedDate < expiresAt,
            state.key != nil
        else {
            clearLocked()
            return .locked(
                inactivityTimeoutSeconds: inactivityTimeoutSeconds
            )
        }
        return KeyHelperStatus(
            isUnlocked: true,
            sessionExpiresAt: expiresAt,
            inactivityTimeoutSeconds: inactivityTimeoutSeconds
        )
    }

    /// Test and diagnostic visibility into whether key bytes are still held.
    /// Unlike `load`, this does not perform lazy expiration.
    var hasResidentKey: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state.key != nil
    }

    private func scheduleExpirationLocked(
        from now: ContinuousClock.Instant,
        wallTime: Date
    ) {
        expirationTask?.cancel()
        expirationGeneration += 1
        let generation = expirationGeneration
        let deadline = now.advanced(by: inactivityTimeout)
        state.deadline = deadline
        state.expiresAt = wallTime.addingTimeInterval(
            inactivityTimeoutSeconds
        )
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
        authenticationGeneration += 1
        expirationTask = nil
    }

    private func clearLocked() {
        if state.key != nil { authenticationGeneration += 1 }
        expirationTask?.cancel()
        expirationTask = nil
        expirationGeneration += 1
        state = State()
    }
}
