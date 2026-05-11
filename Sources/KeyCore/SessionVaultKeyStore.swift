import Foundation

public final class SessionVaultKeyStore: VaultKeyStoring, KeySessionStatusReporting {
    private struct SessionState {
        var mode: KeychainMode?
        var cachedKeyData: Data?
        var lastAccessAt: Date?
    }

    private let underlying: VaultKeyStoring
    private let inactivityTimeout: TimeInterval
    private let now: () -> Date
    private let queue = DispatchQueue(label: "work.tvr.key.session-vault-key-store")
    private var state = SessionState()

    public init(
        underlying: VaultKeyStoring,
        inactivityTimeout: TimeInterval = 15 * 60,
        now: @escaping () -> Date = Date.init
    ) {
        self.underlying = underlying
        self.inactivityTimeout = inactivityTimeout
        self.now = now
    }

    public func loadKey(mode: KeychainMode, reason: String, createIfMissing: Bool) throws -> Data {
        try queue.sync {
            let currentTime = now()

            if state.mode == mode,
               let cachedKeyData = state.cachedKeyData,
               let lastAccessAt = state.lastAccessAt,
               currentTime.timeIntervalSince(lastAccessAt) < inactivityTimeout {
                state.lastAccessAt = currentTime
                return cachedKeyData
            }

            clearSession()

            do {
                let keyData = try underlying.loadKey(mode: mode, reason: reason, createIfMissing: createIfMissing)
                state.mode = mode
                state.cachedKeyData = keyData
                state.lastAccessAt = currentTime
                return keyData
            } catch {
                clearSession()
                throw error
            }
        }
    }

    public func keyExists(mode: KeychainMode) throws -> Bool {
        try queue.sync {
            let currentTime = now()
            if state.mode == mode, currentStatus(at: currentTime).isUnlocked {
                return true
            }

            return try underlying.keyExists(mode: mode)
        }
    }

    public func storeKey(_ keyData: Data, mode: KeychainMode, overwriteExisting: Bool) throws {
        try queue.sync {
            try underlying.storeKey(keyData, mode: mode, overwriteExisting: overwriteExisting)
            clearSession()
        }
    }

    public func invalidate() {
        queue.sync {
            clearSession()
        }
    }

    public func isUnlocked(at date: Date? = nil) -> Bool {
        sessionStatus(at: date).isUnlocked
    }

    public func sessionStatus(at date: Date? = nil) -> KeyHelperStatus {
        queue.sync {
            currentStatus(at: date ?? now())
        }
    }

    private func clearSession() {
        state.mode = nil
        state.cachedKeyData = nil
        state.lastAccessAt = nil
    }

    private func currentStatus(at currentTime: Date) -> KeyHelperStatus {
        guard let cachedKeyData = state.cachedKeyData,
              !cachedKeyData.isEmpty,
              let lastAccessAt = state.lastAccessAt else {
            return .locked(inactivityTimeoutSeconds: inactivityTimeout)
        }

        let sessionExpiresAt = lastAccessAt.addingTimeInterval(inactivityTimeout)
        guard currentTime < sessionExpiresAt else {
            clearSession()
            return .locked(inactivityTimeoutSeconds: inactivityTimeout)
        }

        return KeyHelperStatus(
            isUnlocked: true,
            sessionExpiresAt: sessionExpiresAt,
            inactivityTimeoutSeconds: inactivityTimeout
        )
    }
}
