import Foundation

public final class SessionVaultKeyStore: VaultKeyStoring {
    private struct SessionState {
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

    public func loadKey(reason: String, createIfMissing: Bool) throws -> Data {
        try queue.sync {
            let currentTime = now()

            if let cachedKeyData = state.cachedKeyData,
               let lastAccessAt = state.lastAccessAt,
               currentTime.timeIntervalSince(lastAccessAt) < inactivityTimeout {
                state.lastAccessAt = currentTime
                return cachedKeyData
            }

            clearSession()

            do {
                let keyData = try underlying.loadKey(reason: reason, createIfMissing: createIfMissing)
                state.cachedKeyData = keyData
                state.lastAccessAt = currentTime
                return keyData
            } catch {
                clearSession()
                throw error
            }
        }
    }

    public func invalidate() {
        queue.sync {
            clearSession()
        }
    }

    public func isUnlocked(at date: Date? = nil) -> Bool {
        queue.sync {
            guard let cachedKeyData = state.cachedKeyData,
                  !cachedKeyData.isEmpty,
                  let lastAccessAt = state.lastAccessAt else {
                return false
            }

            let currentTime = date ?? now()
            return currentTime.timeIntervalSince(lastAccessAt) < inactivityTimeout
        }
    }

    private func clearSession() {
        state.cachedKeyData = nil
        state.lastAccessAt = nil
    }
}
