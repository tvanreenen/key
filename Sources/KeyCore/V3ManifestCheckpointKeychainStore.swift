import Foundation
import Security

/// Stores manifest rollback anchors locally and without Keychain
/// synchronization. Checkpoints are integrity state, not secrets, so reads do
/// not prompt for user presence.
final class V3ManifestCheckpointKeychainStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let configuration: RuntimeConfiguration
    private let lock = NSLock()

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func loadCheckpoint(vaultID: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return try loadCheckpointWithoutLock(vaultID: vaultID)
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {
        let decodedCheckpoint = try V3ManifestCheckpoint(canonicalBytes: checkpoint)
        guard decodedCheckpoint.vaultID == vaultID else {
            throw V3ManifestReplayError.vaultMismatch
        }

        lock.lock()
        defer { lock.unlock() }

        let current = try loadCheckpointWithoutLock(vaultID: vaultID)
        guard current == expectedCheckpoint else {
            throw V3ManifestCheckpointStoreError.conflict
        }

        let query = try baseQuery(vaultID: vaultID)
        if current == nil {
            var attributes = query
            attributes[kSecAttrLabel as String] = "key v3 manifest checkpoint"
            attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            attributes[kSecValueData as String] = checkpoint
            let status = SecItemAdd(attributes as CFDictionary, nil)
            if status == errSecDuplicateItem {
                throw V3ManifestCheckpointStoreError.conflict
            }
            guard status == errSecSuccess else {
                throw V3ManifestCheckpointStoreError.keychainStatus(status)
            }
            return
        }

        let status = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: checkpoint] as CFDictionary
        )
        if status == errSecItemNotFound {
            throw V3ManifestCheckpointStoreError.conflict
        }
        guard status == errSecSuccess else {
            throw V3ManifestCheckpointStoreError.keychainStatus(status)
        }
    }

    private func loadCheckpointWithoutLock(vaultID: String) throws -> Data? {
        var query = try baseQuery(vaultID: vaultID)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw V3ManifestCheckpointStoreError.keychainStatus(status)
        }
        guard let data = item as? Data else {
            throw V3ManifestCheckpointStoreError.keychainStatus(errSecInternalError)
        }
        return data
    }

    private func baseQuery(vaultID: String) throws -> [String: Any] {
        guard !configuration.vaultService.isEmpty,
              let accessGroup = configuration.keychainAccessGroup,
              !accessGroup.isEmpty
        else {
            throw V3ManifestCheckpointStoreError.invalidConfiguration
        }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "\(configuration.vaultService).v3-manifest-checkpoint",
            kSecAttrAccount as String: vaultID,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false
        ]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }
}
