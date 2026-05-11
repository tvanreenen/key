import CryptoKit
import Foundation
import LocalAuthentication
import Security

public protocol VaultKeyStoring {
    func loadKey(mode: KeychainMode, reason: String, createIfMissing: Bool) throws -> Data
    func keyExists(mode: KeychainMode) throws -> Bool
    func storeKey(_ keyData: Data, mode: KeychainMode, overwriteExisting: Bool) throws
    func invalidate()
}

public final class VaultKeyStore: VaultKeyStoring {
    private let configuration: RuntimeConfiguration

    public init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    public func loadKey(mode: KeychainMode, reason: String, createIfMissing: Bool) throws -> Data {
        if try keyExists(mode: mode) {
            return try loadExistingKey(mode: mode, reason: reason)
        }

        guard createIfMissing else {
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }

        let keyData = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
        try storeKey(keyData, mode: mode, overwriteExisting: false)
        return keyData
    }

    public func keyExists(mode: KeychainMode) throws -> Bool {
        var query = try baseQuery(mode: mode)
        let context = makeAuthenticationContext()
        context.interactionNotAllowed = true
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return true
        case errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw AppError.keychain("Failed to query Keychain (\(status)).")
        }
    }

    public func storeKey(_ keyData: Data, mode: KeychainMode, overwriteExisting: Bool) throws {
        if overwriteExisting {
            try deleteKeyIfPresent(mode: mode)
        }

        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            accessibilityClass(for: mode),
            .userPresence,
            &accessControlError
        ) else {
            let message = (accessControlError?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.keychain("Failed to create vault key access control: \(message)")
        }

        var query = try baseQuery(mode: mode)
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount,
            kSecAttrLabel as String: "key vault key",
            kSecAttrAccessControl as String: accessControl,
            kSecValueData as String: keyData
        ]) { _, new in new }

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem, overwriteExisting {
            throw AppError.keychain("Failed to replace vault key in Keychain (\(status)).")
        }
        guard status == errSecSuccess else {
            throw AppError.keychain("Failed to store vault key in Keychain (\(status)).")
        }
    }

    private func loadExistingKey(mode: KeychainMode, reason: String) throws -> Data {
        var query = try baseQuery(mode: mode)
        let context = makeAuthenticationContext()
        context.localizedReason = reason
        var item: CFTypeRef?
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw AppError.entryNotFound("Vault key does not exist yet.")
            }
            if status == errSecAuthFailed || status == errSecUserCanceled {
                throw AppError.authFailed("Authentication was cancelled or failed.")
            }
            throw AppError.keychain("Failed to load vault key from Keychain (\(status)).")
        }

        guard let data = item as? Data else {
            throw AppError.keychain("Keychain returned an unexpected vault key payload.")
        }

        return data
    }

    public func invalidate() {
        // Stateless key access has no in-memory session to clear.
    }

    private func deleteKeyIfPresent(mode: KeychainMode) throws {
        var query = try baseQuery(mode: mode)
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount
        ]) { _, new in new }

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppError.keychain("Failed to replace vault key in Keychain (\(status)).")
        }
    }

    private func baseQuery(mode: KeychainMode) throws -> [String: Any] {
        guard !configuration.vaultService.isEmpty, !configuration.vaultAccount.isEmpty else {
            throw AppError.invalidConfiguration("Vault key service configuration is missing.")
        }
        guard let accessGroup = configuration.keychainAccessGroup, !accessGroup.isEmpty else {
            throw AppError.invalidConfiguration("This build is not configured with a shared keychain access group.")
        }

        var query: [String: Any] = [:]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        query[kSecAttrAccessGroup as String] = accessGroup
        query[kSecAttrSynchronizable as String] = mode == .icloud
        return query
    }

    private func accessibilityClass(for mode: KeychainMode) -> CFString {
        switch mode {
        case .local:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .icloud:
            return kSecAttrAccessibleWhenUnlocked
        }
    }

    private func makeAuthenticationContext() -> LAContext {
        LAContext()
    }
}
