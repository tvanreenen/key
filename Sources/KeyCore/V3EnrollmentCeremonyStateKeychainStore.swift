import Foundation
import Security

protocol V3EnrollmentCeremonyStateStoring: Sendable {
    func loadState(
        vaultID: String,
        invitationDigest: Data
    ) throws -> Data?

    func replaceState(
        _ state: Data,
        expectedState: Data?,
        vaultID: String,
        invitationDigest: Data
    ) throws
}

/// Persists replay and resumption state outside file-provider synchronization.
///
/// Ceremony state contains authenticated public messages rather than secrets,
/// so reads do not request user presence. Device-only accessibility prevents a
/// synchronized Keychain item from becoming a second untrusted transport.
final class V3EnrollmentCeremonyStateKeychainStore:
    V3EnrollmentCeremonyStateStoring,
    @unchecked Sendable
{
    private let configuration: RuntimeConfiguration
    // On macOS 15+, Synchronization.Mutex can replace this compatibility lock.
    private static let lock = NSLock()

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func loadState(
        vaultID: String,
        invitationDigest: Data
    ) throws -> Data? {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        return try loadWithoutLock(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
    }

    func replaceState(
        _ state: Data,
        expectedState: Data?,
        vaultID: String,
        invitationDigest: Data
    ) throws {
        let decoded = try V3EnrollmentCeremonyState(
            canonicalBytes: state
        )
        guard decoded.vaultID == vaultID,
            decoded.invitationDigest == invitationDigest
        else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }

        Self.lock.lock()
        defer { Self.lock.unlock() }
        let current = try loadWithoutLock(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        guard current == expectedState else {
            throw V3EnrollmentCeremonyStateError.conflict
        }

        let query = try baseQuery(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        if current == nil {
            var attributes = query
            attributes[kSecAttrLabel as String] =
                "key v3 enrollment ceremony state"
            attributes[kSecAttrAccessible as String] =
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            attributes[kSecValueData as String] = state
            let status = SecItemAdd(attributes as CFDictionary, nil)
            if status == errSecDuplicateItem {
                throw V3EnrollmentCeremonyStateError.conflict
            }
            guard status == errSecSuccess else {
                throw V3EnrollmentCeremonyStateError.keychainStatus(
                    status
                )
            }
            return
        }

        let status = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: state] as CFDictionary
        )
        if status == errSecItemNotFound {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        guard status == errSecSuccess else {
            throw V3EnrollmentCeremonyStateError.keychainStatus(status)
        }
    }

    private func loadWithoutLock(
        vaultID: String,
        invitationDigest: Data
    ) throws -> Data? {
        var query = try baseQuery(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        // SAFETY: Security.framework writes one retained result into the
        // stack-local optional for the duration of this synchronous call.
        let status = unsafe SecItemCopyMatching(
            query as CFDictionary,
            &item
        )
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw V3EnrollmentCeremonyStateError.keychainStatus(
                status == errSecSuccess ? errSecInternalError : status
            )
        }
        return data
    }

    private func baseQuery(
        vaultID: String,
        invitationDigest: Data
    ) throws -> [String: Any] {
        guard isValidV3UUID(vaultID),
            invitationDigest.count == 32,
            !configuration.vaultService.isEmpty,
            let accessGroup = configuration.keychainAccessGroup,
            !accessGroup.isEmpty
        else {
            throw V3EnrollmentCeremonyStateError.invalidConfiguration
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String:
                "\(configuration.vaultService).v3-enrollment-ceremony",
            kSecAttrAccount as String:
                "\(vaultID).\(Base64URL.encode(invitationDigest))",
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false,
        ]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }
}
