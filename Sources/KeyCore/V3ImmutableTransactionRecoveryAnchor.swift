import Foundation
internal import JSONCanonicalization
import Security

enum V3ImmutableTransactionRecoveryAnchorError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidAnchor
    case conflict
    case invalidConfiguration
    case keychainStatus(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidAnchor:
            "The device-local version 3 transaction recovery anchor is invalid."
        case .conflict:
            "The device-local version 3 transaction recovery anchor changed concurrently."
        case .invalidConfiguration:
            "Version 3 transaction recovery storage is not configured."
        case let .keychainStatus(status):
            "Version 3 transaction recovery Keychain operation failed (\(status))."
        }
    }
}

enum V3ImmutableTransactionRecoveryAnchorPhase:
    String,
    Equatable,
    Sendable
{
    /// The device has reserved this operation, but shared intent may not yet
    /// have become durable. No repository publication can have begun.
    case prepared

    /// The exact shared intent was made durable before any staging or
    /// immutable publication began.
    case recoverable
}

/// Small device-local ownership record for one shared recovery intent.
///
/// Transaction files can synchronize with the vault. This non-synchronizing
/// anchor prevents one device from interpreting or deleting another device's
/// partially delivered transaction state.
struct V3ImmutableTransactionRecoveryAnchor: Equatable, Sendable {
    let operationID: VaultTransactionOperationID
    let vaultID: String
    let intentDigest: Data
    let phase: V3ImmutableTransactionRecoveryAnchorPhase

    init(
        operationID: VaultTransactionOperationID,
        vaultID: String,
        intentDigest: Data,
        phase: V3ImmutableTransactionRecoveryAnchorPhase
    ) throws {
        guard isValidV3UUID(vaultID), intentDigest.count == 32 else {
            throw V3ImmutableTransactionRecoveryAnchorError.invalidAnchor
        }
        self.operationID = operationID
        self.vaultID = vaultID
        self.intentDigest = intentDigest
        self.phase = phase
    }

    init(canonicalBytes: Data) throws {
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3ImmutableTransactionRecoveryAnchorError.invalidAnchor
        }
        guard CanonicalJSON.encode(json) == canonicalBytes,
              let object = json.objectValue,
              Set(object.map(\.0)) == Set([
                  "format",
                  "intentDigest",
                  "operationID",
                  "phase",
                  "vaultID",
                  "version"
              ]),
              anchorString("format", in: object)
                == "key-vault-transaction-recovery-anchor",
              anchorInteger("version", in: object) == 1,
              let operationIDValue = anchorString(
                  "operationID",
                  in: object
              ),
              let operationID = try? VaultTransactionOperationID(
                  validating: operationIDValue
              ),
              let vaultID = anchorString("vaultID", in: object),
              let digestValue = anchorString("intentDigest", in: object),
              let intentDigest = Base64URL.decodeCanonical(digestValue),
              let phaseValue = anchorString("phase", in: object),
              let phase = V3ImmutableTransactionRecoveryAnchorPhase(
                  rawValue: phaseValue
              )
        else {
            throw V3ImmutableTransactionRecoveryAnchorError.invalidAnchor
        }
        try self.init(
            operationID: operationID,
            vaultID: vaultID,
            intentDigest: intentDigest,
            phase: phase
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            (
                "format",
                .string("key-vault-transaction-recovery-anchor")
            ),
            ("version", .integer(1)),
            ("operationID", .string(operationID.rawValue)),
            ("vaultID", .string(vaultID)),
            ("intentDigest", .string(Base64URL.encode(intentDigest))),
            ("phase", .string(phase.rawValue))
        ]))
    }
}

protocol V3ImmutableTransactionRecoveryAnchorStoring: Sendable {
    func loadRecoveryAnchor(vaultID: String) throws -> Data?

    func replaceRecoveryAnchor(
        _ anchor: Data?,
        expectedAnchor: Data?,
        vaultID: String
    ) throws
}

/// Persists transaction ownership beside the device-local checkpoint and
/// explicitly outside Keychain synchronization.
final class V3ImmutableTransactionRecoveryAnchorKeychainStore:
    V3ImmutableTransactionRecoveryAnchorStoring,
    Sendable
{
    private let configuration: RuntimeConfiguration
    private let lock = NSLock()

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return try loadWithoutLock(vaultID: vaultID)
    }

    func replaceRecoveryAnchor(
        _ anchor: Data?,
        expectedAnchor: Data?,
        vaultID: String
    ) throws {
        if let anchor {
            let decoded = try V3ImmutableTransactionRecoveryAnchor(
                canonicalBytes: anchor
            )
            guard decoded.vaultID == vaultID else {
                throw V3ImmutableTransactionRecoveryAnchorError.invalidAnchor
            }
        }

        lock.lock()
        defer { lock.unlock() }
        let current = try loadWithoutLock(vaultID: vaultID)
        guard current == expectedAnchor else {
            throw V3ImmutableTransactionRecoveryAnchorError.conflict
        }

        let query = try baseQuery(vaultID: vaultID)
        if let anchor {
            if current == nil {
                var attributes = query
                attributes[kSecAttrLabel as String] =
                    "key v3 transaction recovery anchor"
                attributes[kSecAttrAccessible as String] =
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                attributes[kSecValueData as String] = anchor
                let status = SecItemAdd(attributes as CFDictionary, nil)
                if status == errSecDuplicateItem {
                    throw V3ImmutableTransactionRecoveryAnchorError.conflict
                }
                guard status == errSecSuccess else {
                    throw V3ImmutableTransactionRecoveryAnchorError
                        .keychainStatus(status)
                }
                return
            }
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: anchor] as CFDictionary
            )
            if status == errSecItemNotFound {
                throw V3ImmutableTransactionRecoveryAnchorError.conflict
            }
            guard status == errSecSuccess else {
                throw V3ImmutableTransactionRecoveryAnchorError
                    .keychainStatus(status)
            }
            return
        }

        guard current != nil else {
            return
        }
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            throw V3ImmutableTransactionRecoveryAnchorError.conflict
        }
        guard status == errSecSuccess else {
            throw V3ImmutableTransactionRecoveryAnchorError
                .keychainStatus(status)
        }
    }

    private func loadWithoutLock(vaultID: String) throws -> Data? {
        var query = try baseQuery(vaultID: vaultID)
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
            throw V3ImmutableTransactionRecoveryAnchorError
                .keychainStatus(
                    status == errSecSuccess ? errSecInternalError : status
                )
        }
        return data
    }

    private func baseQuery(vaultID: String) throws -> [String: Any] {
        guard isValidV3UUID(vaultID),
              !configuration.vaultService.isEmpty,
              let accessGroup = configuration.keychainAccessGroup,
              !accessGroup.isEmpty
        else {
            throw V3ImmutableTransactionRecoveryAnchorError
                .invalidConfiguration
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String:
                "\(configuration.vaultService).v3-transaction-recovery",
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

private func anchorMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func anchorString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    anchorMember(name, in: object)?.stringValue
}

private func anchorInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    anchorMember(name, in: object)?.integerValue
}
