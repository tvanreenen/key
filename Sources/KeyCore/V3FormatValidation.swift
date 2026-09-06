import CryptoKit
import Foundation

let v3MaximumSafeInteger: UInt64 = 9_007_199_254_740_991

public enum V3VaultKeyIDError: Error, Equatable, LocalizedError {
    case invalidVaultID
    case invalidVaultKey
    case invalidEncoding

    public var errorDescription: String? {
        switch self {
        case .invalidVaultID:
            "A version 3 vault-key ID requires a canonical vault UUID."
        case .invalidVaultKey:
            "A version 3 vault-key ID requires a 32-byte vault key."
        case .invalidEncoding:
            "A version 3 vault-key ID must be a canonical base64url-encoded 32-byte value."
        }
    }
}

/// Vault-scoped, non-secret identity of one exact version 3 vault key.
///
/// The identifier is a domain-separated HKDF-SHA256 output. It can be stored
/// in authenticated metadata without disclosing the vault key.
public struct V3VaultKeyID: Equatable, Hashable, Sendable {
    private static let derivationInfo = Data("work.tvr.key/v3/vault-key-id".utf8)

    public let rawValue: String

    public init(rawValue: String) throws {
        guard let bytes = Base64URL.decodeCanonical(rawValue),
              bytes.count == 32
        else {
            throw V3VaultKeyIDError.invalidEncoding
        }
        self.rawValue = rawValue
    }

    public static func derive(
        vaultKey: Data,
        vaultID: String
    ) throws -> V3VaultKeyID {
        guard vaultKey.count == 32 else {
            throw V3VaultKeyIDError.invalidVaultKey
        }
        guard let salt = v3UUIDBytes(vaultID) else {
            throw V3VaultKeyIDError.invalidVaultID
        }
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: vaultKey),
            salt: salt,
            info: derivationInfo,
            outputByteCount: 32
        )
        let bytes = derived.withUnsafeBytes { Data($0) }
        return try V3VaultKeyID(rawValue: Base64URL.encode(bytes))
    }
}

func isValidV3UUID(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard bytes.count == 36,
          bytes.enumerated().allSatisfy({ index, byte in
              if [8, 13, 18, 23].contains(index) {
                  return byte == UInt8(ascii: "-")
              }
              return (byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9"))
                  || (byte >= UInt8(ascii: "a") && byte <= UInt8(ascii: "f"))
          })
    else {
        return false
    }
    return UUID(uuidString: value) != nil
}

func v3UUIDBytes(_ value: String) -> Data? {
    guard isValidV3UUID(value) else {
        return nil
    }
    let compact = value.replacingOccurrences(of: "-", with: "")
    var bytes = Data()
    bytes.reserveCapacity(16)
    var index = compact.startIndex
    for _ in 0..<16 {
        let next = compact.index(index, offsetBy: 2)
        guard let byte = UInt8(compact[index..<next], radix: 16) else {
            return nil
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}

func isValidV3EntryName(_ name: String) -> Bool {
    let utf8 = Data(name.utf8)
    let segments = name.split(separator: "/", omittingEmptySubsequences: false)
    return !name.isEmpty
        && name.unicodeScalars.count <= 1_024
        && utf8.count <= 1_024
        && utf8 == Data(name.precomposedStringWithCanonicalMapping.utf8)
        && name.first != "/"
        && name.last != "/"
        && !name.contains("\\")
        && !name.unicodeScalars.contains(where: isV3ControlCharacter)
        && !hasLeadingOrTrailingWhitespace(name)
        && segments.allSatisfy({
            !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255
        })
}

func normalizedV3EntryName(_ name: String) throws -> String {
    let normalized = name.precomposedStringWithCanonicalMapping
    guard isValidV3EntryName(normalized) else {
        throw AppError.invalidEntryName(
            "Entry name '\(name)' is invalid. Use a name like github/personal: no leading or trailing whitespace or slashes, backslashes, control characters, or empty, '.' or '..' path parts. Names can use up to 1,024 UTF-8 bytes, with up to 255 bytes per path part."
        )
    }
    return normalized
}

func v3ManifestEntryPrecedes(
    _ lhs: V3ManifestEntry,
    _ rhs: V3ManifestEntry
) -> Bool {
    let lhsName = Data(lhs.name.utf8)
    let rhsName = Data(rhs.name.utf8)
    return lhsName.lexicographicallyPrecedes(rhsName)
        || (lhsName == rhsName
            && Data(lhs.entryID.utf8).lexicographicallyPrecedes(
                Data(rhs.entryID.utf8)
            ))
}

func isV3ControlCharacter(_ scalar: UnicodeScalar) -> Bool {
    scalar.value <= 0x1F || (0x7F...0x9F).contains(scalar.value)
}

func isValidV3DeviceDisplayName(_ name: String) -> Bool {
    !name.isEmpty
        && name.unicodeScalars.count <= 128
        && Data(name.utf8)
            == Data(name.precomposedStringWithCanonicalMapping.utf8)
        && !name.unicodeScalars.contains(where: isV3ControlCharacter)
}

private func hasLeadingOrTrailingWhitespace(_ value: String) -> Bool {
    guard let first = value.unicodeScalars.first,
          let last = value.unicodeScalars.last
    else {
        return false
    }
    return CharacterSet.whitespacesAndNewlines.contains(first)
        || CharacterSet.whitespacesAndNewlines.contains(last)
}
