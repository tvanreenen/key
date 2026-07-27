import Foundation
import JSONCanonicalization

public enum V3EntryAuthenticationContextError: Error, Equatable, LocalizedError {
    case invalidVaultID
    case invalidEntryID
    case invalidName
    case invalidKeyEpoch
    case invalidRevision

    public var errorDescription: String? {
        switch self {
        case .invalidVaultID:
            "The version 3 entry context has an invalid vault ID."
        case .invalidEntryID:
            "The version 3 entry context has an invalid entry ID."
        case .invalidName:
            "The version 3 entry context has an invalid entry name."
        case .invalidKeyEpoch:
            "The version 3 entry context has an invalid key epoch."
        case .invalidRevision:
            "The version 3 entry context has an invalid revision."
        }
    }
}

/// Immutable identity metadata authenticated alongside a version 3 entry.
///
/// Construct opening contexts only from an authenticated manifest. Creating a
/// context validates its representation but does not establish that its values
/// are trusted.
public struct V3EntryAuthenticationContext: Equatable, Sendable {
    private static let domain = "work.tvr.key/v3/entry-aad"

    public let vaultID: String
    public let entryID: String
    public let name: String
    public let type: SecretEntryType
    public let keyEpoch: UInt64
    public let revision: UInt64

    public init(
        vaultID: String,
        entryID: String,
        name: String,
        type: SecretEntryType,
        keyEpoch: UInt64,
        revision: UInt64
    ) throws {
        guard isValidV3UUID(vaultID) else {
            throw V3EntryAuthenticationContextError.invalidVaultID
        }
        guard isValidV3UUID(entryID) else {
            throw V3EntryAuthenticationContextError.invalidEntryID
        }
        guard isValidV3EntryName(name) else {
            throw V3EntryAuthenticationContextError.invalidName
        }
        guard keyEpoch <= v3MaximumSafeInteger else {
            throw V3EntryAuthenticationContextError.invalidKeyEpoch
        }
        guard revision > 0, revision <= v3MaximumSafeInteger else {
            throw V3EntryAuthenticationContextError.invalidRevision
        }

        self.vaultID = vaultID
        self.entryID = entryID
        self.name = name
        self.type = type
        self.keyEpoch = keyEpoch
        self.revision = revision
    }

    public init(vaultID: String, entry: V3ManifestEntry) throws {
        try self.init(
            vaultID: vaultID,
            entryID: entry.entryID,
            name: entry.name,
            type: entry.type,
            keyEpoch: entry.keyEpoch,
            revision: entry.revision
        )
    }

    /// The canonical JSON bytes for the duplicated entry identity fields.
    public var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            ("format", .string("key-vault-entry")),
            ("version", .integer(3)),
            ("vaultID", .string(vaultID)),
            ("entryID", .string(entryID)),
            ("name", .string(name)),
            ("type", .string(type.rawValue)),
            ("keyEpoch", .integer(keyEpoch)),
            ("revision", .integer(revision))
        ]))
    }

    /// The exact bytes that version 3 AES-GCM sealing and opening must use.
    public var associatedData: Data {
        var result = Data(Self.domain.utf8)
        result.append(0)
        result.append(canonicalBytes)
        return result
    }
}
