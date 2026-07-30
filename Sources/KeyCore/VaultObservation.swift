import Foundation

/// Stable process exit codes for CLI automation.
///
/// Human-readable messages may improve over time. These values and the
/// corresponding `KeyServiceErrorCode` values are the compatibility contract
/// for scripts.
public enum KeyExitCode: Int32, Codable, Equatable, Sendable {
    case success = 0
    case failure = 1
    case usage = 2
    case notFound = 3
    case conflict = 4
    case temporarilyUnavailable = 5
    case securityFailure = 6
    case authenticationFailure = 7
    case configurationFailure = 8
}

public enum KeyServiceErrorCode: String, Codable, Equatable, Sendable {
    case invalidUsage = "invalid_usage"
    case invalidEntryName = "invalid_entry_name"
    case invalidSecret = "invalid_secret"
    case entryExists = "entry_exists"
    case entryNotFound = "entry_not_found"
    case invalidSecretFile = "invalid_secret_file"
    case vaultKeyMismatch = "vault_key_mismatch"
    case authenticationUnavailable = "authentication_unavailable"
    case authenticationFailed = "authentication_failed"
    case invalidConfiguration = "invalid_configuration"
    case keychainFailure = "keychain_failure"
    case ioFailure = "io_failure"
    case serviceFailure = "service_failure"
    case operationRefused = "operation_refused"
    case vaultIncomplete = "vault_incomplete"
    case contentConflict = "content_conflict"
    case securityConflict = "security_conflict"
    case rollbackDetected = "rollback_detected"
    case recoveryRequired = "recovery_required"
    case conflictNotFound = "conflict_not_found"
    case conflictVersionNotFound = "conflict_version_not_found"
    case expectedHeadsChanged = "expected_heads_changed"

    public var exitCode: KeyExitCode {
        switch self {
        case .invalidUsage:
            .usage
        case .entryNotFound, .conflictNotFound, .conflictVersionNotFound:
            .notFound
        case .entryExists, .contentConflict, .expectedHeadsChanged:
            .conflict
        case .vaultIncomplete:
            .temporarilyUnavailable
        case .vaultKeyMismatch, .invalidSecretFile, .securityConflict,
            .rollbackDetected, .recoveryRequired:
            .securityFailure
        case .authenticationUnavailable, .authenticationFailed:
            .authenticationFailure
        case .invalidConfiguration:
            .configurationFailure
        case .invalidEntryName, .invalidSecret, .keychainFailure, .ioFailure,
            .serviceFailure, .operationRefused:
            .failure
        }
    }
}

public enum VaultStorageFormat: String, Codable, Equatable, Sendable {
    case version2 = "v2"
    case version3 = "v3"
}

public enum VaultHealth: String, Codable, Equatable, Sendable {
    case ready
    case incomplete
    case contentConflicted = "content_conflicted"
    case securityConflicted = "security_conflicted"
    case rollbackDetected = "rollback_detected"
    case recoveryRequired = "recovery_required"

    public var exitCode: KeyExitCode {
        switch self {
        case .ready:
            .success
        case .incomplete:
            .temporarilyUnavailable
        case .contentConflicted:
            .conflict
        case .securityConflicted, .rollbackDetected, .recoveryRequired:
            .securityFailure
        }
    }
}

public enum VaultIssueCode: String, Codable, Equatable, Sendable {
    case transportUnavailable = "transport_unavailable"
    case referencedObjectUnavailable = "referenced_object_unavailable"
    case invalidReferencedObject = "invalid_referenced_object"
    case resourceLimitExceeded = "resource_limit_exceeded"
    case authorityDiverged = "authority_diverged"
    case ambiguousHistory = "ambiguous_history"
    case revisionRollback = "revision_rollback"
    case conflictingRevision = "conflicting_revision"
    case interruptedTransaction = "interrupted_transaction"
}

public enum VaultEntryCountBasis: String, Codable, Equatable, Sendable {
    case effective
    case lastTrusted = "last_trusted"
}

public struct VaultEntrySummary: Codable, Equatable, Sendable {
    public let count: Int
    public let basis: VaultEntryCountBasis

    public init(count: Int, basis: VaultEntryCountBasis) {
        precondition(count >= 0)
        self.count = count
        self.basis = basis
    }

    public static func effective(_ count: Int) -> VaultEntrySummary {
        VaultEntrySummary(count: count, basis: .effective)
    }

    public static func lastTrusted(_ count: Int) -> VaultEntrySummary {
        VaultEntrySummary(count: count, basis: .lastTrusted)
    }
}

public struct VaultIssue: Codable, Equatable, Sendable {
    public let code: VaultIssueCode
    public let message: String

    public init(code: VaultIssueCode, message: String) {
        self.code = code
        self.message = message
    }
}

/// One read-only snapshot of the vault state visible to the helper.
///
/// It intentionally contains no secret values, vault keys, wrapped keys, or
/// device attribution that cannot be authenticated by the current format.
public struct VaultStatus: Codable, Equatable, Sendable {
    public let format: VaultStorageFormat
    public let health: VaultHealth
    public let entries: VaultEntrySummary
    public let conflictCount: Int
    public let trustedVersionID: String?
    public let issues: [VaultIssue]

    public var entryCount: Int {
        entries.count
    }

    public init(
        format: VaultStorageFormat,
        health: VaultHealth,
        entries: VaultEntrySummary,
        conflictCount: Int = 0,
        trustedVersionID: String? = nil,
        issues: [VaultIssue] = []
    ) {
        precondition(conflictCount >= 0)
        self.format = format
        self.health = health
        self.entries = entries
        self.conflictCount = conflictCount
        self.trustedVersionID = trustedVersionID
        self.issues = issues
    }
}

public enum VaultConflictKind: String, Codable, Equatable, Sendable {
    case concurrentCreation = "concurrent_creation"
    case editEdit = "edit_edit"
    case deleteEdit = "delete_edit"
    case renameEdit = "rename_edit"
    case conflictingRename = "conflicting_rename"
    case destinationCollision = "destination_collision"
    case revisionRollback = "revision_rollback"
    case conflictingRevision = "conflicting_revision"
}

enum VaultConflictResolutionPolicy: Equatable, Sendable {
    case chooseVersion
    case recoveryRequired
}

extension VaultConflictKind {
    var resolutionPolicy: VaultConflictResolutionPolicy {
        switch self {
        case .revisionRollback:
            .recoveryRequired
        case .concurrentCreation, .editEdit, .deleteEdit, .renameEdit,
            .conflictingRename, .destinationCollision, .conflictingRevision:
            .chooseVersion
        }
    }
}

public struct VaultConflictSummary: Codable, Equatable, Sendable {
    public let id: String
    public let entryName: String?
    public let kind: VaultConflictKind
    public let versionCount: Int

    public init(
        id: String,
        entryName: String?,
        kind: VaultConflictKind,
        versionCount: Int
    ) {
        precondition(versionCount > 0)
        self.id = id
        self.entryName = entryName
        self.kind = kind
        self.versionCount = versionCount
    }
}

/// One authenticated head's value for a conflict.
///
/// `entryName == nil` represents deletion. The short version ID is only an
/// address within the exact conflict snapshot identified by its conflict ID.
public struct VaultConflictVersion: Codable, Equatable, Sendable {
    public let id: String
    public let entryName: String?
    public let entryType: SecretEntryType?
    public let revision: UInt64?
    public let previouslyTrustedOnThisMac: Bool

    public init(
        id: String,
        entryName: String?,
        entryType: SecretEntryType?,
        revision: UInt64?,
        previouslyTrustedOnThisMac: Bool
    ) {
        self.id = id
        self.entryName = entryName
        self.entryType = entryType
        self.revision = revision
        self.previouslyTrustedOnThisMac = previouslyTrustedOnThisMac
    }
}

public struct VaultConflictDetail: Codable, Equatable, Sendable {
    public let summary: VaultConflictSummary
    public let versions: [VaultConflictVersion]

    public init(
        summary: VaultConflictSummary,
        versions: [VaultConflictVersion]
    ) {
        precondition(!versions.isEmpty)
        self.summary = summary
        self.versions = versions
    }
}

public struct VaultConflictResolution: Codable, Equatable, Sendable {
    public let conflictID: String
    public let versionID: String

    public init(conflictID: String, versionID: String) {
        self.conflictID = conflictID
        self.versionID = versionID
    }
}

enum VaultUXServiceError: Error, Equatable, LocalizedError {
    case vaultIncomplete
    case contentConflict
    case securityConflict
    case rollbackDetected
    case recoveryRequired
    case conflictNotFound
    case conflictVersionNotFound
    case expectedHeadsChanged
    case unavailableForCurrentFormat

    var errorDescription: String? {
        switch self {
        case .vaultIncomplete:
            "Newer vault files are not available yet. Wait for the file provider and retry, or use --allow-stale for an explicit read of the last complete version."
        case .contentConflict:
            "That entry has multiple authenticated versions. Use `key conflict show` and select a version explicitly."
        case .securityConflict:
            "Authenticated vault versions disagree about authority. Key will not choose one automatically."
        case .rollbackDetected:
            "An authenticated branch moves an entry to an older revision. Key will not accept the rollback."
        case .recoveryRequired:
            "The vault requires recovery before this operation can continue."
        case .conflictNotFound:
            "That conflict is no longer present. Run `key conflict list` again."
        case .conflictVersionNotFound:
            "That conflict version is no longer present. Run `key conflict show` again."
        case .expectedHeadsChanged:
            "The vault changed after you reviewed the conflict. No resolution was applied; review the current conflicts and try again."
        case .unavailableForCurrentFormat:
            "Conflict commands are available only when a version 3 vault has an unresolved content conflict."
        }
    }
}

protocol VaultUXServicing {
    func status() throws -> VaultStatus
    func authorizeRead(name: String, allowStale: Bool) throws
    func authorizeMutation() throws
    func conflicts() throws -> [VaultConflictSummary]
    func conflict(id: String) throws -> VaultConflictDetail
    func conflictValue(id: String, versionID: String) throws -> String
    func resolve(_ resolutions: [VaultConflictResolution]) throws
}

struct V2VaultUXService: VaultUXServicing {
    let entryStore: EntryStore

    func status() throws -> VaultStatus {
        VaultStatus(
            format: .version2,
            health: .ready,
            entries: .effective(try entryStore.listEntries().count)
        )
    }

    func conflicts() throws -> [VaultConflictSummary] {
        []
    }

    func authorizeRead(name _: String, allowStale _: Bool) throws {}

    func authorizeMutation() throws {}

    func conflict(id _: String) throws -> VaultConflictDetail {
        throw VaultUXServiceError.unavailableForCurrentFormat
    }

    func conflictValue(
        id _: String,
        versionID _: String
    ) throws -> String {
        throw VaultUXServiceError.unavailableForCurrentFormat
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw VaultUXServiceError.unavailableForCurrentFormat
    }
}
