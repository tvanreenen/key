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

/// Stable semantic failure codes returned across the service boundary.
///
/// Scripts should use these values instead of matching human-readable errors.
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

/// The on-disk format represented by a vault observation.
public enum VaultStorageFormat: String, Codable, Equatable, Sendable {
    case version2 = "v2"
    case version3 = "v3"
}

/// The safety state that governs reads, mutations, and process exit status.
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

/// A stable machine-readable explanation for a non-ready vault state.
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

/// Identifies which authenticated state an entry total describes.
public enum VaultEntryCountBasis: String, Codable, Equatable, Sendable {
    case effective
    case lastTrusted = "last_trusted"
}

/// An entry total paired with the authenticated state used to calculate it.
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

    private enum CodingKeys: String, CodingKey {
        case count
        case basis
    }
}

/// A stable issue code accompanied by a human-readable explanation.
public struct VaultIssue: Codable, Equatable, Sendable {
    public let code: VaultIssueCode
    public let message: String

    public init(code: VaultIssueCode, message: String) {
        self.code = code
        self.message = message
    }

    private enum CodingKeys: String, CodingKey {
        case code
        case message
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

    private enum CodingKeys: String, CodingKey {
        case format
        case health
        case entries
        case conflictCount
        case trustedVersionID
        case issues
    }
}

/// Authenticated, non-secret metadata for one device recorded by a v3 vault.
public struct V3VaultDeviceSummary: Codable, Equatable, Sendable {
    public let deviceID: String
    public let displayName: String
    public let role: V3DeviceRole
    public let status: V3DeviceStatus

    public init(
        deviceID: String,
        displayName: String,
        role: V3DeviceRole,
        status: V3DeviceStatus
    ) {
        self.deviceID = deviceID
        self.displayName = displayName
        self.role = role
        self.status = status
    }

    private enum CodingKeys: String, CodingKey {
        case deviceID
        case displayName
        case role
        case status
    }
}

/// Device membership from one exact authenticated vault state.
///
/// `currentDeviceID` comes from device-local enrollment metadata. It labels
/// this Mac for the user but never contributes vault authority.
public struct V3VaultDeviceInventory: Codable, Equatable, Sendable {
    public let vaultID: String
    public let mode: V3VaultMode
    public let currentDeviceID: String?
    public let devices: [V3VaultDeviceSummary]

    public init(
        vaultID: String,
        mode: V3VaultMode,
        currentDeviceID: String?,
        devices: [V3VaultDeviceSummary]
    ) {
        self.vaultID = vaultID
        self.mode = mode
        self.currentDeviceID = currentDeviceID
        self.devices = devices
    }

    private enum CodingKeys: String, CodingKey {
        case vaultID
        case mode
        case currentDeviceID
        case devices
    }
}

/// The authenticated ambiguity that requires inspection or recovery.
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

/// CLI-safe metadata describing one unresolved authenticated conflict.
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

    private enum CodingKeys: String, CodingKey {
        case id
        case entryName
        case kind
        case versionCount
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

    private enum CodingKeys: String, CodingKey {
        case id
        case entryName
        case entryType
        case revision
        case previouslyTrustedOnThisMac
    }
}

/// Every authenticated version available for one conflict.
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

    private enum CodingKeys: String, CodingKey {
        case summary
        case versions
    }
}

/// One explicit version choice for one current conflict.
public struct VaultConflictResolution: Codable, Equatable, Sendable {
    public let conflictID: String
    public let versionID: String

    public init(conflictID: String, versionID: String) {
        self.conflictID = conflictID
        self.versionID = versionID
    }

    private enum CodingKeys: String, CodingKey {
        case conflictID
        case versionID
    }
}
