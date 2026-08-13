import Foundation

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

enum VaultUXServiceError: Error, Equatable, LocalizedError {
    case vaultIncomplete
    case contentConflict
    case catchUpContentConflict
    case securityConflict
    case rollbackDetected
    case recoveryRequired
    case deviceIdentityUnavailable
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
        case .catchUpContentConflict:
            "Authenticated newer vault history has competing content versions. Key will not choose one automatically. Normal writes are paused; use --allow-stale only for an explicit read of the version already trusted on this Mac."
        case .securityConflict:
            "Authenticated vault versions disagree about authority. Key will not choose one automatically."
        case .rollbackDetected:
            "An authenticated branch moves an entry to an older revision. Key will not accept the rollback."
        case .recoveryRequired:
            "The vault requires recovery before this operation can continue."
        case .deviceIdentityUnavailable:
            "This Mac has no usable enrolled device identity for this vault. Use a surviving enrolled Mac to enroll this Mac again. If no enrolled Mac survives, the vault is permanently inaccessible; synchronized vault files alone cannot recover it."
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

/// Supplies vault policy and conflict operations to concurrent helper requests.
///
/// Conforming types must make every requirement safe for simultaneous calls.
protocol VaultUXServicing: Sendable {
    func status() throws -> VaultStatus
    func authorizeRead(name: String, allowStale: Bool) throws
    func authorizeMutation() throws
    func conflicts() throws -> [VaultConflictSummary]
    func conflict(id: String) throws -> VaultConflictDetail
    func conflictValue(id: String, versionID: String) throws -> String
    func resolve(_ resolutions: [VaultConflictResolution]) throws
}

/// Version 2 has no graph state or conflicts, so its policy is always ready.
///
/// The lock documents and enforces this adapter's `Sendable` guarantee even
/// though the existing `EntryStore` predates Swift concurrency annotations.
final class V2VaultUXService: VaultUXServicing, @unchecked Sendable {
    private let lock = NSLock()
    private let entryStore: EntryStore

    init(entryStore: EntryStore) {
        self.entryStore = entryStore
    }

    func status() throws -> VaultStatus {
        try lock.withLock {
            VaultStatus(
                format: .version2,
                health: .ready,
                entries: .effective(try entryStore.listEntries().count)
            )
        }
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
