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
    case deviceRevoked
    case conflictNotFound
    case conflictVersionNotFound
    case expectedHeadsChanged
    case unavailableForCurrentFormat

    var errorDescription: String? {
        switch self {
        case .vaultIncomplete:
            "Some newer vault files are unavailable on this Mac. Check file synchronization before retrying. To read the last complete version already verified on this Mac, use --allow-stale; the value may be out of date."
        case .contentConflict:
            "That entry has conflicting changes. Run `key conflict list`, then `key conflict show <conflict-id>` to review the versions."
        case .catchUpContentConflict:
            "Newer vault history contains competing edits. Saving changes is paused because Key cannot choose between them safely. Use --allow-stale only if you want to read the last complete version already verified on this Mac; it may be out of date."
        case .securityConflict:
            "Vault history contains conflicting changes to device access or encryption keys. Key cannot safely choose between them. Keep vault files and local records intact for investigation."
        case .rollbackDetected:
            "Vault history would move an entry back to an older revision. Key has blocked this rollback. Run `key status --verbose` to inspect the problem; keep vault files and local records intact."
        case .recoveryRequired:
            "Key cannot safely continue with the available vault state. Keep vault files and local records intact for investigation. Do not delete them or run init to bypass this check."
        case .deviceIdentityUnavailable:
            "This Mac no longer has usable access credentials for this vault. A Mac that still has access must invite it again; see `key help share`. If no enrolled Mac survives, the vault is permanently inaccessible. The vault folder alone cannot restore access."
        case .deviceRevoked:
            "This Mac's access to the vault was removed. A Mac that still has access must invite it again; see `key help share`."
        case .conflictNotFound:
            "That conflict is no longer present. Run `key conflict list` again."
        case .conflictVersionNotFound:
            "That version is no longer part of the conflict. Run `key conflict list`, then review it again with `key conflict show <conflict-id>`."
        case .expectedHeadsChanged:
            "The vault changed after you reviewed the conflict. No resolution was applied; review the current conflicts and try again."
        case .unavailableForCurrentFormat:
            "Conflict resolution is available only for unresolved entry conflicts in a device-enrolled vault."
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
