import Foundation

struct V3ResolvedConflictSelection: Equatable, Sendable {
    let conflictID: String
    let entryID: String?
    let selectedEntry: V3ManifestEntry?
}

struct V3ConflictResolutionPlan: Equatable, Sendable {
    let selections: [V3ResolvedConflictSelection]
    let expectedHeads: [V3VaultHead]
}

/// Converts one complete, freshly observed CLI choice set into internal
/// authenticated selectors. It performs no decryption or publication.
struct V3ConflictResolutionPlanner: Sendable {
    func plan(
        _ resolutions: [VaultConflictResolution],
        snapshot: V3VaultUXSnapshot
    ) throws -> V3ConflictResolutionPlan {
        guard snapshot.conflicts.allSatisfy({
            $0.summary.kind.resolutionPolicy == .chooseVersion
        }) else {
            throw AppError.operationRefused(
                "A revision rollback cannot be accepted as an ordinary content resolution."
            )
        }
        guard snapshot.status.health == .contentConflicted else {
            throw VaultUXServiceError.expectedHeadsChanged
        }

        let resolutionIDs = resolutions.map(\.conflictID)
        guard Set(resolutionIDs).count == resolutions.count,
              Set(resolutionIDs) == Set(snapshot.selections.keys)
        else {
            throw AppError.operationRefused(
                "Resolve every current conflict exactly once. Run `key conflict list` and provide one <conflict-id>=<version-id> choice for each result."
            )
        }

        let selected = try resolutions.map { resolution in
            guard let selection = snapshot.selections[
                resolution.conflictID
            ] else {
                throw VaultUXServiceError.expectedHeadsChanged
            }
            guard let entry = selection.versions[resolution.versionID] else {
                throw VaultUXServiceError.conflictVersionNotFound
            }
            return V3ResolvedConflictSelection(
                conflictID: resolution.conflictID,
                entryID: selection.entryID,
                selectedEntry: entry
            )
        }
        return V3ConflictResolutionPlan(
            selections: selected,
            expectedHeads: snapshot.expectedHeads
        )
    }
}

/// Binds CLI conflict actions to a freshly authenticated repository snapshot.
///
/// The service never keeps a mutable "current conflict" token. Every command
/// observes again, and conflict IDs include the exact authenticated head set.
/// If synchronized history changes after review, the old IDs no longer match
/// and resolution fails without publishing anything.
struct V3VaultUXService: VaultUXServicing {
    typealias SnapshotProvider = @Sendable () throws -> V3VaultUXSnapshot
    typealias ValueReader = @Sendable (
        _ entry: V3ManifestEntry,
        _ expectedHeads: [V3VaultHead]
    ) throws -> String
    typealias ResolutionPublisher = @Sendable (
        _ selections: [V3ResolvedConflictSelection],
        _ expectedHeads: [V3VaultHead]
    ) throws -> Void

    private let snapshotProvider: SnapshotProvider
    private let valueReader: ValueReader
    private let resolutionPublisher: ResolutionPublisher

    init(
        snapshotProvider: @escaping SnapshotProvider,
        valueReader: @escaping ValueReader,
        resolutionPublisher: @escaping ResolutionPublisher
    ) {
        self.snapshotProvider = snapshotProvider
        self.valueReader = valueReader
        self.resolutionPublisher = resolutionPublisher
    }

    func status() throws -> VaultStatus {
        try snapshotProvider().status
    }

    func authorizeRead(
        name: String,
        allowStale: Bool
    ) throws {
        let snapshot = try snapshotProvider()
        switch snapshot.status.health {
        case .ready:
            return
        case .incomplete:
            guard allowStale else {
                throw VaultUXServiceError.vaultIncomplete
            }
        case .contentConflicted:
            let isConflicted = snapshot.conflicts.contains { conflict in
                conflict.summary.entryName == name
                    || conflict.versions.contains {
                        $0.entryName == name
                    }
            }
            guard !isConflicted else {
                throw VaultUXServiceError.contentConflict
            }
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .rollbackDetected:
            throw VaultUXServiceError.rollbackDetected
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    func authorizeMutation() throws {
        switch try snapshotProvider().status.health {
        case .ready:
            return
        case .incomplete:
            throw VaultUXServiceError.vaultIncomplete
        case .contentConflicted:
            throw VaultUXServiceError.contentConflict
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .rollbackDetected:
            throw VaultUXServiceError.rollbackDetected
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    func conflicts() throws -> [VaultConflictSummary] {
        try snapshotProvider().conflicts.map(\.summary)
    }

    func conflict(id: String) throws -> VaultConflictDetail {
        guard let conflict = try snapshotProvider().conflicts.first(
            where: { $0.summary.id == id }
        ) else {
            throw VaultUXServiceError.conflictNotFound
        }
        return conflict
    }

    func conflictValue(
        id: String,
        versionID: String
    ) throws -> String {
        let snapshot = try snapshotProvider()
        guard let selection = snapshot.selections[id] else {
            throw VaultUXServiceError.conflictNotFound
        }
        guard let stored = selection.versions[versionID] else {
            throw VaultUXServiceError.conflictVersionNotFound
        }
        guard let entry = stored else {
            throw AppError.operationRefused(
                "That authenticated version deleted the entry and has no secret value to read."
            )
        }
        return try valueReader(entry, snapshot.expectedHeads)
    }

    func resolve(
        _ resolutions: [VaultConflictResolution]
    ) throws {
        let snapshot = try snapshotProvider()
        let plan = try V3ConflictResolutionPlanner().plan(
            resolutions,
            snapshot: snapshot
        )
        try resolutionPublisher(plan.selections, plan.expectedHeads)
    }
}
