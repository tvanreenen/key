import CryptoKit
import Foundation

/// Projects authenticated reconciliation conflicts into CLI-safe metadata.
struct V3ConflictObservationBuilder: Sendable {
    func build(
        _ report: V3ContentConflictReport,
        entries: VaultEntrySummary,
        trustedVersionID: String?,
        trustedHeadDigest: Data,
        trustedEntries: Set<V3ManifestEntry>
    ) -> V3VaultUXSnapshot {
        let headIDs = versionIDs(report.heads)
        var details: [VaultConflictDetail] = []
        var selections: [String: V3ConflictSelection] = [:]
        var rollbackFound = false

        for conflict in report.entryConflicts {
            let kind = vaultConflictKind(conflict.kind)
            if conflict.kind == .revisionRollback {
                rollbackFound = true
            }
            let id = conflictID(
                heads: report.heads,
                kind: kind.rawValue,
                subject: conflict.entryID
            )
            let versions = conflict.versions.compactMap { version
                -> VaultConflictVersion? in
                guard let versionID = headIDs[version.head] else {
                    return nil
                }
                return VaultConflictVersion(
                    id: versionID,
                    entryName: version.entry?.name,
                    entryType: version.entry?.type,
                    revision: version.entry?.revision,
                    previouslyTrustedOnThisMac:
                        version.head.envelopeDigest == trustedHeadDigest
                        || version.entry.map(trustedEntries.contains) == true
                )
            }
            let name = conflict.commonAncestorEntry?.name
                ?? conflict.versions.compactMap(\.entry?.name).first
            let summary = VaultConflictSummary(
                id: id,
                entryName: name,
                kind: kind,
                versionCount: versions.count
            )
            details.append(
                VaultConflictDetail(summary: summary, versions: versions)
            )
            selections[id] = V3ConflictSelection(
                entryID: conflict.entryID,
                versions: Dictionary(
                    uniqueKeysWithValues: conflict.versions.compactMap {
                        version in
                        guard let versionID = headIDs[version.head] else {
                            return nil
                        }
                        return (versionID, version.entry)
                    }
                )
            )
        }

        for conflict in report.destinationConflicts {
            let id = conflictID(
                heads: report.heads,
                kind: VaultConflictKind.destinationCollision.rawValue,
                subject: conflict.name
            )
            let versionIDs = uniqueEntryVersionIDs(conflict.entries)
            let versions = conflict.entries.compactMap { entry
                -> VaultConflictVersion? in
                guard let versionID = versionIDs[entry] else {
                    return nil
                }
                return VaultConflictVersion(
                    id: versionID,
                    entryName: entry.name,
                    entryType: entry.type,
                    revision: entry.revision,
                    previouslyTrustedOnThisMac:
                        trustedEntries.contains(entry)
                )
            }
            let summary = VaultConflictSummary(
                id: id,
                entryName: conflict.name,
                kind: .destinationCollision,
                versionCount: versions.count
            )
            details.append(
                VaultConflictDetail(summary: summary, versions: versions)
            )
            selections[id] = V3ConflictSelection(
                entryID: nil,
                versions: Dictionary(
                    uniqueKeysWithValues: conflict.entries.compactMap {
                        entry in
                        guard let versionID = versionIDs[entry] else {
                            return nil
                        }
                        return (versionID, entry)
                    }
                )
            )
        }

        details.sort { $0.summary.id < $1.summary.id }
        let health: VaultHealth = rollbackFound
            ? .rollbackDetected
            : .contentConflicted
        let issues = rollbackFound
            ? [
                VaultIssue(
                    code: .revisionRollback,
                    message: "Vault history would move an entry back to an older revision. Key cannot accept this rollback as an ordinary conflict choice."
                )
            ]
            : []
        return V3VaultUXSnapshot(
            status: VaultStatus(
                format: .version3,
                health: health,
                entries: entries,
                conflictCount: details.count,
                trustedVersionID: trustedVersionID,
                issues: issues
            ),
            conflicts: details,
            expectedHeads: report.heads,
            selections: selections
        )
    }
}

private func vaultConflictKind(
    _ kind: V3EntryConflictKind
) -> VaultConflictKind {
    switch kind {
    case .concurrentCreation:
        .concurrentCreation
    case .editEdit:
        .editEdit
    case .deleteEdit:
        .deleteEdit
    case .renameEdit:
        .renameEdit
    case .conflictingRename:
        .conflictingRename
    case .revisionRollback:
        .revisionRollback
    case .conflictingRevision:
        .conflictingRevision
    }
}

private func versionIDs(
    _ heads: [V3VaultHead]
) -> [V3VaultHead: String] {
    let digests = heads.map(\.envelopeDigest)
    let encoded = digests.map(v3LowercaseHex)
    let length = uniquePrefixLength(encoded)
    return Dictionary(
        uniqueKeysWithValues: zip(heads, encoded).map {
            ($0.0, String($0.1.prefix(length)))
        }
    )
}

private func uniqueEntryVersionIDs(
    _ entries: [V3ManifestEntry]
) -> [V3ManifestEntry: String] {
    let encoded = entries.map(\.ciphertextDigest)
    let length = uniquePrefixLength(encoded)
    return Dictionary(
        uniqueKeysWithValues: zip(entries, encoded).map {
            ($0.0, String($0.1.prefix(length)))
        }
    )
}

private func uniquePrefixLength(_ values: [String]) -> Int {
    guard let maximum = values.map(\.count).max() else {
        return 16
    }
    var length = min(16, maximum)
    while length < maximum {
        let prefixes = values.map { String($0.prefix(length)) }
        if Set(prefixes).count == values.count {
            return length
        }
        length += 2
    }
    return maximum
}

private func conflictID(
    heads: [V3VaultHead],
    kind: String,
    subject: String
) -> String {
    var input = Data("work.tvr.key/v3/conflict-id/v1".utf8)
    input.append(0)
    for head in heads.sorted(by: {
        $0.envelopeDigest.lexicographicallyPrecedes($1.envelopeDigest)
    }) {
        input.append(head.envelopeDigest)
    }
    input.append(0)
    input.append(Data(kind.utf8))
    input.append(0)
    input.append(Data(subject.utf8))
    return "c-" + v3LowercaseHex(Data(SHA256.hash(data: input)))
}
