import CryptoKit
import Foundation

/// CLI-safe projection of one authenticated repository observation.
///
/// The snapshot retains internal selectors for later reads and resolution, but
/// its public status and conflict values contain no ciphertext, keys, wrapped
/// keys, or unauthenticated device attribution.
struct V3VaultUXSnapshot: Equatable, Sendable {
    let status: VaultStatus
    let conflicts: [VaultConflictDetail]
    let expectedHeads: [V3VaultHead]
    let selections: [String: V3ConflictSelection]
}

struct V3ConflictSelection: Equatable, Sendable {
    let entryID: String?
    let versions: [String: V3ManifestEntry?]
}

struct V3VaultObservationBuilder: Sendable {
    private let reconciler: V3ManifestReconciler

    init(reconciler: V3ManifestReconciler = V3ManifestReconciler()) {
        self.reconciler = reconciler
    }

    func build(
        _ classification: V3VaultRepositoryClassification
    ) throws -> V3VaultUXSnapshot {
        let trustedVersionID = classification.ancestryProof.map {
            String(
                v3LowercaseHex($0.checkpoint.envelopeDigest).prefix(16)
            )
        }
        let entryCount = checkpointEntryCount(
            classification.ancestryProof
        )

        switch classification.status {
        case .ready:
            return snapshot(
                health: .ready,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: [],
                heads: classification.heads
            )
        case .incomplete:
            return snapshot(
                health: .incomplete,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: classification.issues.map(vaultIssue),
                heads: classification.heads
            )
        case .securityConflicted:
            return snapshot(
                health: .securityConflicted,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: [
                    VaultIssue(
                        code: .authorityDiverged,
                        message: "Authenticated versions disagree about vault authority. Key will not select one automatically."
                    )
                ],
                heads: classification.heads
            )
        case .recoveryRequired:
            return snapshot(
                health: .recoveryRequired,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: classification.issues.map(vaultIssue),
                heads: classification.heads
            )
        case .contentConflicted:
            guard let proof = classification.ancestryProof else {
                return snapshot(
                    health: .recoveryRequired,
                    entryCount: entryCount,
                    trustedVersionID: trustedVersionID,
                    issues: [
                        VaultIssue(
                            code: .invalidReferencedObject,
                            message: "Authenticated conflict details are unavailable."
                        )
                    ],
                    heads: classification.heads
                )
            }
            return try buildReconciliationSnapshot(
                proof: proof,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                trustedEntries: checkpointEntries(proof)
            )
        }
    }

    private func buildReconciliationSnapshot(
        proof: V3ManifestAncestryProof,
        entryCount: Int,
        trustedVersionID: String?,
        trustedEntries: Set<V3ManifestEntry>
    ) throws -> V3VaultUXSnapshot {
        let expectedHeads = try proof.heads.map(V3VaultHead.init)
        switch try reconciler.reconcile(proof) {
        case .noMergeRequired:
            return snapshot(
                health: .ready,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: [],
                heads: expectedHeads
            )
        case .automaticMerge:
            return snapshot(
                health: .ready,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: [],
                heads: expectedHeads
            )
        case let .securityConflict(heads):
            return snapshot(
                health: .securityConflicted,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: [
                    VaultIssue(
                        code: .authorityDiverged,
                        message: "Authenticated versions disagree about vault authority. Key will not select one automatically."
                    )
                ],
                heads: heads
            )
        case .historyConflict:
            return snapshot(
                health: .recoveryRequired,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: [
                    VaultIssue(
                        code: .ambiguousHistory,
                        message: "Authenticated history has more than one nearest common ancestor. Key will not guess which history to merge."
                    )
                ],
                heads: expectedHeads
            )
        case let .contentConflict(report):
            return contentConflictSnapshot(
                report,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                trustedHeadDigest: proof.checkpoint.envelopeDigest,
                trustedEntries: trustedEntries
            )
        }
    }

    private func contentConflictSnapshot(
        _ report: V3ContentConflictReport,
        entryCount: Int,
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
                    message: "At least one authenticated branch moves an entry to an older revision. Key will not resolve a rollback as an ordinary content choice."
                )
            ]
            : []
        return V3VaultUXSnapshot(
            status: VaultStatus(
                format: .version3,
                health: health,
                entryCount: entryCount,
                conflictCount: details.count,
                trustedVersionID: trustedVersionID,
                issues: issues
            ),
            conflicts: details,
            expectedHeads: report.heads,
            selections: selections
        )
    }

    private func snapshot(
        health: VaultHealth,
        entryCount: Int,
        trustedVersionID: String?,
        issues: [VaultIssue],
        heads: [V3VaultHead]
    ) -> V3VaultUXSnapshot {
        V3VaultUXSnapshot(
            status: VaultStatus(
                format: .version3,
                health: health,
                entryCount: entryCount,
                trustedVersionID: trustedVersionID,
                issues: issues
            ),
            conflicts: [],
            expectedHeads: heads,
            selections: [:]
        )
    }
}

private func checkpointEntryCount(
    _ proof: V3ManifestAncestryProof?
) -> Int {
    checkpointEntries(proof).count
}

private func checkpointEntries(
    _ proof: V3ManifestAncestryProof?
) -> Set<V3ManifestEntry> {
    guard let proof,
          let manifest = proof.manifests.first(where: {
              $0.envelopeDigest == proof.checkpoint.envelopeDigest
          })
    else {
        return []
    }
    return Set(manifest.envelope.content.manifest.entries)
}

private func vaultIssue(
    _ issue: V3VaultRepositoryIssue
) -> VaultIssue {
    switch issue {
    case .manifestDirectoryUnavailable:
        VaultIssue(
            code: .transportUnavailable,
            message: "The manifest directory is not available yet."
        )
    case .manifestUnavailable:
        VaultIssue(
            code: .referencedObjectUnavailable,
            message: "A referenced manifest is not available yet."
        )
    case .entryUnavailable:
        VaultIssue(
            code: .referencedObjectUnavailable,
            message: "A referenced encrypted entry is not available yet."
        )
    case .invalidReferencedObject:
        VaultIssue(
            code: .invalidReferencedObject,
            message: "A referenced immutable object failed validation."
        )
    case .resourceLimitExceeded:
        VaultIssue(
            code: .resourceLimitExceeded,
            message: "Repository inspection exceeded a safety limit."
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
