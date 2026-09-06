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
        _ classification: V3VaultRepositoryClassification,
        trustedCurrent: V3TrustedManifest
    ) throws -> V3VaultUXSnapshot {
        if let proof = classification.ancestryProof {
            guard proof.checkpoint == trustedCurrent.checkpoint else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
        }
        let trustedVersionID = String(
            v3LowercaseHex(
                trustedCurrent.checkpoint.envelopeDigest
            ).prefix(16)
        )
        let trustedEntries = Set(
            trustedCurrent.envelope.content.manifest.entries
        )
        let lastTrustedEntries = VaultEntrySummary.lastTrusted(
            trustedEntries.count
        )

        switch classification.status {
        case .ready:
            return snapshot(
                health: .ready,
                entries: .effective(
                    try readyEntryCount(classification.ancestryProof)
                ),
                trustedVersionID: trustedVersionID,
                issues: [],
                heads: classification.heads
            )
        case .incomplete:
            return snapshot(
                health: .incomplete,
                entries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                issues: classification.issues.map(vaultIssue),
                heads: classification.heads
            )
        case .securityConflicted:
            return snapshot(
                health: .securityConflicted,
                entries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                issues: [
                    VaultIssue(
                        code: .authorityDiverged,
                        message: "Vault history contains conflicting changes to device access or encryption keys. Key cannot safely choose between them."
                    )
                ],
                heads: classification.heads
            )
        case .recoveryRequired:
            return snapshot(
                health: .recoveryRequired,
                entries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                issues: classification.issues.map(vaultIssue),
                heads: classification.heads
            )
        case .contentConflicted:
            guard let proof = classification.ancestryProof else {
                return snapshot(
                    health: .recoveryRequired,
                    entries: lastTrustedEntries,
                    trustedVersionID: trustedVersionID,
                    issues: [
                        VaultIssue(
                            code: .invalidReferencedObject,
                            message: "Key could not verify the details of these conflicts."
                        )
                    ],
                    heads: classification.heads
                )
            }
            return try buildReconciliationSnapshot(
                proof: proof,
                lastTrustedEntries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                trustedEntries: trustedEntries
            )
        }
    }

    private func buildReconciliationSnapshot(
        proof: V3ManifestAncestryProof,
        lastTrustedEntries: VaultEntrySummary,
        trustedVersionID: String?,
        trustedEntries: Set<V3ManifestEntry>
    ) throws -> V3VaultUXSnapshot {
        let expectedHeads = try proof.heads.map(V3VaultHead.init)
        switch try reconciler.reconcile(proof) {
        case let .noMergeRequired(head):
            return snapshot(
                health: .ready,
                entries: .effective(
                    try entryCount(for: head, in: proof)
                ),
                trustedVersionID: trustedVersionID,
                issues: [],
                heads: expectedHeads
            )
        case let .automaticMerge(plan):
            return snapshot(
                health: .ready,
                entries: .effective(
                    plan.content.manifest.entries.count
                ),
                trustedVersionID: trustedVersionID,
                issues: [],
                heads: expectedHeads
            )
        case let .securityConflict(heads):
            return snapshot(
                health: .securityConflicted,
                entries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                issues: [
                    VaultIssue(
                        code: .authorityDiverged,
                        message: "Vault history contains conflicting changes to device access or encryption keys. Key cannot safely choose between them."
                    )
                ],
                heads: heads
            )
        case .historyConflict:
            return snapshot(
                health: .recoveryRequired,
                entries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                issues: [
                    VaultIssue(
                        code: .ambiguousHistory,
                        message: "Key found more than one possible shared starting point for these changes. It cannot safely combine their histories."
                    )
                ],
                heads: expectedHeads
            )
        case let .contentConflict(report):
            return V3ConflictObservationBuilder().build(
                report,
                entries: lastTrustedEntries,
                trustedVersionID: trustedVersionID,
                trustedHeadDigest: proof.checkpoint.envelopeDigest,
                trustedEntries: trustedEntries
            )
        }
    }

    private func snapshot(
        health: VaultHealth,
        entries: VaultEntrySummary,
        trustedVersionID: String?,
        issues: [VaultIssue],
        heads: [V3VaultHead]
    ) -> V3VaultUXSnapshot {
        V3VaultUXSnapshot(
            status: VaultStatus(
                format: .version3,
                health: health,
                entries: entries,
                trustedVersionID: trustedVersionID,
                issues: issues
            ),
            conflicts: [],
            expectedHeads: heads,
            selections: [:]
        )
    }
}

private func readyEntryCount(
    _ proof: V3ManifestAncestryProof?
) throws -> Int {
    guard let proof, proof.heads.count == 1,
          let head = proof.heads.first
    else {
        throw V3ManifestReconciliationError.invalidAncestryProof
    }
    return head.envelope.content.manifest.entries.count
}

private func entryCount(
    for head: V3VaultHead,
    in proof: V3ManifestAncestryProof
) throws -> Int {
    guard let manifest = proof.heads.first(where: {
        $0.envelopeDigest == head.envelopeDigest
    }) else {
        throw V3ManifestReconciliationError.invalidAncestryProof
    }
    return manifest.envelope.content.manifest.entries.count
}

private func vaultIssue(
    _ issue: V3VaultRepositoryIssue
) -> VaultIssue {
    switch issue {
    case .manifestDirectoryUnavailable:
        VaultIssue(
            code: .transportUnavailable,
            message: "The folder containing vault history is unavailable."
        )
    case .manifestUnavailable:
        VaultIssue(
            code: .referencedObjectUnavailable,
            message: "A required vault-history file is unavailable."
        )
    case .entryUnavailable:
        VaultIssue(
            code: .referencedObjectUnavailable,
            message: "A required encrypted entry file is unavailable."
        )
    case .invalidReferencedObject:
        VaultIssue(
            code: .invalidReferencedObject,
            message: "A required vault file failed verification. Keep the files intact for investigation."
        )
    case .resourceLimitExceeded:
        VaultIssue(
            code: .resourceLimitExceeded,
            message: "Checking the vault exceeded Key's size or item-count limits."
        )
    }
}
