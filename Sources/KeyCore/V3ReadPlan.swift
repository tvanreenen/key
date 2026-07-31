import Foundation

/// The authenticated repository state that must still hold when plaintext is
/// released.
enum V3ReadAuthority: Equatable, Sendable {
    /// Read from deterministic current state and require the exact observed
    /// checkpoint and head set to remain current.
    case current(V3ExpectedRepositoryState)

    /// Read only from the exact local checkpoint explicitly accepted by the
    /// caller while newer synchronized state is incomplete.
    case lastTrusted(V3ManifestCheckpoint)
}

/// A sealed work order for one immutable version 3 entry read.
///
/// The plan contains no plaintext or vault key. Its entry fields came from
/// authenticated manifest state, and its digest identifies the only object the
/// executor may open.
struct V3AuthenticatedReadPlan: Equatable, Sendable {
    let authority: V3ReadAuthority
    let vaultID: String
    let entry: V3ManifestEntry
    let ciphertextDigest: Data

    fileprivate init(
        authority: V3ReadAuthority,
        vaultID: String,
        entry: V3ManifestEntry
    ) throws {
        guard let ciphertextDigest = Base64URL.decodeCanonical(
            entry.ciphertextDigest
        ), ciphertextDigest.count == 32,
              (try? V3EntryAuthenticationContext(
                  vaultID: vaultID,
                  entry: entry
              )) != nil
        else {
            throw V3EncryptedEntryError.invalidTrustedContext
        }

        switch authority {
        case let .current(expected):
            guard expected.checkpoint.vaultID == vaultID,
                  !expected.heads.isEmpty,
                  expected.heads.allSatisfy({ $0.vaultID == vaultID })
            else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
        case let .lastTrusted(checkpoint):
            guard checkpoint.vaultID == vaultID else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
        }

        self.authority = authority
        self.vaultID = vaultID
        self.entry = entry
        self.ciphertextDigest = ciphertextDigest
    }
}

/// Resolves user intent into an exact authenticated immutable-entry read.
///
/// Planning is pure: it performs no filesystem access, key lookup, decryption,
/// checkpoint update, or publication.
struct V3AuthenticatedReadPlanner: Sendable {
    private let reconciler: V3ManifestReconciler

    init(reconciler: V3ManifestReconciler = V3ManifestReconciler()) {
        self.reconciler = reconciler
    }

    func planRead(
        named name: String,
        allowStale: Bool,
        classification: V3VaultRepositoryClassification,
        trustedCurrent: V3TrustedManifest
    ) throws -> V3AuthenticatedReadPlan {
        let name = try normalizedReadName(name)
        switch classification.status {
        case .incomplete:
            guard allowStale else {
                throw VaultUXServiceError.vaultIncomplete
            }
            return try plan(
                named: name,
                in: trustedCurrent.envelope.content.manifest.entries,
                vaultID: trustedCurrent.checkpoint.vaultID,
                authority: .lastTrusted(trustedCurrent.checkpoint)
            )
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        case .ready, .contentConflicted:
            break
        }

        let proof = try requiredProof(
            classification,
            trustedCurrent: trustedCurrent
        )
        let expected = try expectedState(for: proof)
        let vaultID = trustedCurrent.checkpoint.vaultID

        switch try reconciler.reconcile(proof) {
        case let .noMergeRequired(head):
            guard let manifest = proof.heads.first(where: {
                $0.envelopeDigest == head.envelopeDigest
            }) else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
            return try plan(
                named: name,
                in: manifest.envelope.content.manifest.entries,
                vaultID: vaultID,
                authority: .current(expected)
            )
        case let .automaticMerge(merge):
            guard normalizedHeads(merge.parentHeads) == expected.heads else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
            return try plan(
                named: name,
                in: merge.content.manifest.entries,
                vaultID: vaultID,
                authority: .current(expected)
            )
        case let .contentConflict(report):
            guard normalizedHeads(report.heads) == expected.heads else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
            if report.entryConflicts.contains(where: {
                $0.kind == .revisionRollback
            }) {
                throw VaultUXServiceError.rollbackDetected
            }
            guard !conflicts(name, report: report) else {
                throw VaultUXServiceError.contentConflict
            }
            return try plan(
                named: name,
                in: report.entriesReconciledByID,
                vaultID: vaultID,
                authority: .current(expected)
            )
        case .securityConflict:
            throw VaultUXServiceError.securityConflict
        case .historyConflict:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    /// Rebinds a conflict version selected from a previous UX snapshot to a
    /// fresh authenticated proof before an executor may read it.
    func planConflictRead(
        entry selectedEntry: V3ManifestEntry,
        expectedHeads: [V3VaultHead],
        classification: V3VaultRepositoryClassification,
        trustedCurrent: V3TrustedManifest
    ) throws -> V3AuthenticatedReadPlan {
        guard classification.status == .contentConflicted else {
            throw VaultUXServiceError.expectedHeadsChanged
        }
        let proof = try requiredProof(
            classification,
            trustedCurrent: trustedCurrent
        )
        let expected = try expectedState(for: proof)
        guard normalizedHeads(expectedHeads) == expected.heads else {
            throw VaultUXServiceError.expectedHeadsChanged
        }

        guard case let .contentConflict(report) =
                try reconciler.reconcile(proof),
              normalizedHeads(report.heads) == expected.heads
        else {
            throw VaultUXServiceError.expectedHeadsChanged
        }

        let authenticatedVersions =
            report.entryConflicts.flatMap(\.versions).compactMap(\.entry)
            + report.destinationConflicts.flatMap(\.entries)
        guard authenticatedVersions.contains(selectedEntry) else {
            throw VaultUXServiceError.conflictVersionNotFound
        }

        return try V3AuthenticatedReadPlan(
            authority: .current(expected),
            vaultID: trustedCurrent.checkpoint.vaultID,
            entry: selectedEntry
        )
    }

    private func plan(
        named name: String,
        in entries: [V3ManifestEntry],
        vaultID: String,
        authority: V3ReadAuthority
    ) throws -> V3AuthenticatedReadPlan {
        let matches = entries.filter { $0.name == name }
        guard let entry = matches.first else {
            throw AppError.entryNotFound("Entry '\(name)' was not found.")
        }
        guard matches.count == 1 else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        return try V3AuthenticatedReadPlan(
            authority: authority,
            vaultID: vaultID,
            entry: entry
        )
    }
}

private func requiredProof(
    _ classification: V3VaultRepositoryClassification,
    trustedCurrent: V3TrustedManifest
) throws -> V3ManifestAncestryProof {
    guard let proof = classification.ancestryProof,
          proof.checkpoint == trustedCurrent.checkpoint
    else {
        throw V3ManifestReconciliationError.invalidAncestryProof
    }
    let proofHeads = try proof.heads.map(
        V3VaultHead.init(verifiedManifest:)
    )
    guard normalizedHeads(classification.heads)
        == normalizedHeads(proofHeads)
    else {
        throw V3ManifestReconciliationError.invalidAncestryProof
    }
    return proof
}

private func expectedState(
    for proof: V3ManifestAncestryProof
) throws -> V3ExpectedRepositoryState {
    let heads = try proof.heads.map(V3VaultHead.init(verifiedManifest:))
    let normalized = normalizedHeads(heads)
    guard !normalized.isEmpty,
          Set(normalized).count == normalized.count,
          normalized.allSatisfy({
              $0.vaultID == proof.checkpoint.vaultID
          })
    else {
        throw V3ManifestReconciliationError.invalidAncestryProof
    }
    return V3ExpectedRepositoryState(
        checkpoint: proof.checkpoint,
        heads: normalized
    )
}

private func conflicts(
    _ name: String,
    report: V3ContentConflictReport
) -> Bool {
    if report.destinationConflicts.contains(where: { $0.name == name }) {
        return true
    }
    return report.entryConflicts.contains { conflict in
        conflict.commonAncestorEntry?.name == name
            || conflict.versions.contains { $0.entry?.name == name }
    }
}

private func normalizedHeads(
    _ heads: [V3VaultHead]
) -> [V3VaultHead] {
    heads.sorted {
        $0.envelopeDigest.lexicographicallyPrecedes($1.envelopeDigest)
    }
}

private func normalizedReadName(_ name: String) throws -> String {
    let normalized = name.precomposedStringWithCanonicalMapping
    guard isValidV3EntryName(normalized) else {
        throw AppError.invalidEntryName(
            "Entry name '\(name)' is not valid for a version 3 vault."
        )
    }
    return normalized
}
