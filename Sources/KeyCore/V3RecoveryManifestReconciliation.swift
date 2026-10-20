import Foundation

/// Logical entries and exact parents for a future same-epoch merge. This is
/// not an encoded candidate, fresh source observation or checkpoint authority.
struct V3RecoveryAutomaticMergePlan: Equatable, Sendable {
  let commonAncestor: V3VaultHead
  let parentHeads: [V3VaultHead]
  let entries: [V3ManifestEntry]
}

enum V3RecoveryManifestReconciliationResult: Equatable, Sendable {
  case noMergeRequired(head: V3VaultHead)
  case automaticMerge(V3RecoveryAutomaticMergePlan)
  case contentConflict(V3ContentConflictReport)
  case historyConflict(V3HistoryConflict)
}

/// Pure reconciliation of an observer-authenticated, closed same-epoch DAG.
/// The observation's constructor is confined to the production observer, which
/// checks current/new branch snapshots and exact authority/coverage; older
/// comparison records are linked transitively to the durable local checkpoint.
/// No profile projection, decryption, publication or private operation occurs.
struct V3RecoveryManifestReconciler: Sendable {
  func reconcile(_ observed: V3RecoverySameEpochObservation) throws
    -> V3RecoveryManifestReconciliationResult
  {
    let heads = try observed.heads.map {
      try V3VaultHead(vaultID: observed.checkpoint.vaultID, envelopeDigest: $0)
    }
    guard let first = heads.first else {
      throw V3ManifestReconciliationError.invalidAncestryProof
    }
    guard heads.count > 1 else { return .noMergeRequired(head: first) }
    let common = try V3RecoveryContentAncestry(observed).nearestCommonAncestors(of: observed.heads)
    guard !common.isEmpty else { throw V3ManifestReconciliationError.invalidAncestryProof }
    guard common.count == 1 else {
      return .historyConflict(
        V3HistoryConflict(
          heads: heads,
          commonAncestors: try common.map {
            try V3VaultHead(vaultID: observed.checkpoint.vaultID, envelopeDigest: $0)
          }))
    }
    guard let ancestorDigest = common.first,
      let ancestor = observed.envelopes[ancestorDigest]
    else { throw V3ManifestReconciliationError.invalidAncestryProof }
    let ancestorHead = try V3VaultHead(
      vaultID: observed.checkpoint.vaultID, envelopeDigest: ancestorDigest)
    let versions = try heads.map { head in
      guard let envelope = observed.envelopes[head.envelopeDigest] else {
        throw V3ManifestReconciliationError.invalidAncestryProof
      }
      return (head: head, entries: envelope.body.fields.entries)
    }
    let compared = try V3EntryReconciler().reconcile(
      ancestorEntries: ancestor.body.fields.entries, versions: versions)
    if !compared.entryConflicts.isEmpty || !compared.destinationConflicts.isEmpty {
      return .contentConflict(
        V3ContentConflictReport(
          commonAncestor: ancestorHead, heads: heads, entriesReconciledByID: compared.entries,
          entryConflicts: compared.entryConflicts,
          destinationConflicts: compared.destinationConflicts))
    }
    return .automaticMerge(
      V3RecoveryAutomaticMergePlan(
        commonAncestor: ancestorHead, parentHeads: heads, entries: compared.entries))
  }

}
