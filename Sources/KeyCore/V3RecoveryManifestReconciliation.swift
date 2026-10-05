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
}

/// Pure reconciliation of an observer-authenticated, closed same-epoch tree.
/// The observation's constructor is confined to the production observer, which
/// checks every manifest/snapshot and exact authority/coverage from a local floor.
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
    let firstPath = try path(first.envelopeDigest, in: observed)
    var common = Set(firstPath)
    for head in heads.dropFirst() {
      common.formIntersection(try path(head.envelopeDigest, in: observed))
    }
    // Single-parent forward history has one nearest common ancestor. Stop at
    // the authenticated floor; its older parents do not extend this authority.
    guard let ancestorDigest = firstPath.first(where: common.contains),
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

  private func path(_ head: Data, in observed: V3RecoverySameEpochObservation) throws -> [Data] {
    var path: [Data] = []
    var seen = Set<Data>()
    var next = head
    while true {
      guard seen.insert(next).inserted, let envelope = observed.envelopes[next] else {
        throw V3ManifestReconciliationError.invalidAncestryProof
      }
      path.append(next)
      if next == observed.checkpoint.envelopeDigest { return path }
      guard envelope.parents.count == 1, let parent = envelope.parents.first else {
        throw V3ManifestReconciliationError.invalidAncestryProof
      }
      next = parent
    }
  }
}
