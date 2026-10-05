import Foundation

/// Exact same-epoch ancestry committed transitively by a locally pinned manifest.
/// This grants neither checkpoint replacement nor snapshot authority. It is used
/// only when a visible branch cannot be explained from the current forward cut.
/// Older entry ciphertext is not read; missing required manifests fail closed.
struct V3RecoveryCheckpointAncestry {
  let root: Data
  let committedDigests: Set<Data>

  init(
    graph: inout V3RecoveryManifestGraph, checkpoint: V3RecoveryContentCommit, vaultKey: Data
  ) throws {
    try V3RecoveryContentMutationValidator(limits: graph.limits).validateParent(
      checkpoint.envelope, checkpoint: checkpoint.checkpoint, vaultKey: vaultKey)
    let boundary = V3RecoveryEpochBoundary()
    let progress = V3RecoveryContentProgressValidator()
    var committed: [Data: V3RecoveryManifestEnvelope] = [
      checkpoint.checkpoint.envelopeDigest: checkpoint.envelope
    ]
    var pending = [checkpoint.checkpoint.envelopeDigest]
    var inspected = Set<Data>()
    var roots = Set<Data>()
    while let digest = pending.popLast() {
      guard inspected.insert(digest).inserted, let child = committed[digest] else { continue }
      if child.parents.isEmpty {
        roots.insert(digest)
        continue
      }
      if !child.authorizations.isEmpty {
        guard child.parents.count == 1,
          child.body.transitionProof?.parentEnvelopeDigest == child.parents.first
        else { throw V3RecoveryValidationError.invalidTransition }
        // Exact checkpoint-linked boundary identity, not a new authentication
        // of that older epoch. Its parent/snapshots need not be available here.
        roots.insert(digest)
        continue
      }
      var parents: [V3RecoveryManifestEnvelope] = []
      for parentDigest in child.parents {
        try graph.observe(parentDigest)
        let parent = try graph.envelope(parentDigest)
        try boundary.verifyCurrentAuthentication(parent, vaultKey: vaultKey)
        parents.append(parent)
        if committed.updateValue(parent, forKey: parentDigest) == nil {
          pending.append(parentDigest)
        }
      }
      guard !parents.isEmpty,
        parents.count > 1 || child.body.fields.entries != parents[0].body.fields.entries
      else { throw V3RecoveryValidationError.invalidTransition }
      try boundary.verifySameEpochMetadata(child, parents: parents)
      try progress.validate(child, parents: parents)
    }
    guard roots.count == 1, let root = roots.first else {
      throw V3RecoveryValidationError.unanchoredParent
    }
    let digests = Set(committed.keys)
    // Independently enforce acyclicity, closure and the existing depth bound.
    _ = try graph.topologicalOrder(digests, floor: root)
    self.root = root
    committedDigests = digests
  }
}
