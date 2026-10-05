import CryptoKit
import Foundation

enum V3RecoveryValidationError: Error, Equatable {
  case sourceUnavailable
  case resourceLimit
  case invalidObject
  case unsupportedState
  case anchorMismatch
  case unanchoredParent
  case invalidTransition
  case contentConflict
  case authorityConflict
  case closedEpochBranch
  case recipientRevoked
  case sourceChanged
  case entryUnavailable
  case invalidPayload
}

/// Publicly checked history and one exact wrapper, not MAC-trusted state.
/// Only the selector below can construct it. No historical keys are retained.
struct V3RecoveryPublicSelection: Equatable, Sendable {
  let anchor: V3RecoveryAnchor
  let credentialPublicKey: Data
  let epochRoot: V3RecoveryManifestEnvelope
  let head: V3RecoveryManifestEnvelope
  let currentEpoch: [V3RecoveryManifestEnvelope]
  let context: V3RecoveryHPKEContext
  let wrappedKey: V3RecoveryWrappedKey
  let observedManifestBytes: [Data: Data]
  let listedDigests: [Data]
  let listedObjectCount: Int

  fileprivate init(
    anchor: V3RecoveryAnchor, credentialPublicKey: Data,
    epochRoot: V3RecoveryManifestEnvelope, head: V3RecoveryManifestEnvelope,
    currentEpoch: [V3RecoveryManifestEnvelope], context: V3RecoveryHPKEContext,
    wrappedKey: V3RecoveryWrappedKey, observedManifestBytes: [Data: Data],
    listedDigests: [Data], listedObjectCount: Int
  ) {
    self.anchor = anchor
    self.credentialPublicKey = credentialPublicKey
    self.epochRoot = epochRoot
    self.head = head
    self.currentEpoch = currentEpoch
    self.context = context
    self.wrappedKey = wrappedKey
    self.observedManifestBytes = observedManifestBytes
    self.listedDigests = listedDigests
    self.listedObjectCount = listedObjectCount
  }
}

/// Domain verifier over published immutable objects. The platform must supply
/// the anchor and credential from one bound token read, not provider metadata.
/// No token discovery, administration, private operation or checkpoint write.
struct V3RecoveryHistorySelector: Sendable {
  let source: any V3ImmutableObjectReading
  let limits: V3ManifestRepositoryLimits
  let maximumParentEdges: Int

  init(
    source: any V3ImmutableObjectReading, limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384
  ) {
    precondition(maximumParentEdges > 0)
    self.source = source
    self.limits = limits
    self.maximumParentEdges = maximumParentEdges
  }

  func select(anchor: V3RecoveryAnchor, credentialPublicKey: Data) throws
    -> V3RecoveryPublicSelection
  {
    guard try V3RecoveryRecipientID.derive(publicKey: credentialPublicKey) == anchor.recipientID
    else {
      throw V3RecoveryValidationError.anchorMismatch
    }
    var graph = V3RecoveryManifestGraph(
      source: source, limits: limits, maximumParentEdges: maximumParentEdges)
    let inventory = try graph.loadInventory(floor: anchor.floor.envelopeDigest)
    let listed = inventory.digests
    let objectCount = inventory.objectCount
    let floor = try graph.envelope(anchor.floor.envelopeDigest)
    guard floor.body.fields.vaultID == anchor.floor.vaultID,
      let floorRecipient = floor.body.recovery.recipients.first(where: {
        $0.recipientID == anchor.recipientID
      }),
      floorRecipient.registrationID == anchor.registrationID, floorRecipient.slot == anchor.slot,
      floorRecipient.status == .active, floorRecipient.publicKey == credentialPublicKey
    else { throw V3RecoveryValidationError.anchorMismatch }

    let order = try graph.anchoredOrder(
      floor: anchor.floor.envelopeDigest, vaultID: anchor.floor.vaultID)
    let reachable = Set(order)
    var envelopes: [Data: V3RecoveryManifestEnvelope] = [:]
    var roots: [Data: Data] = [:]
    var previousRoot: [Data: Data] = [:]
    var seenKeyIDs = Set<V3VaultKeyID>()
    var seenTransitionIDs = Set<String>()
    var seenEpochPublicKeys = Set<Data>()
    var entryReferences = Set<V3EntryObjectKey>()
    let boundary = V3RecoveryEpochBoundary()
    for digest in order {
      let child = try graph.envelope(digest)
      guard child.body.fields.vaultID == anchor.floor.vaultID else {
        throw V3RecoveryValidationError.anchorMismatch
      }
      for entry in child.body.fields.entries {
        guard let encoded = Base64URL.decodeCanonical(entry.ciphertextDigest) else {
          throw V3RecoveryValidationError.invalidObject
        }
        entryReferences.insert(V3EntryObjectKey(entryID: entry.entryID, digest: encoded))
        guard entryReferences.count <= limits.maximumReferencedEntryObjects else {
          throw V3RecoveryValidationError.resourceLimit
        }
      }
      if digest == anchor.floor.envelopeDigest {
        roots[digest] = digest
      } else {
        let parents = child.parents.compactMap { envelopes[$0] }
        guard parents.count == child.parents.count else {
          throw V3RecoveryValidationError.unanchoredParent
        }
        if parents.allSatisfy({ $0.body.fields.keyID == child.body.fields.keyID }) {
          try boundary.verifySameEpochMetadata(child, parents: parents)
          try V3RecoveryContentProgressValidator().validate(child, parents: parents)
          guard let first = parents.first, let root = roots[first.digest],
            parents.allSatisfy({ roots[$0.digest] == root })
          else { throw V3RecoveryValidationError.authorityConflict }
          roots[digest] = root
        } else {
          guard parents.count == 1, let parent = parents.first, let oldRoot = roots[parent.digest]
          else {
            throw V3RecoveryValidationError.authorityConflict
          }
          try boundary.verifyBoundary(child, parent: parent)
          try requireAuthorityPolicy(child, parent: parent)
          roots[digest] = digest
          previousRoot[digest] = oldRoot
        }
      }
      if roots[digest] == digest {
        guard seenKeyIDs.insert(child.body.fields.keyID).inserted,
          seenTransitionIDs.insert(child.body.fields.authorityTransitionID).inserted,
          seenEpochPublicKeys.insert(child.body.epochSigningKey.publicKey).inserted
        else { throw V3RecoveryValidationError.invalidTransition }
      }
      envelopes[digest] = child
    }
    let heads = order.filter { digest in
      (graph.children[digest] ?? []).allSatisfy { !reachable.contains($0) }
    }
    guard heads.count == 1, let headDigest = heads.first else {
      let headRoots = Set(heads.compactMap { roots[$0] })
      if headRoots.count == 1 { throw V3RecoveryValidationError.contentConflict }
      // The roots form a tree. All heads are comparable iff they lie on
      // the ancestor chain of the last topologically ordered head root.
      guard let lastRoot = order.last(where: { headRoots.contains($0) }) else {
        throw V3RecoveryValidationError.invalidTransition
      }
      var chain: Set<Data> = [lastRoot]
      var current = lastRoot
      while let parent = previousRoot[current] {
        chain.insert(parent)
        current = parent
      }
      guard headRoots.isSubset(of: chain) else {
        throw V3RecoveryValidationError.authorityConflict
      }
      throw V3RecoveryValidationError.closedEpochBranch
    }
    guard let head = envelopes[headDigest], let rootDigest = roots[headDigest],
      let root = envelopes[rootDigest],
      let recipient = root.body.recovery.recipients.first(where: {
        $0.recipientID == anchor.recipientID
      }),
      recipient.status == .active, recipient.registrationID == anchor.registrationID,
      recipient.slot == anchor.slot, recipient.publicKey == credentialPublicKey,
      let wrapped = root.body.recovery.wrappedKeys.first(where: {
        $0.recipientID == anchor.recipientID && $0.registrationID == anchor.registrationID
      })
    else { throw V3RecoveryValidationError.recipientRevoked }
    return try V3RecoveryPublicSelection(
      anchor: anchor, credentialPublicKey: credentialPublicKey, epochRoot: root, head: head,
      currentEpoch: order.filter { roots[$0] == rootDigest }.compactMap { envelopes[$0] },
      context: V3RecoveryHPKEContext(
        vaultID: root.body.fields.vaultID, keyID: root.body.fields.keyID,
        authorityTransitionID: root.body.fields.authorityTransitionID,
        recoveryGenerationID: root.body.recovery.generationID, recipient: recipient),
      wrappedKey: wrapped, observedManifestBytes: graph.objects.mapValues(\.bytes),
      listedDigests: listed, listedObjectCount: objectCount)
  }

  private func requireAuthorityPolicy(
    _ child: V3RecoveryManifestEnvelope, parent: V3RecoveryManifestEnvelope
  ) throws {
    let a = parent.body
    let b = child.body
    let devices = Dictionary(
      uniqueKeysWithValues: b.fields.devices.map { ($0.identity.deviceID, $0) })
    for old in a.fields.devices {
      guard let next = devices[old.identity.deviceID], next.identity == old.identity,
        old.status == .active || next.status == .revoked
      else {
        throw V3RecoveryValidationError.invalidTransition
      }
    }
    let oldDeviceIDs = Set(a.fields.devices.map { $0.identity.deviceID })
    guard
      b.fields.devices.filter({ !oldDeviceIDs.contains($0.identity.deviceID) }).allSatisfy({
        $0.status == .active
      }),
      let signer = child.authorizations.first?.signerDeviceID, devices[signer]?.status == .active
    else { throw V3RecoveryValidationError.invalidTransition }
    let recipients = Dictionary(
      uniqueKeysWithValues: b.recovery.recipients.map { ($0.recipientID, $0) })
    for old in a.recovery.recipients {
      guard let next = recipients[old.recipientID], next.publicKey == old.publicKey,
        next.registrationID == old.registrationID, next.slot == old.slot,
        old.status == .active || next.status == .revoked
      else { throw V3RecoveryValidationError.invalidTransition }
    }
    let oldRecipients = Set(a.recovery.recipients.map(\.recipientID))
    guard
      b.recovery.recipients.filter({ !oldRecipients.contains($0.recipientID) }).allSatisfy({
        $0.status == .active
      }),
      (a.recovery.recipients == b.recovery.recipients)
        == (a.recovery.generationID == b.recovery.generationID),
      a.fields.entries.count == b.fields.entries.count,
      zip(a.fields.entries, b.fields.entries).allSatisfy({
        $0.entryID == $1.entryID && $0.name == $1.name && $0.type == $1.type
          && $0.revision == $1.revision
      })
    else { throw V3RecoveryValidationError.invalidTransition }
  }

}
