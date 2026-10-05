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
    var graph = Graph(source: source, limits: limits, maximumParentEdges: maximumParentEdges)
    let listing = try source.manifestDigests(maximumCount: limits.maximumManifestObjects)
    let listed: [Data]
    let objectCount: Int
    switch listing {
    case .available(let digests, let count):
      guard count >= digests.count, count <= limits.maximumManifestObjects,
        Set(digests).count == digests.count, digests.allSatisfy({ $0.count == 32 })
      else { throw V3RecoveryValidationError.resourceLimit }
      listed = digests.sorted { $0.lexicographicallyPrecedes($1) }
      objectCount = count
    case .limitExceeded: throw V3RecoveryValidationError.resourceLimit
    case .unavailable: throw V3RecoveryValidationError.sourceUnavailable
    case .invalid: throw V3RecoveryValidationError.invalidObject
    }
    graph.listedDigests = Set(listed)
    graph.countedObjects = objectCount
    // Opaque unreadable named objects cannot be proven unrelated. Refuse them
    // rather than infer that the visible floor is the latest complete state.
    for digest in listed { try graph.observe(digest) }
    try graph.observe(anchor.floor.envelopeDigest)
    let floor = try graph.envelope(anchor.floor.envelopeDigest)
    guard floor.body.fields.vaultID == anchor.floor.vaultID,
      let floorRecipient = floor.body.recovery.recipients.first(where: {
        $0.recipientID == anchor.recipientID
      }),
      floorRecipient.registrationID == anchor.registrationID, floorRecipient.slot == anchor.slot,
      floorRecipient.status == .active, floorRecipient.publicKey == credentialPublicKey
    else { throw V3RecoveryValidationError.anchorMismatch }

    // Discover visible descendants, then load every required parent ancestry.
    // Stop at the pinned floor; pre-registration ancestry is not recovery trust.
    var reachable = graph.descendants(of: anchor.floor.envelopeDigest)
    var pending = reachable.sorted { $0.lexicographicallyPrecedes($1) }
    var inspected = Set<Data>()
    var cursor = 0
    while true {
      while cursor < pending.count {
        let digest = pending[cursor]
        cursor += 1
        guard inspected.insert(digest).inserted, digest != anchor.floor.envelopeDigest else {
          continue
        }
        try graph.observe(digest)
        guard let parents = graph.objects[digest]?.parents, !parents.isEmpty else {
          throw V3RecoveryValidationError.unanchoredParent
        }
        for parent in parents {
          try graph.observe(parent)
          pending.append(parent)
        }
      }
      reachable = graph.descendants(of: anchor.floor.envelopeDigest)
      let newlyReachable = reachable.subtracting(inspected)
      if newlyReachable.isEmpty { break }
      pending.append(contentsOf: newlyReachable.sorted { $0.lexicographicallyPrecedes($1) })
    }
    guard inspected.isSubset(of: reachable) else {
      throw V3RecoveryValidationError.unanchoredParent
    }
    // A listed same-vault tip whose link to the floor is missing must not
    // disappear merely because descendant discovery cannot yet reach it.
    // Known pre-floor objects remain outside recovery's replay obligation.
    let preFloor = graph.loadedAncestors(of: anchor.floor.envelopeDigest)
    for (digest, object) in graph.objects
    where !reachable.contains(digest)
      && !preFloor.contains(digest)
      && object.vaultID == anchor.floor.vaultID
    {
      throw V3RecoveryValidationError.unanchoredParent
    }
    let order = try graph.topologicalOrder(reachable, floor: anchor.floor.envelopeDigest)
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
          try requireContentProgress(child, parents: parents)
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

  private func requireContentProgress(
    _ child: V3RecoveryManifestEnvelope, parents: [V3RecoveryManifestEnvelope]
  ) throws {
    var prior: [String: [V3ManifestEntry]] = [:]
    for parent in parents {
      for entry in parent.body.fields.entries { prior[entry.entryID, default: []].append(entry) }
    }
    for entry in child.body.fields.entries {
      guard let versions = prior[entry.entryID] else {
        guard entry.revision == 1 else { throw V3RecoveryValidationError.invalidTransition }
        continue
      }
      let maximum = versions.map(\.revision).max() ?? 0
      if versions.contains(entry) {
        guard entry.revision == maximum else { throw V3RecoveryValidationError.invalidTransition }
      } else {
        guard maximum < v3MaximumSafeInteger, entry.revision == maximum + 1 else {
          throw V3RecoveryValidationError.invalidTransition
        }
      }
    }
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

  private struct Graph {
    struct Object {
      let bytes: Data
      let parents: [Data]
      let vaultID: String
    }
    let source: any V3ImmutableObjectReading
    let limits: V3ManifestRepositoryLimits
    let maximumParentEdges: Int
    var objects: [Data: Object] = [:]
    var children: [Data: Set<Data>] = [:]
    var totalBytes = 0
    var edgeCount = 0
    var listedDigests = Set<Data>()
    var countedObjects = 0

    mutating func observe(_ digest: Data) throws {
      guard objects[digest] == nil else { return }
      guard digest.count == 32, objects.count < limits.maximumManifestObjects else {
        throw V3RecoveryValidationError.resourceLimit
      }
      // Directory entries without digest-shaped names still consume budget;
      // required objects absent from that listing must consume it as well.
      if !listedDigests.contains(digest) {
        guard countedObjects < limits.maximumManifestObjects else {
          throw V3RecoveryValidationError.resourceLimit
        }
        countedObjects += 1
      }
      let bytes: Data
      switch try source.readManifest(digest: digest, maximumBytes: limits.maximumManifestBytes) {
      case .available(let data): bytes = data
      case .tooLarge: throw V3RecoveryValidationError.resourceLimit
      case .unavailable: throw V3RecoveryValidationError.sourceUnavailable
      case .invalid: throw V3RecoveryValidationError.invalidObject
      }
      guard bytes.count <= limits.maximumManifestBytes,
        bytes.count <= limits.maximumTotalManifestBytes - totalBytes
      else {
        throw V3RecoveryValidationError.resourceLimit
      }
      guard Data(SHA256.hash(data: bytes)) == digest else {
        throw V3RecoveryValidationError.invalidObject
      }
      let container = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(bytes)
      let metadata = container.metadata
      guard
        let vaultID = container.manifestValue.objectValue?.first(where: { $0.0 == "vaultID" })?.1
          .stringValue,
        isValidV3UUID(vaultID)
      else { throw V3RecoveryValidationError.invalidObject }
      guard metadata.parents.count <= maximumParentEdges - edgeCount else {
        throw V3RecoveryValidationError.resourceLimit
      }
      totalBytes += bytes.count
      edgeCount += metadata.parents.count
      objects[digest] = Object(bytes: bytes, parents: metadata.parents, vaultID: vaultID)
      for parent in metadata.parents { children[parent, default: []].insert(digest) }
    }

    func envelope(_ digest: Data) throws -> V3RecoveryManifestEnvelope {
      guard let object = objects[digest] else { throw V3RecoveryValidationError.sourceUnavailable }
      do { return try V3RecoveryManifestCodec().parseEnvelope(object.bytes) } catch {
        throw V3RecoveryValidationError.unsupportedState
      }
    }

    func descendants(of floor: Data) -> Set<Data> {
      var result: Set<Data> = [floor]
      var queue = [floor]
      var cursor = 0
      while cursor < queue.count {
        let digest = queue[cursor]
        cursor += 1
        for child in children[digest] ?? [] where result.insert(child).inserted {
          queue.append(child)
        }
      }
      return result
    }

    func loadedAncestors(of floor: Data) -> Set<Data> {
      var result = Set<Data>()
      var queue = objects[floor]?.parents ?? []
      var cursor = 0
      while cursor < queue.count {
        let digest = queue[cursor]
        cursor += 1
        guard result.insert(digest).inserted else { continue }
        queue.append(contentsOf: objects[digest]?.parents ?? [])
      }
      return result
    }

    func topologicalOrder(_ reachable: Set<Data>, floor: Data) throws -> [Data] {
      var indegree: [Data: Int] = [:]
      for digest in reachable {
        guard let object = objects[digest],
          digest == floor || object.parents.allSatisfy({ reachable.contains($0) })
        else {
          throw V3RecoveryValidationError.unanchoredParent
        }
        indegree[digest] = digest == floor ? 0 : object.parents.count
      }
      var queue = [floor]
      var depths: [Data: Int] = [floor: 0]
      var cursor = 0
      while cursor < queue.count {
        let digest = queue[cursor]
        cursor += 1
        for child in (children[digest] ?? []).sorted(by: { $0.lexicographicallyPrecedes($1) })
        where reachable.contains(child) {
          depths[child] = max(depths[child] ?? 0, (depths[digest] ?? 0) + 1)
          guard depths[child, default: 0] <= limits.maximumHistoryDepth else {
            throw V3RecoveryValidationError.resourceLimit
          }
          indegree[child, default: 0] -= 1
          if indegree[child] == 0 { queue.append(child) }
        }
      }
      guard queue.count == reachable.count else {
        throw V3RecoveryValidationError.invalidTransition
      }
      return queue
    }
  }
}
