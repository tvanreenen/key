import CryptoKit
import Foundation

/// Bounded published-byte inventory and graph traversal shared by catastrophe
/// recovery and ordinary same-epoch catch-up. Parsing/reachability alone grants
/// no authority; each caller authenticates from its own explicitly bound floor.
struct V3RecoveryManifestGraph {
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

  mutating func loadInventory(floor: Data) throws -> (digests: [Data], objectCount: Int) {
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
    listedDigests = Set(listed)
    countedObjects = objectCount
    // Every named object consumes budget and must have readable canonical bytes.
    for digest in listed { try observe(digest) }
    try observe(floor)
    return (listed, objectCount)
  }

  /// Requires a closed forward graph rooted at a caller-established local or
  /// token floor. This establishes reachability, not manifest authentication.
  mutating func anchoredOrder(floor: Data, vaultID: String) throws -> [Data] {
    // Discover visible descendants, then load every required parent ancestry.
    // Stop at the caller's pinned floor; earlier ancestry grants no new trust.
    var reachable = descendants(of: floor)
    var pending = reachable.sorted { $0.lexicographicallyPrecedes($1) }
    var inspected = Set<Data>()
    var cursor = 0
    while true {
      while cursor < pending.count {
        let digest = pending[cursor]
        cursor += 1
        guard inspected.insert(digest).inserted, digest != floor else {
          continue
        }
        try observe(digest)
        guard let parents = objects[digest]?.parents, !parents.isEmpty else {
          throw V3RecoveryValidationError.unanchoredParent
        }
        for parent in parents {
          try observe(parent)
          pending.append(parent)
        }
      }
      reachable = descendants(of: floor)
      let newlyReachable = reachable.subtracting(inspected)
      if newlyReachable.isEmpty { break }
      pending.append(contentsOf: newlyReachable.sorted { $0.lexicographicallyPrecedes($1) })
    }
    guard inspected.isSubset(of: reachable) else {
      throw V3RecoveryValidationError.unanchoredParent
    }
    // A listed same-vault tip whose link to the floor is missing must not
    // disappear merely because descendant discovery cannot yet reach it.
    // Known pre-floor objects remain outside this forward replay obligation.
    let preFloor = loadedAncestors(of: floor)
    for (digest, object) in objects
    where !reachable.contains(digest)
      && !preFloor.contains(digest)
      && object.vaultID == vaultID
    {
      throw V3RecoveryValidationError.unanchoredParent
    }
    return try topologicalOrder(reachable, floor: floor)
  }

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

/// Entry revision progression shared by public recovery history and ordinary
/// authenticated observation. This is not a publication or merge policy.
struct V3RecoveryContentProgressValidator: Sendable {
  func validate(
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

}
