import Foundation

/// Pure bounded DAG policy over already-authenticated forward history. This
/// performs no provider reads, authentication or checkpoint writes. The floor's
/// earlier parents are deliberately outside this graph.
struct V3RecoveryContentAncestry: Sendable {
  let floor: Data
  let order: [Data]
  let parents: [Data: [Data]]
  private let positions: [Data: Int]

  init(floor: Data, order: [Data], parents: [Data: [Data]]) throws {
    guard order.first == floor, Set(order).count == order.count,
      Set(order) == Set(parents.keys)
    else { throw V3RecoveryValidationError.invalidTransition }
    let positions = Dictionary(
      uniqueKeysWithValues: order.enumerated().map { ($0.element, $0.offset) })
    for (offset, digest) in order.enumerated() where digest != floor {
      guard let incoming = parents[digest], !incoming.isEmpty,
        Set(incoming).count == incoming.count,
        incoming.allSatisfy({ positions[$0].map { $0 < offset } == true })
      else { throw V3RecoveryValidationError.invalidTransition }
    }
    self.floor = floor
    self.order = order
    self.parents = parents
    self.positions = positions
  }

  init(_ observed: V3RecoverySameEpochObservation) throws {
    try self.init(
      floor: observed.graphFloor, order: observed.order,
      parents: observed.envelopes.mapValues(\.parents))
  }

  /// The earliest forward point on every floor-to-head path, not an arbitrary
  /// side of a resolved fork. Immediate dominators use predecessor-chain
  /// intersection (Cooper/Harvey/Kennedy); acyclic topological input needs one
  /// pass, with O(nodes) retained state and O(edges * history depth) work.
  func nextAdvance(after current: Data, to head: Data) throws -> Data? {
    guard positions[current] != nil, positions[head] != nil else {
      throw V3RecoveryValidationError.invalidTransition
    }
    var dominators: [Data: Data] = [floor: floor]
    for digest in order.dropFirst() {
      guard let incoming = parents[digest], var common = incoming.first else {
        throw V3RecoveryValidationError.invalidTransition
      }
      for parent in incoming.dropFirst() {
        var a = common
        var b = parent
        while a != b {
          guard let aPosition = positions[a], let bPosition = positions[b] else {
            throw V3RecoveryValidationError.invalidTransition
          }
          if aPosition > bPosition {
            guard let next = dominators[a] else {
              throw V3RecoveryValidationError.invalidTransition
            }
            a = next
          } else {
            guard let next = dominators[b] else {
              throw V3RecoveryValidationError.invalidTransition
            }
            b = next
          }
        }
        common = a
      }
      dominators[digest] = common
    }
    var descendants: Set<Data> = [current]
    for digest in order where digest != floor {
      if parents[digest, default: []].contains(where: descendants.contains) {
        descendants.insert(digest)
      }
    }
    guard descendants.contains(head) else { throw V3RecoveryValidationError.invalidTransition }
    var chain: [Data] = [head]
    var next = head
    while next != floor {
      guard let prior = dominators[next] else { throw V3RecoveryValidationError.invalidTransition }
      next = prior
      chain.append(next)
    }
    return chain.reversed().first { $0 != current && descendants.contains($0) }
  }

  func nearestCommonAncestors(of heads: [Data]) throws -> [Data] {
    guard let first = heads.first else { throw V3RecoveryValidationError.invalidTransition }
    var common = try ancestors(of: first)
    for head in heads.dropFirst() { common.formIntersection(try ancestors(of: head)) }
    // Mark ancestors of common nodes once. A marked common node has a newer
    // common descendant and therefore cannot be a nearest merge base.
    var pending = common.flatMap { $0 == floor ? [] : parents[$0, default: []] }
    var older = Set<Data>()
    while let digest = pending.popLast() {
      guard older.insert(digest).inserted else { continue }
      if digest != floor { pending.append(contentsOf: parents[digest, default: []]) }
    }
    return common.subtracting(older).sorted { $0.lexicographicallyPrecedes($1) }
  }

  private func ancestors(of head: Data) throws -> Set<Data> {
    guard positions[head] != nil else { throw V3RecoveryValidationError.invalidTransition }
    var result = Set<Data>()
    var pending = [head]
    while let digest = pending.popLast() {
      guard result.insert(digest).inserted else { continue }
      if digest != floor { pending.append(contentsOf: parents[digest, default: []]) }
    }
    return result
  }
}
