import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryContentAncestryTests {
  @Test func boundedDagPolicyMatchesIndependentSetBasedReferenceForEverySixNodeDag() throws {
    let nodes = (0..<6).map { Data([UInt8($0)]) }
    var checked = 0
    // Every non-root node has a nonempty predecessor subset. This enumerates
    // all 9,765 rooted, labelled, topologically ordered six-node DAGs.
    for a in 1..<2 {
      for b in 1..<4 {
        for c in 1..<8 {
          for d in 1..<16 {
            for e in 1..<32 {
              let masks = [0, a, b, c, d, e]
              let incoming = Dictionary(
                uniqueKeysWithValues: nodes.enumerated().map { i, node in
                  (node, (0..<i).filter { masks[i] & (1 << $0) != 0 }.map { nodes[$0] })
                })
              let policy = try V3RecoveryContentAncestry(
                floor: nodes[0], order: nodes, parents: incoming)
              var dominators: [Data: Set<Data>] = [nodes[0]: [nodes[0]]]
              var ancestors: [Data: Set<Data>] = [nodes[0]: [nodes[0]]]
              for node in nodes.dropFirst() {
                let parents = incoming[node]!
                var common = dominators[parents[0]]!
                var all: Set<Data> = [node]
                for parent in parents {
                  common.formIntersection(dominators[parent]!)
                  all.formUnion(ancestors[parent]!)
                }
                common.insert(node)
                dominators[node] = common
                ancestors[node] = all
              }
              let head = nodes[5]
              for current in nodes where ancestors[head]!.contains(current) {
                let expected = nodes.first {
                  $0 != current && dominators[head]!.contains($0)
                    && ancestors[$0]!.contains(current)
                }
                #expect(try policy.nextAdvance(after: current, to: head) == expected)
              }
              let referenced = Set(incoming.values.flatMap { $0 })
              let heads = nodes.filter { !referenced.contains($0) }
              var common = ancestors[heads[0]]!
              for head in heads.dropFirst() { common.formIntersection(ancestors[head]!) }
              let expected = common.filter { candidate in
                !common.contains { $0 != candidate && ancestors[$0]!.contains(candidate) }
              }.sorted { $0.lexicographicallyPrecedes($1) }
              #expect(try policy.nearestCommonAncestors(of: heads) == expected)
              checked += 1
            }
          }
        }
      }
    }
    #expect(checked == 9_765)
  }

  @Test(arguments: 0..<5)
  func malformedOrderAndParentEdgesRefuse(variant: Int) throws {
    let a = Data([0])
    let b = Data([1])
    let c = Data([2])
    let order: [Data]
    let parents: [Data: [Data]]
    switch variant {
    case 0:
      order = [b, a]
      parents = [a: [], b: [a]]
    case 1:
      order = [a, b, b]
      parents = [a: [], b: [a]]
    case 2:
      order = [a, b]
      parents = [a: [], b: [c]]
    case 3:
      order = [a, b]
      parents = [a: [], b: [a, a]]
    default:
      order = [a, b]
      parents = [a: [], b: []]
    }
    #expect(throws: V3RecoveryValidationError.invalidTransition) {
      try V3RecoveryContentAncestry(floor: a, order: order, parents: parents)
    }
  }

  @Test func preFloorParentsDoNotExtendTheGraphAndUnrelatedCurrentCannotAdvance() throws {
    let a = Data([0])
    let b = Data([1])
    let c = Data([2])
    let old = Data([99])
    let policy = try V3RecoveryContentAncestry(
      floor: a, order: [a, b, c], parents: [a: [old], b: [a], c: [a]])
    #expect(try policy.nearestCommonAncestors(of: [b, c]) == [a])
    #expect(try policy.nextAdvance(after: c, to: c) == nil)
    #expect(throws: V3RecoveryValidationError.invalidTransition) {
      try policy.nextAdvance(after: b, to: c)
    }
    #expect(throws: V3RecoveryValidationError.invalidTransition) {
      try policy.nearestCommonAncestors(of: [old])
    }
  }
}
