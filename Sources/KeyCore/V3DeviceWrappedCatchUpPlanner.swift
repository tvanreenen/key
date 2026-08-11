import CryptoKit
import Foundation

/// The safe next action derived from one authenticated repository snapshot.
///
/// Planning is deliberately read-only. Advancing the device-local checkpoint
/// remains a separate, serialized operation that must recheck the expected
/// checkpoint captured here.
enum V3DeviceWrappedCatchUpPlan: Equatable, Sendable {
    case upToDate
    case advance(
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestDigests: [Data]
    )
    /// More than one authenticated descendant remains. A later authority-aware
    /// layer decides whether these are reconcilable content heads or a
    /// competing key transition; this planner never merges them implicitly.
    case multipleHeads([Data])
}

/// One authority-aware action selected before any checkpoint is changed.
enum V3DeviceWrappedCatchUpAction: Equatable, Sendable {
    case upToDate
    /// Advance exactly one manifest, then rediscover both content and key
    /// transitions from the newly trusted checkpoint before proceeding.
    case advanceContent(
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestDigest: Data
    )
    case advanceKey(manifestData: Data, manifestDigest: Data)
    case contentConflict([Data])
    case securityConflict([Data])
}

/// Combines independently authenticated same-key history and key-transition
/// discovery without silently preferring one competing authority branch.
///
/// This remains a read-only decision. The selected content or key-transition
/// service must still reopen its inputs and compare-and-swap the checkpoint.
struct V3DeviceWrappedCatchUpAuthorityPlanner: Sendable {
    func plan(
        content: V3DeviceWrappedCatchUpPlan,
        keyTransition: V3DeviceWrappedKeyTransitionDiscoveryOutcome
    ) throws -> V3DeviceWrappedCatchUpAction {
        let contentHeads = try validatedContentHeads(content)
        let keyHeads = try validatedKeyHeads(keyTransition)

        if keyHeads.count > 1 || (!contentHeads.isEmpty && !keyHeads.isEmpty) {
            return .securityConflict(sortedUnique(contentHeads + keyHeads))
        }
        switch (content, keyTransition) {
        case (.upToDate, .none):
            return .upToDate
        case let (.advance(expectedCheckpoint, manifestDigests), .none):
            guard let nextManifestDigest = manifestDigests.first else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return .advanceContent(
                expectedCheckpoint: expectedCheckpoint,
                manifestDigest: nextManifestDigest
            )
        case let (.multipleHeads(heads), .none):
            return .contentConflict(heads)
        case let (.upToDate, .candidate(manifestData, manifestDigest)):
            return .advanceKey(
                manifestData: manifestData,
                manifestDigest: manifestDigest
            )
        case (.advance, .candidate), (.multipleHeads, .candidate),
                (.upToDate, .competingCandidates),
                (.advance, .competingCandidates),
                (.multipleHeads, .competingCandidates):
            // Every conflicting combination returned above. Keeping these
            // cases explicit makes future enum additions fail at compile time.
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
    }

    private func validatedContentHeads(
        _ plan: V3DeviceWrappedCatchUpPlan
    ) throws -> [Data] {
        switch plan {
        case .upToDate:
            return []
        case let .advance(expectedCheckpoint, manifestDigests):
            guard !manifestDigests.isEmpty,
                  expectedCheckpoint.envelopeDigest.count == 32,
                  manifestDigests.allSatisfy({ $0.count == 32 }),
                  Set(manifestDigests).count == manifestDigests.count,
                  let head = manifestDigests.last
            else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return [head]
        case let .multipleHeads(heads):
            guard heads.count > 1,
                  heads.allSatisfy({ $0.count == 32 }),
                  Set(heads).count == heads.count,
                  heads == heads.sorted(by: {
                      $0.lexicographicallyPrecedes($1)
                  })
            else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return heads
        }
    }

    private func validatedKeyHeads(
        _ outcome: V3DeviceWrappedKeyTransitionDiscoveryOutcome
    ) throws -> [Data] {
        switch outcome {
        case .none:
            return []
        case let .candidate(manifestData, manifestDigest):
            guard manifestDigest.count == 32,
                  Data(SHA256.hash(data: manifestData)) == manifestDigest
            else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return [manifestDigest]
        case let .competingCandidates(digests):
            guard digests.count > 1,
                  digests.allSatisfy({ $0.count == 32 }),
                  Set(digests).count == digests.count,
                  digests == digests.sorted(by: {
                      $0.lexicographicallyPrecedes($1)
                  })
            else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return digests
        }
    }

    private func sortedUnique(_ digests: [Data]) -> [Data] {
        Array(Set(digests)).sorted(by: {
            $0.lexicographicallyPrecedes($1)
        })
    }
}

/// Converts an observer-authenticated manifest graph into a bounded catch-up
/// decision without assigning authority to provider ordering or timestamps.
struct V3DeviceWrappedCatchUpPlanner: Sendable {
    private let limits: V3ManifestRepositoryLimits
    private let usageValidator: V3DeviceWrappedRepositoryUsageValidator

    init(limits: V3ManifestRepositoryLimits = .standard) {
        self.limits = limits
        usageValidator = V3DeviceWrappedRepositoryUsageValidator(
            limits: limits
        )
    }

    func plan(
        _ observation: V3DeviceWrappedRepositoryObservation,
        vaultID: String
    ) throws -> V3DeviceWrappedCatchUpPlan {
        let state = try usageValidator.validatedState(
            observation,
            vaultID: vaultID
        )
        let pathsByHead = try validatedPaths(
            from: state.checkpoint.envelopeDigest,
            heads: state.heads,
            parentsByManifestDigest:
                observation.parentsByManifestDigest
        )

        if state.heads.count > 1 {
            return .multipleHeads(state.heads)
        }
        guard let head = state.heads.first,
              let path = pathsByHead[head]
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        guard !path.isEmpty else {
            return .upToDate
        }
        return .advance(
            expectedCheckpoint: state.checkpoint,
            manifestDigests: path
        )
    }

    private func validatedPaths(
        from checkpointDigest: Data,
        heads: [Data],
        parentsByManifestDigest: [Data: [Data]]
    ) throws -> [Data: [Data]] {
        guard parentsByManifestDigest[checkpointDigest] == [] else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        let referencedParents = Set(
            parentsByManifestDigest.values.flatMap { $0 }
        )
        let derivedHeads = parentsByManifestDigest.keys.filter {
            !referencedParents.contains($0)
        }.sorted(by: { $0.lexicographicallyPrecedes($1) })
        guard derivedHeads == heads else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        var pathsByHead: [Data: [Data]] = [:]
        var reachable: Set<Data> = [checkpointDigest]
        for head in heads {
            var reversePath: [Data] = []
            var visited: Set<Data> = []
            var cursor = head
            while cursor != checkpointDigest {
                guard visited.insert(cursor).inserted,
                      reversePath.count < limits.maximumHistoryDepth,
                      let parents = parentsByManifestDigest[cursor],
                      parents.count == 1,
                      let parent = parents.first
                else {
                    throw V3ImmutableTransactionError.invalidAncestryProof
                }
                reversePath.append(cursor)
                cursor = parent
            }
            let path = reversePath.reversed()
            reachable.formUnion(path)
            pathsByHead[head] = Array(path)
        }

        guard reachable == Set(parentsByManifestDigest.keys) else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return pathsByHead
    }
}
