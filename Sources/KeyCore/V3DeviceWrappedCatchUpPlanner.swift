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
