import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedCatchUpPlannerTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c74b3"
    private static let checkpointDigest = Data(repeating: 0x11, count: 32)
    private static let firstChildDigest = Data(repeating: 0x22, count: 32)
    private static let secondChildDigest = Data(repeating: 0x33, count: 32)
    private static let forkDigest = Data(repeating: 0x44, count: 32)

    @Test
    func reportsAnExactCheckpointAsUpToDate() throws {
        let observation = try observation(
            heads: [Self.checkpointDigest],
            parents: [Self.checkpointDigest: []]
        )

        let plan = try V3DeviceWrappedCatchUpPlanner().plan(
            observation,
            vaultID: Self.vaultID
        )

        #expect(plan == .upToDate)
    }

    @Test
    func returnsTheOrderedPathFromCheckpointToHead() throws {
        let observation = try observation(
            heads: [Self.secondChildDigest],
            parents: [
                Self.checkpointDigest: [],
                Self.firstChildDigest: [Self.checkpointDigest],
                Self.secondChildDigest: [Self.firstChildDigest],
            ]
        )

        let plan = try V3DeviceWrappedCatchUpPlanner().plan(
            observation,
            vaultID: Self.vaultID
        )

        #expect(plan == .advance(
            expectedCheckpoint: observation.checkpoint,
            manifestDigests: [
                Self.firstChildDigest,
                Self.secondChildDigest,
            ]
        ))
    }

    @Test
    func preservesMultipleHeadsForAuthorityAwareClassification() throws {
        let heads = [Self.secondChildDigest, Self.forkDigest].sorted(by: {
            $0.lexicographicallyPrecedes($1)
        })
        let observation = try observation(
            heads: heads,
            parents: [
                Self.checkpointDigest: [],
                Self.firstChildDigest: [Self.checkpointDigest],
                Self.secondChildDigest: [Self.firstChildDigest],
                Self.forkDigest: [Self.firstChildDigest],
            ]
        )

        let plan = try V3DeviceWrappedCatchUpPlanner().plan(
            observation,
            vaultID: Self.vaultID
        )

        #expect(plan == .multipleHeads(heads))
    }

    @Test
    func rejectsAHeadThatDoesNotDescendFromTheCheckpoint() throws {
        let observation = try observation(
            heads: [Self.firstChildDigest],
            parents: [
                Self.checkpointDigest: [],
                Self.firstChildDigest: [Self.secondChildDigest],
                Self.secondChildDigest: [Self.firstChildDigest],
            ]
        )

        #expect(throws: V3ImmutableTransactionError.invalidAncestryProof) {
            _ = try V3DeviceWrappedCatchUpPlanner().plan(
                observation,
                vaultID: Self.vaultID
            )
        }
    }

    @Test
    func rejectsHeadsThatDoNotMatchTheGraph() throws {
        let observation = try observation(
            heads: [Self.firstChildDigest],
            parents: [
                Self.checkpointDigest: [],
                Self.firstChildDigest: [Self.checkpointDigest],
                Self.secondChildDigest: [Self.firstChildDigest],
            ]
        )

        #expect(throws: V3ImmutableTransactionError.invalidAncestryProof) {
            _ = try V3DeviceWrappedCatchUpPlanner().plan(
                observation,
                vaultID: Self.vaultID
            )
        }
    }

    @Test
    func enforcesTheHistoryDepthWhileBuildingThePath() throws {
        let limits = V3ManifestRepositoryLimits(
            maximumManifestObjects: 4,
            maximumHistoryDepth: 1
        )
        let observation = try observation(
            heads: [Self.secondChildDigest],
            parents: [
                Self.checkpointDigest: [],
                Self.firstChildDigest: [Self.checkpointDigest],
                Self.secondChildDigest: [Self.firstChildDigest],
            ],
            maximumHistoryDepth: 1
        )

        #expect(throws: V3ImmutableTransactionError.invalidAncestryProof) {
            _ = try V3DeviceWrappedCatchUpPlanner(limits: limits).plan(
                observation,
                vaultID: Self.vaultID
            )
        }
    }

    private func observation(
        heads: [Data],
        parents: [Data: [Data]],
        maximumHistoryDepth: Int? = nil
    ) throws -> V3DeviceWrappedRepositoryObservation {
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Self.checkpointDigest
        )
        return V3DeviceWrappedRepositoryObservation(
            checkpoint: checkpoint,
            heads: heads,
            manifestDigests: Set(parents.keys),
            parentsByManifestDigest: parents,
            referencedEntryObjects: [],
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount: parents.count,
                maximumHistoryDepth:
                    maximumHistoryDepth ?? max(0, parents.count - 1),
                totalManifestBytes: parents.count,
                referencedEntryObjectCount: 0,
                totalEntryBytes: 0
            )
        )
    }
}
