import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedCatchUpCoordinatorTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96ca4b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96ca4b4"
    private static let vaultKey = Data(0..<32)

    @Test
    func advancesContentThenAKeyEpochUnderOneMutationBoundary() throws {
        let fixture = try Fixture()
        let keyManifestData = Data("owner transition".utf8)
        let keyManifestDigest = Data(SHA256.hash(data: keyManifestData))
        let afterKey = try fixture.trusted(digest: keyManifestDigest)
        fixture.content.plans = [
            fixture.initial.checkpoint.envelopeDigest: .advance(
                expectedCheckpoint: fixture.initial.checkpoint,
                manifestDigests: [fixture.afterContent.checkpoint.envelopeDigest]
            ),
            fixture.afterContent.checkpoint.envelopeDigest: .upToDate,
            afterKey.checkpoint.envelopeDigest: .upToDate,
        ]
        fixture.discovery.outcomes = [
            fixture.initial.checkpoint.envelopeDigest: .none,
            fixture.afterContent.checkpoint.envelopeDigest: .candidate(
                manifestData: keyManifestData,
                manifestDigest: keyManifestDigest
            ),
            afterKey.checkpoint.envelopeDigest: .none,
        ]
        fixture.content.advances = [
            fixture.afterContent.checkpoint.envelopeDigest:
                fixture.afterContent,
        ]
        fixture.keyTransitions.advances = [keyManifestDigest: afterKey]

        let outcome = try fixture.coordinator().catchUp()

        #expect(outcome == .current(
            afterKey,
            progress: V3DeviceWrappedCatchUpProgress(
                contentManifestCount: 1,
                keyEpochCount: 1
            )
        ))
        #expect(fixture.owner.kinds == [.catchUpVault])
        #expect(fixture.content.advancedDigests
            == [fixture.afterContent.checkpoint.envelopeDigest])
        #expect(fixture.keyTransitions.advancedDigests
            == [keyManifestDigest])
    }

    @Test
    func refusesAContentAndKeyTransitionForkBeforeEitherAdvances() throws {
        let fixture = try Fixture()
        let keyManifestData = Data("competing transition".utf8)
        let keyManifestDigest = Data(SHA256.hash(data: keyManifestData))
        fixture.content.plans = [
            fixture.initial.checkpoint.envelopeDigest: .advance(
                expectedCheckpoint: fixture.initial.checkpoint,
                manifestDigests: [fixture.afterContent.checkpoint.envelopeDigest]
            ),
        ]
        fixture.discovery.outcomes = [
            fixture.initial.checkpoint.envelopeDigest: .candidate(
                manifestData: keyManifestData,
                manifestDigest: keyManifestDigest
            ),
        ]
        let expected = [
            fixture.afterContent.checkpoint.envelopeDigest,
            keyManifestDigest,
        ].sorted(by: { $0.lexicographicallyPrecedes($1) })

        let outcome = try fixture.coordinator().catchUp()

        #expect(outcome == .securityConflict(
            fixture.initial,
            manifestDigests: expected,
            progress: V3DeviceWrappedCatchUpProgress(
                contentManifestCount: 0,
                keyEpochCount: 0
            )
        ))
        #expect(fixture.content.advancedDigests.isEmpty)
        #expect(fixture.keyTransitions.advancedDigests.isEmpty)
        #expect(fixture.state.trusted == fixture.initial)
    }

    @Test
    func preservesContentForksForExplicitResolution() throws {
        let fixture = try Fixture()
        let heads = [
            fixture.afterContent.checkpoint.envelopeDigest,
            Data(repeating: 0x33, count: 32),
        ].sorted(by: { $0.lexicographicallyPrecedes($1) })
        fixture.content.plans = [
            fixture.initial.checkpoint.envelopeDigest: .multipleHeads(heads),
        ]
        fixture.discovery.outcomes = [
            fixture.initial.checkpoint.envelopeDigest: .none,
        ]

        let outcome = try fixture.coordinator().catchUp()

        #expect(outcome == .contentConflict(
            fixture.initial,
            manifestDigests: heads,
            progress: V3DeviceWrappedCatchUpProgress(
                contentManifestCount: 0,
                keyEpochCount: 0
            )
        ))
        #expect(fixture.content.advancedDigests.isEmpty)
        #expect(fixture.keyTransitions.advancedDigests.isEmpty)
    }

    @Test
    func boundsCheckpointAdvancementAcrossRepeatedObservations() throws {
        let fixture = try Fixture()
        let third = try fixture.trusted(digest: Data(repeating: 0x44, count: 32))
        fixture.content.plans = [
            fixture.initial.checkpoint.envelopeDigest: .advance(
                expectedCheckpoint: fixture.initial.checkpoint,
                manifestDigests: [fixture.afterContent.checkpoint.envelopeDigest]
            ),
            fixture.afterContent.checkpoint.envelopeDigest: .advance(
                expectedCheckpoint: fixture.afterContent.checkpoint,
                manifestDigests: [third.checkpoint.envelopeDigest]
            ),
        ]
        fixture.discovery.outcomes = [
            fixture.initial.checkpoint.envelopeDigest: .none,
            fixture.afterContent.checkpoint.envelopeDigest: .none,
        ]
        fixture.content.advances = [
            fixture.afterContent.checkpoint.envelopeDigest:
                fixture.afterContent,
            third.checkpoint.envelopeDigest: third,
        ]

        #expect(throws: V3DeviceWrappedCatchUpError.recoveryRequired) {
            _ = try fixture.coordinator(maximumStepCount: 1).catchUp()
        }

        #expect(fixture.state.trusted == fixture.afterContent)
        #expect(fixture.content.advancedDigests
            == [fixture.afterContent.checkpoint.envelopeDigest])
    }

    @Test
    func catchesAKeyTransitionThatArrivesAfterItsParentAdvances() throws {
        let fixture = try Fixture()
        let lateData = Data("late owner transition".utf8)
        let lateDigest = Data(SHA256.hash(data: lateData))
        fixture.content.plans = [
            fixture.initial.checkpoint.envelopeDigest: .advance(
                expectedCheckpoint: fixture.initial.checkpoint,
                manifestDigests: [fixture.afterContent.checkpoint.envelopeDigest]
            ),
            fixture.afterContent.checkpoint.envelopeDigest: .upToDate,
        ]
        fixture.discovery.outcomeSequences = [
            fixture.initial.checkpoint.envelopeDigest: [
                .none,
                .candidate(
                    manifestData: lateData,
                    manifestDigest: lateDigest
                ),
            ],
            fixture.afterContent.checkpoint.envelopeDigest: [.none],
        ]
        fixture.content.advances = [
            fixture.afterContent.checkpoint.envelopeDigest:
                fixture.afterContent,
        ]

        let outcome = try fixture.coordinator().catchUp()

        #expect(outcome == .securityConflict(
            fixture.afterContent,
            manifestDigests: [lateDigest],
            progress: V3DeviceWrappedCatchUpProgress(
                contentManifestCount: 1,
                keyEpochCount: 0
            )
        ))
    }

    @Test
    func catchesContentThatArrivesAfterAKeyTransitionAdvances() throws {
        let fixture = try Fixture()
        let keyData = Data("accepted owner transition".utf8)
        let keyDigest = Data(SHA256.hash(data: keyData))
        let afterKey = try fixture.trusted(digest: keyDigest)
        let lateContent = Data(repeating: 0x55, count: 32)
        fixture.content.planSequences = [
            fixture.initial.checkpoint.envelopeDigest: [
                .upToDate,
                .advance(
                    expectedCheckpoint: fixture.initial.checkpoint,
                    manifestDigests: [lateContent]
                ),
            ],
            afterKey.checkpoint.envelopeDigest: [.upToDate],
        ]
        fixture.discovery.outcomes = [
            fixture.initial.checkpoint.envelopeDigest: .candidate(
                manifestData: keyData,
                manifestDigest: keyDigest
            ),
            afterKey.checkpoint.envelopeDigest: .none,
        ]
        fixture.keyTransitions.advances = [keyDigest: afterKey]

        let outcome = try fixture.coordinator().catchUp()

        #expect(outcome == .securityConflict(
            afterKey,
            manifestDigests: [lateContent],
            progress: V3DeviceWrappedCatchUpProgress(
                contentManifestCount: 0,
                keyEpochCount: 1
            )
        ))
    }

    @Test
    func preservesLateSameEpochSiblingsAsContentConflicts() throws {
        let fixture = try Fixture()
        let accepted = fixture.afterContent.checkpoint.envelopeDigest
        let late = Data(repeating: 0x66, count: 32)
        let heads = [accepted, late].sorted(by: {
            $0.lexicographicallyPrecedes($1)
        })
        fixture.content.planSequences = [
            fixture.initial.checkpoint.envelopeDigest: [
                .advance(
                    expectedCheckpoint: fixture.initial.checkpoint,
                    manifestDigests: [accepted]
                ),
                .multipleHeads(heads),
            ],
            fixture.afterContent.checkpoint.envelopeDigest: [.upToDate],
        ]
        fixture.discovery.outcomes = [
            fixture.initial.checkpoint.envelopeDigest: .none,
            fixture.afterContent.checkpoint.envelopeDigest: .none,
        ]
        fixture.content.advances = [accepted: fixture.afterContent]

        let outcome = try fixture.coordinator().catchUp()

        #expect(outcome == .contentConflict(
            fixture.afterContent,
            manifestDigests: heads,
            progress: V3DeviceWrappedCatchUpProgress(
                contentManifestCount: 1,
                keyEpochCount: 0
            )
        ))
    }

    @Test
    func accessGateAllowsOnlyExplicitStaleContentFallback() throws {
        let fixture = try Fixture()
        let progress = V3DeviceWrappedCatchUpProgress(
            contentManifestCount: 0,
            keyEpochCount: 0
        )
        let digest = Data(repeating: 0x77, count: 32)
        let gate = V3DeviceWrappedCatchUpAccessGate()

        #expect(throws: V3DeviceWrappedCatchUpError.temporaryUnavailable) {
            try gate.requireCurrent {
                .contentConflict(
                    fixture.initial,
                    manifestDigests: [digest],
                    progress: progress
                )
            }
        }
        try gate.requireCurrent(allowStale: true) {
            .contentConflict(
                fixture.initial,
                manifestDigests: [digest],
                progress: progress
            )
        }
        #expect(throws: V3DeviceWrappedCatchUpError.recoveryRequired) {
            try gate.requireCurrent(allowStale: true) {
                .securityConflict(
                    fixture.initial,
                    manifestDigests: [digest],
                    progress: progress
                )
            }
        }
    }

    private final class Fixture: @unchecked Sendable {
        let initial: V3DeviceWrappedTrustedCheckpoint
        let afterContent: V3DeviceWrappedTrustedCheckpoint
        let state: CatchUpCoordinatorState
        let owner = CatchUpCoordinatorMutationOwner()
        let content: CatchUpCoordinatorContentSteps
        let discovery = CatchUpCoordinatorTransitionDiscovery()
        let keyTransitions: CatchUpCoordinatorKeyTransitionSteps

        init() throws {
            let signingKey = try P256.Signing.PrivateKey(
                rawRepresentation: Data(repeating: 0x11, count: 32)
            )
            let wrappingKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: Data(repeating: 0x12, count: 32)
            )
            let identity = try V3EnrollmentDeviceIdentity(
                displayName: "Catch-up Mac",
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey: wrappingKey.publicKey.x963Representation
            )
            let genesis = try V3DeviceWrappedGenesisBuilder()
                .buildPublicationCandidate(
                    vaultID: V3DeviceWrappedCatchUpCoordinatorTests.vaultID,
                    authorityTransitionID:
                        V3DeviceWrappedCatchUpCoordinatorTests.transitionID,
                    entryIDs: [],
                    sourceEntries: [],
                    vaultKey: V3DeviceWrappedCatchUpCoordinatorTests.vaultKey,
                    ownerIdentity: identity
                ).genesis
            let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
                genesis.manifestData
            )
            initial = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: try V3ManifestCheckpoint(
                    vaultID: V3DeviceWrappedCatchUpCoordinatorTests.vaultID,
                    envelopeDigest: Data(repeating: 0x11, count: 32)
                ),
                envelope: envelope
            )
            afterContent = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: try V3ManifestCheckpoint(
                    vaultID: V3DeviceWrappedCatchUpCoordinatorTests.vaultID,
                    envelopeDigest: Data(repeating: 0x22, count: 32)
                ),
                envelope: envelope
            )
            state = CatchUpCoordinatorState(
                trusted: initial,
                vaultKey: V3DeviceWrappedCatchUpCoordinatorTests.vaultKey
            )
            content = CatchUpCoordinatorContentSteps(state: state)
            keyTransitions = CatchUpCoordinatorKeyTransitionSteps(state: state)
        }

        func trusted(digest: Data) throws
            -> V3DeviceWrappedTrustedCheckpoint
        {
            V3DeviceWrappedTrustedCheckpoint(
                checkpoint: try V3ManifestCheckpoint(
                    vaultID: V3DeviceWrappedCatchUpCoordinatorTests.vaultID,
                    envelopeDigest: digest
                ),
                envelope: initial.envelope
            )
        }

        func coordinator(
            maximumStepCount: Int = 32
        ) -> V3DeviceWrappedCatchUpCoordinator {
            V3DeviceWrappedCatchUpCoordinator(
                vaultID: V3DeviceWrappedCatchUpCoordinatorTests.vaultID,
                mutationOwner: owner,
                stateLoader: state,
                contentSteps: content,
                keyTransitionDiscovery: discovery,
                keyTransitionSteps: keyTransitions,
                maximumStepCount: maximumStepCount
            )
        }
    }
}

private final class CatchUpCoordinatorState:
    V3DeviceWrappedMutationStateLoading,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var value: V3DeviceWrappedTrustedCheckpoint
    private let vaultKey: Data

    init(trusted: V3DeviceWrappedTrustedCheckpoint, vaultKey: Data) {
        value = trusted
        self.vaultKey = vaultKey
    }

    var trusted: V3DeviceWrappedTrustedCheckpoint {
        lock.withLock { value }
    }

    func replace(_ trusted: V3DeviceWrappedTrustedCheckpoint) {
        lock.withLock { value = trusted }
    }

    func authenticatedCheckpoint(
        reason _: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        trusted
    }

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
        #expect(keyID == trusted.envelope.body.keyID)
        return vaultKey
    }
}

private final class CatchUpCoordinatorContentSteps:
    V3DeviceWrappedSameEpochCatchUpStepServicing,
    @unchecked Sendable
{
    let state: CatchUpCoordinatorState
    var plans: [Data: V3DeviceWrappedCatchUpPlan] = [:]
    var planSequences: [Data: [V3DeviceWrappedCatchUpPlan]] = [:]
    var advances: [Data: V3DeviceWrappedTrustedCheckpoint] = [:]
    private(set) var advancedDigests: [Data] = []

    init(state: CatchUpCoordinatorState) {
        self.state = state
    }

    func inspect(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey _: Data
    ) throws -> V3DeviceWrappedCatchUpPlan {
        if var sequence = planSequences[
            trusted.checkpoint.envelopeDigest
        ], !sequence.isEmpty {
            let plan = sequence.removeFirst()
            planSequences[trusted.checkpoint.envelopeDigest] = sequence
            return plan
        }
        guard let plan = plans[trusted.checkpoint.envelopeDigest] else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return plan
    }

    func advance(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey _: Data,
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard trusted.checkpoint == expectedCheckpoint,
              let next = advances[manifestDigest]
        else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        advancedDigests.append(manifestDigest)
        state.replace(next)
        return next
    }
}

private final class CatchUpCoordinatorTransitionDiscovery:
    V3DeviceWrappedKeyTransitionDiscovering,
    @unchecked Sendable
{
    var outcomes: [Data: V3DeviceWrappedKeyTransitionDiscoveryOutcome] = [:]
    var outcomeSequences:
        [Data: [V3DeviceWrappedKeyTransitionDiscoveryOutcome]] = [:]

    func discover(
        from parent: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey _: Data
    ) throws -> V3DeviceWrappedKeyTransitionDiscoveryOutcome {
        if var sequence = outcomeSequences[
            parent.checkpoint.envelopeDigest
        ], !sequence.isEmpty {
            let outcome = sequence.removeFirst()
            outcomeSequences[parent.checkpoint.envelopeDigest] = sequence
            return outcome
        }
        guard let outcome = outcomes[parent.checkpoint.envelopeDigest] else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return outcome
    }
}

private final class CatchUpCoordinatorKeyTransitionSteps:
    V3DeviceWrappedKeyTransitionCatchUpStepServicing,
    @unchecked Sendable
{
    let state: CatchUpCoordinatorState
    var advances: [Data: V3DeviceWrappedTrustedCheckpoint] = [:]
    private(set) var advancedDigests: [Data] = []

    init(state: CatchUpCoordinatorState) {
        self.state = state
    }

    func advanceOneEpoch(
        manifestData _: Data,
        manifestDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard let next = advances[manifestDigest] else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        advancedDigests.append(manifestDigest)
        state.replace(next)
        return next
    }
}

private final class CatchUpCoordinatorMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private(set) var kinds: [VaultTransactionMutationKind] = []

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        kinds.append(kind)
        return try mutation(VaultTransactionMutationContext(
            operationID: VaultTransactionOperationID(),
            kind: kind
        ))
    }
}
