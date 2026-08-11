import Foundation

struct V3DeviceWrappedCatchUpProgress: Equatable, Sendable {
    let contentManifestCount: Int
    let keyEpochCount: Int

    var totalStepCount: Int {
        contentManifestCount + keyEpochCount
    }
}

enum V3DeviceWrappedCatchUpCoordinatorOutcome: Equatable, Sendable {
    case current(
        V3DeviceWrappedTrustedCheckpoint,
        progress: V3DeviceWrappedCatchUpProgress
    )
    case contentConflict(
        V3DeviceWrappedTrustedCheckpoint,
        manifestDigests: [Data],
        progress: V3DeviceWrappedCatchUpProgress
    )
    case securityConflict(
        V3DeviceWrappedTrustedCheckpoint,
        manifestDigests: [Data],
        progress: V3DeviceWrappedCatchUpProgress
    )
}

/// Advances an offline device through authenticated content and key epochs.
///
/// One helper mutation boundary covers the complete operation. At every exact
/// checkpoint the coordinator authenticates same-key history, discovers direct
/// owner-authorized key transitions, selects one authority-safe action, and
/// commits at most one step before repeating from newly trusted local state.
struct V3DeviceWrappedCatchUpCoordinator: Sendable {
    private enum AcceptedChildKind: Sendable {
        case content
        case keyTransition
    }

    private struct PassedCheckpoint: Sendable {
        let trusted: V3DeviceWrappedTrustedCheckpoint
        let vaultKey: Data
        let acceptedChildDigest: Data
        let acceptedChildKind: AcceptedChildKind
    }

    private struct PassedCheckpointConflicts: Sendable {
        var content: Set<Data> = []
        var security: Set<Data> = []
    }

    private let vaultID: String
    private let mutationOwner: any VaultTransactionMutationOwning
    private let stateLoader: any V3DeviceWrappedMutationStateLoading
    private let contentSteps:
        any V3DeviceWrappedSameEpochCatchUpStepServicing
    private let keyTransitionDiscovery:
        any V3DeviceWrappedKeyTransitionDiscovering
    private let keyTransitionSteps:
        any V3DeviceWrappedKeyTransitionCatchUpStepServicing
    private let authorityPlanner = V3DeviceWrappedCatchUpAuthorityPlanner()
    private let maximumStepCount: Int

    init(
        vaultID: String,
        mutationOwner: any VaultTransactionMutationOwning,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        contentSteps: any V3DeviceWrappedSameEpochCatchUpStepServicing,
        keyTransitionDiscovery:
            any V3DeviceWrappedKeyTransitionDiscovering,
        keyTransitionSteps:
            any V3DeviceWrappedKeyTransitionCatchUpStepServicing,
        maximumStepCount: Int = V3ManifestRepositoryLimits.standard
            .maximumManifestObjects
    ) {
        precondition(isValidV3UUID(vaultID))
        precondition(maximumStepCount > 0)
        self.vaultID = vaultID
        self.mutationOwner = mutationOwner
        self.stateLoader = stateLoader
        self.contentSteps = contentSteps
        self.keyTransitionDiscovery = keyTransitionDiscovery
        self.keyTransitionSteps = keyTransitionSteps
        self.maximumStepCount = maximumStepCount
    }

    func catchUp() throws -> V3DeviceWrappedCatchUpCoordinatorOutcome {
        try mutationOwner.perform(.catchUpVault) { _ in
            var contentManifestCount = 0
            var keyEpochCount = 0
            var passedCheckpoints: [PassedCheckpoint] = []

            while true {
                let trusted = try stateLoader.authenticatedCheckpoint(
                    reason: "Unlock version 3 vault to authenticate newer device history."
                )
                guard trusted.checkpoint.vaultID == vaultID else {
                    throw V3DeviceWrappedCatchUpError.recoveryRequired
                }
                let vaultKey = try stateLoader.loadVaultKey(
                    keyID: trusted.envelope.body.keyID
                )
                let passedConflicts = try conflictsAfterPassedCheckpoints(
                    passedCheckpoints
                )
                if !passedConflicts.security.isEmpty {
                    return .securityConflict(
                        trusted,
                        manifestDigests: sorted(passedConflicts.security),
                        progress: V3DeviceWrappedCatchUpProgress(
                            contentManifestCount: contentManifestCount,
                            keyEpochCount: keyEpochCount
                        )
                    )
                }
                if !passedConflicts.content.isEmpty {
                    return .contentConflict(
                        trusted,
                        manifestDigests: sorted(passedConflicts.content),
                        progress: V3DeviceWrappedCatchUpProgress(
                            contentManifestCount: contentManifestCount,
                            keyEpochCount: keyEpochCount
                        )
                    )
                }
                let contentPlan = try contentSteps.inspect(
                    trusted: trusted,
                    vaultKey: vaultKey
                )
                let keyTransition = try keyTransitionDiscovery.discover(
                    from: trusted,
                    currentVaultKey: vaultKey
                )
                let action: V3DeviceWrappedCatchUpAction
                do {
                    action = try authorityPlanner.plan(
                        content: contentPlan,
                        keyTransition: keyTransition
                    )
                } catch {
                    throw V3DeviceWrappedCatchUpError.recoveryRequired
                }
                let progress = V3DeviceWrappedCatchUpProgress(
                    contentManifestCount: contentManifestCount,
                    keyEpochCount: keyEpochCount
                )

                switch action {
                case .upToDate:
                    return .current(trusted, progress: progress)
                case let .contentConflict(manifestDigests):
                    return .contentConflict(
                        trusted,
                        manifestDigests: manifestDigests,
                        progress: progress
                    )
                case let .securityConflict(manifestDigests):
                    return .securityConflict(
                        trusted,
                        manifestDigests: manifestDigests,
                        progress: progress
                    )
                case let .advanceContent(
                    expectedCheckpoint,
                    manifestDigest
                ):
                    try requireAnotherStep(progress)
                    let advanced = try contentSteps.advance(
                        trusted: trusted,
                        vaultKey: vaultKey,
                        expectedCheckpoint: expectedCheckpoint,
                        manifestDigest: manifestDigest
                    )
                    try validateAdvance(from: trusted, to: advanced)
                    passedCheckpoints.append(PassedCheckpoint(
                        trusted: trusted,
                        vaultKey: vaultKey,
                        acceptedChildDigest: manifestDigest,
                        acceptedChildKind: .content
                    ))
                    contentManifestCount += 1
                case let .advanceKey(manifestData, manifestDigest):
                    try requireAnotherStep(progress)
                    let advanced = try keyTransitionSteps.advanceOneEpoch(
                        manifestData: manifestData,
                        manifestDigest: manifestDigest
                    )
                    try validateAdvance(from: trusted, to: advanced)
                    passedCheckpoints.append(PassedCheckpoint(
                        trusted: trusted,
                        vaultKey: vaultKey,
                        acceptedChildDigest: manifestDigest,
                        acceptedChildKind: .keyTransition
                    ))
                    keyEpochCount += 1
                }
            }
        }
    }

    /// Rechecks every parent passed during this serialized operation. Provider
    /// arrival is not atomic with local checkpoint replacement, so a sibling
    /// may materialize only after its parent was advanced. The exact accepted
    /// child is harmless; any other authenticated continuation is a conflict.
    private func conflictsAfterPassedCheckpoints(
        _ passedCheckpoints: [PassedCheckpoint]
    ) throws -> PassedCheckpointConflicts {
        var conflicts = PassedCheckpointConflicts()
        for passed in passedCheckpoints {
            let content = try contentSteps.inspect(
                trusted: passed.trusted,
                vaultKey: passed.vaultKey
            )
            switch content {
            case .upToDate:
                break
            case let .advance(_, manifestDigests):
                guard let first = manifestDigests.first else {
                    throw V3DeviceWrappedCatchUpError.recoveryRequired
                }
                if first != passed.acceptedChildDigest,
                   let head = manifestDigests.last {
                    recordContentConflict(
                        head,
                        after: passed,
                        in: &conflicts
                    )
                }
            case let .multipleHeads(manifestDigests):
                for digest in manifestDigests {
                    recordContentConflict(
                        digest,
                        after: passed,
                        in: &conflicts
                    )
                }
            }

            let keyTransition = try keyTransitionDiscovery.discover(
                from: passed.trusted,
                currentVaultKey: passed.vaultKey
            )
            switch keyTransition {
            case .none:
                break
            case let .candidate(_, manifestDigest):
                if manifestDigest != passed.acceptedChildDigest {
                    conflicts.security.insert(manifestDigest)
                }
            case let .competingCandidates(manifestDigests):
                conflicts.security.formUnion(manifestDigests)
            }
        }
        return conflicts
    }

    private func recordContentConflict(
        _ digest: Data,
        after passed: PassedCheckpoint,
        in conflicts: inout PassedCheckpointConflicts
    ) {
        switch passed.acceptedChildKind {
        case .content:
            conflicts.content.insert(digest)
        case .keyTransition:
            conflicts.security.insert(digest)
        }
    }

    private func sorted(_ digests: Set<Data>) -> [Data] {
        digests.sorted(by: { $0.lexicographicallyPrecedes($1) })
    }

    private func requireAnotherStep(
        _ progress: V3DeviceWrappedCatchUpProgress
    ) throws {
        guard progress.totalStepCount < maximumStepCount else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }

    private func validateAdvance(
        from previous: V3DeviceWrappedTrustedCheckpoint,
        to advanced: V3DeviceWrappedTrustedCheckpoint
    ) throws {
        guard advanced.checkpoint.vaultID == vaultID,
              advanced.checkpoint != previous.checkpoint
        else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }
}
