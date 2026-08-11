import CryptoKit
import Foundation

enum V3DeviceWrappedCatchUpError: Error, Equatable, LocalizedError {
    case temporaryUnavailable
    case checkpointChanged
    case authenticationCancelled
    case deviceRevoked
    case upgradeRequired
    case recoveryRequired

    var errorDescription: String? {
        switch self {
        case .temporaryUnavailable:
            "Authenticated newer vault state is not completely available from the file provider yet."
        case .checkpointChanged:
            "The trusted vault checkpoint changed during catch-up. Retry the operation."
        case .authenticationCancelled:
            "Device authentication was cancelled during vault catch-up."
        case .deviceRevoked:
            "This Mac has been revoked and cannot open the next vault-key epoch."
        case .upgradeRequired:
            "Newer authenticated vault history requires a newer version of Key."
        case .recoveryRequired:
            "Authenticated vault catch-up found invalid or substituted state. Recovery is required."
        }
    }
}

enum V3DeviceWrappedSameEpochCatchUpStepOutcome: Equatable, Sendable {
    case upToDate(V3DeviceWrappedTrustedCheckpoint)
    case advancedOneStep(V3DeviceWrappedTrustedCheckpoint)
    case multipleHeads([Data])
}

protocol V3DeviceWrappedSameEpochCatchUpStepServicing: Sendable {
    func inspect(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data
    ) throws -> V3DeviceWrappedCatchUpPlan

    func advance(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data,
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint
}

/// Advances one device by one unambiguous content manifest within its current
/// vault-key epoch.
///
/// The helper mutation owner serializes this local trust change with ordinary
/// publication and enrollment. The live observer authenticates the complete
/// forward graph before this service reopens the next direct child, validates
/// its complete encrypted snapshot, and compare-and-swaps the exact checkpoint.
/// A later coordinator repeats this step while checking for key transitions at
/// every newly trusted checkpoint.
struct V3DeviceWrappedSameEpochCatchUpService: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let stateLoader: any V3DeviceWrappedMutationStateLoading
    private let stepService: V3DeviceWrappedSameEpochCatchUpStepService

    init(
        vaultID: String,
        mutationOwner: any VaultTransactionMutationOwning,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        precondition(isValidV3UUID(vaultID))
        self.mutationOwner = mutationOwner
        self.stateLoader = stateLoader
        stepService = V3DeviceWrappedSameEpochCatchUpStepService(
            vaultID: vaultID,
            repositoryObserver: repositoryObserver,
            source: source,
            checkpointStore: checkpointStore,
            cache: cache,
            limits: limits
        )
    }

    func advanceOneStep()
        throws -> V3DeviceWrappedSameEpochCatchUpStepOutcome
    {
        try mutationOwner.perform(.catchUpVault) { _ in
            let trusted = try stateLoader.authenticatedCheckpoint(
                reason: "Unlock version 3 vault to authenticate newer device history."
            )
            let vaultKey = try stateLoader.loadVaultKey(
                keyID: trusted.envelope.body.keyID
            )
            let plan = try stepService.inspect(
                trusted: trusted,
                vaultKey: vaultKey
            )
            switch plan {
            case .upToDate:
                return .upToDate(trusted)
            case let .multipleHeads(heads):
                return .multipleHeads(heads)
            case let .advance(expectedCheckpoint, manifestDigests):
                guard let nextManifestDigest = manifestDigests.first else {
                    throw V3DeviceWrappedCatchUpError.recoveryRequired
                }
                return .advancedOneStep(try stepService.advance(
                    trusted: trusted,
                    vaultKey: vaultKey,
                    expectedCheckpoint: expectedCheckpoint,
                    manifestDigest: nextManifestDigest
                ))
            }
        }
    }
}

/// Read-only inspection and guarded one-manifest advancement used by the
/// authority-aware catch-up coordinator while it owns mutation serialization.
struct V3DeviceWrappedSameEpochCatchUpStepService:
    V3DeviceWrappedSameEpochCatchUpStepServicing,
    Sendable
{
    private let vaultID: String
    private let repositoryObserver: any V3DeviceWrappedRepositoryObserving
    private let source: any V3ImmutableObjectReading
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let planner: V3DeviceWrappedCatchUpPlanner
    private let contentValidator: V3DeviceWrappedCheckpointContentValidator
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()

    init(
        vaultID: String,
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.repositoryObserver = repositoryObserver
        self.source = source
        self.checkpointStore = checkpointStore
        self.cache = cache
        self.limits = limits
        planner = V3DeviceWrappedCatchUpPlanner(limits: limits)
        contentValidator = V3DeviceWrappedCheckpointContentValidator(
            source: source,
            limits: limits
        )
    }

    func inspect(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data
    ) throws -> V3DeviceWrappedCatchUpPlan {
        guard trusted.checkpoint.vaultID == vaultID else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        let observation: V3DeviceWrappedRepositoryObservation
        do {
            observation = try repositoryObserver.observeRepository(
                from: trusted,
                vaultKeys: [vaultKey]
            )
        } catch let error as V3ImmutableTransactionError {
            throw catchUpError(for: error)
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        guard observation.checkpoint == trusted.checkpoint else {
            throw V3DeviceWrappedCatchUpError.checkpointChanged
        }

        do {
            return try planner.plan(observation, vaultID: vaultID)
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }

    func advance(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data,
        expectedCheckpoint: V3ManifestCheckpoint,
        manifestDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard expectedCheckpoint == trusted.checkpoint else {
            throw V3DeviceWrappedCatchUpError.checkpointChanged
        }
        let manifestData = try loadManifest(manifestDigest)
        let envelope: V3DeviceWrappedManifestEnvelope
        do {
            envelope = try envelopeCodec.parse(manifestData)
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        guard envelope.parents == [expectedCheckpoint.envelopeDigest],
              hasSameAuthority(envelope, trusted.envelope),
              envelope.authorizations.isEmpty,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  envelope.authenticationTag,
                  canonicalContent: envelope.canonicalContentBytes,
                  vaultID: vaultID,
                  vaultKey: vaultKey
              )) == true
        else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }

        switch try contentValidator.validate(
            entries: envelope.body.entries,
            vaultID: vaultID
        ) {
        case .ready:
            break
        case .incomplete:
            throw V3DeviceWrappedCatchUpError.temporaryUnavailable
        case .invalid, .resourceLimitExceeded:
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }

        let checkpoint: V3ManifestCheckpoint
        do {
            checkpoint = try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: manifestDigest
            )
            try checkpointStore.replaceCheckpoint(
                checkpoint.canonicalBytes,
                expectedCheckpoint: trusted.checkpoint.canonicalBytes,
                vaultID: vaultID
            )
        } catch V3ManifestCheckpointStoreError.conflict {
            throw V3DeviceWrappedCatchUpError.checkpointChanged
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }

        // The provider object was reopened immediately before the guarded
        // checkpoint change. Caching is an availability optimization; failure
        // cannot revoke the authority now held by the local checkpoint.
        try? cache.store(manifestData, for: checkpoint)
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: envelope
        )
    }

    private func loadManifest(_ digest: Data) throws -> Data {
        let read: V3RepositoryObjectRead
        do {
            read = try source.readManifest(
                digest: digest,
                maximumBytes: limits.maximumManifestBytes
            )
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        switch read {
        case let .available(data)
            where data.count <= limits.maximumManifestBytes
                && Data(SHA256.hash(data: data)) == digest:
            return data
        case .unavailable:
            throw V3DeviceWrappedCatchUpError.temporaryUnavailable
        case .available, .invalid, .tooLarge:
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }

    private func hasSameAuthority(
        _ lhs: V3DeviceWrappedManifestEnvelope,
        _ rhs: V3DeviceWrappedManifestEnvelope
    ) -> Bool {
        lhs.body.keyID == rhs.body.keyID
            && lhs.body.authorityTransitionID
                == rhs.body.authorityTransitionID
            && lhs.body.devices == rhs.body.devices
            && lhs.body.wrappedKeys == rhs.body.wrappedKeys
    }

    private func catchUpError(
        for error: V3ImmutableTransactionError
    ) -> V3DeviceWrappedCatchUpError {
        switch error {
        case .referencedEntryUnavailable, .publishedManifestUnavailable:
            .temporaryUnavailable
        case .expectedHeadsChanged:
            .checkpointChanged
        case .invalidAncestryProof, .unresolvedConflict,
            .candidateDoesNotMatchAutomaticMerge, .duplicateStagedEntry,
            .invalidStagedEntry, .objectTooLarge, .referencedEntryInvalid,
            .publishedManifestInvalid:
            .recoveryRequired
        }
    }
}
