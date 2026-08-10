import CryptoKit
import Foundation

enum V3DeviceWrappedCatchUpError: Error, Equatable, LocalizedError {
    case temporaryUnavailable
    case checkpointChanged
    case recoveryRequired

    var errorDescription: String? {
        switch self {
        case .temporaryUnavailable:
            "Authenticated newer vault state is not completely available from the file provider yet."
        case .checkpointChanged:
            "The trusted vault checkpoint changed during catch-up. Retry the operation."
        case .recoveryRequired:
            "Authenticated vault catch-up found invalid or substituted state. Recovery is required."
        }
    }
}

enum V3DeviceWrappedCatchUpOutcome: Equatable, Sendable {
    case upToDate(V3DeviceWrappedTrustedCheckpoint)
    case advanced(V3DeviceWrappedTrustedCheckpoint)
    case multipleHeads([Data])
}

/// Advances one device through an unambiguous content-only path within its
/// current vault-key epoch.
///
/// The helper mutation owner serializes this local trust change with ordinary
/// publication and enrollment. The live observer authenticates the complete
/// forward graph before this service reopens the selected head, validates its
/// complete encrypted snapshot, and compare-and-swaps the exact checkpoint.
/// Key-transition catch-up remains a separate increment because it must open
/// and validate each addressed wrapper in sequence.
struct V3DeviceWrappedSameEpochCatchUpService: Sendable {
    private let vaultID: String
    private let mutationOwner: any VaultTransactionMutationOwning
    private let stateLoader: any V3DeviceWrappedMutationStateLoading
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
        mutationOwner: any VaultTransactionMutationOwning,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        repositoryObserver: any V3DeviceWrappedRepositoryObserving,
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.mutationOwner = mutationOwner
        self.stateLoader = stateLoader
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

    func catchUp() throws -> V3DeviceWrappedCatchUpOutcome {
        try mutationOwner.perform(.catchUpVault) { _ in
            try catchUpWithinMutationOwner()
        }
    }

    private func catchUpWithinMutationOwner()
        throws -> V3DeviceWrappedCatchUpOutcome
    {
        let trusted = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to authenticate newer device history."
        )
        let vaultKey = try stateLoader.loadVaultKey(
            keyID: trusted.envelope.body.keyID
        )
        let observation: V3DeviceWrappedRepositoryObservation
        do {
            observation = try repositoryObserver.observeRepository(
                vaultID: vaultID,
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

        let plan: V3DeviceWrappedCatchUpPlan
        do {
            plan = try planner.plan(observation, vaultID: vaultID)
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        switch plan {
        case .upToDate:
            return .upToDate(trusted)
        case let .multipleHeads(heads):
            return .multipleHeads(heads)
        case let .advance(expectedCheckpoint, manifestDigests):
            guard expectedCheckpoint == trusted.checkpoint,
                  let headDigest = manifestDigests.last
            else {
                throw V3DeviceWrappedCatchUpError.recoveryRequired
            }
            return .advanced(try advance(
                trusted: trusted,
                vaultKey: vaultKey,
                manifestDigests: manifestDigests,
                headDigest: headDigest
            ))
        }
    }

    private func advance(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data,
        manifestDigests: [Data],
        headDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        let manifestData = try loadManifest(headDigest)
        let envelope: V3DeviceWrappedManifestEnvelope
        do {
            envelope = try envelopeCodec.parse(manifestData)
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        let expectedParent = manifestDigests.dropLast().last
            ?? trusted.checkpoint.envelopeDigest
        guard envelope.parents == [expectedParent],
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
                envelopeDigest: headDigest
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
