import Foundation

/// Advances the local device through one exact owner-authorized key epoch.
///
/// Candidate discovery remains read-only and outside this type. Once a direct
/// child has been selected, this service serializes the complete trust change
/// with ordinary vault mutations, reopens the exact local parent, authenticates
/// the addressed wrapper and complete resealed snapshot, and advances the
/// checkpoint with an expected-value guard. The checkpoint commits authority
/// before the derived in-memory session and best-effort cache are updated.
struct V3DeviceWrappedKeyTransitionCatchUpService: Sendable {
    typealias IdentityLoader = @Sendable (
        _ vaultID: String,
        _ reason: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)?

    private let vaultID: String
    private let mutationOwner: any VaultTransactionMutationOwning
    private let stateManager: any V3DeviceWrappedKeyTransitionStateManaging
    private let cache: any V3CheckpointManifestCaching
    private let loadIdentity: IdentityLoader
    private let opener: V3DeviceWrappedCatchUpTransitionOpener

    init(
        vaultID: String,
        mutationOwner: any VaultTransactionMutationOwning,
        stateManager: any V3DeviceWrappedKeyTransitionStateManaging,
        source: any V3ImmutableObjectReading,
        cache: any V3CheckpointManifestCaching,
        loadIdentity: @escaping IdentityLoader,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.mutationOwner = mutationOwner
        self.stateManager = stateManager
        self.cache = cache
        self.loadIdentity = loadIdentity
        opener = V3DeviceWrappedCatchUpTransitionOpener(
            source: source,
            limits: limits
        )
    }

    func advance(
        manifestData: Data,
        manifestDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        try mutationOwner.perform(.catchUpVault) { _ in
            try advanceWithinMutationOwner(
                manifestData: manifestData,
                manifestDigest: manifestDigest
            )
        }
    }

    private func advanceWithinMutationOwner(
        manifestData: Data,
        manifestDigest: Data
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        do {
            let trusted = try stateManager.advanceKeyTransition(
                reason: "Unlock version 3 vault to authenticate its next key epoch."
            ) { parent, currentVaultKey in
                guard parent.checkpoint.vaultID == vaultID else {
                    throw V3DeviceWrappedCatchUpError.recoveryRequired
                }
                let identity = try identity()
                do {
                    return try opener.open(
                        manifestData: manifestData,
                        manifestDigest: manifestDigest,
                        parent: parent,
                        currentVaultKey: currentVaultKey,
                        identity: identity,
                        reason: "Open the authenticated next vault-key epoch."
                    )
                } catch let error as
                    V3DeviceWrappedCatchUpTransitionOpeningError
                {
                    throw catchUpError(for: error)
                } catch let error as V3DeviceWrappedUnlockError {
                    throw catchUpError(for: error)
                } catch {
                    throw V3DeviceWrappedCatchUpError.recoveryRequired
                }
            }
            // The checkpoint is already authoritative. The manifest cache only
            // improves offline availability and cannot undo a successful advance.
            try? cache.store(
                trusted.envelope.canonicalBytes,
                for: trusted.checkpoint
            )
            return trusted
        } catch V3DeviceWrappedKeyTransitionStateError.checkpointChanged {
            throw V3DeviceWrappedCatchUpError.checkpointChanged
        } catch V3DeviceWrappedKeyTransitionStateError.recoveryRequired {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        } catch let error as V3DeviceWrappedCatchUpError {
            throw error
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }

    private func identity() throws -> any V3DeviceWrappedVaultKeyUnwrapping {
        do {
            guard let loaded = try loadIdentity(
                vaultID,
                "Authenticate this Mac to open the next vault-key epoch."
            ) else {
                throw V3DeviceWrappedCatchUpError.recoveryRequired
            }
            return loaded
        } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
            throw V3DeviceWrappedCatchUpError.authenticationCancelled
        } catch let error as V3DeviceWrappedCatchUpError {
            throw error
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }

    private func catchUpError(
        for error: V3DeviceWrappedCatchUpTransitionOpeningError
    ) -> V3DeviceWrappedCatchUpError {
        switch error {
        case .temporaryUnavailable:
            .temporaryUnavailable
        case .authenticationCancelled:
            .authenticationCancelled
        case .deviceRevoked:
            .deviceRevoked
        case .recoveryRequired:
            .recoveryRequired
        }
    }

    private func catchUpError(
        for error: V3DeviceWrappedUnlockError
    ) -> V3DeviceWrappedCatchUpError {
        switch error {
        case .unsupportedEnvelopeVersion, .unsupportedProfileVersion:
            .upgradeRequired
        case .invalidManifest, .checkpointMismatch,
                .deviceIdentityMismatch, .deviceNotEnrolled,
                .deviceRevoked, .wrapperMissing,
                .authenticationCancelled, .keyUnwrapFailed,
                .authenticationFailed:
            .recoveryRequired
        }
    }
}
