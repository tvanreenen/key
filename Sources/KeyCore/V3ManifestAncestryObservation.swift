import CryptoKit
import Foundation

/// Produces a complete authenticated ancestry proof from current repository
/// state.
///
/// Implementations must not return incomplete, recovery-required, or
/// unauthenticated state as a proof. Callers use this only from a serialized
/// mutation boundary. Resource usage must be the exact bounded usage captured
/// while producing the proof.
struct V3ManifestAncestryObservation: Equatable, Sendable {
    let proof: V3ManifestAncestryProof
    let resourceUsage: V3ManifestRepositoryUsage
}

protocol V3ManifestAncestryObserving: Sendable {
    func observeAncestry() throws -> V3ManifestAncestryObservation
}

/// Reopens the device-local checkpoint and produces the exact bounded proof
/// used by every live v3 publication path.
struct V3LiveManifestAncestryObserver:
    V3ManifestAncestryObserving
{
    let source: any V3ImmutableObjectReading
    let checkpointStore: any V3ManifestCheckpointStoring
    let vaultID: String
    let vaultKey: Data
    let limits: V3ManifestRepositoryLimits

    init(
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        vaultID: String,
        vaultKey: Data,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.source = source
        self.checkpointStore = checkpointStore
        self.vaultID = vaultID
        self.vaultKey = vaultKey
        self.limits = limits
    }

    func observeAncestry() throws -> V3ManifestAncestryObservation {
        guard let checkpointData = try checkpointStore.loadCheckpoint(
            vaultID: vaultID
        ) else {
            throw VaultUXServiceError.recoveryRequired
        }
        let checkpoint: V3ManifestCheckpoint
        do {
            checkpoint = try V3ManifestCheckpoint(
                canonicalBytes: checkpointData
            )
        } catch {
            throw VaultUXServiceError.recoveryRequired
        }
        guard checkpoint.vaultID == vaultID else {
            throw VaultUXServiceError.recoveryRequired
        }

        let manifestData: Data
        switch try source.readManifest(
            digest: checkpoint.envelopeDigest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case .available(let data)
            where Data(SHA256.hash(data: data))
                == checkpoint.envelopeDigest:
            manifestData = data
        case .unavailable:
            throw VaultUXServiceError.vaultIncomplete
        case .available, .invalid, .tooLarge:
            throw VaultUXServiceError.recoveryRequired
        }

        let trusted: V3TrustedManifest
        do {
            trusted = try V3ManifestReplayProtector(
                store: checkpointStore
            ).trustCurrent(
                manifestData,
                expectedVaultID: vaultID,
                vaultKey: vaultKey
            )
        } catch is V3ManifestError {
            throw VaultUXServiceError.recoveryRequired
        } catch is V3ManifestReplayError {
            throw VaultUXServiceError.recoveryRequired
        }

        let observed = try V3ImmutableObjectRepository(
            source: source,
            limits: limits
        ).observeForPublication(
            trustedCurrent: trusted,
            vaultKeys: [vaultKey]
        )
        switch observed.classification.status {
        case .ready, .contentConflicted:
            break
        case .incomplete:
            throw VaultUXServiceError.vaultIncomplete
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        }
        guard let proof = observed.classification.ancestryProof,
              let usage = observed.resourceUsage
        else {
            throw VaultUXServiceError.recoveryRequired
        }
        return V3ManifestAncestryObservation(
            proof: proof,
            resourceUsage: usage
        )
    }
}
