import CryptoKit
import Foundation

enum V3DeviceWrappedVaultUnlockRuntimeError:
    Error,
    Equatable,
    LocalizedError
{
    case locked
    case temporaryUnavailable
    case checkpointChanged
    case recoveryRequired
    case deviceRevoked
    case legacyAlphaProfile
    case upgradeRequired

    var errorDescription: String? {
        switch self {
        case .locked:
            "The vault is locked. Unlock it to continue."
        case .temporaryUnavailable:
            "The exact trusted vault state is not available from the file provider yet."
        case .checkpointChanged:
            "The trusted vault state changed during unlock. Retry the operation."
        case .recoveryRequired:
            "This Mac cannot authenticate and open its exact trusted vault state. Recovery or re-enrollment is required."
        case .deviceRevoked:
            "This Mac has been revoked from the vault and cannot unlock its current key."
        case .legacyAlphaProfile:
            "This vault uses the replaced prerelease version 3 key profile. Reset or remigrate it with the current alpha."
        case .upgradeRequired:
            "This vault requires a newer version of Key."
        }
    }
}

protocol V3DeviceWrappedIdentityLoading: Sendable {
    func loadDeviceIdentity(
        vaultID: String,
        reason: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)?
}

/// One fully authenticated permanent-profile checkpoint observation.
///
/// The envelope remains bound to the exact device-local checkpoint so callers
/// can revalidate that authority immediately before releasing plaintext.
struct V3DeviceWrappedTrustedCheckpoint: Equatable, Sendable {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3DeviceWrappedManifestEnvelope
}

extension V3EnrollmentDeviceIdentityManager:
    V3DeviceWrappedIdentityLoading
{
    func loadDeviceIdentity(
        vaultID: String,
        reason: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        try loadIdentity(vaultID: vaultID, reason: reason)
    }
}

/// Orchestrates routine permanent-profile unlock without granting provider
/// bytes any authority beyond the exact device-local checkpoint.
///
/// This layer owns transport/cache fallback and user-facing failure classes.
/// Envelope parsing, Secure Enclave HPKE, and in-memory key lifetime remain in
/// their narrower components.
final class V3DeviceWrappedVaultUnlockRuntime: @unchecked Sendable {
    private let vaultID: String
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let source: any V3ImmutableObjectReading
    private let cache: any V3CheckpointManifestCaching
    private let identityLoader: any V3DeviceWrappedIdentityLoading
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let unlocker = V3DeviceWrappedCheckpointUnlocker()
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let unlockLock = NSLock()

    init(
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        source: any V3ImmutableObjectReading,
        cache: any V3CheckpointManifestCaching,
        identityLoader: any V3DeviceWrappedIdentityLoading,
        session: V3DeviceWrappedVaultKeySessionStore
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.checkpointStore = checkpointStore
        self.source = source
        self.cache = cache
        self.identityLoader = identityLoader
        self.session = session
    }

    func unlock(reason: String) throws -> V3DeviceWrappedManifestEnvelope {
        unlockLock.lock()
        defer { unlockLock.unlock() }

        return try unlockLocked(reason: reason).envelope
    }

    /// Authenticates the exact checkpoint using the resident key when
    /// possible, falling back to one user-presence-gated unwrap when locked.
    func authenticatedCheckpoint(
        reason: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        unlockLock.lock()
        defer { unlockLock.unlock() }

        let checkpoint = try loadCheckpoint()
        let loadedManifest = try loadCheckpointManifest(checkpoint)
        let manifestData = loadedManifest.data
        let envelope: V3DeviceWrappedManifestEnvelope
        do {
            guard Data(SHA256.hash(data: manifestData))
                    == checkpoint.envelopeDigest
            else {
                throw V3DeviceWrappedUnlockError.checkpointMismatch
            }
            envelope = try envelopeCodec.parse(manifestData)
            guard envelope.body.vaultID == vaultID else {
                throw V3DeviceWrappedUnlockError.checkpointMismatch
            }
        } catch let error as V3DeviceWrappedUnlockError {
            throw runtimeError(for: error, manifestData: manifestData)
        }

        let vaultKey: Data
        do {
            vaultKey = try session.load(
                vaultID: vaultID,
                keyID: envelope.body.keyID
            )
        } catch {
            // Reload under the same lock. The second observation ensures a
            // provider/checkpoint change cannot be smuggled through the
            // session-miss path.
            return try unlockLocked(reason: reason)
        }

        guard (try? V3ManifestAuthenticator.isValidAuthenticationTag(
            envelope.authenticationTag,
            canonicalContent: envelope.canonicalContentBytes,
            vaultID: vaultID,
            vaultKey: vaultKey
        )) == true else {
            session.invalidate()
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
        try requireUnchangedCheckpoint(checkpoint)
        if loadedManifest.shouldCache {
            try? cache.store(manifestData, for: checkpoint)
        }
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: envelope
        )
    }

    func checkpointForRevalidation(
        vaultID expectedVaultID: String
    ) throws -> V3ManifestCheckpoint {
        guard expectedVaultID == vaultID else {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
        return try loadCheckpoint()
    }

    private func unlockLocked(
        reason: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {

        // A failed explicit unlock must never leave an earlier key resident.
        session.invalidate()
        let checkpoint = try loadCheckpoint()
        let loadedManifest = try loadCheckpointManifest(checkpoint)
        let manifestData = loadedManifest.data
        let identity: any V3DeviceWrappedVaultKeyUnwrapping
        do {
            guard let loaded = try identityLoader.loadDeviceIdentity(
                vaultID: vaultID,
                reason: reason
            ) else {
                throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
            }
            identity = loaded
        } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
            throw V3DeviceWrappedVaultUnlockRuntimeError.locked
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            throw error
        } catch {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }

        do {
            let envelope = try unlocker.unlock(
                checkpoint: checkpoint,
                manifestData: manifestData,
                identity: identity,
                session: session,
                reason: reason,
                validateBeforeSessionInstall: {
                    try requireUnchangedCheckpoint(checkpoint)
                }
            )
            if loadedManifest.shouldCache {
                // The cache is an availability optimization, not an
                // authority store. Authentication success does not depend on
                // this write.
                try? cache.store(manifestData, for: checkpoint)
            }
            return V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: envelope
            )
        } catch let error as V3DeviceWrappedUnlockError {
            throw runtimeError(for: error, manifestData: manifestData)
        }
    }

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
        do {
            return try session.load(vaultID: vaultID, keyID: keyID)
        } catch {
            throw V3DeviceWrappedVaultUnlockRuntimeError.locked
        }
    }

    func lock() {
        unlockLock.lock()
        defer { unlockLock.unlock() }
        session.invalidate()
    }

    private func loadCheckpoint() throws -> V3ManifestCheckpoint {
        do {
            guard let data = try checkpointStore.loadCheckpoint(
                vaultID: vaultID
            ) else {
                throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
            }
            let checkpoint = try V3ManifestCheckpoint(canonicalBytes: data)
            guard checkpoint.vaultID == vaultID else {
                throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
            }
            return checkpoint
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            throw error
        } catch {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
    }

    private func loadCheckpointManifest(
        _ checkpoint: V3ManifestCheckpoint
    ) throws -> (data: Data, shouldCache: Bool) {
        if case let .available(data) = try? cache.load(for: checkpoint) {
            return (data, false)
        }

        let read: V3RepositoryObjectRead
        do {
            read = try source.readManifest(
                digest: checkpoint.envelopeDigest,
                maximumBytes:
                    V3ManifestRepositoryLimits.standard.maximumManifestBytes
            )
        } catch {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
        switch read {
        case let .available(data):
            return (data, true)
        case .unavailable:
            throw V3DeviceWrappedVaultUnlockRuntimeError
                .temporaryUnavailable
        case .invalid, .tooLarge:
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
    }

    private func requireUnchangedCheckpoint(
        _ expected: V3ManifestCheckpoint
    ) throws {
        let data: Data
        do {
            guard let loaded = try checkpointStore.loadCheckpoint(
                vaultID: vaultID
            ) else {
                throw V3DeviceWrappedVaultUnlockRuntimeError
                    .recoveryRequired
            }
            data = loaded
        } catch let error as V3DeviceWrappedVaultUnlockRuntimeError {
            throw error
        } catch {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }

        let current: V3ManifestCheckpoint
        do {
            current = try V3ManifestCheckpoint(canonicalBytes: data)
        } catch {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
        guard current.vaultID == vaultID else {
            throw V3DeviceWrappedVaultUnlockRuntimeError.recoveryRequired
        }
        guard current == expected else {
            throw V3DeviceWrappedVaultUnlockRuntimeError.checkpointChanged
        }
    }

    private func runtimeError(
        for error: V3DeviceWrappedUnlockError,
        manifestData: Data
    ) -> V3DeviceWrappedVaultUnlockRuntimeError {
        switch error {
        case .deviceRevoked:
            return .deviceRevoked
        case .unsupportedEnvelopeVersion,
                .unsupportedProfileVersion:
            return .upgradeRequired
        case .authenticationCancelled:
            return .locked
        case .invalidManifest:
            if let alpha = try? V3ManifestAuthenticator().parse(manifestData),
               alpha.content.manifest.vaultID == vaultID
            {
                return .legacyAlphaProfile
            }
            return .recoveryRequired
        case .checkpointMismatch, .deviceIdentityMismatch,
                .deviceNotEnrolled, .wrapperMissing, .keyUnwrapFailed,
                .authenticationFailed:
            return .recoveryRequired
        }
    }
}
