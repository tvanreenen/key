import CryptoKit
import Foundation

protocol V3DeviceWrappedMutationStateLoading: Sendable {
    func authenticatedCheckpoint(
        reason: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data
}

protocol V3DeviceWrappedVaultMutationServicing:
    VaultMutationServicing
{
    func authorizeMutation() throws
}

/// Plans ordinary permanent-profile mutations from one exact authenticated
/// checkpoint and delegates durability to the device-wrapped publisher.
///
/// This service deliberately knows nothing about Keychain or Secure Enclave
/// representations. Its state loader supplies only an authenticated checkpoint
/// and the matching session key. The publisher factory retains transaction and
/// checkpoint authority, while the immutable source is used only to validate
/// the complete base and authenticate copy or move input.
struct V3DeviceWrappedVaultMutationService:
    V3DeviceWrappedVaultMutationServicing,
    Sendable
{
    typealias PublisherFactory = @Sendable (
        _ operationID: VaultTransactionOperationID
    ) -> any V3DeviceWrappedContentMutationPublishing
    typealias EntryIDGenerator = @Sendable () -> String
    typealias CatchUp = @Sendable (
        _ operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedCatchUpCoordinatorOutcome

    private struct Base {
        let trusted: V3DeviceWrappedTrustedCheckpoint
        let vaultKey: Data
        let publisher: any V3DeviceWrappedContentMutationPublishing
    }

    private let stateLoader: any V3DeviceWrappedMutationStateLoading
    private let source: any V3ImmutableObjectReading
    private let makePublisher: PublisherFactory
    private let makeEntryID: EntryIDGenerator
    private let catchUp: CatchUp?
    private let limits: V3ManifestRepositoryLimits
    private let builder = V3DeviceWrappedManifestCandidateBuilder()
    private let catchUpGate = V3DeviceWrappedCatchUpAccessGate()
    private let contentValidator: V3DeviceWrappedCheckpointContentValidator

    init(
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        source: any V3ImmutableObjectReading,
        makePublisher: @escaping PublisherFactory,
        makeEntryID: @escaping EntryIDGenerator = {
            UUID().uuidString.lowercased()
        },
        catchUp: CatchUp? = nil,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.stateLoader = stateLoader
        self.source = source
        self.makePublisher = makePublisher
        self.makeEntryID = makeEntryID
        self.catchUp = catchUp
        self.limits = limits
        contentValidator = V3DeviceWrappedCheckpointContentValidator(
            source: source,
            limits: limits
        )
    }

    init(
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        catchUp: CatchUp? = nil,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.init(
            stateLoader: stateLoader,
            source: objectStore,
            makePublisher: { operationID in
                V3DeviceWrappedContentMutationPublisher(
                    mutationOwner: DirectVaultTransactionMutationOwner(
                        operationID: operationID
                    ),
                    objectStore: objectStore,
                    checkpointStore: checkpointStore,
                    recoveryAnchorStore: recoveryAnchorStore,
                    cache: cache,
                    limits: limits
                )
            },
            catchUp: catchUp,
            limits: limits
        )
    }

    /// Performs the user-presence gate before the helper enters the concrete
    /// serialized mutation. The mutation itself reopens and revalidates the
    /// checkpoint so this authorization observation is never treated as fresh
    /// publication authority.
    func authorizeMutation() throws {
        let trusted = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to authorize a change."
        )
        _ = try stateLoader.loadVaultKey(keyID: trusted.envelope.body.keyID)
    }

    func add(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        let name = try normalizedV3EntryName(name)
        let plaintext = try normalizedSecret(secret, for: type)
        try perform(operationID: operationID) { base in
            try builder.add(
                to: base.trusted,
                entryID: try freshEntryID(
                    excluding: base.trusted.envelope.body.entries
                ),
                name: name,
                type: type,
                plaintext: plaintext,
                vaultKey: base.vaultKey
            )
        }
    }

    func edit(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        let name = try normalizedV3EntryName(name)
        let plaintext = try normalizedSecret(secret, for: type)
        try perform(operationID: operationID) { base in
            try builder.edit(
                in: base.trusted,
                name: name,
                type: type,
                plaintext: plaintext,
                vaultKey: base.vaultKey
            )
        }
    }

    func copy(
        source sourceName: String,
        destination destinationName: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        let sourceName = try normalizedV3EntryName(sourceName)
        let destinationName = try normalizedV3EntryName(destinationName)
        try perform(operationID: operationID) { base in
            try builder.copy(
                in: base.trusted,
                sourceName: sourceName,
                sourceData: try sourceData(
                    named: sourceName,
                    in: base.trusted
                ),
                destinationEntryID: try freshEntryID(
                    excluding: base.trusted.envelope.body.entries
                ),
                destinationName: destinationName,
                overwrite: overwrite,
                vaultKey: base.vaultKey
            )
        }
    }

    func move(
        source sourceName: String,
        destination destinationName: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        let sourceName = try normalizedV3EntryName(sourceName)
        let destinationName = try normalizedV3EntryName(destinationName)
        try perform(operationID: operationID) { base in
            try builder.move(
                in: base.trusted,
                sourceName: sourceName,
                sourceData: try sourceData(
                    named: sourceName,
                    in: base.trusted
                ),
                destinationName: destinationName,
                overwrite: overwrite,
                vaultKey: base.vaultKey
            )
        }
    }

    func remove(
        name: String,
        operationID: VaultTransactionOperationID
    ) throws {
        let name = try normalizedV3EntryName(name)
        try perform(operationID: operationID) { base in
            try builder.remove(
                from: base.trusted,
                name: name,
                vaultKey: base.vaultKey
            )
        }
    }

    func resolve(
        _: [VaultConflictResolution],
        operationID _: VaultTransactionOperationID
    ) throws {
        throw AppError.operationRefused(
            "Permanent version 3 conflict resolution is unavailable until multi-device history discovery is enabled."
        )
    }

    private func perform(
        operationID: VaultTransactionOperationID,
        build: (Base) throws -> V3DeviceWrappedContentMutationCandidate
    ) throws {
        do {
            try requireCaughtUp(operationID: operationID)
            let base = try prepareBase(operationID: operationID)
            let candidate = try build(base)
            _ = try base.publisher.publish(
                candidate,
                vaultKey: base.vaultKey
            )
        } catch let error as V3DeviceWrappedContentMutationError {
            throw serviceError(for: error)
        } catch let error as V3DeviceWrappedCatchUpError {
            throw serviceError(for: error)
        } catch is V3EncryptedEntryError {
            throw VaultUXServiceError.recoveryRequired
        } catch let error as V3ImmutableTransactionRecoveryError {
            throw serviceError(for: error)
        } catch let error as V3ImmutableTransactionError {
            throw serviceError(for: error)
        } catch let error as V3ManifestCheckpointStoreError {
            throw serviceError(for: error)
        } catch is V3ImmutableTransactionRecoveryAnchorError {
            throw VaultUXServiceError.recoveryRequired
        }
    }

    private func requireCaughtUp(
        operationID: VaultTransactionOperationID
    ) throws {
        guard let catchUp else {
            return
        }
        try catchUpGate.requireCurrent {
            try catchUp(operationID)
        }
    }

    private func prepareBase(
        operationID: VaultTransactionOperationID
    ) throws -> Base {
        let publisher = makePublisher(operationID)
        var trusted = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to publish a guarded change."
        )
        var vaultKey = try stateLoader.loadVaultKey(
            keyID: trusted.envelope.body.keyID
        )
        let recovery = try publisher.recoverInterruptedTransaction(
            vaultID: trusted.checkpoint.vaultID,
            vaultKey: vaultKey
        )
        if recovery != .nothingToRecover {
            trusted = try stateLoader.authenticatedCheckpoint(
                reason: "Revalidate version 3 vault after transaction recovery."
            )
            vaultKey = try stateLoader.loadVaultKey(
                keyID: trusted.envelope.body.keyID
            )
        }
        try requireCompleteBase(trusted)
        return Base(
            trusted: trusted,
            vaultKey: vaultKey,
            publisher: publisher
        )
    }

    private func requireCompleteBase(
        _ trusted: V3DeviceWrappedTrustedCheckpoint
    ) throws {
        switch try contentValidator.validate(
            entries: trusted.envelope.body.entries,
            vaultID: trusted.checkpoint.vaultID
        ) {
        case .ready:
            return
        case .incomplete:
            throw VaultUXServiceError.vaultIncomplete
        case .invalid, .resourceLimitExceeded:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    private func sourceData(
        named name: String,
        in trusted: V3DeviceWrappedTrustedCheckpoint
    ) throws -> Data {
        guard let entry = trusted.envelope.body.entries.first(where: {
            $0.name == name
        }) else {
            throw V3DeviceWrappedContentMutationError.entryNotFound
        }
        guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest),
              digest.count == 32
        else {
            throw VaultUXServiceError.recoveryRequired
        }
        let read: V3RepositoryObjectRead
        do {
            read = try source.readEntry(
                entryID: entry.entryID,
                digest: digest,
                maximumBytes: limits.maximumEntryBytes
            )
        } catch {
            throw VaultUXServiceError.recoveryRequired
        }
        switch read {
        case let .available(data)
            where data.count <= limits.maximumEntryBytes
                && Data(SHA256.hash(data: data)) == digest:
            return data
        case .unavailable:
            throw VaultUXServiceError.vaultIncomplete
        case .available, .invalid, .tooLarge:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    private func freshEntryID(
        excluding entries: [V3ManifestEntry]
    ) throws -> String {
        for _ in 0..<16 {
            let candidate = makeEntryID()
            guard isValidV3UUID(candidate) else {
                throw V3DeviceWrappedContentMutationError.invalidEntryID
            }
            if !entries.contains(where: { $0.entryID == candidate }) {
                return candidate
            }
        }
        throw V3DeviceWrappedContentMutationError.invalidEntryID
    }

    private func normalizedSecret(
        _ secret: String,
        for type: SecretEntryType
    ) throws -> String {
        switch type {
        case .secret:
            secret
        case .totp:
            try TOTPGenerator.normalizeBase32Seed(secret)
        }
    }

    private func serviceError(
        for error: V3DeviceWrappedContentMutationError
    ) -> any Error {
        switch error {
        case .entryNotFound:
            AppError.entryNotFound(error.localizedDescription)
        case .entryExists:
            AppError.entryExists(error.localizedDescription)
        case .unchangedName, .invalidEntryName, .revisionOverflow:
            AppError.operationRefused(error.localizedDescription)
        case .invalidTrustedCheckpoint, .invalidVaultKey, .invalidEntryID,
            .invalidCandidate:
            VaultUXServiceError.recoveryRequired
        }
    }

    private func serviceError(
        for error: V3DeviceWrappedCatchUpError
    ) -> any Error {
        switch error {
        case .temporaryUnavailable, .checkpointChanged:
            VaultUXServiceError.vaultIncomplete
        case .authenticationCancelled:
            AppError.authFailed(error.localizedDescription)
        case .deviceRevoked:
            VaultUXServiceError.deviceRevoked
        case .recoveryRequired:
            VaultUXServiceError.recoveryRequired
        case .upgradeRequired:
            AppError.operationRefused(error.localizedDescription)
        }
    }

    private func serviceError(
        for error: V3ImmutableTransactionRecoveryError
    ) -> VaultUXServiceError {
        switch error {
        case .transactionDirectoryUnavailable,
            .interruptedTransactionPending:
            .vaultIncomplete
        case .invalidRecoveryAnchor, .invalidIntent,
            .checkpointUnavailable, .vaultKeyUnavailable,
            .invalidRecoveryState:
            .recoveryRequired
        }
    }

    private func serviceError(
        for error: V3ImmutableTransactionError
    ) -> VaultUXServiceError {
        switch error {
        case .expectedHeadsChanged:
            .expectedHeadsChanged
        case .referencedEntryUnavailable, .publishedManifestUnavailable:
            .vaultIncomplete
        case .invalidAncestryProof, .unresolvedConflict,
            .candidateDoesNotMatchAutomaticMerge, .duplicateStagedEntry,
            .invalidStagedEntry, .objectTooLarge, .referencedEntryInvalid,
            .publishedManifestInvalid:
            .recoveryRequired
        }
    }

    private func serviceError(
        for error: V3ManifestCheckpointStoreError
    ) -> VaultUXServiceError {
        switch error {
        case .conflict:
            .expectedHeadsChanged
        case .invalidConfiguration, .keychainStatus:
            .recoveryRequired
        }
    }
}
