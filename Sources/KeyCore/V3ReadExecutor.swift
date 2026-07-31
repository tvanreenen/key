import Foundation

enum V3AuthenticatedReadError: Error, Equatable, LocalizedError {
    case entryUnavailable
    case invalidEntryObject
    case entryObjectTooLarge
    case authorityChanged

    var errorDescription: String? {
        switch self {
        case .entryUnavailable:
            "The authenticated encrypted entry is not available yet."
        case .invalidEntryObject:
            "The authenticated encrypted entry could not be read safely."
        case .entryObjectTooLarge:
            "The authenticated encrypted entry exceeds the read safety limit."
        case .authorityChanged:
            "The vault changed before the authenticated read completed."
        }
    }
}

/// Freshly observes read authority while keeping equality enforcement inside
/// the security boundary.
struct V3ReadAuthorityValidator: Sendable {
    typealias CurrentStateProvider = @Sendable (
        _ checkpoint: V3ManifestCheckpoint
    ) throws -> V3ExpectedRepositoryState
    typealias CheckpointProvider = @Sendable (
        _ vaultID: String
    ) throws -> V3ManifestCheckpoint

    private let currentStateProvider: CurrentStateProvider
    private let checkpointProvider: CheckpointProvider

    init(
        currentStateProvider: @escaping CurrentStateProvider,
        checkpointProvider: @escaping CheckpointProvider
    ) {
        self.currentStateProvider = currentStateProvider
        self.checkpointProvider = checkpointProvider
    }

    func validate(_ expected: V3ReadAuthority) throws {
        switch expected {
        case let .current(state):
            guard try currentStateProvider(state.checkpoint) == state else {
                throw V3AuthenticatedReadError.authorityChanged
            }
        case let .lastTrusted(checkpoint):
            guard try checkpointProvider(checkpoint.vaultID) == checkpoint else {
                throw V3AuthenticatedReadError.authorityChanged
            }
        }
    }
}

/// Executes one exact read plan without resolving names or selecting state.
///
/// The authority validator freshly observes the plan's checkpoint and, for
/// current reads, head set immediately before this type releases plaintext.
struct V3AuthenticatedReadExecutor: Sendable {
    typealias VaultKeyProvider = @Sendable (V3VaultKeyID) throws -> Data

    private let source: any V3ImmutableObjectReading
    private let maximumEntryBytes: Int
    private let entryCipher: V3EntryCipher
    private let vaultKeyProvider: VaultKeyProvider
    private let authorityValidator: V3ReadAuthorityValidator

    init(
        rootHandle: VaultRootDirectoryHandle,
        vaultKeyProvider: @escaping VaultKeyProvider,
        authorityValidator: V3ReadAuthorityValidator
    ) {
        self.init(
            source: V3FilesystemImmutableObjectSource(
                rootHandle: rootHandle
            ),
            vaultKeyProvider: vaultKeyProvider,
            authorityValidator: authorityValidator
        )
    }

    init(
        source: any V3ImmutableObjectReading,
        maximumEntryBytes: Int =
            V3ManifestRepositoryLimits.standard.maximumEntryBytes,
        entryCipher: V3EntryCipher = V3EntryCipher(),
        vaultKeyProvider: @escaping VaultKeyProvider,
        authorityValidator: V3ReadAuthorityValidator
    ) {
        precondition(maximumEntryBytes > 0)
        self.source = source
        self.maximumEntryBytes = maximumEntryBytes
        self.entryCipher = entryCipher
        self.vaultKeyProvider = vaultKeyProvider
        self.authorityValidator = authorityValidator
    }

    func execute(_ plan: V3AuthenticatedReadPlan) throws -> String {
        let result = try source.readEntry(
            entryID: plan.entry.entryID,
            digest: plan.ciphertextDigest,
            maximumBytes: maximumEntryBytes
        )
        let data: Data
        switch result {
        case let .available(available):
            guard available.count <= maximumEntryBytes else {
                throw V3AuthenticatedReadError.entryObjectTooLarge
            }
            data = available
        case .unavailable:
            throw V3AuthenticatedReadError.entryUnavailable
        case .invalid:
            throw V3AuthenticatedReadError.invalidEntryObject
        case .tooLarge:
            throw V3AuthenticatedReadError.entryObjectTooLarge
        }

        let vaultKey = try vaultKeyProvider(plan.entry.keyID)
        let plaintext = try entryCipher.openTrusted(
            data,
            vaultID: plan.vaultID,
            manifestEntry: plan.entry,
            vaultKey: vaultKey
        )

        try authorityValidator.validate(plan.authority)
        return plaintext
    }
}
