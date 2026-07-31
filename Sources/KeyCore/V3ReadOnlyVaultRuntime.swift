import Foundation

private struct V3ReadRuntimeState: Sendable {
    let trustedCurrent: V3TrustedManifest
    let classification: V3VaultRepositoryClassification
}

/// Composes checkpoint trust, repository discovery, read planning, and exact
/// immutable-object execution for one device-selected v3 vault.
private struct V3ReadRuntimeContext: Sendable {
    typealias VaultKeyProvider = @Sendable (_ reason: String) throws -> Data

    let vaultID: String
    private let source: any V3ImmutableObjectReading
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let vaultKeyProvider: VaultKeyProvider
    private let repository: V3ImmutableObjectRepository
    private let replayProtector: V3ManifestReplayProtector
    private let planner: V3AuthenticatedReadPlanner
    private let observationBuilder: V3VaultObservationBuilder

    init(
        rootHandle: VaultRootDirectoryHandle,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        vaultKeyProvider: @escaping VaultKeyProvider
    ) {
        let source = V3FilesystemImmutableObjectSource(
            rootHandle: rootHandle
        )
        self.init(
            source: source,
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: vaultKeyProvider
        )
    }

    init(
        source: any V3ImmutableObjectReading,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        vaultKeyProvider: @escaping VaultKeyProvider
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.source = source
        self.checkpointStore = checkpointStore
        self.vaultKeyProvider = vaultKeyProvider
        repository = V3ImmutableObjectRepository(source: source)
        replayProtector = V3ManifestReplayProtector(store: checkpointStore)
        planner = V3AuthenticatedReadPlanner()
        observationBuilder = V3VaultObservationBuilder()
    }

    func snapshot() throws -> V3VaultUXSnapshot {
        let state = try loadState(
            reason: "Unlock version 3 vault to inspect its authenticated state."
        )
        return try observationBuilder.build(
            state.classification,
            trustedCurrent: state.trustedCurrent
        )
    }

    func read(
        name: String,
        allowStale: Bool
    ) throws -> VaultReadValue {
        let state = try loadState(
            reason: "Unlock version 3 vault to read '\(name)'."
        )
        let plan = try planner.planRead(
            named: name,
            allowStale: allowStale,
            classification: state.classification,
            trustedCurrent: state.trustedCurrent
        )
        let plaintext = try executor(
            reason: "Unlock version 3 vault to read '\(name)'."
        ).execute(plan)
        return VaultReadValue(
            type: plan.entry.type,
            plaintext: plaintext
        )
    }

    func unlock() throws {
        _ = try loadState(
            reason: "Unlock and authenticate version 3 vault."
        )
    }

    func authorizeRead(
        name: String,
        allowStale: Bool
    ) throws {
        let state = try loadState(
            reason: "Unlock version 3 vault to authenticate '\(name)'."
        )
        _ = try planner.planRead(
            named: name,
            allowStale: allowStale,
            classification: state.classification,
            trustedCurrent: state.trustedCurrent
        )
    }

    func list(allowStale: Bool) throws -> [String] {
        let state = try loadState(
            reason: "Unlock version 3 vault to list authenticated entries."
        )
        let plan = try planner.planList(
            allowStale: allowStale,
            classification: state.classification,
            trustedCurrent: state.trustedCurrent
        )
        try authorityValidator().validate(plan.authority)
        return plan.entries.map(\.name)
    }

    func readConflict(
        entry: V3ManifestEntry,
        expectedHeads: [V3VaultHead]
    ) throws -> String {
        let state = try loadState(
            reason: "Unlock version 3 vault to read an authenticated conflict version."
        )
        let plan = try planner.planConflictRead(
            entry: entry,
            expectedHeads: expectedHeads,
            classification: state.classification,
            trustedCurrent: state.trustedCurrent
        )
        return try executor(
            reason: "Unlock version 3 vault to read an authenticated conflict version."
        ).execute(plan)
    }

    private func loadState(reason: String) throws -> V3ReadRuntimeState {
        let checkpoint = try currentCheckpoint()
        let manifestData = try checkpointManifestData(checkpoint)
        let vaultKey = try vaultKeyProvider(reason)
        let trustedCurrent = try replayProtector.trustCurrent(
            manifestData,
            expectedVaultID: vaultID,
            vaultKey: vaultKey
        )
        let classification = try repository.classify(
            trustedCurrent: trustedCurrent,
            vaultKeys: [vaultKey]
        )
        return V3ReadRuntimeState(
            trustedCurrent: trustedCurrent,
            classification: classification
        )
    }

    private func currentCheckpoint() throws -> V3ManifestCheckpoint {
        guard let data = try checkpointStore.loadCheckpoint(
            vaultID: vaultID
        ) else {
            throw V3ManifestReplayError.checkpointNotFound
        }
        let checkpoint = try V3ManifestCheckpoint(canonicalBytes: data)
        guard checkpoint.vaultID == vaultID else {
            throw V3ManifestReplayError.vaultMismatch
        }
        return checkpoint
    }

    private func checkpointManifestData(
        _ checkpoint: V3ManifestCheckpoint
    ) throws -> Data {
        switch try source.readManifest(
            digest: checkpoint.envelopeDigest,
            maximumBytes:
                V3ManifestRepositoryLimits.standard.maximumManifestBytes
        ) {
        case let .available(data):
            return data
        case .unavailable:
            throw VaultUXServiceError.vaultIncomplete
        case .invalid, .tooLarge:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    private func executor(
        reason: String
    ) -> V3AuthenticatedReadExecutor {
        V3AuthenticatedReadExecutor(
            source: source,
            vaultKeyProvider: { _ in
                try vaultKeyProvider(reason)
            },
            authorityValidator: authorityValidator()
        )
    }

    private func authorityValidator() -> V3ReadAuthorityValidator {
        V3ReadAuthorityValidator(
            currentStateProvider: { expectedCheckpoint in
                do {
                    let state = try loadState(
                        reason: "Revalidate version 3 vault state."
                    )
                    guard state.trustedCurrent.checkpoint
                            == expectedCheckpoint,
                          let proof = state.classification.ancestryProof,
                          proof.checkpoint == expectedCheckpoint
                    else {
                        throw V3AuthenticatedReadError.authorityChanged
                    }
                    return try V3ExpectedRepositoryState(proof: proof)
                } catch {
                    throw V3AuthenticatedReadError.authorityChanged
                }
            },
            checkpointProvider: { expectedVaultID in
                do {
                    guard expectedVaultID == vaultID else {
                        throw V3AuthenticatedReadError.authorityChanged
                    }
                    return try currentCheckpoint()
                } catch {
                    throw V3AuthenticatedReadError.authorityChanged
                }
            }
        )
    }
}

/// The shipping v3 adapter is intentionally read-only.
///
/// It exposes authenticated status, conflict inspection, logical listing, and
/// exact entry reads while rejecting every mutation before a legacy v2
/// filesystem operation can run.
struct V3ReadOnlyVaultRuntime:
    VaultReadServicing,
    VaultUXServicing,
    Sendable
{
    private let context: V3ReadRuntimeContext
    private let uxService: V3VaultUXService

    init(
        rootHandle: VaultRootDirectoryHandle,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        vaultKeyProvider: @escaping @Sendable (
            _ reason: String
        ) throws -> Data
    ) {
        let context = V3ReadRuntimeContext(
            rootHandle: rootHandle,
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: vaultKeyProvider
        )
        self.init(context: context)
    }

    init(
        source: any V3ImmutableObjectReading,
        vaultID: String,
        checkpointStore: any V3ManifestCheckpointStoring,
        vaultKeyProvider: @escaping @Sendable (
            _ reason: String
        ) throws -> Data
    ) {
        self.init(context: V3ReadRuntimeContext(
            source: source,
            vaultID: vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: vaultKeyProvider
        ))
    }

    private init(context: V3ReadRuntimeContext) {
        self.context = context
        uxService = V3VaultUXService(
            snapshotProvider: {
                try context.snapshot()
            },
            valueReader: { entry, expectedHeads in
                try context.readConflict(
                    entry: entry,
                    expectedHeads: expectedHeads
                )
            },
            resolutionPublisher: { _, _ in
                throw v3ReadOnlyMutationError()
            }
        )
    }

    func unlock() throws {
        try context.unlock()
    }

    func read(
        name: String,
        allowStale: Bool
    ) throws -> VaultReadValue {
        try context.read(name: name, allowStale: allowStale)
    }

    func list(allowStale: Bool) throws -> [String] {
        try context.list(allowStale: allowStale)
    }

    func status() throws -> VaultStatus {
        try uxService.status()
    }

    func authorizeRead(
        name: String,
        allowStale: Bool
    ) throws {
        try context.authorizeRead(name: name, allowStale: allowStale)
    }

    func authorizeMutation() throws {
        throw v3ReadOnlyMutationError()
    }

    func conflicts() throws -> [VaultConflictSummary] {
        try uxService.conflicts()
    }

    func conflict(id: String) throws -> VaultConflictDetail {
        try uxService.conflict(id: id)
    }

    func conflictValue(
        id: String,
        versionID: String
    ) throws -> String {
        try uxService.conflictValue(id: id, versionID: versionID)
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw v3ReadOnlyMutationError()
    }
}

private func v3ReadOnlyMutationError() -> AppError {
    AppError.operationRefused(
        "Version 3 vault writes are not enabled in this release."
    )
}
