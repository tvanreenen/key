import CryptoKit
import Foundation

enum V3ImmutableTransactionError: Error, Equatable, LocalizedError {
    case invalidAncestryProof
    case unresolvedConflict
    case candidateDoesNotMatchAutomaticMerge
    case duplicateStagedEntry
    case invalidStagedEntry
    case objectTooLarge
    case referencedEntryUnavailable(entryID: String, digest: String)
    case publishedManifestUnavailable(digest: String)
    case expectedHeadsChanged

    var errorDescription: String? {
        switch self {
        case .invalidAncestryProof:
            "Version 3 transaction publication requires a checkpoint-linked ancestry proof."
        case .unresolvedConflict:
            "Version 3 vault conflicts must be resolved before publishing a transaction."
        case .candidateDoesNotMatchAutomaticMerge:
            "The candidate manifest does not contain the exact deterministic merge result."
        case .duplicateStagedEntry:
            "A version 3 transaction cannot stage the same immutable entry object twice."
        case .invalidStagedEntry:
            "A staged version 3 entry does not match the candidate manifest or current vault key."
        case .objectTooLarge:
            "The version 3 transaction would exceed a repository resource limit."
        case let .referencedEntryUnavailable(entryID, digest):
            "The candidate manifest references unavailable entry '\(entryID)' at digest '\(digest)'."
        case let .publishedManifestUnavailable(digest):
            "The published version 3 manifest is unavailable or invalid at digest '\(digest)'."
        case .expectedHeadsChanged:
            "The authenticated vault heads changed while the transaction was being staged."
        }
    }
}

enum V3ImmutableTransactionRecoveryError:
    Error,
    Equatable,
    LocalizedError
{
    case transactionDirectoryUnavailable
    case invalidRecoveryAnchor(vaultID: String)
    case invalidIntent(operationID: String)
    case interruptedTransactionPending(operationID: String)
    case checkpointUnavailable(vaultID: String)
    case vaultKeyUnavailable(keyID: String)
    case invalidRecoveryState(operationID: String)

    var errorDescription: String? {
        switch self {
        case .transactionDirectoryUnavailable:
            "Version 3 transaction recovery is waiting for synchronized transaction state."
        case let .invalidRecoveryAnchor(vaultID):
            "Vault '\(vaultID)' has an invalid device-local transaction recovery anchor."
        case let .invalidIntent(operationID):
            "Version 3 transaction '\(operationID)' has an invalid recovery intent."
        case let .interruptedTransactionPending(operationID):
            "Version 3 transaction '\(operationID)' must be recovered before another mutation can publish."
        case let .checkpointUnavailable(vaultID):
            "The device-local checkpoint for vault '\(vaultID)' is unavailable or invalid."
        case let .vaultKeyUnavailable(keyID):
            "Recovery cannot authenticate the candidate manifest because vault key '\(keyID)' is unavailable."
        case let .invalidRecoveryState(operationID):
            "Version 3 transaction '\(operationID)' contains contradictory or invalid recovery state."
        }
    }
}

enum V3ImmutableTransactionRecoveryOutcome: Equatable, Sendable {
    case nothingToRecover
    case completed(operationID: VaultTransactionOperationID)
    case abandoned(operationID: VaultTransactionOperationID)
    case alreadyCompleted(operationID: VaultTransactionOperationID)
}

/// Stages and publishes immutable repository objects.
///
/// Staging paths are non-authoritative transaction state. Publishing must be
/// no-overwrite and durable before returning. An existing destination is
/// successful only when it contains the exact requested bytes.
protocol V3TransactionArtifactStore: V3ImmutableObjectPublishing {
    func persistRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func readRecoveryIntent(
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead

    func removeRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws

}

enum V3ImmutableTransactionPhase: Equatable, Sendable {
    case recoveryAnchorPrepared
    case recoveryIntentPersisted
    case recoveryArmed
    case entryStaged(index: Int)
    case manifestStaged
    case repositoryStateRechecked
    case entryPublished(index: Int)
    case publishedEntriesValidated
    case manifestPublished
    case publishedManifestValidated
    case checkpointAdvanced
    case cleanupCompleted
}

protocol V3ImmutableTransactionPhaseObserving: Sendable {
    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID: VaultTransactionOperationID
    ) throws
}

private struct V3NoopTransactionPhaseObserver:
    V3ImmutableTransactionPhaseObserving
{
    func didReach(
        _: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

struct V3ImmutableTransactionRequest: Sendable {
    let kind: VaultTransactionMutationKind
    let candidateManifestData: Data
    let stagedEntries: [V3EncryptedEntry]
    let candidateVaultKey: Data
}

/// Publishes one authenticated version 3 mutation under the helper's mutation
/// owner.
///
/// The publisher captures authenticated heads inside the owner, stages all
/// new objects, rechecks the exact checkpoint and head set, publishes entries
/// first, publishes the manifest last, and advances the local checkpoint only
/// after the final manifest is durable. A device-local recovery anchor binds
/// this device to the exact shared intent, allowing every interruption phase
/// to resume or safely retain the complete old state without acting on another
/// device's partially synchronized staging.
struct V3ImmutableTransactionPublisher: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let ancestryObserver: any V3ManifestAncestryObserving
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let authenticator: V3ManifestAuthenticator
    private let reconciler: V3ManifestReconciler
    private let limits: V3ManifestRepositoryLimits
    private let validator: V3ImmutableTransactionValidator
    private let recoverer: V3InterruptedTransactionRecoverer
    private let phaseObserver: any V3ImmutableTransactionPhaseObserving

    init(
        mutationOwner: any VaultTransactionMutationOwning,
        ancestryObserver: any V3ManifestAncestryObserving,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        authenticator: V3ManifestAuthenticator = V3ManifestAuthenticator(),
        reconciler: V3ManifestReconciler = V3ManifestReconciler(),
        entryCipher: V3EntryCipher = V3EntryCipher(),
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3ImmutableTransactionPhaseObserving =
            V3NoopTransactionPhaseObserver()
    ) {
        self.mutationOwner = mutationOwner
        self.ancestryObserver = ancestryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.authenticator = authenticator
        self.reconciler = reconciler
        self.limits = limits
        let validator = V3ImmutableTransactionValidator(
            objectStore: objectStore,
            entryCipher: entryCipher,
            limits: limits
        )
        self.validator = validator
        recoverer = V3InterruptedTransactionRecoverer(
            ancestryObserver: ancestryObserver,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            authenticator: authenticator,
            reconciler: reconciler,
            validator: validator,
            limits: limits
        )
        self.phaseObserver = phaseObserver
    }

    func publish(
        _ request: V3ImmutableTransactionRequest
    ) throws -> V3TrustedManifest {
        try mutationOwner.perform(request.kind) { context in
            try publish(
                request,
                operationID: context.operationID
            )
        }
    }

    /// Recovers at most one interrupted operation for `vaultID`.
    ///
    /// Multiple intents are deliberately not ordered or selected: synchronized
    /// operations can represent concurrent branches, and lexical operation-ID
    /// order is not authority. The later conflict UX can present such state
    /// without this layer silently choosing a winner.
    func recoverInterruptedTransaction(
        vaultID: String,
        availableVaultKeys: [Data]
    ) throws -> V3ImmutableTransactionRecoveryOutcome {
        try mutationOwner.perform(.recoverInterruptedTransaction) { _ in
            try recoverer.recover(
                vaultID: vaultID,
                availableVaultKeys: availableVaultKeys
            )
        }
    }

    private func publish(
        _ request: V3ImmutableTransactionRequest,
        operationID: VaultTransactionOperationID
    ) throws -> V3TrustedManifest {
        let requestedVaultID = try authenticator.parse(
            request.candidateManifestData
        ).content.manifest.vaultID
        try requireNoInterruptedTransaction(for: requestedVaultID)
        let initialObservation = try ancestryObserver.observeAncestry()
        let initialProof = initialObservation.proof
        let expectedState = try validator.validatedState(for: initialProof)
        let reconciliation = try reconciler.reconcile(initialProof)
        var stagedEntryBytes = 0
        for entry in request.stagedEntries {
            guard entry.canonicalBytes.count <= limits.maximumEntryBytes,
                  stagedEntryBytes
                      <= limits.maximumTotalEntryBytes
                          - entry.canonicalBytes.count
            else {
                throw V3ImmutableTransactionError.objectTooLarge
            }
            stagedEntryBytes += entry.canonicalBytes.count
        }
        guard request.candidateManifestData.count
                <= limits.maximumManifestBytes,
              request.stagedEntries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3ImmutableTransactionError.objectTooLarge
        }
        guard reconciliation.canPublishAutomatically else {
            throw V3ImmutableTransactionError.unresolvedConflict
        }
        let candidate = try authenticator.verify(
            request.candidateManifestData,
            vaultKey: request.candidateVaultKey,
            trustAnchor: .verifiedParents(initialProof.heads)
        )
        guard candidate.envelope.content.manifest.vaultID
                == initialProof.checkpoint.vaultID
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        guard candidate.envelope.content.manifest.entries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3ImmutableTransactionError.objectTooLarge
        }
        try validator.requirePermittedCandidate(
            candidate,
            reconciliation: reconciliation
        )

        let stagedEntries = try validator.validateStagedEntries(
            request.stagedEntries,
            candidate: candidate,
            vaultKey: request.candidateVaultKey
        )
        var candidateEntrySizes: [V3EntryObjectKey: Int] = [:]
        for entry in candidate.envelope.content.manifest.entries {
            let key = try entryObjectKey(entry)
            guard candidateEntrySizes[key] == nil else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            if let staged = stagedEntries[key] {
                candidateEntrySizes[key] = staged.canonicalBytes.count
            } else {
                candidateEntrySizes[key] = try validator.validatePublishedEntry(
                    entry,
                    vaultID: candidate.envelope.content.manifest.vaultID
                )
            }
        }
        try validator.requireProjectedRepositoryUsage(
            initialObservation,
            candidate: candidate,
            candidateEntrySizes: candidateEntrySizes
        )

        let orderedStagedEntryKeys = stagedEntries.keys.sorted(
            by: entryObjectKeyPrecedes
        )
        let recoveryIntent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: request.kind,
            vaultID: initialProof.checkpoint.vaultID,
            expectedCheckpoint: initialProof.checkpoint,
            expectedHeads: expectedState.heads.map(\.envelopeDigest),
            candidateManifestDigest: candidate.envelopeDigest,
            stagedEntries: orderedStagedEntryKeys.map {
                V3ImmutableTransactionRecoveryEntry(
                    entryID: $0.entryID,
                    digest: $0.digest
                )
            }
        )
        let recoveryIntentData = recoveryIntent.canonicalBytes
        let intentDigest = Data(SHA256.hash(data: recoveryIntentData))
        let preparedAnchor = try V3ImmutableTransactionRecoveryAnchor(
            operationID: operationID,
            vaultID: recoveryIntent.vaultID,
            intentDigest: intentDigest,
            phase: .prepared
        )
        let preparedAnchorData = preparedAnchor.canonicalBytes
        try recoveryAnchorStore.replaceRecoveryAnchor(
            preparedAnchorData,
            expectedAnchor: nil,
            vaultID: recoveryIntent.vaultID
        )
        try phaseObserver.didReach(
            .recoveryAnchorPrepared,
            operationID: operationID
        )
        try objectStore.persistRecoveryIntent(
            recoveryIntentData,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .recoveryIntentPersisted,
            operationID: operationID
        )
        let armedAnchor = try V3ImmutableTransactionRecoveryAnchor(
            operationID: operationID,
            vaultID: recoveryIntent.vaultID,
            intentDigest: intentDigest,
            phase: .recoverable
        )
        let armedAnchorData = armedAnchor.canonicalBytes
        try recoveryAnchorStore.replaceRecoveryAnchor(
            armedAnchorData,
            expectedAnchor: preparedAnchorData,
            vaultID: recoveryIntent.vaultID
        )
        try phaseObserver.didReach(
            .recoveryArmed,
            operationID: operationID
        )

        for (index, key) in orderedStagedEntryKeys.enumerated() {
            guard let entry = stagedEntries[key] else {
                preconditionFailure("A staged entry key must retain its bytes.")
            }
            try objectStore.stageEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID
            )
            try phaseObserver.didReach(
                .entryStaged(index: index),
                operationID: operationID
            )
        }
        try objectStore.stageManifest(
            request.candidateManifestData,
            digest: candidate.envelopeDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestStaged,
            operationID: operationID
        )

        let observedObservation: V3ManifestAncestryObservation
        do {
            observedObservation = try ancestryObserver.observeAncestry()
            let observedState = try validator.validatedState(
                for: observedObservation.proof
            )
            guard observedState == expectedState else {
                throw V3ImmutableTransactionError.expectedHeadsChanged
            }
            try validator.requireProjectedRepositoryUsage(
                observedObservation,
                candidate: candidate,
                candidateEntrySizes: candidateEntrySizes
            )
        } catch {
            try? removeRecoveryArtifacts(
                intent: recoveryIntent,
                intentData: recoveryIntentData,
                anchorData: armedAnchorData,
                stagedEntries: stagedEntries,
                stagedManifestData: request.candidateManifestData
            )
            throw error
        }
        try phaseObserver.didReach(
            .repositoryStateRechecked,
            operationID: operationID
        )

        for (index, key) in orderedStagedEntryKeys.enumerated() {
            guard let entry = stagedEntries[key] else {
                preconditionFailure("A staged entry key must retain its bytes.")
            }
            try objectStore.publishStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID
            )
            try phaseObserver.didReach(
                .entryPublished(index: index),
                operationID: operationID
            )
        }

        for entry in candidate.envelope.content.manifest.entries {
            _ = try validator.validatePublishedEntry(
                entry,
                vaultID: candidate.envelope.content.manifest.vaultID
            )
        }
        try phaseObserver.didReach(
            .publishedEntriesValidated,
            operationID: operationID
        )

        try objectStore.publishStagedManifest(
            request.candidateManifestData,
            digest: candidate.envelopeDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestPublished,
            operationID: operationID
        )
        try validator.validatePublishedManifest(candidate)
        try phaseObserver.didReach(
            .publishedManifestValidated,
            operationID: operationID
        )

        let checkpoint = try V3ManifestCheckpoint(
            verifiedManifest: candidate
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: initialProof.checkpoint.canonicalBytes,
            vaultID: checkpoint.vaultID
        )
        try phaseObserver.didReach(
            .checkpointAdvanced,
            operationID: operationID
        )
        let trusted = V3TrustedManifest(
            verifiedManifest: candidate,
            checkpoint: checkpoint
        )
        if (try? removeRecoveryArtifacts(
            intent: recoveryIntent,
            intentData: recoveryIntentData,
            anchorData: armedAnchorData,
            stagedEntries: stagedEntries,
            stagedManifestData: request.candidateManifestData
        )) != nil {
            try phaseObserver.didReach(
                .cleanupCompleted,
                operationID: operationID
            )
        }
        return trusted
    }

    private func requireNoInterruptedTransaction(
        for vaultID: String
    ) throws {
        guard let data = try recoveryAnchorStore.loadRecoveryAnchor(
            vaultID: vaultID
        ) else {
            return
        }
        guard let anchor = try? V3ImmutableTransactionRecoveryAnchor(
            canonicalBytes: data
        ), anchor.vaultID == vaultID else {
            throw V3ImmutableTransactionRecoveryError.invalidRecoveryAnchor(
                vaultID: vaultID
            )
        }
        throw V3ImmutableTransactionRecoveryError
            .interruptedTransactionPending(
                operationID: anchor.operationID.rawValue
            )
    }

    private func removeRecoveryArtifacts(
        intent: V3ImmutableTransactionRecoveryIntent,
        intentData: Data,
        anchorData: Data,
        stagedEntries: [V3EntryObjectKey: V3EncryptedEntry],
        stagedManifestData: Data
    ) throws {
        for entry in intent.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: entry.entryID,
                digest: entry.digest
            )
            guard let staged = stagedEntries[key] else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
            try objectStore.removeStagedEntry(
                staged.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: intent.operationID
            )
        }
        try objectStore.removeStagedManifest(
            stagedManifestData,
            digest: intent.candidateManifestDigest,
            operationID: intent.operationID
        )
        try recoveryAnchorStore.replaceRecoveryAnchor(
            nil,
            expectedAnchor: anchorData,
            vaultID: intent.vaultID
        )
        try? objectStore.removeRecoveryIntent(
            intentData,
            operationID: intent.operationID
        )
        try? objectStore.removeEmptyTransactionDirectories(
            operationID: intent.operationID,
            entryIDs: intent.stagedEntries.map(\.entryID)
        )
    }

}

private extension V3ManifestReconciliationResult {
    var canPublishAutomatically: Bool {
        switch self {
        case .noMergeRequired, .automaticMerge:
            true
        case .contentConflict, .securityConflict, .historyConflict:
            false
        }
    }
}
