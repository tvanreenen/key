import CryptoKit
import Foundation

protocol VaultMutationServicing: Sendable {
    func add(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws

    func edit(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws

    func copy(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws

    func move(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws

    func remove(
        name: String,
        operationID: VaultTransactionOperationID
    ) throws

    func resolve(
        _ resolutions: [VaultConflictResolution],
        operationID: VaultTransactionOperationID
    ) throws
}

/// Plans and publishes ordinary v3 entry mutations from one freshly
/// authenticated repository state.
///
/// The helper owns serialization and supplies `operationID`. This service
/// never operates on legacy `.secret` paths: it seals immutable entry objects,
/// builds an authenticated child manifest, and delegates all expected-head,
/// staging, durability, and checkpoint work to the transaction publisher.
struct V3VaultMutationService: VaultMutationServicing, Sendable {
    private struct LinearBase {
        let state: V3VaultRuntimeState
        let proof: V3ManifestAncestryProof
        let head: V3VerifiedManifest

        var body: V3ManifestBody {
            head.envelope.content.manifest
        }
    }

    private let context: V3ReadRuntimeContext
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let limits: V3ManifestRepositoryLimits
    private let entryCipher = V3EntryCipher()
    private let manifestBuilder = V3ManifestCandidateBuilder()
    private let reconciler = V3ManifestReconciler()
    private let observationBuilder = V3VaultObservationBuilder()

    init(
        context: V3ReadRuntimeContext,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.context = context
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.limits = limits
    }

    func add(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        let name = try normalizedV3EntryName(name)
        let base = try prepareLinearBase(operationID: operationID)
        guard !base.body.entries.contains(where: { $0.name == name }) else {
            throw AppError.entryExists("Secret '\(name)' already exists.")
        }
        let plaintext = try normalizedSecret(secret, for: type)
        let entryID = freshEntryID(excluding: base.body.entries)
        let encrypted = try seal(
            plaintext,
            entryID: entryID,
            name: name,
            type: type,
            revision: 1,
            base: base
        )
        var entries = base.body.entries
        entries.append(manifestEntry(for: encrypted))
        try publishLinearMutation(
            kind: .addEntry,
            entries: entries,
            stagedEntries: [encrypted],
            base: base,
            operationID: operationID
        )
    }

    func edit(
        name: String,
        secret: String,
        type: SecretEntryType,
        operationID: VaultTransactionOperationID
    ) throws {
        let name = try normalizedV3EntryName(name)
        let base = try prepareLinearBase(operationID: operationID)
        guard let existing = base.body.entries.first(where: {
            $0.name == name
        }) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }
        guard existing.revision < v3MaximumSafeInteger else {
            throw V3EntryResealingError.revisionOverflow
        }
        let plaintext = try normalizedSecret(secret, for: type)
        let encrypted = try seal(
            plaintext,
            entryID: existing.entryID,
            name: name,
            type: type,
            revision: existing.revision + 1,
            base: base
        )
        let replacement = manifestEntry(for: encrypted)
        let entries = base.body.entries.map {
            $0.entryID == existing.entryID ? replacement : $0
        }
        try publishLinearMutation(
            kind: .editEntry,
            entries: entries,
            stagedEntries: [encrypted],
            base: base,
            operationID: operationID
        )
    }

    func copy(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        let source = try normalizedV3EntryName(source)
        let destination = try normalizedV3EntryName(destination)
        guard source != destination else {
            throw AppError.operationRefused(
                "A duplicate needs a different destination name."
            )
        }
        let base = try prepareLinearBase(operationID: operationID)
        guard let sourceEntry = base.body.entries.first(where: {
            $0.name == source
        }) else {
            throw AppError.entryNotFound("Secret '\(source)' was not found.")
        }
        let destinationEntry = base.body.entries.first(where: {
            $0.name == destination
        })
        guard destinationEntry == nil || overwrite else {
            throw AppError.entryExists(
                "Secret '\(destination)' already exists."
            )
        }
        let plaintext = try plaintext(
            for: sourceEntry,
            vaultKey: base.state.vaultKey,
            vaultID: base.body.vaultID
        )
        let encrypted = try seal(
            plaintext,
            entryID: freshEntryID(excluding: base.body.entries),
            name: destination,
            type: sourceEntry.type,
            revision: 1,
            base: base
        )
        var entries = base.body.entries.filter {
            $0.entryID != destinationEntry?.entryID
        }
        entries.append(manifestEntry(for: encrypted))
        try publishLinearMutation(
            kind: .copyEntry,
            entries: entries,
            stagedEntries: [encrypted],
            base: base,
            operationID: operationID
        )
    }

    func move(
        source: String,
        destination: String,
        overwrite: Bool,
        operationID: VaultTransactionOperationID
    ) throws {
        let source = try normalizedV3EntryName(source)
        let destination = try normalizedV3EntryName(destination)
        guard source != destination else {
            throw V3EntryResealingError.unchangedName
        }
        let base = try prepareLinearBase(operationID: operationID)
        guard let sourceEntry = base.body.entries.first(where: {
            $0.name == source
        }) else {
            throw AppError.entryNotFound("Secret '\(source)' was not found.")
        }
        let destinationEntry = base.body.entries.first(where: {
            $0.name == destination
        })
        guard destinationEntry == nil || overwrite else {
            throw AppError.entryExists(
                "Secret '\(destination)' already exists."
            )
        }
        guard sourceEntry.revision < v3MaximumSafeInteger else {
            throw V3EntryResealingError.revisionOverflow
        }
        let plaintext = try plaintext(
            for: sourceEntry,
            vaultKey: base.state.vaultKey,
            vaultID: base.body.vaultID
        )
        let encrypted = try seal(
            plaintext,
            entryID: sourceEntry.entryID,
            name: destination,
            type: sourceEntry.type,
            revision: sourceEntry.revision + 1,
            base: base
        )
        let replacement = manifestEntry(for: encrypted)
        var entries = base.body.entries.filter {
            $0.entryID != sourceEntry.entryID
                && $0.entryID != destinationEntry?.entryID
        }
        entries.append(replacement)
        try publishLinearMutation(
            kind: .moveEntry,
            entries: entries,
            stagedEntries: [encrypted],
            base: base,
            operationID: operationID
        )
    }

    func remove(
        name: String,
        operationID: VaultTransactionOperationID
    ) throws {
        let name = try normalizedV3EntryName(name)
        let base = try prepareLinearBase(operationID: operationID)
        guard let existing = base.body.entries.first(where: {
            $0.name == name
        }) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }
        try publishLinearMutation(
            kind: .removeEntry,
            entries: base.body.entries.filter {
                $0.entryID != existing.entryID
            },
            stagedEntries: [],
            base: base,
            operationID: operationID
        )
    }

    func resolve(
        _ resolutions: [VaultConflictResolution],
        operationID: VaultTransactionOperationID
    ) throws {
        let state = try loadStateAndRecoverIfNeeded(
            operationID: operationID
        )
        guard let proof = state.classification.ancestryProof else {
            throw VaultUXServiceError.recoveryRequired
        }
        let snapshot = try observationBuilder.build(
            state.classification,
            trustedCurrent: state.trustedCurrent
        )
        let plan = try V3ConflictResolutionPlanner().plan(
            resolutions,
            snapshot: snapshot
        )
        guard normalizedHeads(plan.expectedHeads)
                == normalizedHeads(try proof.heads.map(V3VaultHead.init))
        else {
            throw VaultUXServiceError.expectedHeadsChanged
        }
        guard case let .contentConflict(report) = try reconciler.reconcile(
            proof
        ) else {
            throw VaultUXServiceError.expectedHeadsChanged
        }

        var entriesByID = Dictionary(
            uniqueKeysWithValues: report.entriesReconciledByID.map {
                ($0.entryID, $0)
            }
        )
        var stagedEntries: [V3EncryptedEntry] = []
        for selection in plan.selections {
            if let entryID = selection.entryID {
                guard let conflict = report.entryConflicts.first(where: {
                    $0.entryID == entryID
                }) else {
                    throw VaultUXServiceError.expectedHeadsChanged
                }
                guard let selected = selection.selectedEntry else {
                    entriesByID.removeValue(forKey: entryID)
                    continue
                }
                let highestRevision = conflict.versions.compactMap {
                    $0.entry?.revision
                }.max() ?? selected.revision
                guard highestRevision < v3MaximumSafeInteger else {
                    throw V3EntryResealingError.revisionOverflow
                }
                let selectedPlaintext = try plaintext(
                    for: selected,
                    vaultKey: state.vaultKey,
                    vaultID: state.trustedCurrent.checkpoint.vaultID
                )
                let encrypted = try seal(
                    selectedPlaintext,
                    entryID: selected.entryID,
                    name: selected.name,
                    type: selected.type,
                    revision: highestRevision + 1,
                    vaultID: state.trustedCurrent.checkpoint.vaultID,
                    keyID: selected.keyID,
                    vaultKey: state.vaultKey
                )
                entriesByID[entryID] = manifestEntry(for: encrypted)
                stagedEntries.append(encrypted)
            } else {
                guard let selected = selection.selectedEntry else {
                    throw VaultUXServiceError.expectedHeadsChanged
                }
                entriesByID = entriesByID.filter {
                    $0.value.name != selected.name
                        || $0.key == selected.entryID
                }
                entriesByID[selected.entryID] = selected
            }
        }

        guard let authority = proof.heads.first?
            .envelope.content.manifest
        else {
            throw VaultUXServiceError.recoveryRequired
        }
        let body = replacingEntries(
            in: authority,
            with: Array(entriesByID.values)
        )
        let content = V3ManifestContent(
            parents: proof.heads.sorted {
                $0.envelopeDigest.lexicographicallyPrecedes(
                    $1.envelopeDigest
                )
            }.map {
                Base64URL.encode($0.envelopeDigest)
            },
            manifest: body
        )
        let candidate = try manifestBuilder.build(
            content: content,
            vaultKey: state.vaultKey,
            trustAnchor: .verifiedParents(proof.heads)
        )
        try publish(
            V3ImmutableTransactionRequest(
                kind: .resolveConflict,
                candidateManifestData: candidate.data,
                stagedEntries: stagedEntries,
                candidateVaultKey: state.vaultKey
            ),
            state: state,
            operationID: operationID
        )
    }

    private func prepareLinearBase(
        operationID: VaultTransactionOperationID
    ) throws -> LinearBase {
        var state = try loadStateAndRecoverIfNeeded(
            operationID: operationID
        )
        var proof = try requiredProof(from: state)
        switch try reconciler.reconcile(proof) {
        case .noMergeRequired:
            break
        case let .automaticMerge(plan):
            let mergeID = VaultTransactionOperationID()
            let candidate = try manifestBuilder.build(
                content: plan.content,
                vaultKey: state.vaultKey,
                trustAnchor: .verifiedParents(proof.heads)
            )
            try publish(
                V3ImmutableTransactionRequest(
                    kind: .mergeHeads,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: state.vaultKey
                ),
                state: state,
                operationID: mergeID
            )
            state = try loadStateAndRecoverIfNeeded(
                operationID: operationID
            )
            proof = try requiredProof(from: state)
            guard case .noMergeRequired = try reconciler.reconcile(proof)
            else {
                throw VaultUXServiceError.expectedHeadsChanged
            }
        case .contentConflict:
            throw VaultUXServiceError.contentConflict
        case .securityConflict:
            throw VaultUXServiceError.securityConflict
        case .historyConflict:
            throw VaultUXServiceError.recoveryRequired
        }
        guard proof.heads.count == 1, let head = proof.heads.first else {
            throw VaultUXServiceError.recoveryRequired
        }
        return LinearBase(state: state, proof: proof, head: head)
    }

    private func loadStateAndRecoverIfNeeded(
        operationID: VaultTransactionOperationID
    ) throws -> V3VaultRuntimeState {
        var state = try context.loadState(
            reason: "Unlock version 3 vault to publish a guarded change."
        )
        let publisher = makePublisher(
            vaultKey: state.vaultKey,
            operationID: operationID
        )
        do {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: state.trustedCurrent.checkpoint.vaultID,
                availableVaultKeys: [state.vaultKey]
            )
        } catch let error as V3ImmutableTransactionRecoveryError {
            switch error {
            case .transactionDirectoryUnavailable,
                .interruptedTransactionPending:
                throw VaultUXServiceError.vaultIncomplete
            case .invalidRecoveryAnchor, .invalidIntent,
                .checkpointUnavailable, .vaultKeyUnavailable,
                .invalidRecoveryState:
                throw VaultUXServiceError.recoveryRequired
            }
        } catch let error as V3ImmutableTransactionError {
            throw vaultUXError(for: error)
        }
        state = try context.loadState(
            reason: "Revalidate version 3 vault before publication."
        )
        return state
    }

    private func requiredProof(
        from state: V3VaultRuntimeState
    ) throws -> V3ManifestAncestryProof {
        switch state.classification.status {
        case .ready, .contentConflicted:
            guard let proof = state.classification.ancestryProof else {
                throw VaultUXServiceError.recoveryRequired
            }
            return proof
        case .incomplete:
            throw VaultUXServiceError.vaultIncomplete
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        }
    }

    private func publishLinearMutation(
        kind: VaultTransactionMutationKind,
        entries: [V3ManifestEntry],
        stagedEntries: [V3EncryptedEntry],
        base: LinearBase,
        operationID: VaultTransactionOperationID
    ) throws {
        let body = replacingEntries(in: base.body, with: entries)
        let content = V3ManifestContent(
            parents: [Base64URL.encode(base.head.envelopeDigest)],
            manifest: body
        )
        let candidate = try manifestBuilder.build(
            content: content,
            vaultKey: base.state.vaultKey,
            trustAnchor: .verifiedParents([base.head])
        )
        try publish(
            V3ImmutableTransactionRequest(
                kind: kind,
                candidateManifestData: candidate.data,
                stagedEntries: stagedEntries,
                candidateVaultKey: base.state.vaultKey
            ),
            state: base.state,
            operationID: operationID
        )
    }

    private func publish(
        _ request: V3ImmutableTransactionRequest,
        state: V3VaultRuntimeState,
        operationID: VaultTransactionOperationID
    ) throws {
        do {
            _ = try makePublisher(
                vaultKey: state.vaultKey,
                operationID: operationID
            ).publish(request)
        } catch let error as V3ImmutableTransactionError {
            throw vaultUXError(for: error)
        }
    }

    private func makePublisher(
        vaultKey: Data,
        operationID: VaultTransactionOperationID
    ) -> V3ImmutableTransactionPublisher {
        V3ImmutableTransactionPublisher(
            mutationOwner: DirectVaultTransactionMutationOwner(
                operationID: operationID
            ),
            ancestryObserver: V3LiveManifestAncestryObserver(
                source: objectStore,
                checkpointStore: checkpointStore,
                vaultID: context.vaultID,
                vaultKey: vaultKey,
                limits: limits
            ),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            limits: limits
        )
    }

    private func seal(
        _ plaintext: String,
        entryID: String,
        name: String,
        type: SecretEntryType,
        revision: UInt64,
        base: LinearBase
    ) throws -> V3EncryptedEntry {
        try seal(
            plaintext,
            entryID: entryID,
            name: name,
            type: type,
            revision: revision,
            vaultID: base.body.vaultID,
            keyID: base.body.keyID,
            vaultKey: base.state.vaultKey
        )
    }

    private func seal(
        _ plaintext: String,
        entryID: String,
        name: String,
        type: SecretEntryType,
        revision: UInt64,
        vaultID: String,
        keyID: V3VaultKeyID,
        vaultKey: Data
    ) throws -> V3EncryptedEntry {
        try entryCipher.seal(
            plaintext,
            context: V3EntryAuthenticationContext(
                vaultID: vaultID,
                entryID: entryID,
                name: name,
                type: type,
                keyID: keyID,
                revision: revision
            ),
            vaultKey: vaultKey
        )
    }

    private func plaintext(
        for entry: V3ManifestEntry,
        vaultKey: Data,
        vaultID: String
    ) throws -> String {
        guard let digest = Base64URL.decodeCanonical(
            entry.ciphertextDigest
        ), digest.count == 32 else {
            throw VaultUXServiceError.recoveryRequired
        }
        let data: Data
        switch try objectStore.readEntry(
            entryID: entry.entryID,
            digest: digest,
            maximumBytes: limits.maximumEntryBytes
        ) {
        case let .available(value)
            where Data(SHA256.hash(data: value)) == digest:
            data = value
        case .unavailable:
            throw VaultUXServiceError.vaultIncomplete
        case .available, .invalid, .tooLarge:
            throw VaultUXServiceError.recoveryRequired
        }
        let plaintext = try entryCipher.openPlaintextDataTrusted(
            data,
            vaultID: vaultID,
            manifestEntry: entry,
            vaultKey: vaultKey
        )
        guard let value = String(data: plaintext, encoding: .utf8) else {
            throw V3EncryptedEntryError.invalidPlaintext
        }
        return value
    }

    private func replacingEntries(
        in body: V3ManifestBody,
        with entries: [V3ManifestEntry]
    ) -> V3ManifestBody {
        V3ManifestBody(
            vaultID: body.vaultID,
            mode: body.mode,
            keyID: body.keyID,
            devices: body.devices,
            wrappedKeys: body.wrappedKeys,
            entries: entries.sorted(by: v3ManifestEntryPrecedes)
        )
    }

    private func manifestEntry(
        for encrypted: V3EncryptedEntry
    ) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: encrypted.context.entryID,
            name: encrypted.context.name,
            type: encrypted.context.type,
            revision: encrypted.context.revision,
            keyID: encrypted.context.keyID,
            ciphertextDigest: encrypted.ciphertextDigest
        )
    }

    private func freshEntryID(
        excluding entries: [V3ManifestEntry]
    ) -> String {
        var candidate: String
        repeat {
            candidate = UUID().uuidString.lowercased()
        } while entries.contains(where: { $0.entryID == candidate })
        return candidate
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

    private func normalizedHeads(
        _ heads: [V3VaultHead]
    ) -> [V3VaultHead] {
        heads.sorted {
            $0.envelopeDigest.lexicographicallyPrecedes(
                $1.envelopeDigest
            )
        }
    }

    private func vaultUXError(
        for error: V3ImmutableTransactionError
    ) -> VaultUXServiceError {
        switch error {
        case .expectedHeadsChanged:
            .expectedHeadsChanged
        case .unresolvedConflict:
            .contentConflict
        case .referencedEntryUnavailable,
            .publishedManifestUnavailable:
            .vaultIncomplete
        case .invalidAncestryProof,
            .candidateDoesNotMatchAutomaticMerge,
            .duplicateStagedEntry,
            .invalidStagedEntry,
            .objectTooLarge,
            .referencedEntryInvalid,
            .publishedManifestInvalid:
            .recoveryRequired
        }
    }
}
