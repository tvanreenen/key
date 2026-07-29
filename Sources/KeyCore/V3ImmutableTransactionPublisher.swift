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

/// Produces a complete authenticated ancestry proof from current repository
/// state.
///
/// Implementations must not return incomplete, recovery-required, or
/// unauthenticated state as a proof. The publisher calls this only from its
/// serialized mutation boundary. Resource usage must be the exact bounded
/// usage captured while producing the proof.
struct V3ManifestAncestryObservation: Equatable, Sendable {
    let proof: V3ManifestAncestryProof
    let resourceUsage: V3ManifestRepositoryUsage
}

protocol V3ManifestAncestryObserving: Sendable {
    func observeAncestry() throws -> V3ManifestAncestryObservation
}

/// Stages and publishes immutable repository objects.
///
/// Staging paths are local transaction state and have no manifest authority.
/// Publishing must be no-overwrite and durable before returning. An existing
/// destination is successful only when it contains the exact requested bytes.
protocol V3ImmutableObjectPublishing: V3ImmutableObjectReading {
    func stageEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func stageManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func publishStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws

    func publishStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws
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
/// after the final manifest is durable. TXN-408 adds recovery for interruption
/// after immutable publication begins.
struct V3ImmutableTransactionPublisher: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let ancestryObserver: any V3ManifestAncestryObserving
    private let objectStore: any V3ImmutableObjectPublishing
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let authenticator: V3ManifestAuthenticator
    private let reconciler: V3ManifestReconciler
    private let entryCipher: V3EntryCipher
    private let limits: V3ManifestRepositoryLimits

    init(
        mutationOwner: any VaultTransactionMutationOwning,
        ancestryObserver: any V3ManifestAncestryObserving,
        objectStore: any V3ImmutableObjectPublishing,
        checkpointStore: any V3ManifestCheckpointStoring,
        authenticator: V3ManifestAuthenticator = V3ManifestAuthenticator(),
        reconciler: V3ManifestReconciler = V3ManifestReconciler(),
        entryCipher: V3EntryCipher = V3EntryCipher(),
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.mutationOwner = mutationOwner
        self.ancestryObserver = ancestryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.authenticator = authenticator
        self.reconciler = reconciler
        self.entryCipher = entryCipher
        self.limits = limits
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

    private func publish(
        _ request: V3ImmutableTransactionRequest,
        operationID: VaultTransactionOperationID
    ) throws -> V3TrustedManifest {
        let initialObservation = try ancestryObserver.observeAncestry()
        let initialProof = initialObservation.proof
        let expectedState = try validatedState(for: initialProof)
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
        try requirePermittedCandidate(
            candidate,
            reconciliation: reconciliation
        )

        let stagedEntries = try validateStagedEntries(
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
                candidateEntrySizes[key] = try validatePublishedEntry(
                    entry,
                    vaultID: candidate.envelope.content.manifest.vaultID
                )
            }
        }
        try requireProjectedRepositoryUsage(
            initialObservation,
            candidate: candidate,
            candidateEntrySizes: candidateEntrySizes
        )

        for key in stagedEntries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let entry = stagedEntries[key] else {
                preconditionFailure("A staged entry key must retain its bytes.")
            }
            try objectStore.stageEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID
            )
        }
        try objectStore.stageManifest(
            request.candidateManifestData,
            digest: candidate.envelopeDigest,
            operationID: operationID
        )

        let observedObservation = try ancestryObserver.observeAncestry()
        let observedState = try validatedState(
            for: observedObservation.proof
        )
        guard observedState == expectedState else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
        try requireProjectedRepositoryUsage(
            observedObservation,
            candidate: candidate,
            candidateEntrySizes: candidateEntrySizes
        )

        for key in stagedEntries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let entry = stagedEntries[key] else {
                preconditionFailure("A staged entry key must retain its bytes.")
            }
            try objectStore.publishStagedEntry(
                entry.canonicalBytes,
                entryID: key.entryID,
                digest: key.digest,
                operationID: operationID
            )
        }

        for entry in candidate.envelope.content.manifest.entries {
            _ = try validatePublishedEntry(
                entry,
                vaultID: candidate.envelope.content.manifest.vaultID
            )
        }

        try objectStore.publishStagedManifest(
            request.candidateManifestData,
            digest: candidate.envelopeDigest,
            operationID: operationID
        )
        try validatePublishedManifest(candidate)

        let checkpoint = try V3ManifestCheckpoint(
            verifiedManifest: candidate
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: initialProof.checkpoint.canonicalBytes,
            vaultID: checkpoint.vaultID
        )
        return V3TrustedManifest(
            verifiedManifest: candidate,
            checkpoint: checkpoint
        )
    }

    private func validatedState(
        for proof: V3ManifestAncestryProof
    ) throws -> V3ExpectedRepositoryState {
        let state = try state(for: proof)
        var manifestsByDigest: [Data: V3VerifiedManifest] = [:]
        for manifest in proof.manifests {
            guard manifestsByDigest.updateValue(
                manifest,
                forKey: manifest.envelopeDigest
            ) == nil else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
        }
        guard let checkpointManifest = manifestsByDigest[
            proof.checkpoint.envelopeDigest
        ], checkpointManifest.envelope.content.manifest.vaultID
            == proof.checkpoint.vaultID,
            proof.heads.allSatisfy({
                manifestsByDigest[$0.envelopeDigest] == $0
            })
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        var checkpointLinkedHeadFound = false
        for head in proof.heads {
            var visited: Set<Data> = []
            if descends(
                head.envelopeDigest,
                from: proof.checkpoint.envelopeDigest,
                manifestsByDigest: manifestsByDigest,
                visited: &visited
            ) {
                checkpointLinkedHeadFound = true
                break
            }
        }
        guard checkpointLinkedHeadFound else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return state
    }

    private func requireProjectedRepositoryUsage(
        _ observation: V3ManifestAncestryObservation,
        candidate: V3VerifiedManifest,
        candidateEntrySizes: [V3EntryObjectKey: Int]
    ) throws {
        let proof = observation.proof
        let usage = observation.resourceUsage
        var proofManifestBytes = 0
        var existingEntryObjects: Set<V3EntryObjectKey> = []
        for manifest in proof.manifests {
            let byteCount = manifest.envelope.canonicalBytes.count
            guard proofManifestBytes <= Int.max - byteCount else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            proofManifestBytes += byteCount
            for entry in manifest.envelope.content.manifest.entries {
                existingEntryObjects.insert(try entryObjectKey(entry))
            }
        }

        guard usage.manifestObjectCount >= proof.manifests.count,
              usage.maximumHistoryDepth >= 0,
              usage.totalManifestBytes >= proofManifestBytes,
              usage.referencedEntryObjectCount == existingEntryObjects.count,
              usage.totalEntryBytes >= 0,
              usage.manifestObjectCount <= limits.maximumManifestObjects,
              usage.maximumHistoryDepth <= limits.maximumHistoryDepth,
              usage.totalManifestBytes <= limits.maximumTotalManifestBytes,
              usage.referencedEntryObjectCount
                <= limits.maximumReferencedEntryObjects,
              usage.totalEntryBytes <= limits.maximumTotalEntryBytes,
              !proof.manifests.contains(where: {
                  $0.envelopeDigest == candidate.envelopeDigest
              })
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        var additionalEntryCount = 0
        var additionalEntryBytes = 0
        for entry in candidate.envelope.content.manifest.entries {
            let key = try entryObjectKey(entry)
            guard let byteCount = candidateEntrySizes[key],
                  byteCount >= 0
            else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
            if existingEntryObjects.insert(key).inserted {
                guard additionalEntryBytes
                    <= limits.maximumTotalEntryBytes - byteCount
                else {
                    throw V3ImmutableTransactionError.objectTooLarge
                }
                additionalEntryCount += 1
                additionalEntryBytes += byteCount
            }
        }

        let candidateManifestBytes = candidate.envelope.canonicalBytes.count
        guard usage.manifestObjectCount < limits.maximumManifestObjects,
              usage.maximumHistoryDepth < limits.maximumHistoryDepth,
              usage.totalManifestBytes
                <= limits.maximumTotalManifestBytes - candidateManifestBytes,
              usage.referencedEntryObjectCount
                <= limits.maximumReferencedEntryObjects
                    - additionalEntryCount,
              usage.totalEntryBytes
                <= limits.maximumTotalEntryBytes - additionalEntryBytes
        else {
            throw V3ImmutableTransactionError.objectTooLarge
        }
    }

    private func state(
        for proof: V3ManifestAncestryProof
    ) throws -> V3ExpectedRepositoryState {
        var heads = try proof.heads.map(V3VaultHead.init(verifiedManifest:))
        heads.sort(by: vaultHeadPrecedes)
        guard !heads.isEmpty,
              Set(heads.map(\.envelopeDigest)).count == heads.count,
              heads.allSatisfy({ $0.vaultID == proof.checkpoint.vaultID })
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return V3ExpectedRepositoryState(
            checkpoint: proof.checkpoint,
            heads: heads
        )
    }

    private func requirePermittedCandidate(
        _ candidate: V3VerifiedManifest,
        reconciliation: V3ManifestReconciliationResult
    ) throws {
        switch reconciliation {
        case .noMergeRequired:
            return
        case let .automaticMerge(plan):
            guard candidate.envelope.content == plan.content else {
                throw V3ImmutableTransactionError
                    .candidateDoesNotMatchAutomaticMerge
            }
        case .contentConflict, .securityConflict, .historyConflict:
            throw V3ImmutableTransactionError.unresolvedConflict
        }
    }

    private func validateStagedEntries(
        _ entries: [V3EncryptedEntry],
        candidate: V3VerifiedManifest,
        vaultKey: Data
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        let body = candidate.envelope.content.manifest
        var candidateEntries: [V3EntryObjectKey: V3ManifestEntry] = [:]
        for entry in body.entries {
            candidateEntries[try entryObjectKey(entry)] = entry
        }

        var stagedEntries: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        for stagedEntry in entries {
            guard let digest = Base64URL.decodeCanonical(
                stagedEntry.ciphertextDigest
            ), digest.count == 32 else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
            let key = V3EntryObjectKey(
                entryID: stagedEntry.context.entryID,
                digest: digest
            )
            guard stagedEntries[key] == nil else {
                throw V3ImmutableTransactionError.duplicateStagedEntry
            }
            guard let manifestEntry = candidateEntries[key],
                  stagedEntry.context == (try? V3EntryAuthenticationContext(
                      vaultID: body.vaultID,
                      entry: manifestEntry
                  )),
                  manifestEntry.keyID == body.keyID,
                  (try? entryCipher.openPlaintextDataTrusted(
                      stagedEntry.canonicalBytes,
                      vaultID: body.vaultID,
                      manifestEntry: manifestEntry,
                      vaultKey: vaultKey
                  )) != nil
            else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
            stagedEntries[key] = stagedEntry
        }
        return stagedEntries
    }

    private func validatePublishedEntry(
        _ entry: V3ManifestEntry,
        vaultID: String
    ) throws -> Int {
        let key = try entryObjectKey(entry)
        let result = try objectStore.readEntry(
            entryID: key.entryID,
            digest: key.digest,
            maximumBytes: V3ManifestRepositoryLimits.standard.maximumEntryBytes
        )
        guard case let .available(data) = result,
              Data(SHA256.hash(data: data)) == key.digest,
              let parsed = try? entryCipher.parse(data),
              parsed.context == (try? V3EntryAuthenticationContext(
                  vaultID: vaultID,
                  entry: entry
              ))
        else {
            throw V3ImmutableTransactionError.referencedEntryUnavailable(
                entryID: entry.entryID,
                digest: entry.ciphertextDigest
            )
        }
        return data.count
    }

    private func validatePublishedManifest(
        _ candidate: V3VerifiedManifest
    ) throws {
        let result = try objectStore.readManifest(
            digest: candidate.envelopeDigest,
            maximumBytes: V3ManifestRepositoryLimits.standard.maximumManifestBytes
        )
        guard case let .available(data) = result,
              data == candidate.envelope.canonicalBytes
        else {
            throw V3ImmutableTransactionError.publishedManifestUnavailable(
                digest: Base64URL.encode(candidate.envelopeDigest)
            )
        }
    }
}

private struct V3ExpectedRepositoryState: Equatable {
    let checkpoint: V3ManifestCheckpoint
    let heads: [V3VaultHead]
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

private struct V3EntryObjectKey: Hashable {
    let entryID: String
    let digest: Data
}

private func entryObjectKey(
    _ entry: V3ManifestEntry
) throws -> V3EntryObjectKey {
    guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest),
          digest.count == 32
    else {
        throw V3ImmutableTransactionError.invalidStagedEntry
    }
    return V3EntryObjectKey(
        entryID: entry.entryID,
        digest: digest
    )
}

private func entryObjectKeyPrecedes(
    _ lhs: V3EntryObjectKey,
    _ rhs: V3EntryObjectKey
) -> Bool {
    Data(lhs.entryID.utf8).lexicographicallyPrecedes(Data(rhs.entryID.utf8))
        || (lhs.entryID == rhs.entryID
            && lhs.digest.lexicographicallyPrecedes(rhs.digest))
}

private func vaultHeadPrecedes(
    _ lhs: V3VaultHead,
    _ rhs: V3VaultHead
) -> Bool {
    Data(lhs.vaultID.utf8).lexicographicallyPrecedes(Data(rhs.vaultID.utf8))
        || (lhs.vaultID == rhs.vaultID
            && lhs.envelopeDigest.lexicographicallyPrecedes(
                rhs.envelopeDigest
            ))
}

private func descends(
    _ candidate: Data,
    from ancestor: Data,
    manifestsByDigest: [Data: V3VerifiedManifest],
    visited: inout Set<Data>
) -> Bool {
    if candidate == ancestor {
        return true
    }
    guard visited.insert(candidate).inserted,
          let manifest = manifestsByDigest[candidate]
    else {
        return false
    }
    for encodedParent in manifest.envelope.content.parents {
        guard let parent = Base64URL.decodeCanonical(encodedParent),
              parent.count == 32
        else {
            continue
        }
        if descends(
            parent,
            from: ancestor,
            manifestsByDigest: manifestsByDigest,
            visited: &visited
        ) {
            return true
        }
    }
    return false
}
