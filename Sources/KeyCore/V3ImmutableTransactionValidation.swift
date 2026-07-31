import CryptoKit
import Foundation

struct V3EntryObjectKey: Hashable, Sendable {
    let entryID: String
    let digest: Data
}

/// Shared validation policy for initial publication and interrupted recovery.
///
/// Keeping these checks in one value prevents the two state machines from
/// drifting into different authentication, entry, or resource-limit rules.
struct V3ImmutableTransactionValidator: Sendable {
    private let objectStore: any V3TransactionArtifactStore
    private let entryCipher: V3EntryCipher
    private let limits: V3ManifestRepositoryLimits

    init(
        objectStore: any V3TransactionArtifactStore,
        entryCipher: V3EntryCipher,
        limits: V3ManifestRepositoryLimits
    ) {
        self.objectStore = objectStore
        self.entryCipher = entryCipher
        self.limits = limits
    }

    func validatedState(
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
            }) else {
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

    func requireProjectedRepositoryUsage(
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

    func requirePermittedCandidate(
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

    func validateStagedEntries(
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

    func parseEncryptedEntry(_ data: Data) throws -> V3EncryptedEntry {
        try entryCipher.parse(data)
    }

    func validatePublishedEntry(
        _ entry: V3ManifestEntry,
        vaultID: String
    ) throws -> Int {
        let key = try entryObjectKey(entry)
        let result = try objectStore.readEntry(
            entryID: key.entryID,
            digest: key.digest,
            maximumBytes: limits.maximumEntryBytes
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

    func validatePublishedManifest(
        _ candidate: V3VerifiedManifest
    ) throws {
        let result = try objectStore.readManifest(
            digest: candidate.envelopeDigest,
            maximumBytes: limits.maximumManifestBytes
        )
        guard case let .available(data) = result,
              data == candidate.envelope.canonicalBytes
        else {
            throw V3ImmutableTransactionError.publishedManifestUnavailable(
                digest: Base64URL.encode(candidate.envelopeDigest)
            )
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
}

func entryObjectKey(
    _ entry: V3ManifestEntry
) throws -> V3EntryObjectKey {
    guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest),
          digest.count == 32
    else {
        throw V3ImmutableTransactionError.invalidStagedEntry
    }
    return V3EntryObjectKey(entryID: entry.entryID, digest: digest)
}

func entryObjectKeyPrecedes(
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
