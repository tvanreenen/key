import Foundation

/// One authenticated permanent-profile repository snapshot captured at a
/// serialized mutation boundary.
///
/// The observer owns graph authentication and exact resource accounting. The
/// publisher uses the returned object sets to avoid counting immutable objects
/// twice when resuming a partially published transaction.
struct V3DeviceWrappedRepositoryObservation: Equatable, Sendable {
    let checkpoint: V3ManifestCheckpoint
    let heads: [Data]
    let manifestDigests: Set<Data>
    let parentsByManifestDigest: [Data: [Data]]
    let referencedEntryObjects: Set<V3EntryObjectKey>
    let resourceUsage: V3ManifestRepositoryUsage
}

protocol V3DeviceWrappedRepositoryObserving: Sendable {
    func observeRepository(
        vaultID: String,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation

    func observeRepository(
        from trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation
}

extension V3DeviceWrappedRepositoryObserving {
    func observeRepository(
        from trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        let observation = try observeRepository(
            vaultID: trusted.checkpoint.vaultID,
            vaultKeys: vaultKeys
        )
        guard observation.checkpoint == trusted.checkpoint else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
        return observation
    }
}

struct V3DeviceWrappedExpectedRepositoryState: Equatable, Sendable {
    let checkpoint: V3ManifestCheckpoint
    let heads: [Data]
}

/// Validates one observer result and projects a key-rotation candidate onto its
/// exact existing immutable-object usage.
struct V3DeviceWrappedRepositoryUsageValidator: Sendable {
    private let limits: V3ManifestRepositoryLimits

    init(limits: V3ManifestRepositoryLimits) {
        self.limits = limits
    }

    func validatedState(
        _ observation: V3DeviceWrappedRepositoryObservation,
        vaultID: String
    ) throws -> V3DeviceWrappedExpectedRepositoryState {
        let usage = observation.resourceUsage
        guard observation.checkpoint.vaultID == vaultID,
              !observation.heads.isEmpty,
              observation.heads.allSatisfy({ $0.count == 32 }),
              Set(observation.heads).count == observation.heads.count,
              observation.heads == observation.heads.sorted(by: {
                  $0.lexicographicallyPrecedes($1)
              }),
              observation.manifestDigests.contains(
                  observation.checkpoint.envelopeDigest
              ),
              observation.heads.allSatisfy(
                  observation.manifestDigests.contains
              ),
              observation.parentsByManifestDigest.keys.allSatisfy(
                  observation.manifestDigests.contains
              ),
              observation.parentsByManifestDigest[
                  observation.checkpoint.envelopeDigest
              ] != nil,
              observation.heads.allSatisfy({
                  observation.parentsByManifestDigest[$0] != nil
              }),
              observation.parentsByManifestDigest.values.allSatisfy({ parents in
                  parents.allSatisfy({ $0.count == 32 })
                    && Set(parents).count == parents.count
                    && parents == parents.sorted(by: {
                        $0.lexicographicallyPrecedes($1)
                    })
                    && parents.allSatisfy({
                        observation.parentsByManifestDigest[$0] != nil
                    })
              }),
              usage.manifestObjectCount
                >= observation.manifestDigests.count,
              usage.referencedEntryObjectCount
                == observation.referencedEntryObjects.count,
              usage.manifestObjectCount >= 0,
              usage.maximumHistoryDepth >= 0,
              usage.totalManifestBytes >= 0,
              usage.referencedEntryObjectCount >= 0,
              usage.totalEntryBytes >= 0,
              usage.manifestObjectCount <= limits.maximumManifestObjects,
              usage.maximumHistoryDepth <= limits.maximumHistoryDepth,
              usage.totalManifestBytes <= limits.maximumTotalManifestBytes,
              usage.referencedEntryObjectCount
                <= limits.maximumReferencedEntryObjects,
              usage.totalEntryBytes <= limits.maximumTotalEntryBytes
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return V3DeviceWrappedExpectedRepositoryState(
            checkpoint: observation.checkpoint,
            heads: observation.heads
        )
    }

    func requireRecoveryPublicationState(
        _ observation: V3DeviceWrappedRepositoryObservation,
        expectedParentDigest: Data,
        candidateDigest: Data,
        candidateAlreadyPublished: Bool
    ) throws {
        if !candidateAlreadyPublished {
            guard observation.heads == [expectedParentDigest] else {
                throw V3ImmutableTransactionError.expectedHeadsChanged
            }
            return
        }
        guard observation.parentsByManifestDigest[candidateDigest] != nil,
              observation.heads.allSatisfy({
                  manifest(
                      $0,
                      descendsFrom: candidateDigest,
                      in: observation.parentsByManifestDigest
                  )
              })
        else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
    }

    func requireProjectedUsage(
        _ observation: V3DeviceWrappedRepositoryObservation,
        candidateManifestDigest: Data,
        candidateManifestBytes: Int,
        candidateEntries: [V3EntryObjectKey: V3EncryptedEntry]
    ) throws {
        let usage = observation.resourceUsage
        let addsManifest = !observation.manifestDigests.contains(
            candidateManifestDigest
        )
        let additionalManifestCount = addsManifest ? 1 : 0
        let additionalManifestBytes = addsManifest
            ? candidateManifestBytes
            : 0
        let additionalHistoryDepth = addsManifest ? 1 : 0

        var observedEntries = observation.referencedEntryObjects
        var additionalEntryCount = 0
        var additionalEntryBytes = 0
        for key in candidateEntries.keys.sorted(by: entryObjectKeyPrecedes) {
            guard let entry = candidateEntries[key] else {
                preconditionFailure("Validated entries must retain bytes.")
            }
            if observedEntries.insert(key).inserted {
                let byteCount = entry.canonicalBytes.count
                guard byteCount <= limits.maximumEntryBytes,
                      byteCount
                        <= limits.maximumTotalEntryBytes
                            - additionalEntryBytes
                else {
                    throw V3ImmutableTransactionError.objectTooLarge
                }
                additionalEntryCount += 1
                additionalEntryBytes += byteCount
            }
        }

        guard candidateManifestDigest.count == 32,
              candidateManifestBytes >= 0,
              candidateManifestBytes <= limits.maximumManifestBytes,
              usage.manifestObjectCount
                <= limits.maximumManifestObjects
                    - additionalManifestCount,
              limits.maximumHistoryDepth >= additionalHistoryDepth,
              usage.maximumHistoryDepth
                <= limits.maximumHistoryDepth - additionalHistoryDepth,
              usage.totalManifestBytes
                <= limits.maximumTotalManifestBytes
                    - additionalManifestBytes,
              usage.referencedEntryObjectCount
                <= limits.maximumReferencedEntryObjects
                    - additionalEntryCount,
              usage.totalEntryBytes
                <= limits.maximumTotalEntryBytes - additionalEntryBytes
        else {
            throw V3ImmutableTransactionError.objectTooLarge
        }
    }

    private func manifest(
        _ descendantDigest: Data,
        descendsFrom ancestorDigest: Data,
        in parentsByManifestDigest: [Data: [Data]]
    ) -> Bool {
        var pending = [descendantDigest]
        var visited: Set<Data> = []
        while let digest = pending.popLast() {
            if digest == ancestorDigest {
                return true
            }
            guard visited.insert(digest).inserted,
                  let parents = parentsByManifestDigest[digest]
            else {
                continue
            }
            pending.append(contentsOf: parents)
        }
        return false
    }
}
