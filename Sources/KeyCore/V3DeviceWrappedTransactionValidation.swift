import CryptoKit
import Foundation

struct V3DeviceWrappedValidatedContentMutation: Sendable {
    let envelope: V3DeviceWrappedManifestEnvelope
    let manifestDigest: Data
    let stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
}

/// Shared permanent-profile validation for initial publication and recovery.
///
/// This type has no checkpoint or transaction-state authority. It validates
/// exact immutable bytes, the content-only parent transition, staged entry
/// coverage, and the bounded candidate snapshot supplied by its caller.
struct V3DeviceWrappedTransactionValidator: Sendable {
    private let objectStore: any V3TransactionArtifactStore
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()

    init(
        objectStore: any V3TransactionArtifactStore,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits
    ) {
        self.objectStore = objectStore
        self.cache = cache
        self.limits = limits
    }

    func validate(
        manifestData: Data,
        manifestDigest: Data,
        expectedCheckpoint: V3ManifestCheckpoint,
        kind: VaultTransactionMutationKind,
        stagedEntries: [V3EncryptedEntry],
        vaultKey: Data
    ) throws -> V3DeviceWrappedValidatedContentMutation {
        guard manifestData.count <= limits.maximumManifestBytes,
              manifestDigest.count == 32,
              Data(SHA256.hash(data: manifestData)) == manifestDigest,
              stagedEntries.count <= limits.maximumReferencedEntryObjects
        else {
            throw V3ImmutableTransactionError.objectTooLarge
        }

        let parent = try loadParent(
            expectedCheckpoint,
            vaultKey: vaultKey
        )
        let candidate = try parseAndAuthenticate(
            manifestData,
            vaultKey: vaultKey
        )
        try requireContentOnlyTransition(
            from: parent,
            to: candidate,
            expectedCheckpoint: expectedCheckpoint,
            kind: kind
        )

        let changedEntries = try changedCandidateEntries(
            from: parent.body.entries,
            to: candidate.body.entries
        )
        let staged = try validateStagedEntries(
            stagedEntries,
            candidate: candidate,
            expectedEntries: changedEntries,
            vaultKey: vaultKey
        )
        try validateCandidateSnapshot(
            candidate,
            stagedEntries: staged
        )
        return V3DeviceWrappedValidatedContentMutation(
            envelope: candidate,
            manifestDigest: manifestDigest,
            stagedEntries: staged
        )
    }

    func validateStagedObjects(
        _ validated: V3DeviceWrappedValidatedContentMutation,
        operationID: VaultTransactionOperationID
    ) throws {
        for key in validated.stagedEntries.keys.sorted(
            by: entryObjectKeyPrecedes
        ) {
            guard let entry = validated.stagedEntries[key] else {
                preconditionFailure("A staged entry must retain its bytes.")
            }
            try requireExact(
                objectStore.readStagedEntry(
                    entryID: key.entryID,
                    digest: key.digest,
                    operationID: operationID,
                    maximumBytes: limits.maximumEntryBytes
                ),
                expected: entry.canonicalBytes,
                unavailable: .invalidStagedEntry,
                invalid: .invalidStagedEntry
            )
        }
    }

    func validatePublishedEntries(
        _ envelope: V3DeviceWrappedManifestEnvelope
    ) throws {
        var totalBytes = 0
        for entry in envelope.body.entries {
            let count = try validatePublishedEntry(
                entry,
                vaultID: envelope.body.vaultID
            )
            guard count <= limits.maximumTotalEntryBytes - totalBytes else {
                throw V3ImmutableTransactionError.objectTooLarge
            }
            totalBytes += count
        }
    }

    func validatePublishedManifest(
        _ validated: V3DeviceWrappedValidatedContentMutation
    ) throws {
        let result = try objectStore.readManifest(
            digest: validated.manifestDigest,
            maximumBytes: limits.maximumManifestBytes
        )
        try requireExact(
            result,
            expected: validated.envelope.canonicalBytes,
            unavailable: .publishedManifestUnavailable(
                digest: Base64URL.encode(validated.manifestDigest)
            ),
            invalid: .publishedManifestInvalid(
                digest: Base64URL.encode(validated.manifestDigest)
            )
        )
    }

    func parseEncryptedEntry(_ data: Data) throws -> V3EncryptedEntry {
        try entryCipher.parse(data)
    }

    private func loadParent(
        _ checkpoint: V3ManifestCheckpoint,
        vaultKey: Data
    ) throws -> V3DeviceWrappedManifestEnvelope {
        let data: Data
        if case let .available(value) = try? cache.load(for: checkpoint) {
            data = value
        } else {
            let result = try objectStore.readManifest(
                digest: checkpoint.envelopeDigest,
                maximumBytes: limits.maximumManifestBytes
            )
            switch result {
            case let .available(value):
                data = value
            case .unavailable:
                throw V3ImmutableTransactionError
                    .publishedManifestUnavailable(
                        digest: Base64URL.encode(
                            checkpoint.envelopeDigest
                        )
                    )
            case .invalid, .tooLarge:
                throw V3ImmutableTransactionError
                    .publishedManifestInvalid(
                        digest: Base64URL.encode(
                            checkpoint.envelopeDigest
                        )
                    )
            }
        }
        guard Data(SHA256.hash(data: data)) == checkpoint.envelopeDigest else {
            throw V3ImmutableTransactionError.publishedManifestInvalid(
                digest: Base64URL.encode(checkpoint.envelopeDigest)
            )
        }
        let envelope = try parseAndAuthenticate(data, vaultKey: vaultKey)
        guard envelope.body.vaultID == checkpoint.vaultID else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return envelope
    }

    private func parseAndAuthenticate(
        _ data: Data,
        vaultKey: Data
    ) throws -> V3DeviceWrappedManifestEnvelope {
        let envelope: V3DeviceWrappedManifestEnvelope
        do {
            envelope = try envelopeCodec.parse(data)
        } catch {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        guard vaultKey.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: vaultKey,
                  vaultID: envelope.body.vaultID
              )) == envelope.body.keyID,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  envelope.authenticationTag,
                  canonicalContent: envelope.canonicalContentBytes,
                  vaultID: envelope.body.vaultID,
                  vaultKey: vaultKey
              )) == true
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return envelope
    }

    private func requireContentOnlyTransition(
        from parent: V3DeviceWrappedManifestEnvelope,
        to candidate: V3DeviceWrappedManifestEnvelope,
        expectedCheckpoint: V3ManifestCheckpoint,
        kind: VaultTransactionMutationKind
    ) throws {
        guard candidate.parents == [expectedCheckpoint.envelopeDigest],
              candidate.authorizations.isEmpty,
              candidate.body.vaultID == parent.body.vaultID,
              candidate.body.keyID == parent.body.keyID,
              candidate.body.authorityTransitionID
                == parent.body.authorityTransitionID,
              candidate.body.devices == parent.body.devices,
              candidate.body.wrappedKeys == parent.body.wrappedKeys
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        let parentByID = Dictionary(
            uniqueKeysWithValues: parent.body.entries.map {
                ($0.entryID, $0)
            }
        )
        let candidateByID = Dictionary(
            uniqueKeysWithValues: candidate.body.entries.map {
                ($0.entryID, $0)
            }
        )
        let added = candidate.body.entries.filter {
            parentByID[$0.entryID] == nil
        }
        let removed = parent.body.entries.filter {
            candidateByID[$0.entryID] == nil
        }
        let updated: [(old: V3ManifestEntry, new: V3ManifestEntry)] =
            candidate.body.entries.compactMap { entry in
            guard let old = parentByID[entry.entryID], old != entry else {
                return nil
            }
            return (old: old, new: entry)
        }
        guard added.allSatisfy({ $0.revision == 1 }),
              updated.allSatisfy({ change in
                  change.old.revision < v3MaximumSafeInteger
                      && change.new.revision == change.old.revision + 1
              })
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        let permitted: Bool
        switch kind {
        case .addEntry:
            permitted = added.count == 1
                && removed.isEmpty
                && updated.isEmpty
        case .editEntry:
            permitted = added.isEmpty
                && removed.isEmpty
                && updated.count == 1
                && updated[0].old.name == updated[0].new.name
        case .copyEntry:
            permitted = added.count == 1
                && updated.isEmpty
                && removed.count <= 1
                && (removed.first?.name == added[0].name
                    || removed.isEmpty)
        case .moveEntry:
            permitted = added.isEmpty
                && updated.count == 1
                && removed.count <= 1
                && updated[0].old.name != updated[0].new.name
                && updated[0].old.type == updated[0].new.type
                && (removed.first?.name == updated[0].new.name
                    || removed.isEmpty)
        case .removeEntry:
            permitted = added.isEmpty
                && updated.isEmpty
                && removed.count == 1
        case .resolveConflict, .mergeHeads, .migrateToV3, .enrollDevice,
            .recoverInterruptedTransaction:
            permitted = false
        }
        guard permitted else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
    }

    private func changedCandidateEntries(
        from parent: [V3ManifestEntry],
        to candidate: [V3ManifestEntry]
    ) throws -> [V3EntryObjectKey: V3ManifestEntry] {
        let parentByID = Dictionary(
            uniqueKeysWithValues: parent.map { ($0.entryID, $0) }
        )
        var result: [V3EntryObjectKey: V3ManifestEntry] = [:]
        for entry in candidate where parentByID[entry.entryID] != entry {
            let key = try entryObjectKey(entry)
            guard result.updateValue(entry, forKey: key) == nil else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
        }
        return result
    }

    private func validateStagedEntries(
        _ entries: [V3EncryptedEntry],
        candidate: V3DeviceWrappedManifestEnvelope,
        expectedEntries: [V3EntryObjectKey: V3ManifestEntry],
        vaultKey: Data
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var totalBytes = 0
        for encrypted in entries {
            guard encrypted.canonicalBytes.count <= limits.maximumEntryBytes,
                  encrypted.canonicalBytes.count
                    <= limits.maximumTotalEntryBytes - totalBytes,
                  let digest = Base64URL.decodeCanonical(
                      encrypted.ciphertextDigest
                  ), digest.count == 32
            else {
                throw V3ImmutableTransactionError.objectTooLarge
            }
            totalBytes += encrypted.canonicalBytes.count
            let key = V3EntryObjectKey(
                entryID: encrypted.context.entryID,
                digest: digest
            )
            guard result[key] == nil else {
                throw V3ImmutableTransactionError.duplicateStagedEntry
            }
            guard let manifestEntry = expectedEntries[key],
                  encrypted.context == (try? V3EntryAuthenticationContext(
                      vaultID: candidate.body.vaultID,
                      entry: manifestEntry
                  )),
                  (try? entryCipher.openPlaintextDataTrusted(
                      encrypted.canonicalBytes,
                      vaultID: candidate.body.vaultID,
                      manifestEntry: manifestEntry,
                      vaultKey: vaultKey
                  )) != nil
            else {
                throw V3ImmutableTransactionError.invalidStagedEntry
            }
            result[key] = encrypted
        }
        guard Set(result.keys) == Set(expectedEntries.keys) else {
            throw V3ImmutableTransactionError.invalidStagedEntry
        }
        return result
    }

    private func validateCandidateSnapshot(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
    ) throws {
        guard candidate.body.entries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3ImmutableTransactionError.objectTooLarge
        }
        var totalBytes = 0
        for entry in candidate.body.entries {
            let key = try entryObjectKey(entry)
            let count: Int
            if let staged = stagedEntries[key] {
                count = staged.canonicalBytes.count
            } else {
                count = try validatePublishedEntry(
                    entry,
                    vaultID: candidate.body.vaultID
                )
            }
            guard count <= limits.maximumTotalEntryBytes - totalBytes else {
                throw V3ImmutableTransactionError.objectTooLarge
            }
            totalBytes += count
        }
    }

    private func validatePublishedEntry(
        _ entry: V3ManifestEntry,
        vaultID: String
    ) throws -> Int {
        let key = try entryObjectKey(entry)
        let result = try objectStore.readEntry(
            entryID: key.entryID,
            digest: key.digest,
            maximumBytes: limits.maximumEntryBytes
        )
        let data: Data
        switch result {
        case let .available(value):
            data = value
        case .unavailable:
            throw V3ImmutableTransactionError.referencedEntryUnavailable(
                entryID: entry.entryID,
                digest: entry.ciphertextDigest
            )
        case .invalid, .tooLarge:
            throw V3ImmutableTransactionError.referencedEntryInvalid(
                entryID: entry.entryID,
                digest: entry.ciphertextDigest
            )
        }
        guard Data(SHA256.hash(data: data)) == key.digest,
              let parsed = try? entryCipher.parse(data),
              parsed.context == (try? V3EntryAuthenticationContext(
                  vaultID: vaultID,
                  entry: entry
              ))
        else {
            throw V3ImmutableTransactionError.referencedEntryInvalid(
                entryID: entry.entryID,
                digest: entry.ciphertextDigest
            )
        }
        return data.count
    }

    private func requireExact(
        _ result: V3RepositoryObjectRead,
        expected: Data,
        unavailable: V3ImmutableTransactionError,
        invalid: V3ImmutableTransactionError
    ) throws {
        switch result {
        case let .available(data) where data == expected:
            return
        case .unavailable:
            throw unavailable
        case .available, .invalid, .tooLarge:
            throw invalid
        }
    }
}
