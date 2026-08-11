import CryptoKit
import Foundation

/// Reopens the permanent-profile checkpoint and discovers only authenticated
/// descendants that extend it under one of the explicitly supplied key epochs.
/// Unrelated provider objects consume the repository budget but gain no
/// authority from their filenames, timestamps, or presence in the directory.
struct V3LiveDeviceWrappedRepositoryObserver:
    V3DeviceWrappedRepositoryObserving,
    Sendable
{
    private let source: any V3ImmutableObjectReading
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let cache: any V3CheckpointManifestCaching
    private let limits: V3ManifestRepositoryLimits
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()

    init(
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.source = source
        self.checkpointStore = checkpointStore
        self.cache = cache
        self.limits = limits
    }

    func observeRepository(
        vaultID: String,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        let checkpoint = try loadCheckpoint(vaultID: vaultID)
        return try observeRepository(
            checkpoint: checkpoint,
            checkpointData: loadCheckpointManifest(checkpoint),
            vaultKeys: vaultKeys
        )
    }

    func observeRepository(
        from trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        let checkpoint = trusted.checkpoint
        let checkpointData = trusted.envelope.canonicalBytes
        guard checkpoint.vaultID == trusted.envelope.body.vaultID,
              Data(SHA256.hash(data: checkpointData))
                == checkpoint.envelopeDigest
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return try observeRepository(
            checkpoint: checkpoint,
            checkpointData: checkpointData,
            vaultKeys: vaultKeys
        )
    }

    private func observeRepository(
        checkpoint: V3ManifestCheckpoint,
        checkpointData: Data,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        let vaultID = checkpoint.vaultID
        let keysByID = try validatedKeys(vaultKeys, vaultID: vaultID)
        let listing = try loadManifestListing()

        var manifestData: [Data: Data] = [:]
        var parsed: [Data: V3DeviceWrappedManifestEnvelope] = [:]
        var accountedManifestDigests: Set<Data> = []
        var totalManifestBytes = 0

        func accountManifest(_ data: Data, digest: Data) throws {
            guard accountedManifestDigests.insert(digest).inserted else {
                return
            }
            guard data.count
                    <= limits.maximumTotalManifestBytes - totalManifestBytes
            else {
                throw V3ImmutableTransactionError.objectTooLarge
            }
            totalManifestBytes += data.count
        }

        func retainManifest(_ data: Data, digest: Data) throws {
            guard Data(SHA256.hash(data: data)) == digest else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            if let existing = manifestData[digest] {
                guard existing == data else {
                    throw V3ImmutableTransactionError.invalidAncestryProof
                }
                return
            }
            guard data.count <= limits.maximumManifestBytes else {
                throw V3ImmutableTransactionError.objectTooLarge
            }
            manifestData[digest] = data
            if let envelope = try? envelopeCodec.parse(data) {
                parsed[digest] = envelope
            }
        }

        for digest in listing.digests.sorted(by: {
            $0.lexicographicallyPrecedes($1)
        }) {
            switch try source.readManifest(
                digest: digest,
                maximumBytes: limits.maximumManifestBytes
            ) {
            case let .available(data):
                try accountManifest(data, digest: digest)
                if Data(SHA256.hash(data: data)) == digest {
                    try retainManifest(data, digest: digest)
                }
            case .unavailable, .invalid, .tooLarge:
                // An unrelated or incompletely synchronized object is not an
                // authority input. A reachable object is diagnosed below.
                continue
            }
        }

        try accountManifest(
            checkpointData,
            digest: checkpoint.envelopeDigest
        )
        try retainManifest(
            checkpointData,
            digest: checkpoint.envelopeDigest
        )
        guard let checkpointEnvelope = parsed[checkpoint.envelopeDigest],
              checkpointEnvelope.body.vaultID == vaultID,
              try authenticates(checkpointEnvelope, using: keysByID)
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        var authenticated: [Data: V3DeviceWrappedManifestEnvelope] = [
            checkpoint.envelopeDigest: checkpointEnvelope,
        ]
        var parentsByDigest: [Data: [Data]] = [
            checkpoint.envelopeDigest: [],
        ]
        var historyDepth: [Data: Int] = [checkpoint.envelopeDigest: 0]
        var entryObjects: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var totalEntryBytes = 0

        func entries(
            for envelope: V3DeviceWrappedManifestEnvelope
        ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
            var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
            for manifestEntry in envelope.body.entries {
                let key = try entryObjectKey(manifestEntry)
                let encrypted: V3EncryptedEntry
                if let existing = entryObjects[key] {
                    encrypted = existing
                } else {
                    guard entryObjects.count
                            < limits.maximumReferencedEntryObjects
                    else {
                        throw V3ImmutableTransactionError.objectTooLarge
                    }
                    let read = try source.readEntry(
                        entryID: key.entryID,
                        digest: key.digest,
                        maximumBytes: limits.maximumEntryBytes
                    )
                    let data: Data
                    switch read {
                    case let .available(value):
                        data = value
                    case .unavailable:
                        throw V3ImmutableTransactionError
                            .referencedEntryUnavailable(
                                entryID: key.entryID,
                                digest: Base64URL.encode(key.digest)
                            )
                    case .invalid, .tooLarge:
                        throw V3ImmutableTransactionError
                            .referencedEntryInvalid(
                                entryID: key.entryID,
                                digest: Base64URL.encode(key.digest)
                            )
                    }
                    guard data.count <= limits.maximumEntryBytes,
                          data.count
                            <= limits.maximumTotalEntryBytes - totalEntryBytes,
                          Data(SHA256.hash(data: data)) == key.digest,
                          let value = try? entryCipher.parse(data)
                    else {
                        throw V3ImmutableTransactionError
                            .referencedEntryInvalid(
                                entryID: key.entryID,
                                digest: Base64URL.encode(key.digest)
                            )
                    }
                    totalEntryBytes += data.count
                    entryObjects[key] = value
                    encrypted = value
                }
                guard encrypted.context == (try? V3EntryAuthenticationContext(
                    vaultID: vaultID,
                    entry: manifestEntry
                )), result.updateValue(encrypted, forKey: key) == nil
                else {
                    throw V3ImmutableTransactionError.referencedEntryInvalid(
                        entryID: key.entryID,
                        digest: Base64URL.encode(key.digest)
                    )
                }
            }
            return result
        }

        var madeProgress = true
        while madeProgress {
            madeProgress = false
            for digest in parsed.keys.sorted(by: {
                $0.lexicographicallyPrecedes($1)
            })
            where authenticated[digest] == nil {
                guard let candidate = parsed[digest],
                      candidate.body.vaultID == vaultID,
                      try authenticates(candidate, using: keysByID),
                      candidate.parents.contains(where: {
                          authenticated[$0] != nil
                      })
                else {
                    continue
                }
                guard candidate.parents.count == 1,
                      let parentDigest = candidate.parents.first,
                      let parent = authenticated[parentDigest],
                      let parentDepth = historyDepth[parentDigest],
                      parentDepth < limits.maximumHistoryDepth,
                      let candidateData = manifestData[digest]
                else {
                    throw V3ImmutableTransactionError.invalidAncestryProof
                }
                try validateTransition(
                    candidate,
                    candidateData: candidateData,
                    candidateDigest: digest,
                    parent: parent,
                    parentDigest: parentDigest,
                    keysByID: keysByID,
                    entries: entries
                )
                authenticated[digest] = candidate
                parentsByDigest[digest] = candidate.parents
                historyDepth[digest] = parentDepth + 1
                madeProgress = true
            }
        }

        for envelope in authenticated.values {
            _ = try entries(for: envelope)
        }
        let parentDigests = Set(parentsByDigest.values.flatMap { $0 })
        let heads = authenticated.keys.filter {
            !parentDigests.contains($0)
        }.sorted(by: { $0.lexicographicallyPrecedes($1) })
        guard !heads.isEmpty else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }

        return V3DeviceWrappedRepositoryObservation(
            checkpoint: checkpoint,
            heads: heads,
            manifestDigests: Set(manifestData.keys),
            parentsByManifestDigest: parentsByDigest,
            referencedEntryObjects: Set(entryObjects.keys),
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount: max(
                    listing.objectCount,
                    manifestData.count
                ),
                maximumHistoryDepth: historyDepth.values.max() ?? 0,
                totalManifestBytes: totalManifestBytes,
                referencedEntryObjectCount: entryObjects.count,
                totalEntryBytes: totalEntryBytes
            )
        )
    }

    private func validateTransition(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        candidateData: Data,
        candidateDigest: Data,
        parent: V3DeviceWrappedManifestEnvelope,
        parentDigest: Data,
        keysByID: [V3VaultKeyID: Data],
        entries: (V3DeviceWrappedManifestEnvelope) throws
            -> [V3EntryObjectKey: V3EncryptedEntry]
    ) throws {
        if hasSameAuthority(candidate, parent) {
            try validateContentTransition(candidate, parent: parent)
            return
        }
        guard let currentVaultKey = keysByID[parent.body.keyID],
              let nextVaultKey = keysByID[candidate.body.keyID],
              let authorization = candidate.authorizations.first,
              let owner = parent.body.devices.first(where: {
                  $0.identity.deviceID == authorization.signerDeviceID
              })?.identity
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        let parentCheckpoint = try V3ManifestCheckpoint(
            vaultID: parent.body.vaultID,
            envelopeDigest: parentDigest
        )
        let stagedEntryMap = try entries(candidate)
        let stagedEntries = try candidate.body.entries.map { entry in
            let key = try entryObjectKey(entry)
            guard let encrypted = stagedEntryMap[key] else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return encrypted
        }
        let transition = V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: parentCheckpoint,
            body: candidate.body,
            manifestData: candidateData,
            manifestDigest: candidateDigest,
            stagedEntries: stagedEntries,
            transcriptDigest: Data(repeating: 0, count: 32)
        )
        do {
            _ = try V3DeviceWrappedEnrollmentTransitionValidator(
                limits: limits
            ).validateAnchored(
                transition,
                parent: V3DeviceWrappedTrustedCheckpoint(
                    checkpoint: parentCheckpoint,
                    envelope: parent
                ),
                currentEntries: try entries(parent),
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                expectedOwner: owner
            )
        } catch {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
    }

    private func validateContentTransition(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        parent: V3DeviceWrappedManifestEnvelope
    ) throws {
        guard candidate.authorizations.isEmpty,
              candidate.body.entries != parent.body.entries
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        let parentByID = Dictionary(uniqueKeysWithValues:
            parent.body.entries.map { ($0.entryID, $0) }
        )
        for entry in candidate.body.entries {
            if let previous = parentByID[entry.entryID] {
                guard entry == previous
                        || (previous.revision < v3MaximumSafeInteger
                            && entry.revision == previous.revision + 1)
                else {
                    throw V3ImmutableTransactionError.invalidAncestryProof
                }
            } else if entry.revision != 1 {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
        }
    }

    private func hasSameAuthority(
        _ lhs: V3DeviceWrappedManifestEnvelope,
        _ rhs: V3DeviceWrappedManifestEnvelope
    ) -> Bool {
        lhs.body.keyID == rhs.body.keyID
            && lhs.body.authorityTransitionID
                == rhs.body.authorityTransitionID
            && lhs.body.devices == rhs.body.devices
            && lhs.body.wrappedKeys == rhs.body.wrappedKeys
    }

    private func authenticates(
        _ envelope: V3DeviceWrappedManifestEnvelope,
        using keysByID: [V3VaultKeyID: Data]
    ) throws -> Bool {
        guard let key = keysByID[envelope.body.keyID] else {
            return false
        }
        return try V3ManifestAuthenticator.isValidAuthenticationTag(
            envelope.authenticationTag,
            canonicalContent: envelope.canonicalContentBytes,
            vaultID: envelope.body.vaultID,
            vaultKey: key
        )
    }

    private func validatedKeys(
        _ keys: [Data],
        vaultID: String
    ) throws -> [V3VaultKeyID: Data] {
        guard isValidV3UUID(vaultID), !keys.isEmpty else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        var result: [V3VaultKeyID: Data] = [:]
        for key in keys {
            guard key.count == 32 else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            let keyID = try V3VaultKeyID.derive(
                vaultKey: key,
                vaultID: vaultID
            )
            if let existing = result[keyID], existing != key {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            result[keyID] = key
        }
        return result
    }

    private func loadCheckpoint(
        vaultID: String
    ) throws -> V3ManifestCheckpoint {
        guard let data = try checkpointStore.loadCheckpoint(vaultID: vaultID),
              let checkpoint = try? V3ManifestCheckpoint(
                  canonicalBytes: data
              ), checkpoint.vaultID == vaultID
        else {
            throw V3ImmutableTransactionError.invalidAncestryProof
        }
        return checkpoint
    }

    private func loadCheckpointManifest(
        _ checkpoint: V3ManifestCheckpoint
    ) throws -> Data {
        if case let .available(data) = try? cache.load(for: checkpoint) {
            return data
        }
        switch try source.readManifest(
            digest: checkpoint.envelopeDigest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case let .available(data):
            return data
        case .unavailable:
            throw V3ImmutableTransactionError.publishedManifestUnavailable(
                digest: Base64URL.encode(checkpoint.envelopeDigest)
            )
        case .invalid, .tooLarge:
            throw V3ImmutableTransactionError.publishedManifestInvalid(
                digest: Base64URL.encode(checkpoint.envelopeDigest)
            )
        }
    }

    private func loadManifestListing() throws -> (
        digests: [Data],
        objectCount: Int
    ) {
        switch try source.manifestDigests(
            maximumCount: limits.maximumManifestObjects
        ) {
        case let .available(digests, objectCount):
            return (digests, objectCount)
        case .unavailable:
            throw V3ImmutableTransactionError.publishedManifestUnavailable(
                digest: "repository"
            )
        case .invalid:
            throw V3ImmutableTransactionError.invalidAncestryProof
        case .limitExceeded:
            throw V3ImmutableTransactionError.objectTooLarge
        }
    }
}
