import CryptoKit
import Foundation

/// Exact observed bytes, not an authorization to advance a checkpoint.
struct V3RecoveryRegistrationRepositoryState: Equatable, Sendable {
  let base: V3RecoveryManifestEnvelope
  let entries: [V3EntryObjectKey: V3EncryptedEntry]
  let manifestBytes: [Data: Data]
  let listedObjectCount: Int
  let candidatePublished: Bool
  let referencedEntries: [V3EntryObjectKey: V3EncryptedEntry]
  let usage: V3ManifestRepositoryUsage
}

/// A deliberately narrow publication observer. The locally trusted checkpoint
/// is the floor, as in the shipping observer. Above it, only one exact locally
/// owned registration candidate is accepted, with full same-plaintext checks
/// owned by the service. Competing edits/rotations/branches require catch-up;
/// this component cannot select, merge or adopt them using recovery's reduced
/// historical-verification rules. Pre-floor objects consume resource budget.
struct V3RecoveryRegistrationRepository: Sendable {
  let source: any V3ImmutableObjectReading
  let limits: V3ManifestRepositoryLimits

  func observe(
    checkpoint: V3ManifestCheckpoint, currentVaultKey: Data,
    candidate: V3RecoveryRegistrationPreparation? = nil, nextVaultKey: Data? = nil
  ) throws -> V3RecoveryRegistrationRepositoryState {
    let digests: [Data]
    let objectCount: Int
    switch try source.manifestDigests(maximumCount: limits.maximumManifestObjects) {
    case .available(let values, let count):
      guard count >= values.count, count <= limits.maximumManifestObjects,
        Set(values).count == values.count, values.allSatisfy({ $0.count == 32 })
      else { throw V3RecoveryValidationError.resourceLimit }
      digests = values
      objectCount = count
    case .unavailable: throw V3RecoveryValidationError.sourceUnavailable
    case .invalid: throw V3RecoveryValidationError.invalidObject
    case .limitExceeded: throw V3RecoveryValidationError.resourceLimit
    }
    guard digests.contains(checkpoint.envelopeDigest) else {
      throw V3RecoveryValidationError.sourceUnavailable
    }
    var bytes: [Data: Data] = [:]
    var parents: [Data: [Data]] = [:]
    var vaultIDs: [Data: String] = [:]
    var total = 0
    var edgeCount = 0
    for digest in digests {
      let data = try readManifest(digest)
      guard data.count <= limits.maximumTotalManifestBytes - total,
        Data(SHA256.hash(data: data)) == digest
      else { throw V3RecoveryValidationError.invalidObject }
      total += data.count
      let container = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(data)
      guard
        let vaultID = container.manifestValue.objectValue?.first(where: { $0.0 == "vaultID" })?.1
          .stringValue,
        isValidV3UUID(vaultID), container.metadata.parents.count <= 16_384 - edgeCount
      else { throw V3RecoveryValidationError.resourceLimit }
      edgeCount += container.metadata.parents.count
      bytes[digest] = data
      parents[digest] = container.metadata.parents
      vaultIDs[digest] = vaultID
    }
    guard let baseBytes = bytes[checkpoint.envelopeDigest] else {
      throw V3RecoveryValidationError.sourceUnavailable
    }
    let base = try V3RecoveryManifestCodec().parseEnvelope(baseBytes)
    let validator = V3RecoveryRegistrationValidator(limits: limits)
    try validator.validateParent(base, checkpoint: checkpoint, vaultKey: currentVaultKey)
    var ancestors = Set<Data>()
    var pending = base.parents
    while let digest = pending.popLast() {
      guard digest != checkpoint.envelopeDigest else {
        throw V3RecoveryValidationError.invalidTransition
      }
      if ancestors.insert(digest).inserted { pending.append(contentsOf: parents[digest] ?? []) }
    }
    for (digest, vaultID) in vaultIDs where vaultID == checkpoint.vaultID {
      guard
        digest == checkpoint.envelopeDigest || ancestors.contains(digest)
          || digest == candidate?.candidate.digest
      else { throw V3RecoveryValidationError.sourceChanged }
    }
    var retained: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    var entryBytes = 0
    func entries(_ envelope: V3RecoveryManifestEnvelope) throws -> [V3EntryObjectKey:
      V3EncryptedEntry]
    {
      var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for record in envelope.body.fields.entries {
        guard let digest = Base64URL.decodeCanonical(record.ciphertextDigest), digest.count == 32
        else {
          throw V3RecoveryValidationError.invalidObject
        }
        let key = V3EntryObjectKey(entryID: record.entryID, digest: digest)
        let entry: V3EncryptedEntry
        if let existing = retained[key] {
          entry = existing
        } else {
          guard retained.count < limits.maximumReferencedEntryObjects else {
            throw V3RecoveryValidationError.resourceLimit
          }
          let data = try readEntry(key)
          guard data.count <= limits.maximumTotalEntryBytes - entryBytes,
            Data(SHA256.hash(data: data)) == digest
          else { throw V3RecoveryValidationError.invalidObject }
          entryBytes += data.count
          entry = try V3EntryCipher().parse(data)
          retained[key] = entry
        }
        guard
          entry.context
            == (try V3EntryAuthenticationContext(vaultID: checkpoint.vaultID, entry: record)),
          result.updateValue(entry, forKey: key) == nil
        else { throw V3RecoveryValidationError.invalidObject }
      }
      return result
    }
    let baseEntries = try entries(base)
    _ = try validator.plaintexts(base, entries: baseEntries, vaultKey: currentVaultKey)
    let published = candidate.map { bytes[$0.candidate.digest] != nil } ?? false
    if let candidate, published {
      guard bytes[candidate.candidate.digest] == candidate.candidate.canonicalBytes else {
        throw V3RecoveryValidationError.sourceChanged
      }
      try V3RecoveryEpochBoundary().verifyBoundary(candidate.candidate, parent: base)
      let publishedEntries = try entries(candidate.candidate)
      var staged: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for entry in candidate.stagedEntries {
        let key = V3EntryObjectKey(
          entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
        guard staged.updateValue(entry, forKey: key) == nil else {
          throw V3RecoveryValidationError.invalidObject
        }
      }
      guard publishedEntries == staged else { throw V3RecoveryValidationError.sourceChanged }
      if let nextVaultKey {
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
          candidate.candidate, vaultKey: nextVaultKey)
        _ = try validator.plaintexts(
          candidate.candidate, entries: publishedEntries, vaultKey: nextVaultKey)
      }
    }
    return V3RecoveryRegistrationRepositoryState(
      base: base, entries: baseEntries, manifestBytes: bytes, listedObjectCount: objectCount,
      candidatePublished: published, referencedEntries: retained,
      usage: V3ManifestRepositoryUsage(
        manifestObjectCount: objectCount, maximumHistoryDepth: published ? 1 : 0,
        totalManifestBytes: total, referencedEntryObjectCount: retained.count,
        totalEntryBytes: entryBytes))
  }

  func requireProjectedUsage(
    _ state: V3RecoveryRegistrationRepositoryState, candidate: V3RecoveryRegistrationPreparation
  ) throws {
    let addsManifest = state.manifestBytes[candidate.candidate.digest] == nil
    var additionalBytes = 0
    var additionalCount = 0
    for entry in candidate.stagedEntries {
      let key = V3EntryObjectKey(
        entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
      if state.referencedEntries[key] == nil {
        guard entry.canonicalBytes.count <= limits.maximumTotalEntryBytes - additionalBytes else {
          throw V3RecoveryValidationError.resourceLimit
        }
        additionalBytes += entry.canonicalBytes.count
        additionalCount += 1
      }
    }
    guard state.usage.manifestObjectCount <= limits.maximumManifestObjects - (addsManifest ? 1 : 0),
      state.usage.totalManifestBytes <= limits.maximumTotalManifestBytes
        - (addsManifest ? candidate.candidate.canonicalBytes.count : 0),
      limits.maximumHistoryDepth >= 1,
      state.usage.referencedEntryObjectCount <= limits.maximumReferencedEntryObjects
        - additionalCount,
      state.usage.totalEntryBytes <= limits.maximumTotalEntryBytes - additionalBytes
    else { throw V3RecoveryValidationError.resourceLimit }
  }

  func readManifest(_ digest: Data) throws -> Data {
    try read(
      source.readManifest(digest: digest, maximumBytes: limits.maximumManifestBytes),
      maximum: limits.maximumManifestBytes)
  }

  func readEntry(_ key: V3EntryObjectKey) throws -> Data {
    try read(
      source.readEntry(
        entryID: key.entryID, digest: key.digest, maximumBytes: limits.maximumEntryBytes),
      maximum: limits.maximumEntryBytes)
  }

  private func read(_ value: V3RepositoryObjectRead, maximum: Int) throws -> Data {
    switch value {
    case .available(let data):
      guard data.count <= maximum else { throw V3RecoveryValidationError.resourceLimit }
      return data
    case .unavailable: throw V3RecoveryValidationError.sourceUnavailable
    case .invalid: throw V3RecoveryValidationError.invalidObject
    case .tooLarge: throw V3RecoveryValidationError.resourceLimit
    }
  }
}
