import CryptoKit
import Foundation

/// Exact observed bytes, not an authorization to advance a checkpoint.
struct V3ExactTransitionRepositoryState: Equatable, Sendable {
  let baseBytes: Data
  let entries: [V3EntryObjectKey: V3EncryptedEntry]
  let manifestBytes: [Data: Data]
  let listedObjectCount: Int
  let candidatePublished: Bool
  let referencedEntries: [V3EntryObjectKey: V3EncryptedEntry]
  let usage: V3ManifestRepositoryUsage
}

/// Bounded exact-byte inventory and snapshot loading for one locally owned
/// transition. This is not an authenticator, catch-up selector or authority
/// boundary. Domain services authenticate the local floor and candidate.
struct V3ExactTransitionRepository: Sendable {
  let source: any V3ImmutableObjectReading
  let limits: V3ManifestRepositoryLimits

  func observe(
    checkpoint: V3ManifestCheckpoint, expectedBase: Data,
    candidate: V3RecoveryManifestEnvelope? = nil, stagedEntries: [V3EncryptedEntry] = []
  ) throws -> V3ExactTransitionRepositoryState {
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
    guard baseBytes == expectedBase else { throw V3RecoveryValidationError.sourceChanged }
    let container = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(baseBytes)
    let fields: V3DeviceWrappedManifestFields
    switch try V3RecoveryManifestCodec().decodeBody(container.manifestValue) {
    case .permanent(let body): fields = body.fields
    case .recovery(let body): fields = body.fields
    }
    guard fields.vaultID == checkpoint.vaultID else {
      throw V3RecoveryValidationError.invalidObject
    }
    var ancestors = Set<Data>()
    var pending = container.metadata.parents
    while let digest = pending.popLast() {
      guard digest != checkpoint.envelopeDigest else {
        throw V3RecoveryValidationError.invalidTransition
      }
      if ancestors.insert(digest).inserted { pending.append(contentsOf: parents[digest] ?? []) }
    }
    for (digest, vaultID) in vaultIDs where vaultID == checkpoint.vaultID {
      guard
        digest == checkpoint.envelopeDigest || ancestors.contains(digest)
          || digest == candidate?.digest
      else { throw V3RecoveryValidationError.sourceChanged }
    }
    var retained: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    var entryBytes = 0
    func entries(_ fields: V3DeviceWrappedManifestFields) throws -> [V3EntryObjectKey:
      V3EncryptedEntry]
    {
      var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for record in fields.entries {
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
    let baseEntries = try entries(fields)
    let published = candidate.map { bytes[$0.digest] != nil } ?? false
    if let candidate, published {
      guard bytes[candidate.digest] == candidate.canonicalBytes else {
        throw V3RecoveryValidationError.sourceChanged
      }
      guard try V3RecoveryManifestCodec().parseEnvelope(candidate.canonicalBytes) == candidate
      else {
        throw V3RecoveryValidationError.invalidObject
      }
      let publishedEntries = try entries(candidate.body.fields)
      var staged: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for entry in stagedEntries {
        let key = V3EntryObjectKey(
          entryID: entry.context.entryID, digest: Data(SHA256.hash(data: entry.canonicalBytes)))
        guard staged.updateValue(entry, forKey: key) == nil else {
          throw V3RecoveryValidationError.invalidObject
        }
      }
      guard publishedEntries == staged else { throw V3RecoveryValidationError.sourceChanged }

    }
    return V3ExactTransitionRepositoryState(
      baseBytes: baseBytes, entries: baseEntries, manifestBytes: bytes,
      listedObjectCount: objectCount,
      candidatePublished: published, referencedEntries: retained,
      usage: V3ManifestRepositoryUsage(
        manifestObjectCount: objectCount, maximumHistoryDepth: published ? 1 : 0,
        totalManifestBytes: total, referencedEntryObjectCount: retained.count,
        totalEntryBytes: entryBytes))
  }

  func requireProjectedUsage(
    _ state: V3ExactTransitionRepositoryState, candidate: V3RecoveryManifestEnvelope,
    stagedEntries: [V3EncryptedEntry]
  ) throws {
    let addsManifest = state.manifestBytes[candidate.digest] == nil
    var additionalBytes = 0
    var additionalCount = 0
    for entry in stagedEntries {
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
        - (addsManifest ? candidate.canonicalBytes.count : 0),
      limits.maximumHistoryDepth >= 1,
      state.usage.referencedEntryObjectCount <= limits.maximumReferencedEntryObjects
        - additionalCount,
      state.usage.totalEntryBytes <= limits.maximumTotalEntryBytes - additionalBytes
    else { throw V3RecoveryValidationError.resourceLimit }
    try V3RecoveryPublicationBudget.require(
      candidate, manifestBytes: state.manifestBytes,
      objectCount: state.listedObjectCount, limits: limits)
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

/// Publication admission over supplied immutable history, not token provenance
/// or a replacement for full old/new snapshot validation. Reuse recovery's own
/// verifier so its cumulative depth/reference bounds cannot diverge from saves.
enum V3RecoveryPublicationBudget {
  static func require(
    _ candidate: V3RecoveryManifestEnvelope, manifestBytes: [Data: Data],
    objectCount: Int, limits: V3ManifestRepositoryLimits
  ) throws {
    let active = candidate.body.recovery.recipients.filter { $0.status == .active }
    guard !active.isEmpty else { return }
    let additional = manifestBytes[candidate.digest] == nil ? 1 : 0
    guard objectCount >= manifestBytes.count,
      objectCount <= limits.maximumManifestObjects - additional
    else { throw V3RecoveryValidationError.resourceLimit }
    var projected = manifestBytes
    if let existing = projected[candidate.digest], existing != candidate.canonicalBytes {
      throw V3RecoveryValidationError.sourceChanged
    }
    projected[candidate.digest] = candidate.canonicalBytes
    let source = ProjectedSource(manifests: projected, objectCount: objectCount + additional)
    var carrying: [Data: (envelope: V3RecoveryManifestEnvelope, recipient: V3RecoveryRecipient)] =
      [:]
    var total = 0
    for (digest, bytes) in projected {
      guard bytes.count <= limits.maximumManifestBytes,
        bytes.count <= limits.maximumTotalManifestBytes - total
      else { throw V3RecoveryValidationError.resourceLimit }
      total += bytes.count
      // Older permanent or unsupported profiles may precede registration.
      // The selector independently refuses unsupported reachable descendants.
      guard let envelope = try? V3RecoveryManifestCodec().parseEnvelope(bytes),
        envelope.body.fields.vaultID == candidate.body.fields.vaultID,
        let recipient = active.first(where: { envelope.body.recovery.recipients.contains($0) })
      else { continue }
      carrying[digest] = (envelope, recipient)
    }
    // The earliest continuing registration is a common conservative floor for
    // every active recipient. New registration alone starts at its own floor;
    // adding a backup must not reset a continuing primary's earlier obligation.
    let floors = carrying.filter { _, value in
      value.envelope.parents.allSatisfy { carrying[$0] == nil }
    }
    guard floors.count == 1, let (digest, floor) = floors.first else {
      throw V3RecoveryValidationError.invalidTransition
    }
    let anchor = try V3RecoveryAnchor(
      floor: .init(vaultID: candidate.body.fields.vaultID, envelopeDigest: digest),
      recipientID: floor.recipient.recipientID,
      registrationID: floor.recipient.registrationID, slot: floor.recipient.slot)
    let selected = try V3RecoveryHistorySelector(source: source, limits: limits).select(
      anchor: anchor, credentialPublicKey: floor.recipient.publicKey)
    guard selected.head.digest == candidate.digest else {
      throw V3RecoveryValidationError.sourceChanged
    }
  }

  /// Exact projected bytes only. No disk writes, historical ciphertext reads,
  /// token I/O or private-key dependency. Provider withholding stays out of scope.
  private struct ProjectedSource: V3ImmutableObjectReading {
    let manifests: [Data: Data]
    let objectCount: Int
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      objectCount > maximumCount
        ? .limitExceeded : .available(digests: Array(manifests.keys), objectCount: objectCount)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      guard let bytes = manifests[digest] else { return .unavailable }
      return bytes.count > maximumBytes ? .tooLarge : .available(bytes)
    }
    func readEntry(entryID _: String, digest _: Data, maximumBytes _: Int) throws
      -> V3RepositoryObjectRead
    {
      .unavailable
    }
  }
}
