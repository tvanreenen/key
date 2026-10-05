import Foundation

enum V3RecoveryMergeMutationError: Error, Equatable {
  case invalidCandidate
  case destinationStillConflicted
  case resourceLimit
}

/// All-parent content only, not a saved approval or CLI dispatch. The ordinary
/// publisher does not accept this type; the merge publisher rechecks source/state.
struct V3RecoveryMergeMutationCandidate: Equatable, Sendable {
  let kind: VaultTransactionMutationKind
  let expectedCheckpoint: V3ManifestCheckpoint
  let expectedHeads: [Data]
  let resolutions: [VaultConflictResolution]
  let envelope: V3RecoveryManifestEnvelope
  let stagedEntries: [V3EncryptedEntry]
}

struct V3RecoveryMergeMutationBuilder: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  func buildAutomatic(from observed: V3RecoverySameEpochObservation, vaultKey: Data) throws
    -> V3RecoveryMergeMutationCandidate
  {
    try build(kind: .mergeHeads, resolutions: [], observed: observed, vaultKey: vaultKey)
  }

  func buildResolution(
    _ resolutions: [VaultConflictResolution], from observed: V3RecoverySameEpochObservation,
    vaultKey: Data
  ) throws -> V3RecoveryMergeMutationCandidate {
    try build(
      kind: .resolveConflict, resolutions: resolutions, observed: observed, vaultKey: vaultKey)
  }

  private func build(
    kind: VaultTransactionMutationKind, resolutions: [VaultConflictResolution],
    observed: V3RecoverySameEpochObservation, vaultKey: Data
  ) throws -> V3RecoveryMergeMutationCandidate {
    let validator = V3RecoveryMergeMutationValidator(limits: limits)
    let parents = try validator.validateObservation(observed, vaultKey: vaultKey)
    let planned = try V3RecoveryMergeContentPolicy().plan(
      kind: kind, resolutions: resolutions, observed: observed)
    var records = planned.retained
    var staged: [V3EncryptedEntry] = []
    for (id, choice) in planned.resealed.sorted(by: { $0.key < $1.key }) {
      let source = try V3RecoveryMergeMutationValidator.address(choice.selected)
      guard let entry = observed.entryObjects[source] else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      let bytes = try V3EntryCipher().openPlaintextDataTrusted(
        entry.canonicalBytes, vaultID: observed.checkpoint.vaultID,
        manifestEntry: choice.selected, vaultKey: vaultKey)
      guard let text = String(data: bytes, encoding: .utf8) else {
        throw V3EntrySnapshotValidationError.invalidEntry
      }
      let encrypted = try V3EntryCipher().seal(
        text,
        context: V3EntryAuthenticationContext(
          vaultID: observed.checkpoint.vaultID, entryID: id, name: choice.selected.name,
          type: choice.selected.type, keyID: choice.selected.keyID, revision: choice.revision),
        vaultKey: vaultKey)
      records[id] = V3ResealedEntry(encryptedEntry: encrypted).manifestEntry
      staged.append(encrypted)
    }
    guard let authority = parents.first?.body else {
      throw V3RecoveryMergeMutationError.invalidCandidate
    }
    let entries = records.values.sorted(by: v3ManifestEntryPrecedes)
    try V3RecoveryMergeContentPolicy.requireUniqueDestinations(entries)
    let fields = authority.fields
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: fields.vaultID, keyID: fields.keyID,
        authorityTransitionID: fields.authorityTransitionID,
        devices: fields.devices, wrappedKeys: fields.wrappedKeys, entries: entries),
      epochSigningKey: authority.epochSigningKey, transitionProof: authority.transitionProof,
      recovery: authority.recovery)
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: observed.heads, vaultKey: vaultKey, authorizations: [])
    let candidate = V3RecoveryMergeMutationCandidate(
      kind: kind, expectedCheckpoint: observed.checkpoint, expectedHeads: observed.heads,
      resolutions: resolutions, envelope: envelope, stagedEntries: staged)
    _ = try validator.validate(candidate, observed: observed, vaultKey: vaultKey)
    return candidate
  }
}

/// Recomputes choices from the exact observed head set and independently checks
/// metadata, staging, complete AEAD snapshots and selected-plaintext preservation.
/// This supplies no provider freshness, pending-state or checkpoint-write permit.
struct V3RecoveryMergeMutationValidator: Sendable {
  let limits: V3ManifestRepositoryLimits
  init(limits: V3ManifestRepositoryLimits = .standard) { self.limits = limits }

  @discardableResult
  func validate(
    _ candidate: V3RecoveryMergeMutationCandidate, observed: V3RecoverySameEpochObservation,
    vaultKey: Data
  ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
    let parents = try validateObservation(observed, vaultKey: vaultKey)
    guard candidate.expectedCheckpoint == observed.checkpoint,
      candidate.expectedHeads == observed.heads,
      candidate.envelope.parents == observed.heads,
      candidate.envelope.canonicalBytes.count <= limits.maximumManifestBytes,
      candidate.envelope.body.fields.entries.count <= limits.maximumReferencedEntryObjects,
      candidate.stagedEntries.count <= limits.maximumReferencedEntryObjects
    else { throw V3RecoveryMergeMutationError.invalidCandidate }
    let boundary = V3RecoveryEpochBoundary()
    try boundary.verifyCurrentAuthentication(candidate.envelope, vaultKey: vaultKey)
    try boundary.verifySameEpochMetadata(candidate.envelope, parents: parents)
    try V3RecoveryContentProgressValidator().validate(candidate.envelope, parents: parents)
    let planned = try V3RecoveryMergeContentPolicy().plan(
      kind: candidate.kind, resolutions: candidate.resolutions, observed: observed)
    let records = candidate.envelope.body.fields.entries
    try V3RecoveryMergeContentPolicy.requireUniqueDestinations(records)
    guard Set(records.map(\.entryID)) == Set(planned.retained.keys).union(planned.resealed.keys)
    else { throw V3RecoveryMergeMutationError.invalidCandidate }
    var expectedStaged = Set<V3EntryObjectKey>()
    for record in records {
      if let retained = planned.retained[record.entryID] {
        guard record == retained else { throw V3RecoveryMergeMutationError.invalidCandidate }
      } else if let choice = planned.resealed[record.entryID] {
        guard record.name == choice.selected.name, record.type == choice.selected.type,
          record.keyID == choice.selected.keyID, record.revision == choice.revision
        else { throw V3RecoveryMergeMutationError.invalidCandidate }
        expectedStaged.insert(try Self.address(record))
      } else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
    }
    let snapshots = V3EntrySnapshotValidator(limits: limits)
    let staged = try snapshots.entryMap(candidate.stagedEntries)
    guard Set(staged.keys) == expectedStaged else {
      throw V3RecoveryMergeMutationError.invalidCandidate
    }
    for entry in candidate.stagedEntries {
      guard try V3EntryCipher().parse(entry.canonicalBytes) == entry else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
    }
    try requireProjectedUsage(candidate, observed: observed, staged: staged)
    var complete: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    for record in records {
      let address = try Self.address(record)
      guard let entry = staged[address] ?? observed.entryObjects[address] else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      complete[address] = entry
    }
    let plaintexts = try snapshots.plaintexts(
      fields: candidate.envelope.body.fields, entries: complete, vaultKey: vaultKey)
    for (id, choice) in planned.resealed {
      guard let source = observed.entryObjects[try Self.address(choice.selected)] else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      let selected = try V3EntryCipher().openPlaintextDataTrusted(
        source.canonicalBytes, vaultID: observed.checkpoint.vaultID,
        manifestEntry: choice.selected, vaultKey: vaultKey)
      guard plaintexts[id] == selected else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
    }
    return complete
  }

  func validateObservation(_ observed: V3RecoverySameEpochObservation, vaultKey: Data) throws
    -> [V3RecoveryManifestEnvelope]
  {
    guard observed.heads.count > 1,
      observed.envelopes.count <= limits.maximumManifestObjects,
      observed.entryObjects.count <= limits.maximumReferencedEntryObjects,
      let floor = observed.envelopes[observed.checkpoint.envelopeDigest]
    else { throw V3RecoveryMergeMutationError.invalidCandidate }
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      floor, checkpoint: observed.checkpoint, vaultKey: vaultKey)
    var total = 0
    for bytes in observed.observedManifestBytes.values {
      guard bytes.count <= limits.maximumManifestBytes,
        bytes.count <= limits.maximumTotalManifestBytes - total
      else { throw V3RecoveryMergeMutationError.resourceLimit }
      total += bytes.count
    }
    _ = try depths(observed)
    total = 0
    for entry in observed.entryObjects.values {
      guard entry.canonicalBytes.count <= limits.maximumEntryBytes,
        entry.canonicalBytes.count <= limits.maximumTotalEntryBytes - total
      else { throw V3RecoveryMergeMutationError.resourceLimit }
      total += entry.canonicalBytes.count
    }
    let snapshots = V3EntrySnapshotValidator(limits: limits)
    return try observed.heads.map { digest in
      guard let envelope = observed.envelopes[digest] else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: vaultKey)
      var entries: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for record in envelope.body.fields.entries {
        let address = try Self.address(record)
        guard let entry = observed.entryObjects[address] else {
          throw V3RecoveryMergeMutationError.invalidCandidate
        }
        entries[address] = entry
      }
      _ = try snapshots.plaintexts(
        fields: envelope.body.fields, entries: entries, vaultKey: vaultKey)
      return envelope
    }
  }

  private func requireProjectedUsage(
    _ candidate: V3RecoveryMergeMutationCandidate, observed: V3RecoverySameEpochObservation,
    staged: [V3EntryObjectKey: V3EncryptedEntry]
  ) throws {
    let listed = Set(observed.listedDigests)
    let required = observed.observedManifestBytes.keys.filter { !listed.contains($0) }.count
    let addsManifest = observed.observedManifestBytes[candidate.envelope.digest] == nil
    guard
      observed.listedObjectCount + required
        <= limits.maximumManifestObjects - (addsManifest ? 1 : 0)
    else {
      throw V3RecoveryMergeMutationError.resourceLimit
    }
    var total = addsManifest ? candidate.envelope.canonicalBytes.count : 0
    var edges = addsManifest ? candidate.envelope.parents.count : 0
    for bytes in observed.observedManifestBytes.values {
      guard bytes.count <= limits.maximumTotalManifestBytes - total else {
        throw V3RecoveryMergeMutationError.resourceLimit
      }
      total += bytes.count
      let count = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(bytes).metadata.parents
        .count
      guard count <= 16_384 - edges else { throw V3RecoveryMergeMutationError.resourceLimit }
      edges += count
    }
    var entries = observed.entryObjects
    for (address, entry) in staged { entries[address] = entry }
    guard entries.count <= limits.maximumReferencedEntryObjects else {
      throw V3RecoveryMergeMutationError.resourceLimit
    }
    total = 0
    for entry in entries.values {
      guard entry.canonicalBytes.count <= limits.maximumTotalEntryBytes - total else {
        throw V3RecoveryMergeMutationError.resourceLimit
      }
      total += entry.canonicalBytes.count
    }
    let parentDepths = try depths(observed)
    let maximum = observed.heads.compactMap { parentDepths[$0] }.max() ?? 0
    guard maximum < limits.maximumHistoryDepth else {
      throw V3RecoveryMergeMutationError.resourceLimit
    }
  }

  private func depths(_ observed: V3RecoverySameEpochObservation) throws -> [Data: Int] {
    var result: [Data: Int] = [observed.graphFloor: 0]
    for digest in observed.order where digest != observed.graphFloor {
      guard let envelope = observed.envelopes[digest], !envelope.parents.isEmpty,
        envelope.parents.allSatisfy({ result[$0] != nil }),
        let depth = envelope.parents.compactMap({ result[$0] }).max()
      else { throw V3RecoveryMergeMutationError.invalidCandidate }
      guard depth < limits.maximumHistoryDepth else {
        throw V3RecoveryMergeMutationError.resourceLimit
      }
      result[digest] = depth + 1
    }
    return result
  }

  static func address(_ entry: V3ManifestEntry) throws -> V3EntryObjectKey {
    guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest), digest.count == 32 else {
      throw V3RecoveryMergeMutationError.invalidCandidate
    }
    return V3EntryObjectKey(entryID: entry.entryID, digest: digest)
  }
}

private struct V3RecoveryMergeContentPolicy {
  struct Choice {
    let selected: V3ManifestEntry
    let revision: UInt64
  }
  struct Plan {
    var retained: [String: V3ManifestEntry]
    var resealed: [String: Choice]
  }

  func plan(
    kind: VaultTransactionMutationKind, resolutions: [VaultConflictResolution],
    observed: V3RecoverySameEpochObservation
  ) throws -> Plan {
    switch (kind, try V3RecoveryManifestReconciler().reconcile(observed)) {
    case (.mergeHeads, .automaticMerge(let merge)):
      guard resolutions.isEmpty else { throw V3RecoveryMergeMutationError.invalidCandidate }
      return Plan(
        retained: Dictionary(uniqueKeysWithValues: merge.entries.map { ($0.entryID, $0) }),
        resealed: [:])
    case (.resolveConflict, .contentConflict(let report)):
      guard let floor = observed.envelopes[observed.checkpoint.envelopeDigest] else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      let snapshot = V3ConflictObservationBuilder().build(
        report, entries: .lastTrusted(floor.body.fields.entries.count), trustedVersionID: nil,
        trustedHeadDigest: observed.checkpoint.envelopeDigest,
        trustedEntries: Set(floor.body.fields.entries))
      let choices = try V3ConflictResolutionPlanner().plan(resolutions, snapshot: snapshot)
      guard choices.expectedHeads.map(\.envelopeDigest) == observed.heads else {
        throw V3RecoveryMergeMutationError.invalidCandidate
      }
      var plan = Plan(
        retained: Dictionary(
          uniqueKeysWithValues: report.entriesReconciledByID.map { ($0.entryID, $0) }),
        resealed: [:])
      for choice in choices.selections {
        if let id = choice.entryID {
          guard let selected = choice.selectedEntry else { continue }
          let maximum = observed.heads.compactMap { observed.envelopes[$0] }
            .flatMap { $0.body.fields.entries }.filter { $0.entryID == id }.map(\.revision).max()
          guard let maximum, maximum < v3MaximumSafeInteger else {
            throw V3EntryResealingError.revisionOverflow
          }
          plan.resealed[id] = Choice(selected: selected, revision: maximum + 1)
        } else {
          guard let selected = choice.selectedEntry,
            let destination = report.destinationConflicts.first(where: {
              $0.entries.contains(selected)
            })
          else { throw V3RecoveryMergeMutationError.invalidCandidate }
          for entry in destination.entries where entry.entryID != selected.entryID {
            plan.retained.removeValue(forKey: entry.entryID)
          }
        }
      }
      return plan
    default: throw V3RecoveryMergeMutationError.invalidCandidate
    }
  }

  static func requireUniqueDestinations(_ entries: [V3ManifestEntry]) throws {
    guard Set(entries.map { Data($0.name.utf8) }).count == entries.count else {
      throw V3RecoveryMergeMutationError.destinationStillConflicted
    }
  }
}
