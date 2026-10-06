import CryptoKit
import Foundation

enum V3RecoveryKeyTransitionCatchUpError: Error, Equatable {
  case invalidDevice, deviceRevoked
}

enum V3RecoveryKeyTransitionCatchUpOutcome: Sendable {
  // Same-epoch coordination remains the ordinary content service's work.
  case noKeyTransition
  // A verified prefix, never a claim that the provider's latest state was reached.
  case advancedOneEpoch(V3RecoveryContentCommit)
}

/// Public policy for one already-published epoch, not ceremony approval,
/// possession verification, consent or permission to publish new authority.
/// Existing independent planners still own the individual roster decisions.
struct V3RecoveryPublishedEpochPolicy: Sendable {
  let limits: V3ManifestRepositoryLimits

  func validate(_ child: V3RecoveryManifestEnvelope, parent: V3RecoveryManifestEnvelope) throws {
    guard let signer = child.authorizations.first?.signerDeviceID,
      let owner = parent.body.fields.devices.first(where: {
        $0.identity.deviceID == signer && $0.status == .active
      })?.identity,
      child.body.fields.devices.contains(.init(identity: owner, status: .active))
    else { throw V3RecoveryValidationError.invalidTransition }
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: parent.body.fields.vaultID, envelopeDigest: parent.digest)
    let oldDevices = parent.body.fields.devices
    let newDevices = child.body.fields.devices
    let oldRecipients = parent.body.recovery.recipients
    let newRecipients = child.body.recovery.recipients
    if oldDevices == newDevices {
      if oldRecipients == newRecipients {
        try V3RecoveryKeyRotationValidator(limits: limits).preflightPublic(
          .init(expectedCheckpoint: checkpoint, envelope: child, stagedEntries: []),
          parent: parent, expectedOwner: owner)
        return
      }
      if oldRecipients.count == newRecipients.count {
        let changes = zip(oldRecipients, newRecipients).filter { $0 != $1 }
        guard changes.count == 1, let (before, _) = changes.first else {
          throw V3RecoveryValidationError.invalidTransition
        }
        let plan = try V3RecoveryRecipientRemovalPlanner(limits: limits).planMetadata(
          checkpoint: checkpoint, parent: parent, authorizingDeviceID: signer,
          removing: before.recipientID)
        try V3RecoveryRecipientRemovalValidator(limits: limits).preflightPublic(
          .init(plan: plan, envelope: child, stagedEntries: []), parent: parent,
          expectedOwner: owner)
        return
      }
      let oldIDs = Set(oldRecipients.map(\.recipientID))
      let additions = newRecipients.filter { !oldIDs.contains($0.recipientID) }
      guard additions.count == 1, let added = additions.first, added.status == .active,
        added.publicKey != parent.body.epochSigningKey.publicKey,
        newRecipients.filter({ oldIDs.contains($0.recipientID) }) == oldRecipients,
        child.body.recovery.generationID != parent.body.recovery.generationID
      else { throw V3RecoveryValidationError.invalidTransition }
    } else {
      guard oldRecipients == newRecipients,
        child.body.recovery.generationID == parent.body.recovery.generationID
      else { throw V3RecoveryValidationError.invalidTransition }
      if oldDevices.count == newDevices.count {
        let changes = zip(oldDevices, newDevices).filter { $0 != $1 }
        guard changes.count == 1, let (before, _) = changes.first else {
          throw V3RecoveryValidationError.invalidTransition
        }
        let plan = try V3DeviceRevocationRosterPolicy().plan(
          checkpoint: checkpoint, devices: oldDevices, authorizingDeviceID: signer,
          revoking: before.identity.deviceID)
        try V3RecoveryDeviceRevocationValidator(limits: limits).preflightPublic(
          .init(plan: plan, envelope: child, stagedEntries: []), parent: parent,
          expectedOwner: owner)
        return
      }
      let oldIDs = Set(oldDevices.map { $0.identity.deviceID })
      let additions = newDevices.filter { !oldIDs.contains($0.identity.deviceID) }
      guard additions.count == 1, let added = additions.first, added.status == .active,
        newDevices
          == (try V3RecoveryDeviceEnrollmentValidator(limits: limits).resultingDevices(
            parent: oldDevices, joining: added.identity))
      else { throw V3RecoveryValidationError.invalidTransition }
    }
    try V3RecoveryEpochSnapshotValidator(limits: limits).preflightPublic(
      child, checkpoint: checkpoint, parent: parent, stagedEntryCount: 0,
      expectedOwner: owner)
  }
}

/// Bounded observed history and ciphertext, not checkpoint or MAC authority for
/// unopened future epochs. Construction is confined to the observer below.
struct V3RecoveryKeyTransitionObservation: Equatable, Sendable {
  let envelopes: [Data: V3RecoveryManifestEnvelope]
  let order: [Data]
  let roots: [Data: Data]
  let entries: [V3EntryObjectKey: V3EncryptedEntry]
  let manifestBytes: [Data: Data]
  let listedDigests: [Data]
  let listedObjectCount: Int
  let head: V3RecoveryManifestEnvelope
  let transition: V3RecoveryManifestEnvelope?

  fileprivate init(
    envelopes: [Data: V3RecoveryManifestEnvelope], order: [Data], roots: [Data: Data],
    entries: [V3EntryObjectKey: V3EncryptedEntry], manifestBytes: [Data: Data],
    listedDigests: [Data], listedObjectCount: Int, head: V3RecoveryManifestEnvelope,
    transition: V3RecoveryManifestEnvelope?
  ) {
    self.envelopes = envelopes
    self.order = order
    self.roots = roots
    self.entries = entries
    self.manifestBytes = manifestBytes
    self.listedDigests = listedDigests
    self.listedObjectCount = listedObjectCount
    self.head = head
    self.transition = transition
  }

  func snapshot(_ envelope: V3RecoveryManifestEnvelope) throws
    -> [V3EntryObjectKey: V3EncryptedEntry]
  {
    var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    for record in envelope.body.fields.entries {
      let address = try V3RecoveryMergeMutationValidator.address(record)
      guard let entry = entries[address] else { throw V3RecoveryValidationError.entryUnavailable }
      result[address] = entry
    }
    return result
  }
}

/// Ordinary catch-up starts at an authenticated local floor, not a token anchor.
/// Every visible public boundary and required ciphertext is checked before Mac
/// UI. Current-epoch snapshots authenticate here; the selected next epoch must
/// still authenticate and compare complete plaintexts after its addressed unwrap.
struct V3RecoveryKeyTransitionRepositoryObserver: Sendable {
  let source: any V3ImmutableObjectReading
  let limits: V3ManifestRepositoryLimits
  let maximumParentEdges: Int

  func observe(from floor: V3RecoveryContentCommit, vaultKey: Data) throws
    -> V3RecoveryKeyTransitionObservation
  {
    try V3RecoveryContentMutationValidator(limits: limits).validateParent(
      floor.envelope, checkpoint: floor.checkpoint, vaultKey: vaultKey)
    var graph = V3RecoveryManifestGraph(
      source: source, limits: limits, maximumParentEdges: maximumParentEdges)
    let inventory = try graph.loadInventory(floor: floor.checkpoint.envelopeDigest)
    guard graph.objects[floor.checkpoint.envelopeDigest]?.bytes == floor.envelope.canonicalBytes
    else { throw V3RecoveryValidationError.sourceChanged }
    let order: [Data]
    let graphFloor: Data
    let committed: Set<Data>
    do {
      order = try graph.anchoredOrder(
        floor: floor.checkpoint.envelopeDigest, vaultID: floor.checkpoint.vaultID)
      graphFloor = floor.checkpoint.envelopeDigest
      committed = [graphFloor]
    } catch V3RecoveryValidationError.unanchoredParent {
      let ancestry = try V3RecoveryCheckpointAncestry(
        graph: &graph, checkpoint: floor, vaultKey: vaultKey)
      order = try graph.anchoredOrder(floor: ancestry.root, vaultID: floor.checkpoint.vaultID)
      graphFloor = ancestry.root
      committed = ancestry.committedDigests
    }
    let boundary = V3RecoveryEpochBoundary()
    var envelopes: [Data: V3RecoveryManifestEnvelope] = [:]
    var roots: [Data: Data] = [:]
    var previousRoots: [Data: Data] = [:]
    var seenKeys = Set<V3VaultKeyID>()
    var seenIDs = Set<String>()
    var seenPublicKeys = Set<Data>()
    var transitions: [V3RecoveryManifestEnvelope] = []
    var entries: [V3EntryObjectKey: V3EncryptedEntry] = [:]
    var totalEntryBytes = 0
    for digest in order {
      let child = try graph.envelope(digest)
      guard child.body.fields.vaultID == floor.checkpoint.vaultID else {
        throw V3RecoveryValidationError.invalidTransition
      }
      if digest == graphFloor {
        roots[digest] = digest
      } else {
        let parents = child.parents.compactMap { envelopes[$0] }
        guard !parents.isEmpty, parents.count == child.parents.count else {
          throw V3RecoveryValidationError.unanchoredParent
        }
        if parents.allSatisfy({ $0.body.fields.keyID == child.body.fields.keyID }) {
          guard parents.count > 1 || child.body.fields.entries != parents[0].body.fields.entries,
            let root = roots[parents[0].digest],
            parents.allSatisfy({ roots[$0.digest] == root })
          else { throw V3RecoveryValidationError.invalidTransition }
          try boundary.verifySameEpochMetadata(child, parents: parents)
          try V3RecoveryContentProgressValidator().validate(child, parents: parents)
          roots[digest] = root
        } else {
          guard parents.count == 1, let parent = parents.first, let root = roots[parent.digest]
          else { throw V3RecoveryValidationError.authorityConflict }
          try V3RecoveryPublishedEpochPolicy(limits: limits).validate(child, parent: parent)
          roots[digest] = digest
          previousRoots[digest] = root
          if root == graphFloor { transitions.append(child) }
        }
      }
      if roots[digest] == digest {
        guard seenKeys.insert(child.body.fields.keyID).inserted,
          seenIDs.insert(child.body.fields.authorityTransitionID).inserted,
          seenPublicKeys.insert(child.body.epochSigningKey.publicKey).inserted
        else { throw V3RecoveryValidationError.invalidTransition }
      }
      envelopes[digest] = child
      if child.body.fields.keyID == floor.envelope.body.fields.keyID {
        try boundary.verifyCurrentAuthentication(child, vaultKey: vaultKey)
      }
      // Exact committed ancestors explain branches, but obsolete ciphertext is
      // not replayed. The floor and every uncommitted snapshot remain mandatory.
      if committed.contains(digest), digest != floor.checkpoint.envelopeDigest { continue }
      for record in child.body.fields.entries {
        let address = try V3RecoveryMergeMutationValidator.address(record)
        let entry: V3EncryptedEntry
        if let retained = entries[address] {
          entry = retained
        } else {
          guard entries.count < limits.maximumReferencedEntryObjects else {
            throw V3RecoveryValidationError.resourceLimit
          }
          let data: Data
          switch try source.readEntry(
            entryID: address.entryID, digest: address.digest, maximumBytes: limits.maximumEntryBytes
          )
          {
          case .available(let bytes): data = bytes
          case .unavailable: throw V3RecoveryValidationError.entryUnavailable
          case .invalid: throw V3RecoveryValidationError.invalidObject
          case .tooLarge: throw V3RecoveryValidationError.resourceLimit
          }
          guard data.count <= limits.maximumEntryBytes,
            data.count <= limits.maximumTotalEntryBytes - totalEntryBytes
          else { throw V3RecoveryValidationError.resourceLimit }
          guard Data(SHA256.hash(data: data)) == address.digest else {
            throw V3RecoveryValidationError.invalidObject
          }
          entry = try V3EntryCipher().parse(data)
          totalEntryBytes += data.count
          entries[address] = entry
        }
        guard
          entry.context
            == (try V3EntryAuthenticationContext(
              vaultID: floor.checkpoint.vaultID, entry: record))
        else { throw V3RecoveryValidationError.invalidObject }
      }
      if child.body.fields.keyID == floor.envelope.body.fields.keyID {
        var snapshot: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        for record in child.body.fields.entries {
          let address = try V3RecoveryMergeMutationValidator.address(record)
          snapshot[address] = entries[address]
        }
        _ = try V3EntrySnapshotValidator(limits: limits).plaintexts(
          fields: child.body.fields, entries: snapshot, vaultKey: vaultKey)
      }
    }
    let parents = Set(envelopes.values.flatMap(\.parents))
    let heads = order.filter { !parents.contains($0) }
    if heads.count != 1 {
      let headRoots = Set(heads.compactMap { roots[$0] })
      if headRoots.count == 1 { throw V3RecoveryValidationError.contentConflict }
      guard let last = order.last(where: { headRoots.contains($0) }) else {
        throw V3RecoveryValidationError.invalidTransition
      }
      var chain: Set<Data> = [last]
      var current = last
      while let previous = previousRoots[current] {
        chain.insert(previous)
        current = previous
      }
      throw headRoots.isSubset(of: chain)
        ? V3RecoveryValidationError.closedEpochBranch : .authorityConflict
    }
    guard transitions.count <= 1 else { throw V3RecoveryValidationError.authorityConflict }
    if let transition = transitions.first {
      guard graph.descendants(of: floor.checkpoint.envelopeDigest).contains(transition.digest)
      else {
        throw V3RecoveryValidationError.closedEpochBranch
      }
    }
    guard let headDigest = heads.first, let head = envelopes[headDigest] else {
      throw V3RecoveryValidationError.invalidTransition
    }
    return .init(
      envelopes: envelopes, order: order, roots: roots, entries: entries,
      manifestBytes: graph.objects.mapValues(\.bytes), listedDigests: inventory.digests,
      listedObjectCount: inventory.objectCount, head: head, transition: transitions.first)
  }
}

/// One serialized, fully validated ordinary key transition. The caller supplies
/// an exact unlocked Mac session. Later epochs require explicit further steps,
/// not a retry of a failed operation or catastrophe recovery's reduced replay.
struct V3RecoveryKeyTransitionCatchUpService: Sendable {
  private let mutationOwner: any VaultTransactionMutationOwning
  private let identity: any V3DeviceWrappedVaultKeyUnwrapping
  private let session: V3DeviceWrappedVaultKeySessionStore
  private let checkpoints: any V3ManifestCheckpointStoring
  private let ownership: [any V3ImmutableTransactionRecoveryAnchorStoring]
  private let cache: any V3CheckpointManifestCaching
  private let observer: V3RecoveryKeyTransitionRepositoryObserver

  init(
    mutationOwner: any VaultTransactionMutationOwning,
    identity: any V3DeviceWrappedVaultKeyUnwrapping,
    session: V3DeviceWrappedVaultKeySessionStore, source: any V3ImmutableObjectReading,
    checkpointStore: any V3ManifestCheckpointStoring,
    recoveryAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    registrationAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    adoptionAnchorStore: any V3ImmutableTransactionRecoveryAnchorStoring,
    cache: any V3CheckpointManifestCaching, limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384
  ) {
    precondition(maximumParentEdges > 0)
    self.mutationOwner = mutationOwner
    self.identity = identity
    self.session = session
    checkpoints = checkpointStore
    ownership = [recoveryAnchorStore, registrationAnchorStore, adoptionAnchorStore]
    self.cache = cache
    observer = .init(source: source, limits: limits, maximumParentEdges: maximumParentEdges)
  }

  func advanceOneEpoch(from floor: V3RecoveryContentCommit) throws
    -> V3RecoveryKeyTransitionCatchUpOutcome
  {
    try mutationOwner.perform(.catchUpVault) { _ in
      do {
        try requireState(floor.checkpoint)
        guard identity.vaultID == floor.checkpoint.vaultID,
          floor.envelope.body.fields.devices.contains(
            .init(identity: identity.publicIdentity, status: .active))
        else { throw V3RecoveryKeyTransitionCatchUpError.invalidDevice }
        let ticket = session.beginAuthentication()
        let oldKey = try session.load(
          vaultID: floor.checkpoint.vaultID, keyID: floor.envelope.body.fields.keyID)
        let observed = try observer.observe(from: floor, vaultKey: oldKey)
        try requireStable(observed, from: floor, key: oldKey, checkpoint: floor.checkpoint)
        try session.requireCurrent(ticket)
        guard
          observed.head.body.fields.devices.contains(
            .init(identity: identity.publicIdentity, status: .active))
        else { throw V3RecoveryKeyTransitionCatchUpError.deviceRevoked }
        guard let candidate = observed.transition else { return .noKeyTransition }
        guard
          candidate.body.fields.devices.contains(
            .init(identity: identity.publicIdentity, status: .active))
        else { throw V3RecoveryKeyTransitionCatchUpError.deviceRevoked }
        guard
          let wrapper = candidate.body.fields.wrappedKeys.first(where: {
            $0.recipientDeviceID == identity.publicIdentity.deviceID
          }), let parentDigest = candidate.parents.first,
          let parent = observed.envelopes[parentDigest]
        else { throw V3RecoveryKeyTransitionCatchUpError.invalidDevice }
        let nextKey = try identity.unwrapDeviceWrappedVaultKey(
          wrapper.wrappedKey,
          context: candidate.body.deviceContext(
            recipientDeviceID: identity.publicIdentity.deviceID),
          reason: "Use this Mac's access credentials to open the updated vault key.")
        try session.requireCurrent(ticket)
        try V3RecoveryEpochBoundary().verifyCurrentAuthentication(candidate, vaultKey: nextKey)
        try V3RecoveryEpochSnapshotValidator(limits: observer.limits).validateSnapshots(
          candidate, stagedEntries: Array(try observed.snapshot(candidate).values),
          parent: parent, currentEntries: observed.snapshot(parent),
          currentVaultKey: oldKey, nextVaultKey: nextKey)
        // Full authentication of the selected next epoch, including all visible
        // content descendants. Unopened later epochs remain public-only prefixes.
        for digest in observed.order where observed.roots[digest] == candidate.digest {
          guard let envelope = observed.envelopes[digest] else {
            throw V3RecoveryValidationError.invalidTransition
          }
          try V3RecoveryEpochBoundary().verifyCurrentAuthentication(envelope, vaultKey: nextKey)
          _ = try V3EntrySnapshotValidator(limits: observer.limits).plaintexts(
            fields: envelope.body.fields, entries: observed.snapshot(envelope), vaultKey: nextKey)
        }
        try requireStable(observed, from: floor, key: oldKey, checkpoint: floor.checkpoint)
        try session.requireCurrent(ticket)
        let checkpoint = try V3ManifestCheckpoint(
          vaultID: floor.checkpoint.vaultID, envelopeDigest: candidate.digest)
        do {
          try checkpoints.replaceCheckpoint(
            checkpoint.canonicalBytes, expectedCheckpoint: floor.checkpoint.canonicalBytes,
            vaultID: floor.checkpoint.vaultID)
        } catch V3ManifestCheckpointStoreError.conflict {
          throw V3RecoveryContentCatchUpError.checkpointChanged
        }
        // Cache failure cannot undo committed authority. UI/source/pending races
        // after CAS still refuse session installation, never checkpoint rollback.
        try? cache.store(candidate.canonicalBytes, for: checkpoint)
        try requireStable(observed, from: floor, key: oldKey, checkpoint: checkpoint)
        try session.install(
          nextKey, vaultID: checkpoint.vaultID, keyID: candidate.body.fields.keyID,
          authenticationTicket: ticket)
        return .advancedOneEpoch(.init(checkpoint: checkpoint, envelope: candidate))
      } catch {
        session.invalidate()
        throw error
      }
    }
  }

  private func requireStable(
    _ observed: V3RecoveryKeyTransitionObservation, from floor: V3RecoveryContentCommit,
    key: Data, checkpoint: V3ManifestCheckpoint
  ) throws {
    try requireState(checkpoint)
    guard try observer.observe(from: floor, vaultKey: key) == observed else {
      throw V3RecoveryValidationError.sourceChanged
    }
    try requireState(checkpoint)
  }

  private func requireState(_ checkpoint: V3ManifestCheckpoint) throws {
    for store in ownership where try store.loadRecoveryAnchor(vaultID: checkpoint.vaultID) != nil {
      throw V3RecoveryContentCatchUpError.localMutationPending
    }
    guard try checkpoints.loadCheckpoint(vaultID: checkpoint.vaultID) == checkpoint.canonicalBytes
    else { throw V3RecoveryContentCatchUpError.checkpointChanged }
  }
}
