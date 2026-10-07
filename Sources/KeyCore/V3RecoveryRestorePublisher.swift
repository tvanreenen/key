import Darwin
import Foundation

enum V3RecoveryRestorePublicationError: Error, Equatable {
  case preparationUnavailable
  case destinationChanged
  case wrapperMismatch
}

enum V3RecoveryRestorePublicationPhase: Equatable, Sendable {
  case preparationConfirmed
  case deviceWrapperVerified
  case entryPublished(index: Int)
  case publishedEntriesVerified
  case manifestPublished
  case publishedSnapshotVerified
}

protocol V3RecoveryRestorePublicationPhaseObserving: Sendable {
  func didReach(_ phase: V3RecoveryRestorePublicationPhase) throws
}

private struct V3NoopRestorePublicationObserver: V3RecoveryRestorePublicationPhaseObserving {
  func didReach(_: V3RecoveryRestorePublicationPhase) throws {}
}

/// Publication is not checkpoint installation, saved consent or selection.
struct V3RecoveryRestorePublicationReport: Equatable, Sendable {
  let checkpoint: V3ManifestCheckpoint
  let ownerDeviceID: String
  let entryCount: Int
}

/// Explicit publication/reconciliation of one locally owned preparation.
/// Caller supplies fresh scoped source/key/identity and serializes the ceremony.
/// No credential creation, resealing, cleanup, trust installation or selection.
struct V3RecoveryRestorePublisher: Sendable {
  private let journal: V3RecoveryRestoreJournal
  private let limits: V3ManifestRepositoryLimits
  private let observer: any V3RecoveryRestorePublicationPhaseObserving
  private let writeObserver: any V3AtomicStagedObjectWriteObserving

  init(
    journal: V3RecoveryRestoreJournal, limits: V3ManifestRepositoryLimits = .standard,
    observer: any V3RecoveryRestorePublicationPhaseObserving = V3NoopRestorePublicationObserver(),
    writeObserver: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) {
    self.journal = journal
    self.limits = limits
    self.observer = observer
    self.writeObserver = writeObserver
  }

  /// A later call must authenticate again; it never creates replacement keys.
  /// Only missing pre-manifest objects may be installed. A present manifest
  /// requires its complete exact snapshot and is never repaired here.
  func publish(
    sourceVaultID: String, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    identity: any V3DeviceWrappedVaultKeyUnwrapping
  ) throws -> V3RecoveryRestorePublicationReport {
    try environment.requireUnselectedConfiguration()
    let bundle = try journal.confirmPreparation(
      sourceVaultID: sourceVaultID, snapshot: snapshot, environment: environment,
      vaultKey: vaultKey, expectedOwner: identity.publicIdentity)
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: environment.destination, writeObserver: writeObserver)
    try observer.didReach(.preparationConfirmed)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    _ = try inventory(bundle, store: store)
    _ = try environment.validateCandidate(
      bundle.publication(restoring: snapshot), restoring: snapshot, vaultKey: vaultKey,
      expectedOwner: identity.publicIdentity, limits: limits)

    let session = V3DeviceWrappedVaultKeySessionStore()
    defer { session.invalidate() }
    _ = try V3DeviceWrappedCheckpointUnlocker().unlock(
      checkpoint: bundle.intent.destinationCheckpoint,
      manifestData: bundle.manifest.canonicalBytes, identity: identity, session: session,
      reason: "Verify this Mac's access to the prepared restored vault.",
      validateBeforeSessionInstall: {
        try requireCurrent(bundle, snapshot: snapshot, environment: environment)
        _ = try inventory(bundle, store: store)
      })
    guard
      try session.load(
        vaultID: bundle.manifest.body.vaultID, keyID: bundle.intent.destinationKeyID) == vaultKey
    else { throw V3RecoveryRestorePublicationError.wrapperMismatch }
    try observer.didReach(.deviceWrapperVerified)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    var state = try inventory(bundle, store: store)

    if !state.manifestPresent {
      for (index, entry) in bundle.entries.enumerated() {
        try requireCurrent(bundle, snapshot: snapshot, environment: environment)
        state = try inventory(bundle, store: store)
        let path = pathForEntry(entry)
        if !state.entries.contains(path) {
          // The complete encrypted bundle is already the durable staging area.
          // Reuse the atomic no-overwrite writer directly at the final address.
          try store.writeStagedObject(entry.canonicalBytes, at: path)
        }
        try confirmEntry(entry, store: store)
        try observer.didReach(.entryPublished(index: index))
        try requireCurrent(bundle, snapshot: snapshot, environment: environment)
        _ = try inventory(bundle, store: store)
      }
      state = try inventory(bundle, store: store)
      guard state.entries.count == bundle.entries.count else {
        throw V3RecoveryRestorePublicationError.destinationChanged
      }
      try observer.didReach(.publishedEntriesVerified)
      try requireCurrent(bundle, snapshot: snapshot, environment: environment)
      state = try inventory(bundle, store: store)
      guard state.entries.count == bundle.entries.count else {
        throw V3RecoveryRestorePublicationError.destinationChanged
      }
      // Synchronize every entry again before making the manifest visible.
      for entry in bundle.entries { try confirmEntry(entry, store: store) }
      try requireCurrent(bundle, snapshot: snapshot, environment: environment)
      state = try inventory(bundle, store: store)
      guard state.entries.count == bundle.entries.count else {
        throw V3RecoveryRestorePublicationError.destinationChanged
      }
      if !state.manifestPresent {
        try store.writeStagedObject(
          bundle.manifest.canonicalBytes,
          at: manifestPath(for: bundle.intent.destinationCheckpoint.envelopeDigest))
      }
      try observer.didReach(.manifestPublished)
    }

    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    try confirmSnapshot(bundle, store: store)
    _ = try environment.validateCandidate(
      bundle.publication(restoring: snapshot), restoring: snapshot, vaultKey: vaultKey,
      expectedOwner: identity.publicIdentity, limits: limits)
    try observer.didReach(.publishedSnapshotVerified)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    try confirmSnapshot(bundle, store: store)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    return .init(
      checkpoint: bundle.intent.destinationCheckpoint, ownerDeviceID: bundle.intent.ownerDeviceID,
      entryCount: bundle.entries.count)
  }

  private func requireCurrent(
    _ bundle: V3RecoveryRestoreBundle, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment
  ) throws {
    guard
      let pending = try journal.loadPending(
        sourceVaultID: bundle.intent.sourceAnchor.floor.vaultID),
      pending.reservationOwnership.phase == .recoverable,
      pending.preparationOwnership?.phase == .recoverable,
      pending.preparation?.canonicalBytes == bundle.canonicalBytes
    else { throw V3RecoveryRestorePublicationError.preparationUnavailable }
    try pending.reservation.requireSnapshot(snapshot)
    try environment.requireCurrent(bundle.intent.locations)
    try environment.requireSnapshot(snapshot)
  }

  /// Trust installation must recheck the actual complete published snapshot,
  /// not rely on a prior report. This path cannot install or repair objects.
  func confirmPublished(
    sourceVaultID: String, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreBundle {
    let bundle = try journal.confirmPreparation(
      sourceVaultID: sourceVaultID, snapshot: snapshot, environment: environment,
      vaultKey: vaultKey, expectedOwner: expectedOwner)
    let store = V3FilesystemTransactionArtifactStore(rootHandle: environment.destination)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    try confirmSnapshot(bundle, store: store)
    _ = try environment.validateCandidate(
      bundle.publication(restoring: snapshot), restoring: snapshot, vaultKey: vaultKey,
      expectedOwner: expectedOwner, limits: limits)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    try confirmSnapshot(bundle, store: store)
    try requireCurrent(bundle, snapshot: snapshot, environment: environment)
    return bundle
  }

  /// Selected completion can retain only the complete preparation pin. This
  /// path still verifies exact published inventory without repairing anything.
  func confirmFinalization(
    _ state: V3RecoveryRestoreFinalizationState, snapshot: V3RecoveryVerifiedSnapshot,
    environment: V3RecoveryRestoreEnvironment, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity
  ) throws -> V3RecoveryRestoreBundle {
    let bundle = try journal.confirmFinalization(
      state, snapshot: snapshot,
      environment: environment, vaultKey: vaultKey, expectedOwner: expectedOwner)
    let store = V3FilesystemTransactionArtifactStore(rootHandle: environment.destination)
    try confirmSnapshot(bundle, store: store)
    _ = try environment.validateCandidate(
      bundle.publication(restoring: snapshot),
      restoring: snapshot, vaultKey: vaultKey, expectedOwner: expectedOwner, limits: limits)
    _ = try journal.confirmFinalization(
      state, snapshot: snapshot,
      environment: environment, vaultKey: vaultKey, expectedOwner: expectedOwner)
    try confirmSnapshot(bundle, store: store)
    _ = try journal.confirmFinalization(
      state, snapshot: snapshot,
      environment: environment, vaultKey: vaultKey, expectedOwner: expectedOwner)
    return bundle
  }

  private struct Inventory {
    let entries: Set<String>
    let manifestPresent: Bool
  }

  /// Permit only a subset of the exact owned addresses, including empty parent
  /// folders from interrupted creation. Unknown files/partials remain untouched.
  /// A manifest without all of its exact entries is damage, not resumable staging.
  private func inventory(
    _ bundle: V3RecoveryRestoreBundle, store: V3FilesystemTransactionArtifactStore
  )
    throws -> Inventory
  {
    let root = store.rootHandle
    let allowedRoot: Set<String> =
      bundle.entries.isEmpty ? ["manifests"] : ["entries", "manifests"]
    let roots = try names(root: root, path: nil, allowed: allowedRoot) ?? []
    var found = Set<String>()
    if roots.contains("entries") {
      let ids = Set(bundle.entries.map { $0.context.entryID })
      let directories = try names(root: root, path: "entries", allowed: ids) ?? []
      for entry in bundle.entries where directories.contains(entry.context.entryID) {
        let path = pathForEntry(entry)
        let filename = String(path.split(separator: "/").last!)
        let objects =
          try names(
            root: root, path: "entries/\(entry.context.entryID)", allowed: [filename]) ?? []
        if objects.contains(filename) {
          try requireExact(entry.canonicalBytes, at: path, store: store)
          found.insert(path)
        }
      }
    }
    let manifest = manifestPath(for: bundle.intent.destinationCheckpoint.envelopeDigest)
    let filename = String(manifest.split(separator: "/").last!)
    let objects =
      roots.contains("manifests")
      ? try names(root: root, path: "manifests", allowed: [filename]) ?? [] : []
    let manifestPresent = objects.contains(filename)
    if manifestPresent {
      try requireExact(bundle.manifest.canonicalBytes, at: manifest, store: store)
      guard found.count == bundle.entries.count else {
        throw V3RecoveryRestorePublicationError.destinationChanged
      }
    }
    try root.requireConfiguredRootIdentity()
    return .init(entries: found, manifestPresent: manifestPresent)
  }

  private func names(root: VaultRootDirectoryHandle, path: String?, allowed: Set<String>) throws
    -> Set<String>?
  {
    func read(_ descriptor: Int32) throws -> Set<String> {
      // A new open description avoids sharing directory position across checks.
      let listing = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard listing >= 0 else { throw V3RecoveryRestorePublicationError.destinationChanged }
      defer { close(listing) }
      guard
        case .names(let names, let count) = directoryEntryNames(
          descriptor: listing, maximumCount: allowed.count + 1), count == names.count,
        Set(names).isSubset(of: allowed)
      else { throw V3RecoveryRestorePublicationError.destinationChanged }
      return Set(names)
    }
    if let path {
      do {
        return try root.withResolvedDescriptor(at: path, expecting: .directory) {
          try read($0.rawValue)
        }
      } catch VaultPathResolutionError.notFound {
        return nil
      }
    }
    return try root.withFileDescriptor { try read($0) }
  }

  private func requireExact(
    _ bytes: Data, at path: String, store: V3FilesystemTransactionArtifactStore
  )
    throws
  {
    guard
      case .available(let observed) = try store.readRecoveryObject(
        at: path, maximumBytes: bytes.count), observed == bytes
    else { throw V3RecoveryRestorePublicationError.destinationChanged }
  }

  private func confirmEntry(_ entry: V3EncryptedEntry, store: V3FilesystemTransactionArtifactStore)
    throws
  {
    try store.confirmDurableRecoveryObject(
      entry.canonicalBytes, at: pathForEntry(entry),
      directories: ["entries/\(entry.context.entryID)", "entries"])
  }

  private func confirmSnapshot(
    _ bundle: V3RecoveryRestoreBundle, store: V3FilesystemTransactionArtifactStore
  ) throws {
    let state = try inventory(bundle, store: store)
    guard state.manifestPresent, state.entries.count == bundle.entries.count else {
      throw V3RecoveryRestorePublicationError.destinationChanged
    }
    for entry in bundle.entries { try confirmEntry(entry, store: store) }
    try store.confirmDurableRecoveryObject(
      bundle.manifest.canonicalBytes,
      at: manifestPath(for: bundle.intent.destinationCheckpoint.envelopeDigest),
      directories: ["manifests"])
    _ = try inventory(bundle, store: store)
  }

  private func pathForEntry(_ entry: V3EncryptedEntry) -> String {
    entryPath(
      entryID: entry.context.entryID,
      digest: V3ResealedEntry(encryptedEntry: entry).manifestEntry.ciphertextDigest)
  }
}
