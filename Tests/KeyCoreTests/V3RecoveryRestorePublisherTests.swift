import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real contained publication, software wrapper opening and memory ownership.
/// No real vault, token, native credential, checkpoint or config selection.
struct V3RecoveryRestorePublisherTests {
  typealias Base = V3RecoveryRestoreJournalTests
  @available(macOS 26.0, *)
  private typealias Fixture = Base.Fixture
  typealias Core = V3RecoveryRegistrationTests
  private enum Stop: Error { case interrupted }
  private static let phases: [V3RecoveryRestorePublicationPhase] = [
    .preparationConfirmed, .deviceWrapperVerified, .entryPublished(index: 0),
    .entryPublished(index: 1), .publishedEntriesVerified, .manifestPublished,
    .publishedSnapshotVerified,
  ]

  @Test(arguments: [false, true])
  func publishesExactOwnedSnapshotAndExplicitlyReconcilesWithoutNewCiphertext(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let (reservation, owner, bundle) = try f.prepare()
    let sourceBefore = try Base().files(f.source.root)
    let localBefore = try Base().files(f.configRootURL)
    let pins = [f.reservations.value, f.preparations.value]
    let identity = Identity(owner: owner)
    let report = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
      vaultKey: Base.key, identity: identity)
    #expect(report.checkpoint == bundle.intent.destinationCheckpoint)
    #expect(report.entryCount == bundle.entries.count && identity.calls.value == 1)
    let destinationBefore = try Base().files(f.environment.destination.rootURL)
    #expect(destinationBefore.count == bundle.entries.count + 1)
    for entry in bundle.entries {
      #expect(try Data(contentsOf: objectURL(f, entry)) == entry.canonicalBytes)
    }
    #expect(try Data(contentsOf: manifestURL(f, bundle)) == bundle.manifest.canonicalBytes)
    let later = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(),
      environment: f.reopen(reservation.locations), vaultKey: Base.key, identity: identity)
    #expect(later == report && identity.calls.value == 2)
    #expect(try Base().files(f.environment.destination.rootURL) == destinationBefore)
    #expect(try Base().files(f.configRootURL) == localBefore)
    #expect(try Base().files(f.source.root) == sourceBefore)
    #expect([f.reservations.value, f.preparations.value] == pins)
    #expect(try !f.config.hasConfiguration())
    #expect(f.source.core.owner.unwraps == 0)
  }

  @Test(arguments: phases)
  func eachPublicationBoundaryLeavesAnExactExplicitlyResumableAttempt(
    phase: V3RecoveryRestorePublicationPhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (reservation, owner, bundle) = try f.prepare()
    let local = try Base().files(f.configRootURL)
    let identity = Identity(owner: owner)
    #expect(throws: Stop.interrupted) {
      try publisher(f, observer: Observer { if $0 == phase { throw Stop.interrupted } }).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    let committed = [.manifestPublished, .publishedSnapshotVerified].contains(phase)
    #expect(FileManager.default.fileExists(atPath: manifestURL(f, bundle).path) == committed)
    let before = try Base().files(f.environment.destination.rootURL)
    let report = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(),
      environment: f.reopen(reservation.locations), vaultKey: Base.key, identity: identity)
    let after = try Base().files(f.environment.destination.rootURL)
    for (path, bytes) in before { #expect(after[path] == bytes) }
    #expect(after.count == bundle.entries.count + 1 && report.entryCount == bundle.entries.count)
    #expect(try Base().files(f.configRootURL) == local)
    #expect(try !f.config.hasConfiguration())
    #expect(identity.calls.value == (phase == .preparationConfirmed ? 1 : 2))
  }

  @Test(arguments: [false, true])
  func interruptionInsideAtomicInstallationKeepsManifestLast(manifest: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (reservation, owner, bundle) = try f.prepare()
    let identity = Identity(owner: owner)
    #expect(throws: Stop.interrupted) {
      try publisher(
        f,
        writeObserver: Writer { path in
          if path.hasPrefix(manifest ? "manifests/" : "entries/") { throw Stop.interrupted }
        }
      ).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    #expect(!FileManager.default.fileExists(atPath: manifestURL(f, bundle).path))
    #expect(try Base().files(f.environment.destination.rootURL).count == (manifest ? 2 : 0))
    _ = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(),
      environment: f.reopen(reservation.locations), vaultKey: Base.key, identity: identity)
    #expect(try Data(contentsOf: manifestURL(f, bundle)) == bundle.manifest.canonicalBytes)
    #expect(identity.calls.value == 2)
  }

  @Test(arguments: [
    V3RecoveryRestorePublicationPhase.preparationConfirmed, .deviceWrapperVerified,
    .publishedEntriesVerified, .manifestPublished, .publishedSnapshotVerified,
  ])
  func emptyVaultReconcilesEveryReachablePublicationBoundary(
    phase: V3RecoveryRestorePublicationPhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: true)
    defer { f.remove() }
    let (reservation, owner, bundle) = try f.prepare()
    let identity = Identity(owner: owner)
    #expect(throws: Stop.interrupted) {
      try publisher(f, observer: Observer { if $0 == phase { throw Stop.interrupted } }).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    let report = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(),
      environment: f.reopen(reservation.locations), vaultKey: Base.key, identity: identity)
    #expect(report.entryCount == 0)
    #expect(try Base().files(f.environment.destination.rootURL).count == 1)
    #expect(try Data(contentsOf: manifestURL(f, bundle)) == bundle.manifest.canonicalBytes)
    #expect(
      !FileManager.default.fileExists(
        atPath: f.environment.destination.rootURL.appendingPathComponent("entries").path))
  }

  @Test(arguments: 0..<3)
  func onlyKnownEmptyParentsFromInterruptedCreationAreAllowed(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, bundle) = try f.prepare()
    let path =
      variant == 0
      ? "entries"
      : (variant == 1 ? "entries/\(bundle.entries[0].context.entryID)" : "manifests")
    try FileManager.default.createDirectory(
      at: f.environment.destination.rootURL.appendingPathComponent(path),
      withIntermediateDirectories: true)
    let report = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
      vaultKey: Base.key, identity: Identity(owner: owner))
    #expect(report.entryCount == bundle.entries.count)
    #expect(try Base().files(f.environment.destination.rootURL).count == bundle.entries.count + 1)
  }

  @Test(arguments: 0..<9)
  func unexpectedDestinationObjectsRefuseBeforeWrapperOpening(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, bundle) = try f.prepare()
    let root = f.environment.destination.rootURL
    let entry = objectURL(f, bundle.entries[0])
    let bad: URL
    switch variant {
    case 0: bad = root.appendingPathComponent("unrelated")
    case 1: bad = root.appendingPathComponent("entries/unknown/object")
    case 2: bad = entry.deletingLastPathComponent().appendingPathComponent("other.json")
    case 3: bad = entry.deletingLastPathComponent().appendingPathComponent(".orphan.partial")
    case 4: bad = root.appendingPathComponent("manifests/unrelated.json")
    case 5: bad = entry
    case 6: bad = root.appendingPathComponent("entries")
    case 7: bad = root.appendingPathComponent("manifests")
    default: bad = entry
    }
    try FileManager.default.createDirectory(
      at: bad.deletingLastPathComponent(), withIntermediateDirectories: true)
    if variant == 7 {
      try FileManager.default.createDirectory(at: bad, withIntermediateDirectories: false)
      try Data("unexpected".utf8).write(to: bad.appendingPathComponent("nested"))
    } else if variant == 8 {
      let external = f.base.appendingPathComponent("external")
      try bundle.entries[0].canonicalBytes.write(to: external)
      try FileManager.default.createSymbolicLink(at: bad, withDestinationURL: external)
    } else {
      try Data("unexpected".utf8).write(to: bad)
    }
    let before = try Base().files(root)
    let identity = Identity(owner: owner)
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    #expect(identity.calls.value == 0)
    #expect(try Base().files(root) == before)
    #expect(!FileManager.default.fileExists(atPath: manifestURL(f, bundle).path))
  }

  @Test(arguments: 0..<4)
  func aPublishedManifestNeverAuthorizesRepairOfMissingOrChangedFiles(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, bundle) = try f.prepare()
    _ = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
      vaultKey: Base.key, identity: Identity(owner: owner))
    let entry = objectURL(f, bundle.entries[0])
    switch variant {
    case 0: try FileManager.default.removeItem(at: entry)
    case 1: try Data("changed".utf8).write(to: entry)
    case 2: try Data("changed".utf8).write(to: manifestURL(f, bundle))
    default:
      try Data("unknown".utf8).write(
        to: f.environment.destination.rootURL.appendingPathComponent("unrelated"))
    }
    let before = try Base().files(f.environment.destination.rootURL)
    let identity = Identity(owner: owner)
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    #expect(identity.calls.value == 0)
    #expect(try Base().files(f.environment.destination.rootURL) == before)
  }

  @Test(arguments: 0..<5)
  func authenticationFailureMakesNoPublicationAndNeverRetries(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, _) = try f.prepare()
    let identity = Identity(
      owner: try variant == 2 ? Base.Owner() : owner,
      vaultID: variant == 3 ? Core.vaultID : Base.vaultID,
      wrongPrivateKey: variant == 1,
      onUnwrap: {
        if variant == 0 { throw V3EnrollmentDeviceIdentityStoreError.authenticationCancelled }
      })
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: variant == 4 ? Data(repeating: 0, count: 32) : Base.key, identity: identity)
    }
    #expect(identity.calls.value == (variant < 2 ? 1 : 0))
    #expect(try Base().files(f.environment.destination.rootURL).isEmpty)
    // A separate explicit call can use the same saved preparation and actual
    // addressed identity; failure did not replace credentials or ciphertext.
    _ = try publisher(f).publish(
      sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
      vaultKey: Base.key, identity: Identity(owner: owner))
  }

  @Test(arguments: 0..<6)
  func changesAcrossWrapperOpeningCannotPublish(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, _) = try f.prepare()
    let identity = Identity(owner: owner, onUnwrap: mutation(f, variant: variant))
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    #expect(identity.calls.value == 1)
    let files = try Base().files(f.environment.destination.rootURL)
    #expect(files.count == (variant == 5 ? 1 : 0))
  }

  @Test(arguments: 0..<8)
  func changesBeforeManifestPublicationLeaveTheAttemptUnselected(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, bundle) = try f.prepare()
    let action: @Sendable () throws -> Void
    if variant < 6 {
      action = mutation(f, variant: variant)
    } else {
      let url = objectURL(f, bundle.entries[0])
      action = {
        if variant == 6 {
          try FileManager.default.removeItem(at: url)
        } else {
          try Data("changed".utf8).write(to: url)
        }
      }
    }
    #expect(throws: (any Error).self) {
      try publisher(f, observer: Observer { if $0 == .publishedEntriesVerified { try action() } })
        .publish(
          sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
          vaultKey: Base.key, identity: Identity(owner: owner))
    }
    #expect(!FileManager.default.fileExists(atPath: manifestURL(f, bundle).path))
  }

  @Test(arguments: 0..<3)
  func finalRecordOrDestinationChangesRefuseWithoutClearingOwnership(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, bundle) = try f.prepare()
    let action = mutation(f, variant: variant == 2 ? 5 : variant + 2)
    let reservationPin = f.reservations.value
    #expect(throws: (any Error).self) {
      try publisher(f, observer: Observer { if $0 == .publishedSnapshotVerified { try action() } })
        .publish(
          sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
          vaultKey: Base.key, identity: Identity(owner: owner))
    }
    #expect(f.reservations.value == reservationPin)
    #expect(try Data(contentsOf: manifestURL(f, bundle)) == bundle.manifest.canonicalBytes)
  }

  @Test(arguments: 0..<3)
  func noExactOwnedPreparationMeansNoWrapperOpening(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, _) = try f.prepare()
    if variant == 0 {
      f.reservations.value = nil
      f.preparations.value = nil
    }
    if variant == 1 { try FileManager.default.removeItem(at: f.record("preparation.json")) }
    if variant == 2 { try Data("changed".utf8).write(to: f.record("preparation.json")) }
    let identity = Identity(owner: owner)
    #expect(throws: (any Error).self) {
      try publisher(f).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    #expect(identity.calls.value == 0)
    #expect(try Base().files(f.environment.destination.rootURL).isEmpty)
  }

  @Test(arguments: 0..<3)
  func publicationBudgetsRefuseBeforePrivateOperationOrDestinationWrites(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, _) = try f.prepare()
    let identity = Identity(owner: owner)
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 4, maximumHistoryDepth: 4,
      maximumReferencedEntryObjects: variant == 0 ? 1 : 2,
      maximumManifestBytes: variant == 1 ? 1 : 1_000_000,
      maximumEntryBytes: variant == 2 ? 1 : 1_000_000,
      maximumTotalManifestBytes: 4_000_000, maximumTotalEntryBytes: 2_000_000)
    #expect(throws: (any Error).self) {
      try V3RecoveryRestorePublisher(journal: f.journal(), limits: limits).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: identity)
    }
    #expect(identity.calls.value == 0)
    #expect(try Base().files(f.environment.destination.rootURL).isEmpty)
  }

  @available(macOS 26.0, *)
  private func publisher(
    _ f: Fixture,
    observer: any V3RecoveryRestorePublicationPhaseObserving = Observer(action: { _ in }),
    writeObserver: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) throws -> V3RecoveryRestorePublisher {
    try .init(journal: f.journal(), observer: observer, writeObserver: writeObserver)
  }

  @available(macOS 26.0, *)
  private func mutation(_ f: Fixture, variant: Int) -> @Sendable () throws -> Void {
    let config = f.config.initializationConfigFileURL
    let destination = f.environment.destination.rootURL
    let record = f.record("preparation.json")
    let source = f.source
    let pin = f.preparations
    return {
      switch variant {
      case 0: try Data("unrelated".utf8).write(to: config)
      case 1:
        let edit = try source.build(
          .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
        _ = try source.publisher().publish(edit, vaultKey: Core.nextKey)
      case 2: pin.value = nil
      case 3: try Data("changed".utf8).write(to: record)
      case 4:
        try FileManager.default.moveItem(
          at: destination, to: destination.appendingPathExtension("preserved"))
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: false)
      default: try Data("unknown".utf8).write(to: destination.appendingPathComponent("unrelated"))
      }
    }
  }

  @available(macOS 26.0, *)
  private func objectURL(_ f: Fixture, _ entry: V3EncryptedEntry) -> URL {
    f.environment.destination.rootURL.appendingPathComponent(
      entryPath(
        entryID: entry.context.entryID,
        digest: V3ResealedEntry(encryptedEntry: entry).manifestEntry.ciphertextDigest))
  }
  @available(macOS 26.0, *)
  private func manifestURL(_ f: Fixture, _ bundle: V3RecoveryRestoreBundle) -> URL {
    f.environment.destination.rootURL.appendingPathComponent(
      manifestPath(for: bundle.intent.destinationCheckpoint.envelopeDigest))
  }
  private struct Observer: V3RecoveryRestorePublicationPhaseObserving {
    let action: @Sendable (V3RecoveryRestorePublicationPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestorePublicationPhase) throws { try action(phase) }
  }
  private struct Writer: V3AtomicStagedObjectWriteObserving {
    let action: @Sendable (String) throws -> Void
    func didReach(_ phase: V3AtomicStagedObjectWritePhase) throws {
      if case .temporaryFileSynchronized(let path) = phase { try action(path) }
    }
  }
  struct Identity: V3DeviceWrappedVaultKeyUnwrapping {
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let wrapping: P256.KeyAgreement.PrivateKey
    let calls = Core.Counter()
    let onUnwrap: @Sendable () throws -> Void
    init(
      owner: Base.Owner, vaultID: String = Base.vaultID, wrongPrivateKey: Bool = false,
      onUnwrap: @escaping @Sendable () throws -> Void = {}
    ) {
      self.vaultID = vaultID
      publicIdentity = owner.identity
      wrapping = wrongPrivateKey ? .init() : owner.wrapping
      self.onUnwrap = onUnwrap
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason _: String
    ) throws -> Data {
      calls.increment()
      try onUnwrap()
      return try V3VaultKeyHPKE().unwrap(
        wrappedKey, recipientPrivateKey: wrapping, context: context)
    }
  }
}
