import Foundation
import Testing

@testable import KeyCore

/// Real disposable config/publication/cache and ordinary runtime. Software
/// identities and memory checkpoint/ownership replace only native boundaries.
struct V3RecoveryRestoreSelectionInstallerTests {
  private typealias Base = V3RecoveryRestoreJournalTests
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Identity = V3RecoveryRestorePublisherTests.Identity
  private enum Stop: Error { case interrupted }
  private static let phases: [V3RecoveryRestoreSelectionPhase] = [
    .restoreVerified, .configurationSelected, .selectionConfirmed,
  ]

  @Test(arguments: [false, true])
  func selectsLastAndReconcilesExactSelectionWithFreshOrdinaryAccess(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness(empty: empty)
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    let source = try Base().files(h.f.source.root)
    let pins = [h.f.reservations.value, h.f.preparations.value]
    let calls = h.f.calls.value
    let report = try h.select(snapshot: snapshot)
    #expect(!report.wasAlreadySelected && report.trust.entryCount == snapshot.entries.count)
    #expect(h.identity.calls.value == 2 && h.f.calls.value == calls)
    #expect(try Data(contentsOf: h.configURL) == h.configurationBytes())
    let config = try h.f.config.load()
    #expect(config.vaultID == Base.vaultID && config.keychainMode == .local)
    #expect(config.vaultDirectoryURL == h.f.environment.destination.rootURL)
    let before = try Base().files(h.f.configRootURL)
    let again = try h.select(snapshot: snapshot)
    #expect(again.wasAlreadySelected && again.trust == report.trust)
    #expect(h.identity.calls.value == 4 && h.f.calls.value == calls)
    #expect(try Base().files(h.f.configRootURL) == before)
    #expect([h.f.reservations.value, h.f.preparations.value] == pins)
    #expect(try Base().files(h.f.source.root) == source)
    #expect(h.f.source.core.owner.unwraps == 0)

    // A separately constructed ordinary runtime uses only the saved config,
    // checkpoint, cache and identity. No prepared key/session is provided.
    let session = V3DeviceWrappedVaultKeySessionStore()
    defer { session.invalidate() }
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try .init(opening: config.vaultDirectoryURL))
    let runtime = V3DeviceWrappedReadOnlyVaultRuntime(
      source: store,
      unlockRuntime: .init(
        vaultID: try #require(config.vaultID), checkpointStore: h.checkpoints,
        source: store, cache: h.cache, identityLoader: h.loader, session: session))
    try runtime.unlock()
    #expect(try runtime.list(allowStale: false) == snapshot.entries.map(\.name).sorted())
    for entry in snapshot.entries {
      let value = try runtime.read(name: entry.name, allowStale: false)
      #expect(value.type == entry.type && Data(value.plaintext.utf8) == Data(entry.plaintext.utf8))
    }
    #expect(h.identity.calls.value == 5)
  }

  @Test(arguments: phases, [false, true])
  func everySelectionBoundaryRetainsExactStateForExplicitContinuation(
    phase: V3RecoveryRestoreSelectionPhase, alreadySelected: Bool
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    if alreadySelected { _ = try h.select(snapshot: snapshot) }
    let pins = [h.f.reservations.value, h.f.preparations.value]
    #expect(throws: Stop.interrupted) {
      try h.select(
        snapshot: snapshot, observer: Observer { if $0 == phase { throw Stop.interrupted } })
    }
    #expect(h.checkpoints.value == h.bundle.intent.destinationCheckpoint.canonicalBytes)
    #expect(try h.f.config.hasConfiguration() == (alreadySelected || phase != .restoreVerified))
    _ = try h.select(snapshot: snapshot)
    #expect(try Data(contentsOf: h.configURL) == h.configurationBytes())
    #expect([h.f.reservations.value, h.f.preparations.value] == pins)
  }

  @Test(arguments: 0..<8)
  func existingNonexactConfigurationsAreNeverAcceptedOrReplaced(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let bytes = try h.configurationBytes()
    switch variant {
    case 0: try Data("unrelated".utf8).write(to: h.configURL)
    case 1:
      try h.f.config.restoredVaultConfigurationData(
        root: h.f.environment.destination.rootURL, vaultID: Core.vaultID
      ).write(to: h.configURL)
    case 2:
      try h.f.config.restoredVaultConfigurationData(
        root: h.f.source.root, vaultID: Base.vaultID
      ).write(to: h.configURL)
    case 3: try (bytes + Data("\n".utf8)).write(to: h.configURL)
    case 4:
      try FileManager.default.createDirectory(at: h.configURL, withIntermediateDirectories: false)
    case 5, 6:
      let external = h.f.base.appendingPathComponent("external.toml")
      if variant == 5 { try bytes.write(to: external) }
      try FileManager.default.createSymbolicLink(at: h.configURL, withDestinationURL: external)
    default:
      try Data(
        String(decoding: bytes, as: UTF8.self)
          .replacingOccurrences(of: "\"local\"", with: "\"icloud\"").utf8
      ).write(to: h.configURL)
    }
    #expect(throws: (any Error).self) { try h.select(snapshot: h.f.open()) }
    #expect(h.identity.calls.value == 0 && h.loader.calls.value == 0)
    #expect(h.checkpoints.value == nil)
    if variant == 4 {
      var directory: ObjCBool = false
      #expect(FileManager.default.fileExists(atPath: h.configURL.path, isDirectory: &directory))
      #expect(directory.boolValue)
    } else if variant == 5 || variant == 6 {
      #expect(
        try FileManager.default.destinationOfSymbolicLink(atPath: h.configURL.path)
          == h.f.base.appendingPathComponent("external.toml").path)
    } else {
      let observed = try Data(contentsOf: h.configURL)
      #expect(observed != bytes)
    }
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  @Test(arguments: 0..<3)
  func selectedConfigurationCannotReconstructMissingOrDifferentTrust(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    _ = try h.select(snapshot: snapshot)
    let trust: Data? =
      variant == 0
      ? nil
      : (variant == 1
        ? Data("bad".utf8)
        : try V3ManifestCheckpoint(
          vaultID: Base.vaultID, envelopeDigest: Data(repeating: 9, count: 32)
        ).canonicalBytes)
    h.checkpoints.value = trust
    let calls = h.identity.calls.value
    #expect(throws: V3RecoveryRestoreTrustError.conflictingCheckpoint) {
      try h.select(snapshot: snapshot)
    }
    #expect(h.checkpoints.value == trust && h.identity.calls.value == calls)
    #expect(try Data(contentsOf: h.configURL) == h.configurationBytes())
  }

  @Test func interruptedTemporaryConfigWriteCannotSelectAndCanBeExplicitlyRetried() throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    #expect(throws: Stop.interrupted) {
      try h.select(snapshot: snapshot, writer: Writer { throw Stop.interrupted })
    }
    #expect(try !h.f.config.hasConfiguration())
    #expect(h.checkpoints.value == h.bundle.intent.destinationCheckpoint.canonicalBytes)
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
    _ = try h.select(snapshot: snapshot)
  }

  @Test(arguments: 0..<6, [false, true])
  func changedStateAfterProofOrAtAtomicWriteStopsSelection(variant: Int, duringWrite: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    let configURL = h.configURL
    let checkpoints = h.checkpoints
    let preparations = h.f.preparations
    let manifest = h.f.environment.destination.rootURL.appendingPathComponent(
      manifestPath(for: h.bundle.intent.destinationCheckpoint.envelopeDigest))
    let source = h.f.source
    let record = h.f.record("preparation.json")
    let change: @Sendable () throws -> Void = {
      switch variant {
      case 0: try Data("other config".utf8).write(to: configURL)
      case 1: checkpoints.value = Data("foreign trust".utf8)
      case 2: preparations.value = nil
      case 3:
        try FileManager.default.removeItem(at: manifest)
      case 4:
        let edit = try source.build(
          .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
        _ = try source.publisher().publish(edit, vaultKey: Core.nextKey)
      default:
        try FileManager.default.removeItem(at: record)
      }
    }
    let observer = Observer { if !duringWrite && $0 == .restoreVerified { try change() } }
    let writer = Writer { if duringWrite { try change() } }
    #expect(throws: (any Error).self) {
      try h.select(snapshot: snapshot, observer: observer, writer: writer)
    }
    #expect(try h.f.config.hasConfiguration() == (variant == 0))
    if variant == 0 { #expect(try Data(contentsOf: h.configURL) == Data("other config".utf8)) }
    #expect(h.f.reservations.value != nil)
  }

  @Test(arguments: 0..<3)
  func postSelectionChangesNeverRollBackConfigOrTrust(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    let checkpoints = h.checkpoints
    let configURL = h.configURL
    let record = h.f.record("preparation.json")
    #expect(throws: (any Error).self) {
      try h.select(
        snapshot: snapshot,
        observer: Observer {
          guard $0 == .configurationSelected else { return }
          if variant == 0 {
            checkpoints.value = Data("foreign".utf8)
          } else if variant == 1 {
            try Data("foreign".utf8).write(to: configURL)
          } else {
            try Data("changed".utf8).write(to: record)
          }
        })
    }
    #expect(
      try Data(contentsOf: h.configURL)
        == (variant == 1 ? Data("foreign".utf8) : h.configurationBytes()))
    #expect(
      h.checkpoints.value
        == (variant == 0
          ? Data("foreign".utf8) : h.bundle.intent.destinationCheckpoint.canonicalBytes))
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  @Test func selectedEnvironmentCannotPublishAgainAndOrdinaryReopenStaysStrict() throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    _ = try h.select(snapshot: snapshot)
    #expect(throws: (any Error).self) { try h.f.reopen(h.bundle.intent.locations) }
    let environment = try h.completionEnvironment()
    let calls = h.identity.calls.value
    #expect(throws: V3RecoveryRestoreError.configurationPresent) {
      try V3RecoveryRestorePublisher(journal: h.f.journal()).publish(
        sourceVaultID: Core.vaultID, snapshot: snapshot, environment: environment,
        vaultKey: Base.key, identity: h.identity)
    }
    #expect(h.identity.calls.value == calls)
    try FileManager.default.removeItem(at: h.configURL)
    #expect(throws: (any Error).self) { try environment.requireCurrent(environment.locations) }
  }

  @Test func completionEnvironmentForAnotherIDCannotReachTheRestoreIdentity() throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    try h.f.config.restoredVaultConfigurationData(
      root: h.f.environment.destination.rootURL, vaultID: Core.vaultID
    ).write(to: h.configURL)
    let environment = try V3RecoveryRestoreEnvironment.reopenForCompletion(
      source: .init(opening: h.f.source.root),
      destination: .init(opening: h.f.environment.destination.rootURL),
      parent: .init(opening: h.f.environment.destinationParent.rootURL), configStore: h.f.config,
      expected: h.bundle.intent.locations, vaultID: Core.vaultID)
    #expect(throws: V3RecoveryRestoreError.configurationPresent) {
      try V3RecoveryRestoreTrustInstaller(
        journal: h.f.journal(), checkpoints: h.checkpoints, cache: h.cache, identities: h.loader
      ).install(
        sourceVaultID: Core.vaultID, snapshot: snapshot, environment: environment,
        vaultKey: Base.key)
    }
    #expect(h.identity.calls.value == 0 && h.loader.calls.value == 0)
    #expect(h.checkpoints.value == nil)
  }

  @Test(arguments: [false, true])
  func damagedSelectedSnapshotIsNotRepairedOrDeselected(manifestMissing: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    _ = try h.select(snapshot: snapshot)
    let path =
      manifestMissing
      ? manifestPath(for: h.bundle.intent.destinationCheckpoint.envelopeDigest)
      : entryPath(
        entryID: h.bundle.entries[0].context.entryID,
        digest: V3ResealedEntry(encryptedEntry: h.bundle.entries[0]).manifestEntry.ciphertextDigest)
    let damaged = h.f.environment.destination.rootURL.appendingPathComponent(path)
    if manifestMissing {
      try FileManager.default.removeItem(at: damaged)
    } else {
      try Data("damaged".utf8).write(to: damaged)
    }
    let files = try Base().files(h.f.environment.destination.rootURL)
    let calls = h.identity.calls.value
    #expect(throws: (any Error).self) { try h.select(snapshot: snapshot) }
    #expect(h.identity.calls.value == calls)
    #expect(try Base().files(h.f.environment.destination.rootURL) == files)
    #expect(try Data(contentsOf: h.configURL) == h.configurationBytes())
    #expect(h.checkpoints.value == h.bundle.intent.destinationCheckpoint.canonicalBytes)
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  @Test(arguments: 0..<3)
  func replacedPhysicalRootsCannotSelectConfiguration(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let snapshot = try h.f.open()
    let root =
      variant == 0
      ? h.f.configRootURL
      : (variant == 1 ? h.f.source.root : h.f.environment.destination.rootURL)
    try FileManager.default.moveItem(
      at: root, to: h.f.base.appendingPathComponent("preserved-root"))
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    #expect(throws: (any Error).self) { try h.select(snapshot: snapshot) }
    #expect(try !h.f.config.hasConfiguration())
    #expect(h.identity.calls.value == 0 && h.checkpoints.value == nil)
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  private struct Observer: V3RecoveryRestoreSelectionPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreSelectionPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreSelectionPhase) throws { try action(phase) }
  }
  private struct Writer: V3AtomicStagedObjectWriteObserving {
    let action: @Sendable () throws -> Void
    func didReach(_: V3AtomicStagedObjectWritePhase) throws { try action() }
  }
  private struct Loader: V3DeviceWrappedIdentityLoading {
    let identity: Identity
    let calls = Core.Counter()
    func loadDeviceIdentity(vaultID: String, reason _: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      calls.increment()
      return vaultID == identity.vaultID ? identity : nil
    }
  }
  @available(macOS 26.0, *)
  private struct Harness {
    let f: Base.Fixture
    let bundle: V3RecoveryRestoreBundle
    let identity: Identity
    let loader: Loader
    let checkpoints = V3RecoveryContentMutationPublisherTests.Checkpoints(Data())
    let cache: V3CheckpointManifestFilesystemCache
    var configURL: URL { f.config.initializationConfigFileURL }
    init(empty: Bool = false) throws {
      f = try Base.Fixture(empty: empty)
      let (_, owner, saved) = try f.prepare()
      bundle = saved
      identity = Identity(owner: owner)
      loader = Loader(identity: identity)
      checkpoints.value = nil
      _ = try V3RecoveryRestorePublisher(journal: f.journal()).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: Identity(owner: owner))
      let cacheRoot = f.base.appendingPathComponent("cache")
      try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: false)
      cache = try .init(rootHandle: .init(opening: cacheRoot))
    }
    func configurationBytes() throws -> Data {
      try f.config.restoredVaultConfigurationData(
        root: f.environment.destination.rootURL, vaultID: Base.vaultID)
    }
    func completionEnvironment() throws -> V3RecoveryRestoreEnvironment {
      try .reopenForCompletion(
        source: .init(opening: f.source.root),
        destination: .init(opening: f.environment.destination.rootURL),
        parent: .init(opening: f.environment.destinationParent.rootURL), configStore: f.config,
        expected: bundle.intent.locations, vaultID: Base.vaultID)
    }
    func select(
      snapshot: V3RecoveryVerifiedSnapshot,
      observer: any V3RecoveryRestoreSelectionPhaseObserving = Observer(action: { _ in }),
      writer: any V3AtomicStagedObjectWriteObserving = Writer(action: {})
    ) throws -> V3RecoveryRestoreSelectionReport {
      try V3RecoveryRestoreSelectionInstaller(
        journal: f.journal(), checkpoints: checkpoints, cache: cache, identities: loader,
        observer: observer, writeObserver: writer
      ).select(
        sourceVaultID: Core.vaultID, snapshot: snapshot, vaultKey: Base.key,
        source: .init(opening: f.source.root),
        destination: .init(opening: f.environment.destination.rootURL),
        parent: .init(opening: f.environment.destinationParent.rootURL), configStore: f.config)
    }
  }
}
