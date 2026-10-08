import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryRestoreTrustInstallerTests {
  private typealias Base = V3RecoveryRestoreJournalTests
  private typealias Identity = V3RecoveryRestorePublisherTests.Identity
  private typealias Core = V3RecoveryRegistrationTests
  private enum Stop: Error { case interrupted }
  private static let phases: [V3RecoveryRestoreTrustPhase] = [
    .publishedSnapshotVerified, .deviceWrapperVerified, .manifestCached,
    .checkpointInstalled, .ordinaryReopenVerified,
  ]

  @Test(arguments: [false, true])
  func exactTrustAndFreshOrdinaryReopenUseNoInjectedKeyOrSourceMac(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness(empty: empty)
    defer { h.f.remove() }
    let before = try Base().files(h.f.source.root)
    let local = try Base().files(h.f.configRootURL)
    let report = try h.install()
    #expect(report.checkpoint == h.bundle.intent.destinationCheckpoint)
    #expect(report.entryCount == h.bundle.entries.count)
    #expect(h.identity.calls.value == 2 && h.loader.calls.value == 2)
    #expect(h.checkpoints.value == report.checkpoint.canonicalBytes)
    #expect(
      try h.cache.load(for: report.checkpoint) == .available(h.bundle.manifest.canonicalBytes))
    let repeated = try h.install()
    #expect(repeated == report && h.identity.calls.value == 4)
    #expect(try Base().files(h.f.source.root) == before)
    #expect(try Base().files(h.f.configRootURL) == local)
    #expect(try !h.f.config.hasConfiguration())
    #expect(h.f.source.core.owner.unwraps == 0)
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  @Test(arguments: phases)
  func everyTrustBoundaryRetainsExactStateForExplicitContinuation(
    phase: V3RecoveryRestoreTrustPhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    #expect(throws: Stop.interrupted) {
      try h.install(observer: Observer { if $0 == phase { throw Stop.interrupted } })
    }
    let installed = [.checkpointInstalled, .ordinaryReopenVerified].contains(phase)
    #expect(
      h.checkpoints.value
        == (installed ? h.bundle.intent.destinationCheckpoint.canonicalBytes : nil))
    let pins = [h.f.reservations.value, h.f.preparations.value]
    _ = try h.install()
    #expect(h.checkpoints.value == h.bundle.intent.destinationCheckpoint.canonicalBytes)
    #expect([h.f.reservations.value, h.f.preparations.value] == pins)
    #expect(try !h.f.config.hasConfiguration())
  }

  @Test(arguments: 0..<3)
  func differentOrMalformedCheckpointIsNeverReplaced(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let different = try V3ManifestCheckpoint(
      vaultID: variant == 1 ? Core.vaultID : Base.vaultID,
      envelopeDigest: Data(repeating: 7, count: 32))
    let bytes = variant == 2 ? Data("malformed".utf8) : different.canonicalBytes
    h.checkpoints.value = bytes
    #expect(throws: V3RecoveryRestoreTrustError.conflictingCheckpoint) { try h.install() }
    #expect(
      h.checkpoints.value == bytes && h.identity.calls.value == 0 && h.loader.calls.value == 0)
  }

  @Test(arguments: [false, true])
  func cacheOrCheckpointFailureCannotSelectOrEraseTrust(cacheFailure: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    if cacheFailure {
      try FileManager.default.moveItem(
        at: h.cacheRoot, to: h.cacheRoot.appendingPathExtension("preserved"))
      try FileManager.default.createDirectory(at: h.cacheRoot, withIntermediateDirectories: false)
    } else {
      h.checkpoints.rejectAdvance = true
    }
    #expect(throws: (any Error).self) { try h.install() }
    #expect(h.checkpoints.value == nil)
    #expect(try !h.f.config.hasConfiguration())
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  @Test(arguments: 0..<4)
  func identityFailureBeforeOrDuringFreshReopenRetainsCommittedCheckpoint(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let counter = Core.Counter()
    let bad = Identity(
      owner: h.owner,
      onUnwrap: {
        counter.increment()
        if variant == 1 || variant == 2, counter.value == (variant == 2 ? 2 : 1) {
          throw V3EnrollmentDeviceIdentityStoreError.authenticationCancelled
        }
      })
    let loader = Loader(identity: bad, missingAt: variant == 0 ? 1 : (variant == 3 ? 2 : nil))
    #expect(throws: (any Error).self) { try h.install(loader: loader) }
    #expect(
      h.checkpoints.value
        == (variant >= 2 ? h.bundle.intent.destinationCheckpoint.canonicalBytes : nil))
    #expect(counter.value == (variant == 0 ? 0 : (variant == 2 ? 2 : 1)))
    #expect(try !h.f.config.hasConfiguration())
    _ = try h.install()
  }

  @Test(arguments: 0..<5)
  func changesBeforeTrustInsertionCannotAdvanceTheCheckpoint(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let source = h.f.source
    let pin = h.f.preparations
    let checkpoints = h.checkpoints
    let config = h.f.config.initializationConfigFileURL
    let entry = h.f.environment.destination.rootURL.appendingPathComponent(
      entryPath(
        entryID: h.bundle.entries[0].context.entryID,
        digest: V3ResealedEntry(encryptedEntry: h.bundle.entries[0]).manifestEntry.ciphertextDigest)
    )
    #expect(throws: (any Error).self) {
      try h.install(
        observer: Observer {
          guard $0 == .manifestCached else { return }
          switch variant {
          case 0: try Data("unrelated".utf8).write(to: config)
          case 1:
            let edit = try source.build(
              .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
            _ = try source.publisher().publish(edit, vaultKey: Core.nextKey)
          case 2: pin.value = nil
          case 3: try FileManager.default.removeItem(at: entry)
          default: checkpoints.value = Data("foreign".utf8)
          }
        })
    }
    #expect(h.checkpoints.value == (variant == 4 ? Data("foreign".utf8) : nil))
  }

  @Test(arguments: 0..<3)
  func finalReopenRechecksCheckpointRecordAndConfiguration(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let checkpoints = h.checkpoints
    let record = h.f.record("preparation.json")
    let config = h.f.config.initializationConfigFileURL
    #expect(throws: (any Error).self) {
      try h.install(
        observer: Observer {
          guard $0 == .ordinaryReopenVerified else { return }
          if variant == 0 {
            checkpoints.value = Data("foreign".utf8)
          } else if variant == 1 {
            try Data("changed".utf8).write(to: record)
          } else {
            try Data("unrelated".utf8).write(to: config)
          }
        })
    }
    #expect(h.identity.calls.value == 2)
    #expect(
      h.checkpoints.value
        == (variant == 0
          ? Data("foreign".utf8) : h.bundle.intent.destinationCheckpoint.canonicalBytes))
    #expect(h.f.reservations.value != nil && h.f.preparations.value != nil)
  }

  @Test(arguments: [false, true])
  func incompletePublishedSnapshotCannotBeRepairedOrTrusted(manifestMissing: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.remove() }
    let path =
      manifestMissing
      ? manifestPath(for: h.bundle.intent.destinationCheckpoint.envelopeDigest)
      : entryPath(
        entryID: h.bundle.entries[0].context.entryID,
        digest: V3ResealedEntry(encryptedEntry: h.bundle.entries[0]).manifestEntry.ciphertextDigest)
    try FileManager.default.removeItem(
      at: h.f.environment.destination.rootURL.appendingPathComponent(path))
    let before = try Base().files(h.f.environment.destination.rootURL)
    #expect(throws: (any Error).self) { try h.install() }
    #expect(h.checkpoints.value == nil && h.identity.calls.value == 0)
    #expect(try Base().files(h.f.environment.destination.rootURL) == before)
  }

  private struct Observer: V3RecoveryRestoreTrustPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreTrustPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreTrustPhase) throws { try action(phase) }
  }
  private struct Loader: V3DeviceWrappedIdentityLoading {
    let identity: Identity
    let missingAt: Int?
    let calls = Core.Counter()
    init(identity: Identity, missingAt: Int? = nil) {
      self.identity = identity
      self.missingAt = missingAt
    }
    func loadDeviceIdentity(vaultID: String, reason _: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      calls.increment()
      return calls.value == missingAt || identity.vaultID != vaultID ? nil : identity
    }
  }
  @available(macOS 26.0, *)
  private struct Harness {
    let f: Base.Fixture
    let owner: Base.Owner
    let bundle: V3RecoveryRestoreBundle
    let identity: Identity
    let loader: Loader
    let checkpoints = V3RecoveryContentMutationPublisherTests.Checkpoints(Data())
    let cacheRoot: URL
    let cache: V3CheckpointManifestFilesystemCache
    init(empty: Bool = false) throws {
      f = try Base.Fixture(empty: empty)
      let (_, preparedOwner, preparedBundle) = try f.prepare()
      owner = preparedOwner
      bundle = preparedBundle
      identity = Identity(owner: owner)
      loader = Loader(identity: identity)
      checkpoints.value = nil
      _ = try V3RecoveryRestorePublisher(journal: f.journal()).publish(
        sourceVaultID: Core.vaultID, snapshot: f.open(), environment: f.environment,
        vaultKey: Base.key, identity: Identity(owner: owner))
      cacheRoot = f.base.appendingPathComponent("cache")
      try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: false)
      cache = try .init(rootHandle: .init(opening: cacheRoot))
    }
    func install(
      loader: Loader? = nil,
      observer: any V3RecoveryRestoreTrustPhaseObserving = Observer(action: { _ in })
    ) throws -> V3RecoveryRestoreTrustReport {
      try V3RecoveryRestoreTrustInstaller(
        journal: f.journal(), checkpoints: checkpoints,
        cache: cache, identities: loader ?? self.loader, observer: observer
      ).install(
        sourceVaultID: Core.vaultID, snapshot: f.open(),
        environment: f.reopen(bundle.intent.locations), vaultKey: Base.key)
    }
  }
}
