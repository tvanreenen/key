import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Published disposable restore and local selection state for selection/finalization tests.
enum V3RecoveryRestoreSelectionTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Base = V3RecoveryRestoreJournalTestSupport
  typealias Identity = V3RecoveryRestoreIdentityTestSupport.Identity
  struct Observer: V3RecoveryRestoreSelectionPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreSelectionPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreSelectionPhase) throws { try action(phase) }
  }
  struct Writer: V3AtomicStagedObjectWriteObserving {
    let action: @Sendable () throws -> Void
    func didReach(_: V3AtomicStagedObjectWritePhase) throws { try action() }
  }
  struct Loader: V3DeviceWrappedIdentityLoading {
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
  struct Harness {
    let f: Base.Fixture
    let bundle: V3RecoveryRestoreBundle
    let identity: Identity
    let loader: Loader
    let checkpoints = V3RecoveryPublicationTestSupport.Checkpoints(Data())
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
