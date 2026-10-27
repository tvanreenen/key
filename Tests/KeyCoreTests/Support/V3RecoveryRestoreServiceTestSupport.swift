import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Restore service, helper/CLI setup, and deliberately fallible saved software Mac identities.
enum V3RecoveryRestoreServiceTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Base = V3RecoveryRestoreJournalTestSupport
  typealias Native = PIVRecoveryTestSupport
  enum Stop: Error { case interrupted }
  struct Observer: V3RecoveryRestoreServicePhaseObserving {
    let action: @Sendable (V3RecoveryRestoreServicePhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreServicePhase) throws { try action(phase) }
  }
  struct JournalObserver: V3RecoveryRestoreJournalPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreJournalPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreJournalPhase) throws { try action(phase) }
  }
  struct Writer: V3AtomicStagedObjectWriteObserving {
    let action: @Sendable (String) throws -> Void
    func didReach(_ phase: V3AtomicStagedObjectWritePhase) throws {
      if case .temporaryFileSynchronized(let path) = phase { try action(path) }
    }
  }

  final class Identities: V3DeviceWrappedGenesisIdentityManaging, @unchecked Sendable {
    let creates = Core.Counter(), loads = Core.Counter()
    private(set) var saved: V3RecoveryRestoreIdentityTestSupport.Identity?
    var failure: Int?
    var onCreate: @Sendable () throws -> Void = {}
    var onUnwrap: @Sendable () throws -> Void = {}
    func createDeviceWrappedIdentity(vaultID: String, displayName _: String, reason _: String)
      throws
      -> any V3DeviceWrappedVaultKeyUnwrapping
    {
      creates.increment()
      try onCreate()
      if failure == 0 { throw Stop.interrupted }
      let identity = V3RecoveryRestoreIdentityTestSupport.Identity(
        owner: try Base.Owner(), vaultID: vaultID, onUnwrap: onUnwrap)
      saved = identity
      if failure == 1 { throw Stop.interrupted }
      return identity
    }
    func loadDeviceIdentity(vaultID: String, reason _: String) throws
      -> (any V3DeviceWrappedVaultKeyUnwrapping)?
    {
      loads.increment()
      guard let saved, failure != 2 else { return nil }
      if failure == 3 {
        return V3RecoveryRestoreIdentityTestSupport.Identity(
          owner: try Base.Owner(), vaultID: vaultID)
      }
      if failure == 4 || failure == 5 {
        return BadIdentity(identity: saved, wrongVault: failure == 4)
      }
      return saved
    }
  }
  private struct BadIdentity: V3DeviceWrappedVaultKeyUnwrapping {
    let identity: V3RecoveryRestoreIdentityTestSupport.Identity
    let wrongVault: Bool
    var vaultID: String { wrongVault ? Core.vaultID : identity.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { identity.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _: V3HPKEWrappedVaultKey, context _: V3VaultKeyHPKEContext, reason _: String
    ) throws -> Data { throw V3EnrollmentDeviceIdentityStoreError.authenticationCancelled }
  }

  // Immutable config value; concurrent service calls share the real mutation
  // owner. Native fixture callbacks and storage have their own locking.
  struct Fixture: @unchecked Sendable {
    let source: V3RecoveryPublicationTestSupport.Fixture
    let base: URL, parent: URL, configRoot: URL
    let config: KeyConfigStore
    let sourceHandle: VaultRootDirectoryHandle, parentHandle: VaultRootDirectoryHandle
    let operation = VaultTransactionOperationID()
    let reservations = Base.Ownership(), preparations = Base.Ownership()
    let identities = Identities()
    let reader: PIVRecoveryTokenReader, agreement: PIVRecoveryAgreement
    let card: Native.Card, provider: Native.Provider
    let owner: VaultTransactionMutationOwner
    let authentication = V3DeviceWrappedVaultKeySessionStore()
    let cancellation = PIVRecoveryCancellation()
    let checkpoints: V3RecoveryPublicationTestSupport.Checkpoints
    let cache: V3CheckpointManifestFilesystemCache
    var destination: URL { parent.appendingPathComponent("restored") }
    init(empty: Bool = false) throws {
      source = try .init(empty: empty)
      sourceHandle = try .init(opening: source.root)
      base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      config = .init(homeDirectoryURL: base.appendingPathComponent("home"))
      configRoot = config.initializationConfigFileURL.deletingLastPathComponent()
      try FileManager.default.createDirectory(at: configRoot, withIntermediateDirectories: true)
      parent = base.appendingPathComponent("destinations")
      try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
      parentHandle = try .init(opening: parent)
      checkpoints = .init(Data())
      checkpoints.value = nil
      let cacheRoot = base.appendingPathComponent("cache")
      try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: false)
      cache = .init(rootHandle: try .init(opening: cacheRoot))
      card = try Native.Card(publicKey: source.core.token.publicKey.x963Representation)
      card.anchor = source.anchor.canonicalBytes
      reader = .init(inventory: Native.Inventory(card: card), gate: PIVTokenOperationGate())
      provider = Native.Provider(token: source.core.token, card: card)
      agreement = .init(reader: reader, provider: provider)
      let operation = self.operation
      owner = .init(makeOperationID: { operation })
    }
    func journal(
      observer: any V3RecoveryRestoreJournalPhaseObserving = JournalObserver(action: { _ in }),
      writer: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
    ) throws -> V3RecoveryRestoreJournal {
      .init(
        configurationRoot: try .init(opening: configRoot), reservationOwnership: reservations,
        preparationOwnership: preparations, observer: observer, writeObserver: writer)
    }
    @available(macOS 26.0, *)
    func prepare(
      name: String = "restored", journal: V3RecoveryRestoreJournal? = nil,
      observation: PIVRecoveryTokenObservation? = nil,
      observer: any V3RecoveryRestoreServicePhaseObserving = Observer(action: { _ in }),
      deadline: DispatchTime = .now() + .seconds(60)
    ) throws -> V3RecoveryRestoreReport {
      try V3RecoveryRestoreService(
        configStore: config, journal: journal ?? self.journal(), identities: identities,
        checkpoints: checkpoints, cache: cache,
        mutationOwner: owner, reader: reader, agreement: agreement, authentication: authentication,
        observer: observer
      ).prepare(
        source: sourceHandle, parent: parentHandle, name: name, deviceName: "Fresh test Mac",
        observation: observation ?? reader.read(try #require(reader.candidates().first)),
        cancellation: cancellation, deadline: deadline)
    }
    func stop(lock: Bool) {
      if lock { authentication.invalidate() } else { cancellation.cancel() }
    }
    func record(_ name: String) -> URL {
      configRoot.appendingPathComponent("v3-restore-attempts/\(operation)/\(name)")
    }
    func remove() {
      source.remove()
      try? FileManager.default.removeItem(at: base)
    }
  }
}
