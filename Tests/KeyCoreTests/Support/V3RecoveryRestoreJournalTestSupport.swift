import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Disposable restore reservations/preparations and exact contained-file snapshots.
enum V3RecoveryRestoreJournalTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Source = V3RecoveryPublicationTestSupport.Fixture
  typealias Ownership = V3RecoveryPublicationTestSupport.Ownership
  static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c5000"
  static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c5001"
  static let ids = [
    "018f4d38-7d5a-7b20-b0f1-97d6e96c5002", "018f4d38-7d5a-7b20-b0f1-97d6e96c5003",
  ]
  static let key = Data(repeating: 0xB8, count: 32)
  struct Observer: V3RecoveryRestoreJournalPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreJournalPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreJournalPhase) throws { try action(phase) }
  }
  struct Owner {
    let wrapping = P256.KeyAgreement.PrivateKey()
    let identity: V3EnrollmentDeviceIdentity
    init() throws {
      identity = try .init(
        displayName: "Fresh Mac fixture",
        signingPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        wrappingPublicKey: wrapping.publicKey.x963Representation)
    }
  }
  @available(macOS 26.0, *)
  struct Fixture {
    let source: Source
    let base: URL
    let config: KeyConfigStore
    var configRootURL: URL { config.initializationConfigFileURL.deletingLastPathComponent() }
    let environment: V3RecoveryRestoreEnvironment
    let operation = VaultTransactionOperationID()
    let reservations = Ownership(), preparations = Ownership()
    let calls = Core.Counter()
    init(empty: Bool = false) throws {
      source = try Source(empty: empty)
      base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      config = .init(homeDirectoryURL: base.appendingPathComponent("home"))
      try FileManager.default.createDirectory(
        at: config.initializationConfigFileURL.deletingLastPathComponent(),
        withIntermediateDirectories: true)
      let parent = base.appendingPathComponent("destinations")
      try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
      environment = try .create(
        source: .init(opening: source.root), in: .init(opening: parent), name: "restored",
        configStore: config)
    }
    func open() throws -> V3RecoveryVerifiedSnapshot {
      let receiver = try PIVHPKEReceiver(publicBytes: source.core.credential.publicKey) {
        [calls, token = source.core.token] peer in
        calls.increment()
        return try token.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: peer)
        ).withUnsafeBytes { Data($0) }
      }
      let selection = try V3RecoveryHistorySelector(source: source.store).select(
        anchor: source.anchor, credentialPublicKey: receiver.publicKey.bytes)
      return try V3RecoverySnapshotVerifier(source: source.store).open(
        selection, boundAnchor: source.anchor, receiver: receiver)
    }
    func candidate(_ snapshot: V3RecoveryVerifiedSnapshot, owner: V3EnrollmentDeviceIdentity) throws
      -> V3RecoveryRestoreCandidate
    {
      try V3RecoveryRestoreCandidateBuilder(source: source.store).build(
        restoring: snapshot,
        vaultID: V3RecoveryRestoreJournalTestSupport.vaultID,
        authorityTransitionID: V3RecoveryRestoreJournalTestSupport.transitionID,
        entryIDs: Array(V3RecoveryRestoreJournalTestSupport.ids.prefix(snapshot.entries.count)),
        vaultKey: V3RecoveryRestoreJournalTestSupport.key, ownerIdentity: owner)
    }
    func journal(
      limits: V3ManifestRepositoryLimits = .standard,
      observer: any V3RecoveryRestoreJournalPhaseObserving = Observer(action: { _ in }),
      writeObserver: any V3AtomicStagedObjectWriteObserving =
        V3NoopAtomicStagedObjectWriteObserver()
    ) throws -> V3RecoveryRestoreJournal {
      .init(
        configurationRoot: try .init(opening: configRootURL), reservationOwnership: reservations,
        preparationOwnership: preparations, limits: limits, observer: observer,
        writeObserver: writeObserver)
    }
    func reserve(_ journal: V3RecoveryRestoreJournal, snapshot: V3RecoveryVerifiedSnapshot) throws
      -> V3RecoveryRestoreReservation
    {
      try journal.reserve(
        environment: environment, snapshot: snapshot, operationID: operation,
        vaultID: V3RecoveryRestoreJournalTestSupport.vaultID,
        transitionID: V3RecoveryRestoreJournalTestSupport.transitionID,
        entryIDs: Array(V3RecoveryRestoreJournalTestSupport.ids.prefix(snapshot.entries.count)))
    }
    func reopen(_ locations: V3RecoveryRestoreLocations) throws -> V3RecoveryRestoreEnvironment {
      try .reopen(
        source: .init(opening: source.root),
        destination: .init(opening: environment.destination.rootURL),
        parent: .init(opening: environment.destinationParent.rootURL), configStore: config,
        expected: locations)
    }
    func prepare() throws -> (V3RecoveryRestoreReservation, Owner, V3RecoveryRestoreBundle) {
      let snapshot = try open()
      let journal = try journal()
      let reservation = try reserve(journal, snapshot: snapshot)
      let owner = try Owner()
      let bundle = try journal.stage(
        candidate(snapshot, owner: owner.identity), reservation: reservation,
        environment: environment, vaultKey: V3RecoveryRestoreJournalTestSupport.key,
        expectedOwner: owner.identity)
      return (reservation, owner, bundle)
    }
    func record(_ name: String) -> URL {
      configRootURL.appendingPathComponent("v3-restore-attempts/\(operation)/\(name)")
    }
    func remove() {
      source.remove()
      try? FileManager.default.removeItem(at: base)
    }
  }
  static func files(_ root: URL) throws -> [String: Data] {
    let urls = try #require(
      FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]))
    var result: [String: Data] = [:]
    for case let url as URL in urls {
      if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
        result[url.path] = try Data(contentsOf: url)
      }
    }
    return result
  }
}
