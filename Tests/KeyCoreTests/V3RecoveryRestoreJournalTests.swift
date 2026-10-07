import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Real contained files and crypto; memory CAS only at the Keychain boundary.
/// No native credential, real configuration, token or destination publication.
struct V3RecoveryRestoreJournalTests {
  typealias Core = V3RecoveryRegistrationTests
  typealias Source = V3RecoveryContentMutationPublisherTests.Fixture
  typealias Ownership = V3RecoveryContentMutationPublisherTests.Ownership
  static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c5000"
  private static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c5001"
  private static let ids = [
    "018f4d38-7d5a-7b20-b0f1-97d6e96c5002", "018f4d38-7d5a-7b20-b0f1-97d6e96c5003",
  ]
  static let key = Data(repeating: 0xB8, count: 32)
  private enum Stop: Error { case interrupted }

  @Test(arguments: [false, true])
  func reservedEncryptedPreparationSurvivesFreshReaderAndKeyOpening(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let before = try files(f.source.root)
    let snapshot = try f.open()
    let journal = try f.journal()
    let reservation = try f.reserve(journal, snapshot: snapshot)
    #expect(
      try V3RecoveryRestoreReservation(canonicalBytes: reservation.canonicalBytes) == reservation)
    #expect(f.preparations.value == nil && f.reservations.value != nil)
    let owner = try Owner()  // Only after successful durable reservation.
    let candidate = try f.candidate(snapshot, owner: owner.identity)
    let bundle = try journal.stage(
      candidate, reservation: reservation, environment: f.environment,
      vaultKey: Self.key, expectedOwner: owner.identity)
    #expect(try V3RecoveryRestoreBundle(canonicalBytes: bundle.canonicalBytes) == bundle)
    let saved = try files(f.configRootURL)
    let context = try V3VaultKeyHPKEContext(
      vaultID: Self.vaultID, keyID: bundle.manifest.body.keyID,
      authorityTransitionID: Self.transitionID, recipientDeviceID: owner.identity.deviceID)
    let reopenedKey = try V3VaultKeyHPKE().unwrap(
      bundle.manifest.body.wrappedKeys[0].wrappedKey,
      recipientPrivateKey: owner.wrapping, context: context)
    let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
    #expect(
      pending.reservationOwnership.phase == .recoverable
        && pending.preparationOwnership?.phase == .recoverable)
    let confirmed = try f.journal().confirmPreparation(
      sourceVaultID: Core.vaultID,
      snapshot: f.open(), environment: f.reopen(reservation.locations), vaultKey: reopenedKey,
      expectedOwner: owner.identity)
    #expect(confirmed.canonicalBytes == bundle.canonicalBytes)
    #expect(try files(f.configRootURL) == saved)
    #expect(try files(f.source.root) == before)
    let text = try #require(String(data: bundle.canonicalBytes, encoding: .utf8))
    for entry in snapshot.entries { #expect(!text.contains(entry.plaintext)) }
    #expect(!text.contains(Base64URL.encode(Self.key)))
    #expect(
      try FileManager.default.contentsOfDirectory(atPath: f.environment.destination.rootURL.path)
        .isEmpty)
    #expect(try !f.config.hasConfiguration())
    #expect(f.calls.value == 2 && f.source.core.owner.unwraps == 0)
  }

  @Test(arguments: [
    V3RecoveryRestoreJournalPhase.reservationPinned, .reservationWritten,
    .reservationDurable, .preparationPinned, .preparationWritten, .preparationVerified,
    .preparationDurable,
  ])
  func interruptionRetainsOwnershipAndOnlyCompletePreparationCanBeConfirmed(
    phase: V3RecoveryRestoreJournalPhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let journal = try f.journal(observer: Observer { if $0 == phase { throw Stop.interrupted } })
    if [.reservationPinned, .reservationWritten, .reservationDurable].contains(phase) {
      #expect(throws: Stop.interrupted) { try f.reserve(journal, snapshot: snapshot) }
      #expect(f.reservations.value != nil && f.preparations.value == nil)
      #expect(throws: (any Error).self) { try f.reserve(f.journal(), snapshot: snapshot) }
      if phase == .reservationPinned {
        #expect(throws: V3RecoveryRestoreJournalError.recordUnavailable) {
          try f.journal().loadPending(sourceVaultID: Core.vaultID)
        }
      } else {
        let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
        #expect(pending.preparation == nil)
        #expect(
          pending.reservationOwnership.phase
            == (phase == .reservationWritten ? .prepared : .recoverable))
      }
    } else {
      let reservation = try f.reserve(journal, snapshot: snapshot)
      let owner = try Owner()
      let candidate = try f.candidate(snapshot, owner: owner.identity)
      #expect(throws: Stop.interrupted) {
        try journal.stage(
          candidate, reservation: reservation, environment: f.environment,
          vaultKey: Self.key, expectedOwner: owner.identity)
      }
      let saved = try files(f.configRootURL)
      #expect(f.reservations.value != nil && f.preparations.value != nil)
      #expect(throws: (any Error).self) {
        try f.journal().stage(
          candidate, reservation: reservation, environment: f.environment,
          vaultKey: Self.key, expectedOwner: owner.identity)
      }
      if phase == .preparationPinned {
        #expect(throws: V3RecoveryRestoreJournalError.recordUnavailable) {
          try f.journal().loadPending(sourceVaultID: Core.vaultID)
        }
      } else {
        let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
        let exact = try #require(pending.preparation).canonicalBytes
        let confirmed = try f.journal().confirmPreparation(
          sourceVaultID: Core.vaultID,
          snapshot: f.open(), environment: f.reopen(reservation.locations), vaultKey: Self.key,
          expectedOwner: owner.identity)
        #expect(confirmed.canonicalBytes == exact)
        #expect(try files(f.configRootURL) == saved)
      }
    }
    #expect(try !f.config.hasConfiguration())
    #expect(
      try FileManager.default.contentsOfDirectory(atPath: f.environment.destination.rootURL.path)
        .isEmpty)
  }

  @Test(arguments: [false, true])
  func atomicWriterInterruptionNeverRegeneratesMissingAuthoritativeBytes(preparation: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let journal = try f.journal(
      writeObserver: WriteObserver { path in
        if path.hasSuffix(preparation ? "preparation.json" : "reservation.json") {
          throw Stop.interrupted
        }
      })
    if preparation {
      let reservation = try f.reserve(journal, snapshot: snapshot)
      let owner = try Owner()
      #expect(throws: Stop.interrupted) {
        try journal.stage(
          f.candidate(snapshot, owner: owner.identity), reservation: reservation,
          environment: f.environment, vaultKey: Self.key, expectedOwner: owner.identity)
      }
    } else {
      #expect(throws: Stop.interrupted) { try f.reserve(journal, snapshot: snapshot) }
    }
    #expect(throws: V3RecoveryRestoreJournalError.recordUnavailable) {
      try f.journal().loadPending(sourceVaultID: Core.vaultID)
    }
    #expect(f.reservations.value != nil)
  }

  @Test(arguments: 0..<6)
  func changedUnavailableOrUncontainedFilesNeverBecomeOwnedPreparation(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    _ = try f.prepare()
    let pins = [f.reservations.value, f.preparations.value]
    let url = f.record(variant == 0 ? "reservation.json" : "preparation.json")
    switch variant {
    case 0, 1: try Data("changed".utf8).write(to: url)
    case 2: try FileManager.default.removeItem(at: url)
    case 3:
      try FileManager.default.removeItem(at: url)
      try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    case 4:
      let external = f.base.appendingPathComponent("external.json")
      try Data(contentsOf: url).write(to: external)
      try FileManager.default.removeItem(at: url)
      try FileManager.default.createSymbolicLink(at: url, withDestinationURL: external)
    default:
      try Data(repeating: 0, count: V3RecoveryRestoreBundle.maximumBytes(limits: smallLimits()) + 1)
        .write(to: url)
    }
    let journal = try f.journal(limits: variant == 5 ? smallLimits() : .standard)
    #expect(throws: (any Error).self) { try journal.loadPending(sourceVaultID: Core.vaultID) }
    #expect([f.reservations.value, f.preparations.value] == pins)
  }

  @Test func filesWithoutLocalPinsAreInertAndRestoreNamespacesAreDistinct() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    _ = try f.prepare()
    let journal = V3RecoveryRestoreJournal(
      configurationRoot: try .init(opening: f.configRootURL),
      reservationOwnership: Ownership(), preparationOwnership: Ownership())
    #expect(try journal.loadPending(sourceVaultID: Core.vaultID) == nil)
    let domains: [V3RecoveryOwnershipNamespace] = [
      .transaction, .registration, .adoption, .restoreReservation, .restorePreparation,
    ]
    #expect(Set(domains.map(\.rawValue)).count == domains.count)
    #expect(Set(domains.map(\.label)).count == domains.count)
  }

  @Test(arguments: 0..<5)
  func confirmationRejectsIncorrectKeyOwnerSourceOrConfiguration(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, owner, _) = try f.prepare()
    let snapshot = try f.open()
    let savedReservation = try Data(contentsOf: f.record("reservation.json"))
    let savedPreparation = try Data(contentsOf: f.record("preparation.json"))
    let pins = [f.reservations.value, f.preparations.value]
    if variant == 2 {
      let edit = try f.source.build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
      _ = try f.source.publisher().publish(edit, vaultKey: Core.nextKey)
    }
    if variant == 3 { try Data("unrelated".utf8).write(to: f.config.initializationConfigFileURL) }
    if variant == 4 {
      try FileManager.default.moveItem(
        at: f.environment.destination.rootURL,
        to: f.environment.destination.rootURL.appendingPathExtension("preserved"))
      try FileManager.default.createDirectory(
        at: f.environment.destination.rootURL, withIntermediateDirectories: false)
    }
    #expect(throws: (any Error).self) {
      try f.journal().confirmPreparation(
        sourceVaultID: Core.vaultID, snapshot: snapshot,
        environment: f.environment,
        vaultKey: variant == 0 ? Data(repeating: 0, count: 32) : Self.key,
        expectedOwner: variant == 1 ? Owner().identity : owner.identity)
    }
    #expect([f.reservations.value, f.preparations.value] == pins)
    #expect(
      try Data(contentsOf: f.record("reservation.json")) == savedReservation
    )
    #expect(
      try Data(contentsOf: f.record("preparation.json")) == savedPreparation
    )
  }

  @Test(arguments: 0..<4)
  func ownershipAndRecordChangesAcrossFinalValidationStopDurableReadiness(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let reservation = try f.reserve(f.journal(), snapshot: snapshot)
    let owner = try Owner()
    let phase: V3RecoveryRestoreJournalPhase =
      variant == 3 ? .preparationDurable : .preparationVerified
    let reservations = f.reservations
    let preparations = f.preparations
    let record = f.record(variant == 2 ? "reservation.json" : "preparation.json")
    let observer = Observer {
      guard $0 == phase else { return }
      if variant == 0 { reservations.value = Data([0]) }
      if variant == 1 { preparations.value = Data([0]) }
      if variant >= 2 { try Data("changed after validation".utf8).write(to: record) }
    }
    #expect(throws: (any Error).self) {
      try f.journal(observer: observer).stage(
        f.candidate(snapshot, owner: owner.identity),
        reservation: reservation, environment: f.environment, vaultKey: Self.key,
        expectedOwner: owner.identity)
    }
    #expect(try !f.config.hasConfiguration())
    #expect(
      try FileManager.default.contentsOfDirectory(atPath: f.environment.destination.rootURL.path)
        .isEmpty)
  }

  @Test(arguments: 0..<4)
  func invalidReservedIdentifiersLeaveNoOwnershipOrRecords(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    #expect(throws: (any Error).self) {
      try f.journal().reserve(
        environment: f.environment, snapshot: snapshot, operationID: f.operation,
        vaultID: variant == 0 ? Core.vaultID : Self.vaultID,
        transitionID: variant == 1
          ? snapshot.selection.head.body.fields.authorityTransitionID : Self.transitionID,
        entryIDs: variant == 2
          ? [Self.ids[0], Self.ids[0]] : (variant == 3 ? ["invalid"] : Self.ids))
    }
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(try files(f.configRootURL).isEmpty)
  }

  @Test func usedAndResumeDirectoriesCannotReserveAgain() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let reservation = try f.reserve(f.journal(), snapshot: snapshot)
    let unused = V3RecoveryRestoreJournal(
      configurationRoot: try .init(opening: f.configRootURL),
      reservationOwnership: Ownership(), preparationOwnership: Ownership())
    for environment in [f.environment, try f.reopen(reservation.locations)] {
      #expect(throws: (any Error).self) {
        try unused.reserve(
          environment: environment, snapshot: snapshot, operationID: .init(),
          vaultID: Self.vaultID, transitionID: Self.transitionID, entryIDs: Self.ids)
      }
    }
  }

  @Test(arguments: 0..<3)
  func validCandidateCannotSubstituteReservedIdentifiers(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let reservation = try f.reserve(f.journal(), snapshot: snapshot)
    let saved = try files(f.configRootURL)
    let pin = f.reservations.value
    let owner = try Owner()
    let candidate = try V3RecoveryRestoreCandidateBuilder(source: f.source.store).build(
      restoring: snapshot, vaultID: variant == 0 ? UUID().uuidString.lowercased() : Self.vaultID,
      authorityTransitionID: variant == 1 ? UUID().uuidString.lowercased() : Self.transitionID,
      entryIDs: variant == 2 ? Array(Self.ids.reversed()) : Self.ids,
      vaultKey: Self.key, ownerIdentity: owner.identity)
    #expect(throws: V3RecoveryRestoreError.invalidIntent) {
      try f.journal().stage(
        candidate, reservation: reservation, environment: f.environment,
        vaultKey: Self.key, expectedOwner: owner.identity)
    }
    #expect(f.reservations.value == pin && f.preparations.value == nil)
    #expect(try files(f.configRootURL) == saved)
  }

  @Test func reservationBudgetRefusalPrecedesPinsAndDirectoryConsumption() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 4, maximumHistoryDepth: 4, maximumReferencedEntryObjects: 1,
      maximumManifestBytes: 1_000_000, maximumEntryBytes: 1_000_000,
      maximumTotalManifestBytes: 4_000_000, maximumTotalEntryBytes: 2_000_000)
    #expect(throws: V3RecoveryRestoreError.resourceLimit) {
      try f.reserve(f.journal(limits: limits), snapshot: snapshot)
    }
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(try files(f.configRootURL).isEmpty)
    // A refused oversized plan never consumes the single-use destination gate.
    _ = try f.reserve(f.journal(), snapshot: snapshot)
  }

  @Test(arguments: 0..<8)
  func bundleCodecChecksPublicBindingsAndBudgetsButDoesNotClaimAuthentication(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let (_, _, bundle) = try f.prepare()
    let json = try CanonicalJSON.parse(bundle.canonicalBytes)
    var root = Dictionary(uniqueKeysWithValues: try #require(json.objectValue))
    if variant == 0 { root["extra"] = .bool(true) }
    if variant == 1 { root["version"] = .integer(2) }
    if variant == 2 { root["entries"] = .array([]) }
    if variant == 3 {
      let entries = try #require(root["entries"]?.arrayValue)
      root["entries"] = .array([entries[0], entries[0]])
    }
    if variant == 4 {
      var intent = Dictionary(uniqueKeysWithValues: try #require(root["intent"]?.objectValue))
      intent["authenticationTag"] = .string(Base64URL.encode(Data(repeating: 0, count: 32)))
      root["intent"] = .object(intent.map { ($0.key, $0.value) })
    }
    let bytes = CanonicalJSON.encode(.object(root.map { ($0.key, $0.value) }))
    if variant == 4 {
      let parsed = try V3RecoveryRestoreBundle(canonicalBytes: bytes)
      #expect(throws: V3RecoveryRestoreError.authenticationFailed) {
        try parsed.intent.authenticate(destinationVaultKey: Self.key)
      }
    } else {
      let limits = V3ManifestRepositoryLimits(
        maximumManifestObjects: 4, maximumHistoryDepth: 4,
        maximumReferencedEntryObjects: variant == 7 ? 1 : 2,
        maximumManifestBytes: variant == 5 ? 1 : 1_000_000,
        maximumEntryBytes: variant == 6 ? 1 : 1_000_000,
        maximumTotalManifestBytes: 4_000_000, maximumTotalEntryBytes: 2_000_000)
      #expect(throws: (any Error).self) {
        try V3RecoveryRestoreBundle(canonicalBytes: bytes, limits: limits)
      }
    }
  }

  @Test func laterSourceAcrossPreparationValidationDoesNotAdvanceItsPin() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let snapshot = try f.open()
    let reservation = try f.reserve(f.journal(), snapshot: snapshot)
    let owner = try Owner()
    let source = f.source
    let observer = Observer {
      guard $0 == .preparationVerified else { return }
      let edit = try source.build(.edit(name: "fixture/secret", type: .secret, plaintext: "later"))
      _ = try source.publisher().publish(edit, vaultKey: Core.nextKey)
    }
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try f.journal(observer: observer).stage(
        f.candidate(snapshot, owner: owner.identity),
        reservation: reservation, environment: f.environment, vaultKey: Self.key,
        expectedOwner: owner.identity)
    }
    let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
    #expect(pending.preparationOwnership?.phase == .prepared)
  }

  private func smallLimits() -> V3ManifestRepositoryLimits {
    .init(
      maximumManifestObjects: 4, maximumHistoryDepth: 4, maximumReferencedEntryObjects: 2,
      maximumManifestBytes: 1, maximumEntryBytes: 1, maximumTotalManifestBytes: 4,
      maximumTotalEntryBytes: 2)
  }
  private struct Observer: V3RecoveryRestoreJournalPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreJournalPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreJournalPhase) throws { try action(phase) }
  }
  private struct WriteObserver: V3AtomicStagedObjectWriteObserving {
    let action: @Sendable (String) throws -> Void
    func didReach(_ phase: V3AtomicStagedObjectWritePhase) throws {
      if case .temporaryFileSynchronized(let path) = phase { try action(path) }
    }
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
        vaultID: V3RecoveryRestoreJournalTests.vaultID,
        authorityTransitionID: V3RecoveryRestoreJournalTests.transitionID,
        entryIDs: Array(V3RecoveryRestoreJournalTests.ids.prefix(snapshot.entries.count)),
        vaultKey: V3RecoveryRestoreJournalTests.key, ownerIdentity: owner)
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
        vaultID: V3RecoveryRestoreJournalTests.vaultID,
        transitionID: V3RecoveryRestoreJournalTests.transitionID,
        entryIDs: Array(V3RecoveryRestoreJournalTests.ids.prefix(snapshot.entries.count)))
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
        environment: environment, vaultKey: V3RecoveryRestoreJournalTests.key,
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
  func files(_ root: URL) throws -> [String: Data] {
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
