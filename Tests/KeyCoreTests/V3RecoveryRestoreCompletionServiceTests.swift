import Foundation
import Testing

@testable import KeyCore

/// Real source authentication, preparation, publication, trust, ordinary reads,
/// selection and cleanup. Only native I/O and local ownership/trust are replaced.
struct V3RecoveryRestoreCompletionServiceTests {
  private typealias Base = V3RecoveryRestoreJournalTests
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Fixture = V3RecoveryRestoreServiceTests.Fixture
  private enum Stop: Error { case interrupted }
  private static let phases: [V3RecoveryRestoreServicePhase] = [
    .preparationDurable,
    .publication(.preparationConfirmed), .publication(.deviceWrapperVerified),
    .publication(.entryPublished(index: 0)), .publication(.entryPublished(index: 1)),
    .publication(.publishedEntriesVerified), .publication(.manifestPublished),
    .publication(.publishedSnapshotVerified),
    .trust(.publishedSnapshotVerified), .trust(.deviceWrapperVerified), .trust(.manifestCached),
    .trust(.checkpointInstalled), .trust(.ordinaryReopenVerified),
    .selection(.restoreVerified), .selection(.configurationSelected),
    .selection(.selectionConfirmed),
    .finalization(.completionVerified), .finalization(.reservationCleared),
    .finalization(.preparationCleared), .finalization(.completionConfirmed), .completionConfirmed,
  ]

  @Test(arguments: [false, true])
  func initialRestoreCompletesWithOneSourceAgreementAndOrdinaryAccessWithoutToken(empty: Bool)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let source = try Base().files(f.source.root)
    let result = try restore(f)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(f.identities.saved?.calls.value == 5)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(try f.journal().loadForCompletion(sourceVaultID: Core.vaultID) == nil)
    #expect(f.checkpoints.value == result.checkpoint.canonicalBytes)
    #expect(try f.config.load().vaultID == result.checkpoint.vaultID)
    #expect(try Base().files(f.destination).count == (empty ? 1 : 3))
    #expect(try Base().files(f.source.root) == source)
    #expect(!f.authentication.hasResidentKey && f.source.core.owner.unwraps == 0)
    // Discard recovery availability, then construct a new ordinary runtime using
    // config + saved identity + trust/cache only. No restore key is injected.
    f.card.anchor = nil
    f.provider.cancel = true
    let session = V3DeviceWrappedVaultKeySessionStore()
    defer { session.invalidate() }
    let (store, unlock) = try ordinary(f, session: session)
    let runtime = V3DeviceWrappedReadOnlyVaultRuntime(source: store, unlockRuntime: unlock)
    try runtime.unlock()
    #expect(
      try runtime.list(allowStale: false) == (empty ? [] : ["fixture/secret", "fixture/totp"]))
    if !empty {
      #expect(
        try runtime.read(name: "fixture/secret", allowStale: false).plaintext
          == "Software fixture secret e\u{301}\r\n")
    }
    let mutations = V3DeviceWrappedVaultMutationService(
      stateLoader: unlock, objectStore: store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: Base.Ownership(), cache: f.cache)
    try mutations.authorizeMutation()
    try mutations.add(
      name: "after/restore", secret: "ordinary saved value", type: .secret, operationID: .init())
    session.invalidate()
    let fresh = V3DeviceWrappedVaultKeySessionStore()
    defer { fresh.invalidate() }
    let (laterStore, laterUnlock) = try ordinary(f, session: fresh)
    let later = V3DeviceWrappedReadOnlyVaultRuntime(source: laterStore, unlockRuntime: laterUnlock)
    try later.unlock()
    #expect(
      try later.read(name: "after/restore", allowStale: false).plaintext == "ordinary saved value")
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(try Base().files(f.source.root) == source)
  }

  @Test(arguments: phases)
  func everyBoundaryRetainsExactEvidenceForExplicitResumeOrOrdinaryStatus(
    phase: V3RecoveryRestoreServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Stop.interrupted) {
      try restore(f, observer: Observer { if $0 == phase { throw Stop.interrupted } })
    }
    let records = try Base().files(f.configRoot).filter { !$0.key.hasSuffix("config.toml") }
    let destination = try Base().files(f.destination)
    let calls = f.identities.saved?.calls.value
    if ownershipWasCleared(phase) {
      #expect(f.reservations.value == nil && f.preparations.value == nil)
      #expect(throws: V3RecoveryRestoreServiceError.noPendingRestore) { try resume(f) }
      #expect(f.provider.requests == 1 && f.identities.saved?.calls.value == calls)
      let session = V3DeviceWrappedVaultKeySessionStore()
      defer { session.invalidate() }
      let (store, unlock) = try ordinary(f, session: session)
      let runtime = V3DeviceWrappedReadOnlyVaultRuntime(source: store, unlockRuntime: unlock)
      try runtime.unlock()
      #expect(try runtime.list(allowStale: false) == ["fixture/secret", "fixture/totp"])
    } else {
      let owned = try #require(try f.journal().loadForCompletion(sourceVaultID: Core.vaultID))
      let result = try resume(f)
      #expect(result.operationID == owned.reservation.operationID)
      #expect(result.checkpoint == owned.preparation?.intent.destinationCheckpoint)
      #expect(f.provider.requests == 2 && f.identities.creates.value == 1)
      #expect(f.reservations.value == nil && f.preparations.value == nil)
    }
    let finalRecords = try Base().files(f.configRoot).filter { !$0.key.hasSuffix("config.toml") }
    #expect(finalRecords == records)
    let finalDestination = try Base().files(f.destination)
    for (path, bytes) in destination { #expect(finalDestination[path] == bytes) }
    #expect(try f.config.hasConfiguration() && !f.authentication.hasResidentKey)
  }

  @Test(arguments: phases, [false, true])
  func lockOrCancellationStopsDurableProgressAndNeverRetries(
    phase: V3RecoveryRestoreServicePhase, lock: Bool
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: (any Error).self) {
      try restore(f, observer: Observer { if $0 == phase { f.stop(lock: lock) } })
    }
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(!f.authentication.hasResidentKey)
    if ownershipWasCleared(phase) {
      #expect(f.reservations.value == nil && f.preparations.value == nil)
    } else {
      #expect(f.preparations.value != nil)
    }
    if phase == .trust(.manifestCached) { #expect(f.checkpoints.value == nil) }
    if phase == .selection(.restoreVerified) { #expect(try !f.config.hasConfiguration()) }
    if phase == .finalization(.completionVerified) { #expect(f.reservations.value != nil) }
    if phase == .finalization(.reservationCleared) {
      #expect(f.reservations.value == nil && f.preparations.value != nil)
    }
  }

  @Test(arguments: 0..<3, [false, true])
  func lateScopeChangeAtEntryManifestAndConfigRenameStopsPublication(target: Int, lock: Bool) throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let seen = V3RecoveryRegistrationTests.Counter()
    #expect(throws: (any Error).self) {
      try restore(
        f,
        writer: Writer { path in
          let matches =
            target == 0
            ? path.hasPrefix("entries/")
            : (target == 1 ? path.hasPrefix("manifests/") : path == "config.toml")
          if matches {
            seen.increment()
            f.stop(lock: lock)
          }
        })
    }
    #expect(seen.value == 1 && f.provider.requests == 1)
    #expect(f.reservations.value != nil && f.preparations.value != nil)
    #expect(try !f.config.hasConfiguration())
    let files = try Base().files(f.destination)
    #expect(files.count == (target == 0 ? 0 : (target == 1 ? 2 : 3)))
    #expect(!files.keys.contains(where: { $0.hasSuffix(".partial") }))
  }

  @Test func completePreparedBytesWithPreparedPinResumeWithoutReencryptionOrCredentialCreation()
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let journal = try f.journal(
      observer: JournalObserver { phase in
        if phase == .preparationWritten { throw Stop.interrupted }
      })
    #expect(throws: Stop.interrupted) { try f.prepare(journal: journal) }
    let before = try Base().files(f.configRoot)
    let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
    #expect(pending.preparationOwnership?.phase == .prepared)
    let result = try resume(f)
    #expect(result.operationID == pending.reservation.operationID)
    #expect(f.provider.requests == 2 && f.identities.creates.value == 1)
    let after = try Base().files(f.configRoot)
    for (path, bytes) in before { #expect(after[path] == bytes) }
    #expect(f.reservations.value == nil && f.preparations.value == nil)
  }

  @Test(arguments: 0..<6)
  func resumePublicPreflightRejectsChangedOrIncompleteStateBeforeAgreement(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    if variant == 0 {
      #expect(throws: Stop.interrupted) {
        try f.prepare(
          observer: Observer { if $0 == .reservationDurable { throw Stop.interrupted } })
      }
    } else {
      _ = try f.prepare()
    }
    let calls = f.identities.saved?.calls.value
    switch variant {
    case 0: break
    case 1: try Data("changed".utf8).write(to: f.record("preparation.json"))
    case 2:
      let edit = try f.source.build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
      _ = try f.source.publisher().publish(edit, vaultKey: Core.nextKey)
    case 3:
      try FileManager.default.moveItem(
        at: f.destination, to: f.base.appendingPathComponent("preserved-destination"))
      try FileManager.default.createDirectory(at: f.destination, withIntermediateDirectories: false)
    case 4: try Data("other config".utf8).write(to: f.config.initializationConfigFileURL)
    default:
      f.reservations.value = nil
      f.preparations.value = nil
    }
    #expect(throws: (any Error).self) { try resume(f) }
    #expect(f.provider.requests == 1 && f.identities.saved?.calls.value == calls)
    #expect(f.identities.creates.value == (variant == 0 ? 0 : 1))
  }

  @Test(arguments: [false, true])
  func selectedResumeRequiresExistingTrustAndDoesNotInsertOrRepairIt(missingCheckpoint: Bool) throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Stop.interrupted) {
      try restore(
        f,
        observer: Observer {
          if $0 == .selection(.configurationSelected) { throw Stop.interrupted }
        })
    }
    let cp = f.checkpoints.value
    let bundle = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID)?.preparation)
    if missingCheckpoint {
      f.checkpoints.value = nil
    } else {
      let checkpoint = bundle.intent.destinationCheckpoint
      let file = f.base.appendingPathComponent("cache/\(checkpoint.vaultID).json")
      try Data("bad cache".utf8).write(to: file)
    }
    let calls = f.identities.saved?.calls.value
    #expect(throws: (any Error).self) { try resume(f) }
    #expect(f.provider.requests == 1 && f.identities.saved?.calls.value == calls)
    #expect(f.checkpoints.value == (missingCheckpoint ? nil : cp))
    #expect(f.reservations.value != nil && f.preparations.value != nil)
  }

  @Test func selectedResumeRefusesLaterOrdinaryEditsRatherThanSilentlyCleaningUp() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Stop.interrupted) {
      try restore(
        f,
        observer: Observer {
          if $0 == .selection(.configurationSelected) { throw Stop.interrupted }
        })
    }
    let session = V3DeviceWrappedVaultKeySessionStore()
    defer { session.invalidate() }
    let (store, unlock) = try ordinary(f, session: session)
    let mutations = V3DeviceWrappedVaultMutationService(
      stateLoader: unlock, objectStore: store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: Base.Ownership(), cache: f.cache)
    try mutations.add(name: "later", secret: "not genesis", type: .secret, operationID: .init())
    let cp = f.checkpoints.value
    let calls = f.identities.saved?.calls.value
    #expect(throws: V3RecoveryRestoreTrustError.conflictingCheckpoint) { try resume(f) }
    #expect(f.checkpoints.value == cp && f.provider.requests == 1)
    #expect(f.identities.saved?.calls.value == calls)
    #expect(f.reservations.value != nil && f.preparations.value != nil)
  }

  @Test(arguments: [false, true])
  func failedHardwareOrMacApprovalRetainsExactPreparationWithoutRetry(hardware: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    _ = try f.prepare()
    let files = try Base().files(f.configRoot)
    let pins = [f.reservations.value, f.preparations.value]
    if hardware { f.provider.cancel = true } else { f.identities.failure = 5 }
    #expect(throws: (any Error).self) { try resume(f) }
    #expect(f.provider.requests == 2 && f.identities.creates.value == 1)
    #expect(try Base().files(f.configRoot) == files)
    #expect([f.reservations.value, f.preparations.value] == pins)
    #expect(try !f.config.hasConfiguration())
  }

  private func ownershipWasCleared(_ phase: V3RecoveryRestoreServicePhase) -> Bool {
    phase == .finalization(.preparationCleared) || phase == .finalization(.completionConfirmed)
      || phase == .completionConfirmed
  }
  private struct Observer: V3RecoveryRestoreServicePhaseObserving {
    let action: @Sendable (V3RecoveryRestoreServicePhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreServicePhase) throws { try action(phase) }
  }
  private struct JournalObserver: V3RecoveryRestoreJournalPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreJournalPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreJournalPhase) throws { try action(phase) }
  }
  private struct Writer: V3AtomicStagedObjectWriteObserving {
    let action: @Sendable (String) throws -> Void
    func didReach(_ phase: V3AtomicStagedObjectWritePhase) throws {
      if case .temporaryFileSynchronized(let path) = phase { try action(path) }
    }
  }
  private func service(
    _ f: Fixture, observer: any V3RecoveryRestoreServicePhaseObserving,
    writer: any V3AtomicStagedObjectWriteObserving
  ) throws -> V3RecoveryRestoreService {
    try .init(
      configStore: f.config, journal: f.journal(), identities: f.identities,
      checkpoints: f.checkpoints, cache: f.cache, mutationOwner: f.owner, reader: f.reader,
      agreement: f.agreement, authentication: f.authentication, observer: observer,
      writeObserver: writer)
  }
  @available(macOS 26.0, *)
  private func restore(
    _ f: Fixture, observer: any V3RecoveryRestoreServicePhaseObserving = Observer(action: { _ in }),
    writer: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) throws -> V3RecoveryRestoreReport {
    try service(f, observer: observer, writer: writer).restore(
      source: f.sourceHandle, parent: f.parentHandle, name: "restored", deviceName: "New Mac",
      observation: f.reader.read(try #require(f.reader.candidates().first)),
      cancellation: f.cancellation,
      deadline: .now() + .seconds(120))
  }
  @available(macOS 26.0, *)
  private func resume(_ f: Fixture) throws -> V3RecoveryRestoreReport {
    try service(
      f, observer: Observer(action: { _ in }), writer: V3NoopAtomicStagedObjectWriteObserver()
    ).resume(
      source: .init(opening: f.source.root), destination: .init(opening: f.destination),
      parent: .init(opening: f.parent),
      observation: f.reader.read(try #require(f.reader.candidates().first)),
      deadline: .now() + .seconds(120))
  }
  private func ordinary(_ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore) throws
    -> (V3FilesystemTransactionArtifactStore, V3DeviceWrappedVaultUnlockRuntime)
  {
    let config = try f.config.load()
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try .init(opening: config.vaultDirectoryURL))
    return (
      store,
      .init(
        vaultID: try #require(config.vaultID), checkpointStore: f.checkpoints,
        source: store, cache: f.cache, identityLoader: f.identities, session: session)
    )
  }
}
