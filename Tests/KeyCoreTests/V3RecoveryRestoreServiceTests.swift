import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Actual native-binding adapters, crypto and contained preparation files.
/// Software card/provider/Mac keys and memory ownership replace native I/O only.
struct V3RecoveryRestoreServiceTests {
  private typealias Fixture = V3RecoveryRestoreServiceTestSupport.Fixture
  private typealias Observer = V3RecoveryRestoreServiceTestSupport.Observer
  private typealias JournalObserver = V3RecoveryRestoreServiceTestSupport.JournalObserver
  private typealias Writer = V3RecoveryRestoreServiceTestSupport.Writer
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Native = PIVRecoveryTestSupport
  typealias Base = V3RecoveryRestoreJournalTestSupport
  private typealias Stop = V3RecoveryRestoreServiceTestSupport.Stop
  private static let phases: [V3RecoveryRestoreServicePhase] = [
    .sourceAuthenticated, .reservationDurable, .identitySaved, .savedWrapperVerified,
    .preparationDurable,
  ]

  @Test(arguments: [false, true])
  func authenticatesOnceThenPreparesOnlyAfterDurableReservationAndSavedCredentialProof(empty: Bool)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let before = try Base.files(f.source.root)
    f.identities.onCreate = {
      let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
      #expect(pending.reservationOwnership.phase == .recoverable)
      #expect(pending.preparation == nil && f.preparations.value == nil)
      #expect(!f.card.inSession)
      #expect(throws: PIVRecoveryTokenError.operationInProgress) { try f.reader.candidates() }
    }
    let result = try f.prepare()
    let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
    let bundle = try #require(pending.preparation)
    let saved = try #require(f.identities.saved)
    #expect(
      result.operationID == f.operation && result.checkpoint == bundle.intent.destinationCheckpoint)
    #expect(result.entryCount == (empty ? 0 : 2) && result.destinationPath == f.destination.path)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(f.identities.loads.value == 1 && saved.calls.value == 1)
    #expect(!f.authentication.hasResidentKey && f.source.core.owner.unwraps == 0)
    #expect(pending.preparationOwnership?.phase == .recoverable)
    #expect(try FileManager.default.contentsOfDirectory(atPath: f.destination.path).isEmpty)
    #expect(try !f.config.hasConfiguration())
    #expect(try Base.files(f.source.root) == before)
    #expect(bundle.manifest.body.devices.map(\.identity) == [saved.publicIdentity])
    let text = String(decoding: bundle.canonicalBytes, as: UTF8.self)
    #expect(!text.contains("Software fixture secret") && !text.contains("JBSWY3DPEHPK3PXP"))
    let files = try Base.files(f.configRoot)
    #expect(files.count == 2)
    #expect(throws: V3RecoveryRestoreJournalError.attemptPending) { try f.prepare(name: "another") }
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(try Base.files(f.configRoot) == files)
    #expect(
      !FileManager.default.fileExists(atPath: f.parent.appendingPathComponent("another").path))
  }

  @Test(arguments: phases, [false, true])
  func lockOrCancellationAtEveryServiceBoundaryStopsWithoutRetry(
    phase: V3RecoveryRestoreServicePhase, lock: Bool
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: (any Error).self) {
      try f.prepare(
        observer: Observer { reached in
          if reached == phase { f.stop(lock: lock) }
        })
    }
    #expect(f.provider.requests == 1 && !f.authentication.hasResidentKey)
    #expect(try !f.config.hasConfiguration())
    if phase == .sourceAuthenticated {
      #expect(!FileManager.default.fileExists(atPath: f.destination.path))
      #expect(f.reservations.value == nil && f.identities.creates.value == 0)
    } else {
      #expect(f.reservations.value != nil)
      #expect(f.identities.creates.value == (phase == .reservationDurable ? 0 : 1))
      let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
      #expect((pending.preparation != nil) == (phase == .preparationDurable))
      #expect(try FileManager.default.contentsOfDirectory(atPath: f.destination.path).isEmpty)
    }
  }

  @Test(arguments: [false, true])
  func lockOrCancellationWhileNativeAgreementIsReturningCannotCreateDestination(lock: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.provider.onAgree = { f.stop(lock: lock) }
    #expect(throws: (any Error).self) { try f.prepare() }
    #expect(f.provider.requests == 1 && f.identities.creates.value == 0)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
  }

  @Test func cancelledProviderNeverRetriesOrCreatesAnyRestoreState() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.provider.cancel = true
    #expect(throws: PIVRecoveryAgreementError.cancelled) { try f.prepare() }
    #expect(f.provider.requests == 1 && f.identities.creates.value == 0)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
  }

  @Test(arguments: 0 ..< 6)
  func publicPreflightRefusesInvalidScopeBeforeAgreement(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    switch variant {
    case 0: f.card.anchor = nil
    case 1: f.card.anchor = Data("unknown".utf8)
    case 2: f.card.pinPolicy = 2
    case 3: f.cancellation.cancel()
    case 4: try Data("unrelated config".utf8).write(to: f.config.initializationConfigFileURL)
    default:
      try FileManager.default.moveItem(
        at: f.source.root, to: f.source.root.appendingPathExtension("old"))
      try FileManager.default.createDirectory(at: f.source.root, withIntermediateDirectories: false)
    }
    #expect(throws: (any Error).self) { try f.prepare() }
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
    if variant == 5 {
      try FileManager.default.removeItem(at: f.source.root.appendingPathExtension("old"))
    }
  }

  @Test func expiredDeadlineNeverRequestsAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: PIVRecoveryAgreementError.deadlineExceeded) { try f.prepare(deadline: .now()) }
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  @Test(arguments: [false, true])
  func foreignOrChangedNativeObservationIsNotAcceptedAsApproval(foreign: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let reader =
      foreign
      ? PIVRecoveryTokenReader(
        inventory: Native.Inventory(card: f.card), gate: PIVTokenOperationGate())
      : f.reader
    let observation = try reader.read(try #require(reader.candidates().first))
    if !foreign { f.card.anchor = nil }
    #expect(throws: foreign ? PIVRecoveryTokenError.invalidSelection : .tokenChanged) {
      try f.prepare(observation: observation)
    }
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
  }

  @Test(arguments: phases)
  func interruptedServiceRetainsEvidenceAndNeverTreatsItAsPermissionToPrepareAgain(
    phase: V3RecoveryRestoreServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Stop.interrupted) {
      try f.prepare(observer: Observer { if $0 == phase { throw Stop.interrupted } })
    }
    #expect(f.provider.requests == 1 && !f.authentication.hasResidentKey)
    if phase != .sourceAuthenticated {
      let pins = [f.reservations.value, f.preparations.value]
      let files = try Base.files(f.configRoot)
      let creates = f.identities.creates.value
      #expect(throws: V3RecoveryRestoreJournalError.attemptPending) {
        try f.prepare(name: "replacement")
      }
      #expect(f.provider.requests == 1 && f.identities.creates.value == creates)
      #expect([f.reservations.value, f.preparations.value] == pins)
      #expect(try Base.files(f.configRoot) == files)
      #expect(
        !FileManager.default.fileExists(atPath: f.parent.appendingPathComponent("replacement").path)
      )
    }
    #expect(try !f.config.hasConfiguration())
  }

  @Test(arguments: 0 ..< 6)
  func uncertainCredentialCreationOrReloadCannotStageOrRegenerate(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.identities.failure = variant
    #expect(throws: (any Error).self) { try f.prepare() }
    let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
    #expect(pending.reservationOwnership.phase == .recoverable && pending.preparation == nil)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    let files = try Base.files(f.configRoot)
    #expect(files.count == 1 && f.preparations.value == nil)
    f.identities.failure = nil
    #expect(throws: V3RecoveryRestoreJournalError.attemptPending) {
      try f.prepare(name: "replacement")
    }
    #expect(f.identities.creates.value == 1 && f.provider.requests == 1)
    #expect(try Base.files(f.configRoot) == files)
    #expect(
      !FileManager.default.fileExists(atPath: f.parent.appendingPathComponent("replacement").path))
  }

  @Test(arguments: [false, true], [false, true])
  func lateLockOrCancellationAtRecordRenameLeavesOnlyOwnedIncompleteState(
    preparation: Bool, lock: Bool
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let journal = try f.journal(
      writer: Writer { path in
        if path.hasSuffix(preparation ? "preparation.json" : "reservation.json") {
          f.stop(lock: lock)
        }
      })
    #expect(throws: (any Error).self) { try f.prepare(journal: journal) }
    #expect(f.provider.requests == 1 && f.reservations.value != nil)
    #expect(f.identities.creates.value == (preparation ? 1 : 0))
    #expect((f.preparations.value != nil) == preparation)
    let record = f.record(preparation ? "preparation.json" : "reservation.json")
    #expect(!FileManager.default.fileExists(atPath: record.path))
    #expect(throws: V3RecoveryRestoreJournalError.recordUnavailable) {
      try f.journal().loadPending(sourceVaultID: Core.vaultID)
    }
    let files = try Base.files(f.configRoot)
    #expect(files.count == (preparation ? 1 : 0))
    #expect(try !f.config.hasConfiguration())
  }

  @Test(arguments: [false, true])
  func lockBeforeOwnershipAdvanceLeavesExactPreparedPin(preparation: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let journal = try f.journal(
      observer: JournalObserver { phase in
        if phase == (preparation ? .preparationVerified : .reservationWritten) {
          f.stop(lock: true)
        }
      })
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try f.prepare(journal: journal)
    }
    let pending = try #require(try f.journal().loadPending(sourceVaultID: Core.vaultID))
    #expect(
      (preparation ? pending.preparationOwnership?.phase : pending.reservationOwnership.phase)
        == .prepared)
    #expect(f.provider.requests == 1)
  }

  @Test(arguments: [false, true])
  func sourceOrTokenChangeDuringMacCredentialProofCannotStage(token: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.identities.onUnwrap = {
      if token {
        f.card.anchor = nil
      } else {
        let edit = try f.source.build(
          .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
        _ = try f.source.publisher().publish(edit, vaultKey: Core.nextKey)
      }
    }
    #expect(throws: (any Error).self) { try f.prepare() }
    #expect(f.provider.requests == 1 && f.preparations.value == nil && f.reservations.value != nil)
    #expect(f.identities.saved?.calls.value == 1 && !f.authentication.hasResidentKey)
    #expect(try !f.config.hasConfiguration())
  }

  @Test func mismatchedJournalRootIsRefusedBeforeHardwareAndDirectoryCreation() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let wrong = f.base.appendingPathComponent("wrong-config")
    try FileManager.default.createDirectory(at: wrong, withIntermediateDirectories: false)
    let journal = V3RecoveryRestoreJournal(
      configurationRoot: try .init(opening: wrong), reservationOwnership: f.reservations,
      preparationOwnership: f.preparations)
    #expect(throws: V3RecoveryRestoreError.locationChanged) { try f.prepare(journal: journal) }
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
  }

  @Test func oneSharedOwnerSerializesTwoCompetingRestoreRequests() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let firstDone = DispatchSemaphore(value: 0)
    let secondDone = DispatchSemaphore(value: 0)
    let observation = try f.reader.read(try #require(f.reader.candidates().first))
    defer { release.signal() }
    DispatchQueue.global().async {
      do {
        _ = try f.prepare(
          observation: observation,
          observer: Observer { phase in
            if phase == .reservationDurable {
              entered.signal()
              #expect(release.wait(timeout: .now() + .seconds(10)) == .success)
            }
          })
      } catch { Issue.record("First restore failed: \(error)") }
      firstDone.signal()
    }
    #expect(entered.wait(timeout: .now() + .seconds(5)) == .success)
    DispatchQueue.global().async {
      #expect(throws: V3RecoveryRestoreJournalError.attemptPending) {
        try f.prepare(name: "second", observation: observation)
      }
      secondDone.signal()
    }
    #expect(secondDone.wait(timeout: .now() + .milliseconds(50)) == .timedOut)
    release.signal()
    #expect(firstDone.wait(timeout: .now() + .seconds(10)) == .success)
    #expect(secondDone.wait(timeout: .now() + .seconds(10)) == .success)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(!FileManager.default.fileExists(atPath: f.parent.appendingPathComponent("second").path))
  }
}
