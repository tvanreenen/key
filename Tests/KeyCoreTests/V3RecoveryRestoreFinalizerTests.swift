import Foundation
import Testing

@testable import KeyCore

/// Disposable selected vault/config/cache, software credentials and memory CAS.
/// No real vault, native Keychain, hardware operation or encrypted file deletion.
struct V3RecoveryRestoreFinalizerTests {
  private typealias Base = V3RecoveryRestoreJournalTests
  private typealias Core = V3RecoveryRegistrationTests
  @available(macOS 26.0, *)
  private typealias Fixture = V3RecoveryRestoreSelectionInstallerTests.Harness
  private enum Stop: Error { case interrupted }
  private static let phases: [V3RecoveryRestoreFinalizationPhase] = [
    .completionVerified, .reservationCleared, .preparationCleared, .completionConfirmed,
  ]

  @Test(arguments: [false, true])
  func selectedFinalizationClearsOnlyPinsAndNoPinsMeansNoSuccessClaim(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness(empty: empty)
    defer { h.f.f.remove() }
    let source = try Base().files(h.f.f.source.root)
    let config = try Base().files(h.f.f.configRootURL)
    let destination = try Base().files(h.f.f.environment.destination.rootURL)
    let calls = h.f.f.calls.value
    let report = try #require(try h.finalize())
    #expect(report.checkpoint == h.f.bundle.intent.destinationCheckpoint)
    #expect(report.entryCount == h.snapshot.entries.count && !report.reservationWasAlreadyCleared)
    #expect(h.f.f.reservations.value == nil && h.f.f.preparations.value == nil)
    #expect(h.f.identity.calls.value == 3 && h.f.f.calls.value == calls)
    #expect(try h.finalize() == nil)
    #expect(h.f.identity.calls.value == 3 && h.f.f.calls.value == calls)
    #expect(try h.f.f.journal().loadPending(sourceVaultID: Core.vaultID) == nil)
    #expect(try Base().files(h.f.f.source.root) == source)
    #expect(try Base().files(h.f.f.configRootURL) == config)
    #expect(try Base().files(h.f.f.environment.destination.rootURL) == destination)
    #expect(h.f.checkpoints.value == report.checkpoint.canonicalBytes)
    #expect(
      try h.f.cache.load(for: report.checkpoint) == .available(h.f.bundle.manifest.canonicalBytes))
    #expect(h.f.f.source.core.owner.unwraps == 0)
  }

  @Test(arguments: phases)
  func eachBoundaryRetainsExactOwnershipOrReturnsNoPendingWorkAfterLastClear(
    phase: V3RecoveryRestoreFinalizationPhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let pins = [h.f.f.reservations.value, h.f.f.preparations.value]
    #expect(throws: Stop.interrupted) {
      try h.finalize(observer: Observer { if $0 == phase { throw Stop.interrupted } })
    }
    let final = [.preparationCleared, .completionConfirmed].contains(phase)
    #expect(h.f.f.reservations.value == (phase == .completionVerified ? pins[0] : nil))
    #expect(h.f.f.preparations.value == (final ? nil : pins[1]))
    if phase == .reservationCleared {
      #expect(throws: V3RecoveryRestoreJournalError.invalidOwnership) {
        try h.f.f.journal().loadPending(sourceVaultID: Core.vaultID)
      }
      let state = try #require(try h.f.f.journal().loadFinalization(sourceVaultID: Core.vaultID))
      let reconstructed = try V3RecoveryRestoreReservation(pinnedBundle: h.f.bundle)
      #expect(
        state.stage == .reservationCleared
          && state.pending.reservation.canonicalBytes
            == reconstructed.canonicalBytes
      )
      #expect(throws: (any Error).self) { try h.f.select(snapshot: h.snapshot) }
    }
    let calls = h.f.identity.calls.value
    let retried = try h.finalize()
    if final {
      #expect(retried == nil && h.f.identity.calls.value == calls)
    } else {
      #expect(try #require(retried).reservationWasAlreadyCleared == (phase == .reservationCleared))
      #expect(h.f.identity.calls.value == calls + 1)
    }
    #expect(h.f.f.reservations.value == nil && h.f.f.preparations.value == nil)
  }

  @Test(arguments: [false, true])
  func failureBeforeEitherCASRetainsResumableStateWithoutRetry(preparation: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let reservations = h.f.f.reservations
    let preparations = h.f.f.preparations
    let pins = [reservations.value, preparations.value]
    (preparation ? preparations : reservations).rejectClear = true
    #expect(throws: (any Error).self) { try h.finalize() }
    #expect(reservations.value == (preparation ? nil : pins[0]))
    #expect(preparations.value == pins[1])
    reservations.rejectClear = false
    preparations.rejectClear = false
    let report = try #require(try h.finalize())
    #expect(report.reservationWasAlreadyCleared == preparation)
    #expect(reservations.value == nil && preparations.value == nil)
  }

  @Test(arguments: [false, true])
  func ambiguousErrorAfterEitherCASNeverRetriesOrRestoresPins(preparation: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let uncertain = UncertainClear(preparation ? h.f.f.preparations : h.f.f.reservations)
    let journal = V3RecoveryRestoreJournal(
      configurationRoot: try .init(opening: h.f.f.configRootURL),
      reservationOwnership: preparation ? h.f.f.reservations : uncertain,
      preparationOwnership: preparation ? uncertain : h.f.f.preparations)
    #expect(throws: Stop.interrupted) { try h.finalize(journal: journal) }
    #expect(uncertain.clears.value == 1 && h.f.f.reservations.value == nil)
    #expect((h.f.f.preparations.value == nil) == preparation)
    if preparation {
      #expect(try h.finalize() == nil)
    } else {
      #expect(try #require(try h.finalize()).reservationWasAlreadyCleared)
    }
    #expect(h.f.f.reservations.value == nil && h.f.f.preparations.value == nil)
  }

  @Test(arguments: 0..<7)
  func missingChangedOrUnauthenticatedCompletionCannotRemoveEitherPin(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let pins = [h.f.f.reservations.value, h.f.f.preparations.value]
    switch variant {
    case 0: try FileManager.default.removeItem(at: h.f.configURL)
    case 1: try Data("other config".utf8).write(to: h.f.configURL)
    case 2: h.f.checkpoints.value = nil
    case 3: h.f.checkpoints.value = Data("other trust".utf8)
    case 4:
      try FileManager.default.removeItem(at: h.f.f.base.appendingPathComponent("cache"))
    case 5:
      try FileManager.default.removeItem(
        at: h.f.f.environment.destination.rootURL.appendingPathComponent(
          manifestPath(for: h.f.bundle.intent.destinationCheckpoint.envelopeDigest)))
    default: break
    }
    #expect(throws: (any Error).self) {
      try h.finalize(vaultKey: variant == 6 ? Data(repeating: 0, count: 32) : Base.key)
    }
    #expect([h.f.f.reservations.value, h.f.f.preparations.value] == pins)
    #expect(h.f.identity.calls.value == 2)
  }

  @Test(arguments: [false, true])
  func unavailableOrCancelledFreshIdentityCannotClearOwnership(missing: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let identity = RefusingIdentity(base: h.f.identity)
    let loader = RefusingLoader(identity: identity, missing: missing)
    let pins = [h.f.f.reservations.value, h.f.f.preparations.value]
    #expect(throws: (any Error).self) { try h.finalize(identities: loader) }
    #expect([h.f.f.reservations.value, h.f.f.preparations.value] == pins)
    #expect(loader.calls.value == 1 && identity.calls.value == (missing ? 0 : 1))
    #expect(h.f.identity.calls.value == 2)
  }

  @Test(arguments: 0..<6, [false, true])
  func changedStateBeforeOrBetweenRemovalStepsStopsFurtherCleanup(variant: Int, halfway: Bool)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let config = h.f.configURL
    let record = h.f.f.record("preparation.json")
    let preparations = h.f.f.preparations
    let reservations = h.f.f.reservations
    let checkpoints = h.f.checkpoints
    let source = h.f.f.source
    let prep = preparations.value
    #expect(throws: (any Error).self) {
      try h.finalize(
        observer: Observer {
          guard $0 == (halfway ? .reservationCleared : .completionVerified) else { return }
          switch variant {
          case 0: try Data("other config".utf8).write(to: config)
          case 1: checkpoints.value = Data("foreign trust".utf8)
          case 2: preparations.value = Data("foreign ownership".utf8)
          case 3: try Data("changed".utf8).write(to: record)
          case 4:
            let edit = try source.build(
              .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
            _ = try source.publisher().publish(edit, vaultKey: Core.nextKey)
          default: reservations.value = Data("foreign ownership".utf8)
          }
        })
    }
    #expect(preparations.value == (variant == 2 ? Data("foreign ownership".utf8) : prep))
    if variant == 5 {
      #expect(reservations.value == Data("foreign ownership".utf8))
    } else {
      #expect((reservations.value == nil) == halfway)
    }
  }

  @Test(arguments: 0..<3)
  func changesAfterLastRemovalCannotReturnSuccessOrRecreateOwnership(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    let config = h.f.configURL
    let record = h.f.f.record("reservation.json")
    let checkpoints = h.f.checkpoints
    #expect(throws: (any Error).self) {
      try h.finalize(
        observer: Observer {
          guard $0 == .preparationCleared else { return }
          if variant == 0 {
            try Data("foreign".utf8).write(to: config)
          } else if variant == 1 {
            checkpoints.value = Data("foreign".utf8)
          } else {
            try Data("changed".utf8).write(to: record)
          }
        })
    }
    #expect(h.f.f.reservations.value == nil && h.f.f.preparations.value == nil)
    let calls = h.f.identity.calls.value
    #expect(try h.finalize() == nil && h.f.identity.calls.value == calls)
  }

  @Test(arguments: 0..<4)
  func preparationOnlyOwnershipMustPinTheExactCompleteBundleAndReservation(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    h.f.f.reservations.value = nil
    let bytes = try #require(h.f.f.preparations.value)
    let pin = try V3ImmutableTransactionRecoveryAnchor(canonicalBytes: bytes)
    if variant == 0 {
      h.f.f.preparations.value = try V3ImmutableTransactionRecoveryAnchor(
        operationID: pin.operationID, vaultID: pin.vaultID, intentDigest: pin.intentDigest,
        phase: .prepared
      ).canonicalBytes
    } else if variant == 1 {
      try Data("changed".utf8).write(to: h.f.f.record("preparation.json"))
    } else if variant == 2 {
      try Data("changed".utf8).write(to: h.f.f.record("reservation.json"))
    } else {
      h.f.f.preparations.value = try V3ImmutableTransactionRecoveryAnchor(
        operationID: .init(), vaultID: pin.vaultID, intentDigest: pin.intentDigest,
        phase: .recoverable
      ).canonicalBytes
    }
    let expected = h.f.f.preparations.value
    #expect(throws: (any Error).self) { try h.finalize() }
    #expect(h.f.f.reservations.value == nil && h.f.f.preparations.value == expected)
    #expect(h.f.identity.calls.value == 2)
  }

  @Test(arguments: [false, true])
  func missingPinsCannotAdoptFilesAndReservationAloneCannotFinalize(bothMissing: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let h = try Harness()
    defer { h.f.f.remove() }
    h.f.f.preparations.value = nil
    if bothMissing { h.f.f.reservations.value = nil }
    if bothMissing {
      #expect(try h.finalize() == nil)
    } else {
      #expect(throws: (any Error).self) { try h.finalize() }
    }
    #expect(h.f.identity.calls.value == 2)
  }

  private struct Observer: V3RecoveryRestoreFinalizationPhaseObserving {
    let action: @Sendable (V3RecoveryRestoreFinalizationPhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreFinalizationPhase) throws { try action(phase) }
  }
  private struct UncertainClear: V3ImmutableTransactionRecoveryAnchorStoring {
    let base: Base.Ownership
    let clears = Core.Counter()
    init(_ base: Base.Ownership) { self.base = base }
    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
      try base.loadRecoveryAnchor(vaultID: vaultID)
    }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID: String) throws {
      try base.replaceRecoveryAnchor(anchor, expectedAnchor: expectedAnchor, vaultID: vaultID)
      if anchor == nil {
        clears.increment()
        throw Stop.interrupted
      }
    }
  }
  private struct RefusingIdentity: V3DeviceWrappedVaultKeyUnwrapping {
    let base: any V3DeviceWrappedVaultKeyUnwrapping
    let calls = Core.Counter()
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _: V3HPKEWrappedVaultKey, context _: V3VaultKeyHPKEContext, reason _: String
    ) throws -> Data {
      calls.increment()
      throw V3EnrollmentDeviceIdentityStoreError.authenticationCancelled
    }
  }
  private struct RefusingLoader: V3DeviceWrappedIdentityLoading {
    let identity: RefusingIdentity
    let missing: Bool
    let calls = Core.Counter()
    func loadDeviceIdentity(vaultID _: String, reason _: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      calls.increment()
      return missing ? nil : identity
    }
  }
  @available(macOS 26.0, *)
  private struct Harness {
    let f: Fixture
    let snapshot: V3RecoveryVerifiedSnapshot
    init(empty: Bool = false) throws {
      f = try Fixture(empty: empty)
      snapshot = try f.f.open()
      _ = try f.select(snapshot: snapshot)
    }
    func finalize(
      journal: V3RecoveryRestoreJournal? = nil, vaultKey: Data = Base.key,
      identities: (any V3DeviceWrappedIdentityLoading)? = nil,
      observer: any V3RecoveryRestoreFinalizationPhaseObserving = Observer(action: { _ in })
    ) throws -> V3RecoveryRestoreFinalizationReport? {
      try V3RecoveryRestoreFinalizer(
        journal: journal ?? f.f.journal(), checkpoints: f.checkpoints, cache: f.cache,
        identities: identities ?? f.loader, observer: observer
      ).finalize(
        sourceVaultID: Core.vaultID, snapshot: snapshot, vaultKey: vaultKey,
        source: .init(opening: f.f.source.root),
        destination: .init(opening: f.f.environment.destination.rootURL),
        parent: .init(opening: f.f.environment.destinationParent.rootURL), configStore: f.f.config)
    }
  }
}
