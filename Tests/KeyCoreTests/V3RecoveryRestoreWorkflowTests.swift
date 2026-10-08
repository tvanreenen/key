import Darwin
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryRestoreWorkflowTests {
  typealias Fixture = V3RecoveryRestoreServiceTests.Fixture
  typealias Base = V3RecoveryRestoreJournalTests
  private enum Stop: Error { case interrupted }

  @Test(arguments: 0..<3)
  func initialRestoreCreatesOnlyLocalScaffoldingThenUsesActualServiceAndOrdinaryCache(layout: Int)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    if layout == 1 { try FileManager.default.removeItem(at: f.configRoot) }
    if layout == 2 { try FileManager.default.removeItem(at: library(f)) }
    let source = try Base().files(f.source.root)
    let box = ScopeBox()
    let workflow = makeWorkflow(
      f,
      observer: Observer { phase in
        if phase == .sourceAuthenticated {
          #expect(!FileManager.default.fileExists(atPath: f.destination.path))
          #expect(f.identities.creates.value == 0 && f.reservations.value == nil)
          #expect(FileManager.default.fileExists(atPath: cacheURL(f).path))
        }
      })
    let host = makeHost(f, workflow: workflow, capture: box)
    let response = host.handle(.recovery(request(f)))
    #expect(response.exitCode == EXIT_SUCCESS)
    #expect(response.value?.contains("no recovery key registered") == true)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(
      try f.config.load().vaultDirectoryURL.standardizedFileURL == f.destination.standardizedFileURL
    )
    #expect(try !#require(box.scope).authentication.hasResidentKey)
    #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
    #expect(try Base().files(f.source.root) == source)
    var metadata = stat()
    #expect(lstat(cacheURL(f).path, &metadata) == 0 && metadata.st_mode & 0o777 == 0o700)
    // Use only the selected config, saved Mac identity and the actual local
    // cache path composed by this workflow. Recovery availability is removed.
    f.card.anchor = nil
    f.provider.cancel = true
    let session = V3DeviceWrappedVaultKeySessionStore()
    defer { session.invalidate() }
    let config = try f.config.load()
    let store = V3FilesystemTransactionArtifactStore(
      rootHandle: try .init(opening: config.vaultDirectoryURL))
    let cache = V3CheckpointManifestFilesystemCache(rootHandle: try .init(opening: cacheURL(f)))
    let unlock = V3DeviceWrappedVaultUnlockRuntime(
      vaultID: try #require(config.vaultID), checkpointStore: f.checkpoints,
      source: store, cache: cache, identityLoader: f.identities, session: session)
    let ordinary = V3DeviceWrappedReadOnlyVaultRuntime(source: store, unlockRuntime: unlock)
    try ordinary.unlock()
    #expect(try ordinary.list(allowStale: false) == ["fixture/secret", "fixture/totp"])
    #expect(
      try ordinary.read(name: "fixture/secret", allowStale: false).plaintext
        == "Software fixture secret e\u{301}\r\n")
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
  }

  @Test(arguments: 0..<12)
  func invalidPublicSelectionOrLocationNeverCreatesLocalMetadataOrRequestsAgreement(variant: Int)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    try FileManager.default.removeItem(at: f.configRoot)
    var source = f.source.root.path
    var destination = f.destination.path
    var token = f.card.tokenID
    var recipient = f.source.anchor.recipientID.rawValue
    switch variant {
    case 0: token = "not-the-selected-token"
    case 1: recipient = Base64URL.encode(Data(repeating: 9, count: 32))
    case 2: f.card.anchor = nil
    case 3: f.card.anchor = Data("unrecognized public record".utf8)
    case 4: f.card.pinPolicy = 1
    case 5: source = f.base.appendingPathComponent("missing-source").path
    case 6: destination = f.base.appendingPathComponent("missing-parent/vault").path
    case 7: destination = "/"
    case 8:
      try FileManager.default.createDirectory(at: f.destination, withIntermediateDirectories: false)
    case 9:
      try FileManager.default.createSymbolicLink(
        at: f.destination, withDestinationURL: f.source.root)
    case 10: try Data("existing fixture".utf8).write(to: f.destination)
    default: destination = f.source.root.appendingPathComponent("must-not-create").path
    }
    let before = try Base().files(f.source.root)
    #expect(throws: (any Error).self) {
      try makeWorkflow(f).handle(
        .restore(
          source: source, destination: destination, tokenID: token, recipientID: recipient,
          deviceName: "Mac"),
        scope: scope())
    }
    #expect(!FileManager.default.fileExists(atPath: f.configRoot.path))
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(try Base().files(f.source.root) == before)
  }

  @Test(arguments: 0..<4)
  func symlinkedLocalMetadataComponentCannotRedirectCreationIntoSource(component: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let paths = [library(f), f.configRoot.deletingLastPathComponent(), f.configRoot, cacheURL(f)]
    let target = paths[component]
    if FileManager.default.fileExists(atPath: target.path) {
      try FileManager.default.removeItem(at: target)
    }
    try FileManager.default.createSymbolicLink(at: target, withDestinationURL: f.source.root)
    let before = try Base().files(f.source.root)
    #expect(throws: (any Error).self) { try makeWorkflow(f).handle(request(f), scope: scope()) }
    #expect(try Base().files(f.source.root) == before)
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
  }

  @Test(arguments: 0..<5)
  func requestedVaultCannotBeCreatedAsAMetadataComponentIncludingAliasedParent(component: Int)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let destination: URL
    if component == 0 || component == 3 {
      try FileManager.default.removeItem(at: library(f))
      destination =
        component == 0
        ? library(f) : library(f).deletingLastPathComponent().appendingPathComponent("library")
    } else if component == 1 || component == 4 {
      try FileManager.default.removeItem(at: f.configRoot)
      let alias = f.base.appendingPathComponent("library-alias")
      try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: library(f))
      destination = alias.appendingPathComponent(
        component == 1 ? "Application Support/Key" : "Application Support/key")
    } else {
      destination = cacheURL(f)
    }
    #expect(throws: V3RecoveryRestoreError.overlappingDirectories) {
      try makeWorkflow(f).handle(request(f, destination: destination), scope: scope())
    }
    #expect(!FileManager.default.fileExists(atPath: destination.path))
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  @Test(arguments: [false, true])
  func metadataAndSourceCannotContainEachOther(sourceContainsHome: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let source: URL
    let config: KeyConfigStore
    if sourceContainsHome {
      source = f.source.root
      config = .init(homeDirectoryURL: source)
    } else {
      source = f.configRoot.appendingPathComponent("source-copy")
      try FileManager.default.copyItem(at: f.source.root, to: source)
      config = f.config
    }
    let before = try Base().files(source)
    #expect(throws: V3RecoveryRestoreError.overlappingDirectories) {
      try makeWorkflow(f, config: config).handle(request(f, source: source), scope: scope())
    }
    #expect(try Base().files(source) == before)
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  @Test(arguments: [
    V3RecoveryRestoreServicePhase.preparationDurable, .selection(.configurationSelected),
    .finalization(.reservationCleared),
  ])
  func freshHostResumeUsesExactNativeSelectorsAndComposedCacheWithoutNewIdentity(
    phase: V3RecoveryRestoreServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let before = try Base().files(f.source.root)
    let interrupted = makeWorkflow(
      f, observer: Observer { if $0 == phase { throw Stop.interrupted } })
    #expect(
      makeHost(f, workflow: interrupted).handle(.recovery(request(f))).exitCode != EXIT_SUCCESS)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    let host = makeHost(f, workflow: makeWorkflow(f))
    #expect(host.handle(.recovery(request(f))).exitCode != EXIT_SUCCESS)
    #expect(f.provider.requests == 1)
    #expect(host.handle(.recovery(request(f, resume: true))).exitCode == EXIT_SUCCESS)
    #expect(f.provider.requests == 2 && f.identities.creates.value == 1)
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(try Base().files(f.source.root) == before)
  }

  @Test(arguments: 0..<4)
  func resumeNeverRecreatesMissingConfigurationCacheDestinationOrParent(component: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Stop.interrupted) {
      try makeWorkflow(
        f, observer: Observer { if $0 == .preparationDurable { throw Stop.interrupted } }
      )
      .handle(request(f), scope: scope())
    }
    let pins = [f.reservations.value, f.preparations.value]
    let target = [f.configRoot, cacheURL(f), f.destination, f.parent][component]
    try FileManager.default.removeItem(at: target)
    #expect(throws: (any Error).self) {
      try makeWorkflow(f).handle(request(f, resume: true), scope: scope())
    }
    #expect(!FileManager.default.fileExists(atPath: target.path))
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect([f.reservations.value, f.preparations.value] == pins)
  }

  @Test func exactCandidateIsSelectedWithoutReadingAnotherAvailableCard() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let other = Connection(card: f.card, token: "other-token", slot: "other-slot") {
      Issue.record("The unselected token must not be read")
    }
    let reader = PIVRecoveryTokenReader(
      inventory: Inventory(cards: [other, f.card]), gate: .init())
    #expect(
      try makeWorkflow(f, reader: reader).handle(request(f), scope: scope()).exitCode
        == EXIT_SUCCESS)
    #expect(f.provider.requests == 1)
  }

  @Test(arguments: [false, true])
  func cancellationOrGenerationChangeAfterPublicReadStopsBeforeMetadataCreation(lock: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    try FileManager.default.removeItem(at: library(f))
    let requestScope = scope()
    let card = Connection(card: f.card, token: f.card.tokenID, slot: f.card.readerSlotName) {
      if lock {
        requestScope.authentication.invalidate()
      } else {
        requestScope.cancellation.cancel()
      }
    }
    let reader = PIVRecoveryTokenReader(inventory: Inventory(cards: [card]), gate: .init())
    #expect(throws: (any Error).self) {
      try makeWorkflow(f, reader: reader).handle(request(f), scope: requestScope)
    }
    #expect(!FileManager.default.fileExists(atPath: library(f).path))
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  @Test(arguments: [KeyProductIdentity.stable, .preview])
  func liveFactoryCompositionDoesNotCreatePathsOrEnableLiveProduct(identity: KeyProductIdentity)
    throws
  {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let config = KeyConfigStore(productIdentity: identity, homeDirectoryURL: home)
    let workflow = V3RecoveryRestoreWorkflow.live(
      configStore: config, runtimeConfiguration: .init(productIdentity: identity))
    withExtendedLifetime(workflow) {}
    #expect(!FileManager.default.fileExists(atPath: home.path))
    let host = KeyServiceHost.live(
      keyStore: MemoryVaultKeyStore(), configStore: config,
      runtimeConfiguration: .init(productIdentity: identity))
    #expect(
      host.handle(
        .recovery(
          .resume(
            source: "/backup", destination: "/restore", tokenID: "token",
            recipientID: Base64URL.encode(Data(repeating: 0, count: 32))))
      ).errorMessage?.contains("not enabled") == true)
    #expect(!FileManager.default.fileExists(atPath: home.path))
  }

  @Test(arguments: [false, true])
  func staleScopeDuringScaffoldingCreationCannotCreateCacheOrVault(lock: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    try FileManager.default.removeItem(at: f.configRoot)
    let requestScope = scope()
    #expect(throws: (any Error).self) {
      try f.config.restoreMetadataRoots(
        source: f.sourceHandle, parent: f.parentHandle,
        name: "restored", create: true
      ) {
        if FileManager.default.fileExists(atPath: f.configRoot.path) {
          if lock {
            requestScope.authentication.invalidate()
          } else {
            requestScope.cancellation.cancel()
          }
        }
        try requestScope.requireCurrent()
      }
    }
    #expect(FileManager.default.fileExists(atPath: f.configRoot.path))
    #expect(!FileManager.default.fileExists(atPath: cacheURL(f).path))
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(try !f.config.hasConfiguration())
  }

  @Test(arguments: 0..<3)
  func existingConfigurationPresenceCannotBeReplacedEvenWhenItIsUnusable(kind: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let path = f.config.initializationConfigFileURL
    if kind == 0 {
      try Data("invalid configuration fixture".utf8).write(to: path)
    } else if kind == 1 {
      try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
    } else {
      try FileManager.default.createSymbolicLink(
        at: path, withDestinationURL: f.base.appendingPathComponent("missing"))
    }
    #expect(throws: (any Error).self) { try makeWorkflow(f).handle(request(f), scope: scope()) }
    #expect(try f.config.hasConfiguration())
    #expect(!FileManager.default.fileExists(atPath: cacheURL(f).path))
    #expect(!FileManager.default.fileExists(atPath: f.destination.path))
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  private func library(_ f: Fixture) -> URL {
    f.configRoot.deletingLastPathComponent().deletingLastPathComponent()
  }
  private func cacheURL(_ f: Fixture) -> URL {
    f.configRoot.appendingPathComponent("v3-checkpoint-manifests")
  }
  private func scope() -> KeyRecoveryRequestScope {
    .init(authentication: .init(), deadline: .now() + 90)
  }
  private func request(
    _ f: Fixture, source: URL? = nil, destination: URL? = nil, resume: Bool = false
  ) -> KeyRecoveryRequest {
    let from = (source ?? f.source.root).path
    let to = (destination ?? f.destination).path
    if resume {
      return .resume(
        source: from, destination: to, tokenID: f.card.tokenID,
        recipientID: f.source.anchor.recipientID.rawValue)
    }
    return .restore(
      source: from, destination: to, tokenID: f.card.tokenID,
      recipientID: f.source.anchor.recipientID.rawValue, deviceName: "New Mac")
  }
  private func makeWorkflow(
    _ f: Fixture, config: KeyConfigStore? = nil, reader: PIVRecoveryTokenReader? = nil,
    observer: any V3RecoveryRestoreServicePhaseObserving = Observer(action: { _ in })
  ) -> V3RecoveryRestoreWorkflow {
    let selectedReader = reader ?? f.reader
    return .init(
      configStore: config ?? f.config, ownership: Ownership(f: f), reservations: f.reservations,
      preparations: f.preparations, identities: f.identities, checkpoints: f.checkpoints,
      reader: selectedReader, agreement: .init(reader: selectedReader, provider: f.provider),
      mutationOwner: f.owner, observer: observer)
  }
  private func makeHost(_ f: Fixture, workflow: V3RecoveryRestoreWorkflow, capture: ScopeBox? = nil)
    -> KeyServiceHost
  {
    KeyServiceHost(
      hasConfiguration: { try f.config.hasConfiguration() },
      makeHandler: {
        Issue.record("Do not compose an ordinary runtime before helper restart")
        return { _ in .success() }
      }, initialize: { _ in "Unused" },
      recovery: .init(
        ownership: Ownership(f: f),
        recover: { request, scope in
          capture?.scope = scope
          return try workflow.capability.recover(request, scope)
        }))
  }
  private struct Ownership: V3RecoveryRestoreOwnershipChecking {
    let f: Fixture
    func hasPendingRestore() -> Bool { f.reservations.value != nil || f.preparations.value != nil }
  }
  private struct Observer: V3RecoveryRestoreServicePhaseObserving {
    let action: @Sendable (V3RecoveryRestoreServicePhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreServicePhase) throws { try action(phase) }
  }
  private struct Inventory: PIVRecoveryTokenInventoryProviding {
    let cards: [any PIVRecoveryTokenConnection]
    func connections(maximumCount: Int) throws -> [any PIVRecoveryTokenConnection] { cards }
  }
  private struct Connection: PIVRecoveryTokenConnection {
    let card: V3RecoveryRegistrationServiceTests.Card
    let token: String, slot: String
    let afterRead: @Sendable () -> Void
    var tokenID: String { token }
    var readerSlotName: String { slot }
    var isValid: Bool { card.isValid }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      let result = try card.withPublicReadSession(lease: lease, consume)
      afterRead()
      return result
    }
  }
  private final class ScopeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: KeyRecoveryRequestScope?
    var scope: KeyRecoveryRequestScope? {
      get { lock.withLock { value } }
      set { lock.withLock { value = newValue } }
    }
  }
}
