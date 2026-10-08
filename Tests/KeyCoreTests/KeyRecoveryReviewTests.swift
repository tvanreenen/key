import Foundation
import Testing

@testable import KeyCore

struct KeyRecoveryReviewTests {
  private typealias Fixture = V3RecoveryRestoreServiceTests.Fixture
  private enum Stop: Error { case unexpected }

  @Test(arguments: [KeyRecoveryReviewRequest.tokens, .source(path: "/source", tokenID: "token")])
  func protocolIsPublicOnlyBoundedAndNeverRequestsShutdown(request: KeyRecoveryReviewRequest) throws
  {
    let outer = KeyServiceRequest.recoveryReview(request)
    let encoded = try JSONEncoder().encode(outer)
    #expect(try JSONDecoder().decode(KeyServiceRequest.self, from: encoded) == outer)
    #expect(KeyXPCClientRole.fullCLI.authorizes(outer))
    #expect(!KeyXPCClientRole.utilityStatus.authorizes(outer))
    #expect(outer.responseTimeoutSeconds == 120 && !outer.requiresHelperShutdownAfterSuccess)
    try request.validate()
    let text = String(decoding: encoded, as: UTF8.self)
    #expect(!text.contains("destination") && !text.contains("recipientID"))
    #expect(!text.contains("PIN") && !text.contains("confirmation") && !text.contains("secret"))
    let previous = Data(#"{"exitCode":0}"#.utf8)
    #expect(try JSONDecoder().decode(KeyServiceResponse.self, from: previous).recoveryReview == nil)
  }

  @Test
  func tokenListingNeverOpensAnyPublicSessionOrAutomaticallySelectsACandidate() throws {
    let f = try Fixture()
    defer { f.remove() }
    let count = Counter()
    let reader = reader(f, after: { _ in count.increment() })
    let workflow = KeyRecoveryReviewWorkflow(reader: reader)
    let result = try workflow.handle(.tokens, scope: scope())
    #expect(
      result.recoveryReview
        == .tokens([
          .init(tokenID: f.card.tokenID, readerSlotName: f.card.readerSlotName)
        ]))
    #expect(count.value == 0 && f.provider.requests == 0 && f.identities.creates.value == 0)
    let empty = KeyRecoveryReviewWorkflow(
      reader: .init(inventory: Inventory(cards: []), gate: PIVTokenOperationGate()))
    #expect(try empty.handle(.tokens, scope: scope()).recoveryReview == .tokens([]))
  }

  @Test(arguments: [false, true])
  func actualCLIHostAndPublicSelectorObserveOnlyPublicState(json: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    // Missing current entry objects must not be mistaken for verified contents.
    // Their absence also establishes that review never tries to open them.
    try FileManager.default.removeItem(at: f.source.root.appendingPathComponent("entries"))
    let before = try V3RecoveryRestoreJournalTests().files(f.source.root)
    let local = try V3RecoveryRestoreJournalTests().files(f.base)
    let workflow = KeyRecoveryReviewWorkflow(reader: f.reader)
    let configurationReads = Counter()
    let host = host(review: workflow.handle, configurationReads: configurationReads)
    let transport = MemoryTransport { host.handle($0) }
    let io = MemoryIO(
      stdinIsTTY: false, pipedInput: "must-not-read", secureInput: "must-not-read",
      onReadLine: { Issue.record("No review approval or credentials may be collected") })
    let app = KeyCLIApplication(
      transport: transport, io: io, clipboard: MemoryClipboard(), configStore: f.config,
      currentDirectory: { f.source.root.deletingLastPathComponent() })
    let arguments =
      [
        "recovery", "review", "--source", f.source.root.lastPathComponent,
        "--token", f.card.tokenID,
      ] + (json ? ["--json"] : [])
    #expect(app.run(arguments: arguments) == EXIT_SUCCESS)
    #expect(transport.requests == [.recoveryReview(request(f))] && io.stderr.isEmpty)
    if json {
      let decoded = try JSONDecoder().decode(
        KeyRecoveryReviewResult.self, from: Data(io.stdout.utf8))
      guard case .source(let source) = decoded else {
        Issue.record("Expected source report")
        return
      }
      #expect(source.recipientID == f.source.anchor.recipientID.rawValue)
      #expect(source.listedEntryCount == 2 && source.observedManifestCount >= 1)
      #expect(source.reportedPINPolicy == "always" && source.reportedTouchPolicy == "always")
      #expect(source.reportedKeyOrigin == "generated")
      #expect(source.assurance == .publicObservationOnly)
      #expect(source.vaultID == f.source.anchor.floor.vaultID)
      #expect(source.registrationID == f.source.anchor.registrationID)
      #expect(
        source.registrationManifestDigest == Base64URL.encode(f.source.anchor.floor.envelopeDigest))
    } else {
      #expect(io.stdout.contains("not content-verified"))
      #expect(io.stdout.contains("does not prove possession"))
      #expect(io.stdout.contains("No saved attempt or restore approval"))
    }
    #expect(!io.stdout.contains("Software fixture secret") && !io.stdout.contains("must-not-read"))
    #expect(try V3RecoveryRestoreJournalTests().files(f.source.root) == before)
    #expect(try V3RecoveryRestoreJournalTests().files(f.base) == local)
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(
      f.reservations.value == nil && f.preparations.value == nil && f.checkpoints.value == nil)
    #expect(try !f.config.hasConfiguration())
    #expect(configurationReads.value == 0)
    #expect(host.handle(.initializeVault(path: "/unused")) == .success("Initialized"))
  }

  @Test(arguments: 0..<7)
  func sourcePathControlCharactersAreQuotedInHumanOutput(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let suffix = ["\n", "\t", "\r", "\"", "\\", "\u{1b}", "'"][variant]
    let moved = f.base.appendingPathComponent("source\(suffix)name")
    try FileManager.default.moveItem(at: f.source.root, to: moved)
    let workflow = KeyRecoveryReviewWorkflow(reader: f.reader)
    let host = host(review: workflow.handle)
    let io = MemoryIO(stdinIsTTY: false)
    let app = KeyCLIApplication(
      transport: MemoryTransport { host.handle($0) }, io: io, clipboard: MemoryClipboard())
    #expect(
      app.run(arguments: ["recovery", "review", "--source", moved.path, "--token", f.card.tokenID])
        == EXIT_SUCCESS)
    #expect(
      io.stdout.split(separator: "\n").contains(
        Substring("Source: \(String(reflecting: moved.path))")))
    #expect(f.provider.requests == 0 && io.stderr.isEmpty)
  }

  @Test(arguments: 0..<7)
  func malformedPathsAndSelectorsNeverReachThePublicWorkflow(variant: Int) {
    var path = "/source"
    var token = "token"
    switch variant {
    case 0: path = "relative"
    case 1: path = ""
    case 2: path += "\0"
    case 3: path = "/" + String(repeating: "p", count: 4_096)
    case 4: token = ""
    case 5: token += "\n"
    default: token = String(repeating: "t", count: 1_025)
    }
    let host = host(review: { _, _ in
      Issue.record("Invalid review must not run")
      return .success()
    })
    #expect(
      host.handle(.recoveryReview(.source(path: path, tokenID: token))).exitCode != EXIT_SUCCESS)
    #expect(host.handle(.initializeVault(path: "/unused")) == .success("Initialized"))
  }

  @Test(arguments: 0..<8)
  func wrongPublicBindingPolicyOrIncompleteHistoryRefusesWithoutChangingAnyState(variant: Int)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    var token = f.card.tokenID
    var path = f.source.root.path
    switch variant {
    case 0: token = "different-token"
    case 1: f.card.anchor = nil
    case 2: f.card.anchor = Data("Unrecognized public fixture".utf8)
    case 3: f.card.pinPolicy = 1
    case 4: path = f.base.appendingPathComponent("missing-source").path
    case 5:
      try FileManager.default.removeItem(
        at: f.source.manifestURL(f.source.anchor.floor.envelopeDigest))
    case 6:
      try Data("Incomplete public fixture".utf8).write(
        to: f.source.manifestURL(f.source.anchor.floor.envelopeDigest))
    default:
      let other = try V3RecoveryAnchor(
        floor: f.source.anchor.floor, recipientID: f.source.anchor.recipientID,
        registrationID: UUID().uuidString.lowercased(), slot: .keyManagement)
      f.card.anchor = other.canonicalBytes
    }
    let before = try V3RecoveryRestoreJournalTests().files(f.source.root)
    let local = try V3RecoveryRestoreJournalTests().files(f.base)
    let workflow = KeyRecoveryReviewWorkflow(reader: f.reader)
    #expect(throws: (any Error).self) {
      try workflow.handle(.source(path: path, tokenID: token), scope: scope())
    }
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(try V3RecoveryRestoreJournalTests().files(f.source.root) == before)
    #expect(try V3RecoveryRestoreJournalTests().files(f.base) == local)
  }

  @Test(arguments: 0..<5)
  func changedTokenSourceOrScopeCannotReleaseAPublicReview(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let requestScope = scope()
    let workflow = KeyRecoveryReviewWorkflow(
      reader: reader(
        f,
        after: { ordinal in
          guard ordinal == 2 else { return }
          switch variant {
          case 0: f.card.anchor = nil
          case 1: f.card.pinPolicy = 1
          case 2: requestScope.cancellation.cancel()
          case 3: requestScope.authentication.invalidate()
          default:
            try FileManager.default.moveItem(
              at: f.source.root, to: f.base.appendingPathComponent("moved-source"))
            try FileManager.default.createDirectory(
              at: f.source.root, withIntermediateDirectories: false)
          }
        }))
    #expect(throws: (any Error).self) { try workflow.handle(request(f), scope: requestScope) }
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  @Test
  func configuredRuntimeAndUncertainOwnershipDoNotBecomeReviewAuthorityOrBlockReview() throws {
    let f = try Fixture()
    defer { f.remove() }
    let workflow = KeyRecoveryReviewWorkflow(reader: f.reader)
    let owner = UnreadableOwnership()
    let host = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success("Ordinary") } },
      initialize: { _ in
        Issue.record("Not setup")
        return ""
      },
      recovery: .init(
        ownership: owner,
        recover: { _, _ in
          Issue.record("Not restore")
          return .success()
        }),
      reviewRecovery: workflow.handle)
    // Warm a separate host's runtime; durable ownership still refuses cold ordinary composition.
    let warm = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success("Ordinary") } },
      initialize: { _ in "" }, reviewRecovery: workflow.handle)
    #expect(warm.handle(.list) == .success("Ordinary"))
    #expect(warm.handle(.recoveryReview(request(f))).exitCode == EXIT_SUCCESS)
    #expect(host.handle(.recoveryReview(request(f))).exitCode == EXIT_SUCCESS)
    #expect(host.handle(.list).exitCode != EXIT_SUCCESS)
    #expect(owner.calls.value == 1)
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
  }

  @Test(arguments: [false, true])
  func reviewDoesNotClearProcessLocalPendingState(failsReview: Bool) {
    let host = KeyServiceHost(
      hasConfiguration: { false },
      makeHandler: {
        Issue.record("Not runtime")
        return { _ in .success() }
      },
      initialize: { _ in
        Issue.record("Pending attempt cannot initialize")
        return ""
      },
      recovery: .init(ownership: ClearOwnership(), recover: { _, _ in throw Stop.unexpected }),
      reviewRecovery: { _, _ in
        if failsReview { throw Stop.unexpected }
        return .init(exitCode: 0, value: nil, errorMessage: nil, recoveryReview: .tokens([]))
      })
    let restore = KeyRecoveryRequest.restore(
      source: "/source", destination: "/destination", tokenID: "token",
      recipientID: Base64URL.encode(Data(repeating: 1, count: 32)), deviceName: "Mac")
    #expect(host.handle(.recovery(restore)).exitCode != EXIT_SUCCESS)
    #expect((host.handle(.recoveryReview(.tokens)).exitCode == EXIT_SUCCESS) == !failsReview)
    #expect(
      host.handle(.initializeVault(path: "/unused")).errorMessage?.contains("saved attempt") == true
    )
  }

  @Test(arguments: [false, true])
  func successfulOrFailedReadNeverMarksAnAttemptPending(fails: Bool) {
    let reads = Counter()
    let host = host(
      review: { _, _ in
        if fails { throw Stop.unexpected }
        return .init(exitCode: 0, value: nil, errorMessage: nil, recoveryReview: .tokens([]))
      }, configurationReads: reads)
    #expect((host.handle(.recoveryReview(.tokens)).exitCode == EXIT_SUCCESS) == !fails)
    #expect(reads.value == 0)
    #expect(host.handle(.initializeVault(path: "/unused")) == .success("Initialized"))
  }

  @Test
  func setupBarrierWaitsForPublicReadWithoutTreatingItAsRestore() {
    let started = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let reviewDone = DispatchSemaphore(value: 0)
    let setupStarted = DispatchSemaphore(value: 0)
    let setupDone = DispatchSemaphore(value: 0)
    let setups = Counter()
    let host = KeyServiceHost(
      hasConfiguration: { false }, makeHandler: { { _ in .success() } },
      initialize: { _ in
        setups.increment()
        return "Initialized"
      },
      reviewRecovery: { _, _ in
        started.signal()
        guard release.wait(timeout: .now() + 5) == .success else { throw Stop.unexpected }
        return .init(exitCode: 0, value: nil, errorMessage: nil, recoveryReview: .tokens([]))
      })
    let box = HostBox(host)
    DispatchQueue.global().async {
      #expect(box.host.handle(.recoveryReview(.tokens)).exitCode == EXIT_SUCCESS)
      reviewDone.signal()
    }
    defer { release.signal() }
    #expect(started.wait(timeout: .now() + 5) == .success)
    DispatchQueue.global().async {
      setupStarted.signal()
      #expect(box.host.handle(.initializeVault(path: "/unused")) == .success("Initialized"))
      setupDone.signal()
    }
    #expect(setupStarted.wait(timeout: .now() + 5) == .success)
    #expect(setupDone.wait(timeout: .now() + .milliseconds(40)) == .timedOut)
    #expect(setups.value == 0)
    release.signal()
    #expect(reviewDone.wait(timeout: .now() + 5) == .success)
    #expect(setupDone.wait(timeout: .now() + 5) == .success && setups.value == 1)
  }

  @Test(arguments: [false, true])
  func lockOrConnectionCancellationDiscardsLateReviewAndLockStillLocksConfiguredRuntime(
    disconnect: Bool
  ) {
    let started = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let done = DispatchSemaphore(value: 0)
    let state = State()
    let connection = KeyServiceConnection()
    let host = KeyServiceHost(
      hasConfiguration: { true },
      makeHandler: {
        { request in
          if request == .lock { state.locks.increment() }
          return .success("Ordinary")
        }
      }, initialize: { _ in "" },
      recovery: .init(
        ownership: ClearOwnership(),
        recover: { _, _ in
          Issue.record("Review must exclude concurrent restore")
          return .success()
        }),
      reviewRecovery: { _, scope in
        state.scope = scope
        started.signal()
        guard release.wait(timeout: .now() + 5) == .success else { throw Stop.unexpected }
        return .init(exitCode: 0, value: nil, errorMessage: nil, recoveryReview: .tokens([]))
      })
    let box = HostBox(host)
    #expect(host.handle(.list) == .success("Ordinary"))
    DispatchQueue.global().async {
      state.response = box.host.handle(.recoveryReview(.tokens), connection: connection)
      done.signal()
    }
    defer { release.signal() }
    #expect(started.wait(timeout: .now() + 5) == .success)
    #expect(
      host.handle(.recoveryReview(.tokens)).errorMessage?.contains("Another recovery") == true)
    #expect(
      host.handle(
        .recovery(
          .resume(
            source: "/source", destination: "/destination", tokenID: "token",
            recipientID: Base64URL.encode(Data(repeating: 1, count: 32))
          ))
      ).errorMessage?.contains("Another recovery") == true)
    if disconnect {
      KeyServiceConnection().invalidate()  // another connection does not cancel this one
      #expect(state.scope?.cancellation.isCancelled == false)
      connection.invalidate()
    } else {
      #expect(host.handle(.lock) == .success("Ordinary"))
      #expect(state.locks.value == 1)
    }
    release.signal()
    #expect(done.wait(timeout: .now() + 5) == .success)
    #expect(state.response?.exitCode != EXIT_SUCCESS && state.response?.recoveryReview == nil)
    #expect(host.handle(.list) == .success("Ordinary"))
  }

  @Test(arguments: [KeyProductIdentity.stable, .preview])
  func shippingHostsKeepBothReadRoutesDisabledWithoutStateCreation(product: KeyProductIdentity) {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let workflow = KeyRecoveryReviewWorkflow.live()
    withExtendedLifetime(workflow) {}
    let host = KeyServiceHost.live(
      keyStore: MemoryVaultKeyStore(), configStore: .init(homeDirectoryURL: home),
      runtimeConfiguration: .init(productIdentity: product))
    for request in [KeyRecoveryReviewRequest.tokens, .source(path: "/source", tokenID: "token")] {
      #expect(host.handle(.recoveryReview(request)).errorMessage?.contains("not enabled") == true)
    }
    #expect(!FileManager.default.fileExists(atPath: home.path))
  }

  @Test
  func tokenCLIUsesNeitherWorkingDirectoryNorConfigurationAndWritesNoHardwarePrompt() throws {
    let transport = MemoryTransport { request in
      #expect(request == .recoveryReview(.tokens))
      return .init(exitCode: 0, value: nil, errorMessage: nil, recoveryReview: .tokens([]))
    }
    for json in [false, true] {
      let io = MemoryIO(stdinIsTTY: false)
      let app = KeyCLIApplication(
        transport: transport, io: io, clipboard: MemoryClipboard(),
        currentDirectory: {
          Issue.record("Listing must not resolve paths")
          return URL(fileURLWithPath: "/")
        })
      #expect(
        app.run(arguments: ["recovery", "tokens"] + (json ? ["--json"] : [])) == EXIT_SUCCESS)
      #expect(io.stderr.isEmpty)
      if json {
        #expect(
          try JSONDecoder().decode(KeyRecoveryReviewResult.self, from: Data(io.stdout.utf8))
            == .tokens([]))
      } else {
        #expect(io.stdout.contains("No connected token candidates"))
        #expect(io.stdout.contains("does not select a key"))
      }
    }
    #expect(transport.requests.count == 2)
  }

  @Test
  func cliRejectsMissingDuplicateCredentialOrMutationOptionsAndMismatchedPayload() throws {
    let valid = ["recovery", "review", "--source", "source", "--token", "token"]
    let bad =
      [
        ["recovery", "review"], Array(valid.dropLast(2)),
        valid + ["--source=other"], valid + ["--token", "other"],
        ["recovery", "review", "--source", "", "--token", "token"],
        ["recovery", "review", "--source", "source", "--token", "bad\nvalue"],
      ]
      + ["--pin", "--puk", "--management-key", "--force", "--recipient", "--destination", "--name"]
      .map { valid + [$0, "not-input"] }
    for arguments in bad {
      let transport = MemoryTransport { _ in
        Issue.record("Bad syntax must not dispatch")
        return .success()
      }
      let io = MemoryIO(stdinIsTTY: false)
      #expect(
        KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard())
          .run(arguments: arguments) == KeyServiceErrorCode.invalidUsage.exitCode.rawValue)
      #expect(transport.requests.isEmpty && io.stdout.isEmpty)
    }
    let f = try Fixture()
    defer { f.remove() }
    let wrong = try KeyRecoveryReviewWorkflow(reader: f.reader).handle(request(f), scope: scope())
    for response in [.success(), .failure("Public review unavailable"), wrong] {
      let io = MemoryIO(stdinIsTTY: false)
      let transport = MemoryTransport { _ in response }
      #expect(
        KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard())
          .run(arguments: ["recovery", "tokens", "--json"]) != EXIT_SUCCESS)
      #expect(io.stdout.isEmpty && transport.requests.count == 1)
      #expect(!io.stderr.contains("key recovery resume"))
    }
  }

  @Test(arguments: 0..<3)
  func credentialInspectionReportsOccupancyWithoutPrivateWorkOrVaultReads(occupancy: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    if occupancy == 0 { f.card.anchor = nil }
    if occupancy == 2 { f.card.anchor = Data([1]) }
    let response = try KeyRecoveryReviewWorkflow(reader: f.reader).handle(
      .credential(tokenID: f.card.tokenID), scope: scope())
    guard case .credential(let credential) = response.recoveryReview else {
      Issue.record("Expected public credential report")
      return
    }
    let states: [KeyRecoveryReviewResult.Credential.AnchorState] = [
      .absent, .recognized, .unrecognized,
    ]
    #expect(credential.anchorState == states[occupancy])
    #expect(credential.recipientID == f.source.anchor.recipientID.rawValue)
    #expect(credential.assurance == .publicObservationOnly)
    #expect(f.provider.requests == 0 && f.identities.creates.value == 0)
    #expect(
      f.reservations.value == nil && f.preparations.value == nil && f.checkpoints.value == nil)
  }

  private func request(_ f: Fixture) -> KeyRecoveryReviewRequest {
    .source(path: f.source.root.path, tokenID: f.card.tokenID)
  }
  private func scope() -> KeyRecoveryRequestScope {
    .init(authentication: .init(), deadline: .now() + 90)
  }
  private func host(
    review:
      @escaping (KeyRecoveryReviewRequest, KeyRecoveryRequestScope) throws -> KeyServiceResponse,
    configurationReads: Counter = Counter()
  ) -> KeyServiceHost {
    KeyServiceHost(
      hasConfiguration: {
        configurationReads.increment()
        return false
      },
      makeHandler: {
        Issue.record("Public review must not compose runtime")
        return { _ in .success() }
      },
      initialize: { _ in "Initialized" }, reviewRecovery: review)
  }
  private func reader(_ f: Fixture, after: @escaping @Sendable (Int) throws -> Void)
    -> PIVRecoveryTokenReader
  {
    .init(
      inventory: Inventory(cards: [Connection(card: f.card, after: after)]),
      gate: PIVTokenOperationGate())
  }
  private struct Inventory: PIVRecoveryTokenInventoryProviding {
    let cards: [any PIVRecoveryTokenConnection]
    func connections(maximumCount: Int) throws -> [any PIVRecoveryTokenConnection] { cards }
  }
  private final class Connection: PIVRecoveryTokenConnection, @unchecked Sendable {
    let card: V3RecoveryRegistrationServiceTests.Card
    let after: @Sendable (Int) throws -> Void
    let count = Counter()
    init(
      card: V3RecoveryRegistrationServiceTests.Card, after: @escaping @Sendable (Int) throws -> Void
    ) {
      self.card = card
      self.after = after
    }
    var tokenID: String { card.tokenID }
    var readerSlotName: String { card.readerSlotName }
    var isValid: Bool { card.isValid }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      let result = try card.withPublicReadSession(lease: lease, consume)
      try after(count.increment())
      return result
    }
  }
  private struct ClearOwnership: V3RecoveryRestoreOwnershipChecking {
    func hasPendingRestore() -> Bool { false }
  }
  private struct UnreadableOwnership: V3RecoveryRestoreOwnershipChecking {
    let calls = Counter()
    func hasPendingRestore() throws -> Bool {
      calls.increment()
      throw Stop.unexpected
    }
  }
  private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    @discardableResult func increment() -> Int {
      lock.withLock {
        count += 1
        return count
      }
    }
    var value: Int { lock.withLock { count } }
  }
  private final class State: @unchecked Sendable {
    let locks = Counter()
    private let lock = NSLock()
    private var stored: KeyServiceResponse?
    private var captured: KeyRecoveryRequestScope?
    var scope: KeyRecoveryRequestScope? {
      get { lock.withLock { captured } }
      set { lock.withLock { captured = newValue } }
    }
    var response: KeyServiceResponse? {
      get { lock.withLock { stored } }
      set { lock.withLock { stored = newValue } }
    }
  }
  private final class HostBox: @unchecked Sendable {
    let host: KeyServiceHost
    init(_ host: KeyServiceHost) { self.host = host }
  }
}
