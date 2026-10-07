import Foundation
import Testing

@testable import KeyCore

struct KeyRecoveryRoutingTests {
  private enum Stop: Error { case interrupted }
  private static let recipient = Base64URL.encode(Data(repeating: 7, count: 32))
  private static let restore = KeyRecoveryRequest.restore(
    source: "/backup", destination: "/new-vault", tokenID: "selected-token",
    recipientID: recipient, deviceName: "New Mac")
  private static let resume = KeyRecoveryRequest.resume(
    source: "/backup", destination: "/new-vault", tokenID: "selected-token",
    recipientID: recipient)

  @Test(arguments: [restore, resume])
  func publicRequestsRoundTripWithoutCredentialsAndRequireBoundedReplyAndRestart(
    action: KeyRecoveryRequest
  ) throws {
    let request = KeyServiceRequest.recovery(action)
    let bytes = try JSONEncoder().encode(request)
    #expect(try JSONDecoder().decode(KeyServiceRequest.self, from: bytes) == request)
    #expect(KeyXPCClientRole.fullCLI.authorizes(request))
    #expect(!KeyXPCClientRole.utilityStatus.authorizes(request))
    #expect(request.responseTimeoutSeconds == 120)
    #expect(KeyRecoveryRequest.maximumDurationSeconds < 120)
    #expect(request.requiresHelperShutdownAfterSuccess)
    let fields = String(decoding: bytes, as: UTF8.self)
    #expect(!fields.contains("secret") && !fields.contains("PIN") && !fields.contains("vaultKey"))
    try action.validate()
    let message = KeyXPCClientTransport.helperRestartTimeoutError(
      for: request, helperName: "Key Agent", timeoutSeconds: 30
    ).localizedDescription
    #expect(message.contains("Do not start another restore"))
  }

  @Test(arguments: 0..<9)
  func invalidPublicSelectorsNeverReachRecoveryOrComposeRuntime(variant: Int) {
    var source = "/backup"
    var destination = "/new-vault"
    var token = "token"
    var recipient = Self.recipient
    var name = "Mac"
    switch variant {
    case 0: source = "relative"
    case 1: destination = ""
    case 2: source += "\0"
    case 3: destination = "/" + String(repeating: "a", count: 4_096)
    case 4: token = ""
    case 5: token += "\0"
    case 6: token = String(repeating: "a", count: 1_025)
    case 7: recipient = "not a recipient"
    default: name = ""
    }
    let host = makeHost(recover: { _, _ in
      Issue.record("Invalid request must not reach recovery")
      return .success()
    })
    let request = KeyRecoveryRequest.restore(
      source: source, destination: destination, tokenID: token, recipientID: recipient,
      deviceName: name)
    #expect(host.handle(.recovery(request)).exitCode != EXIT_SUCCESS)
    #expect(host.handle(.initializeVault(path: "/init")) == .success("Initialized"))
  }

  @Test(arguments: [restore, resume])
  func disabledCapabilityDoesNotReadConfigurationOrComposeAnything(action: KeyRecoveryRequest) {
    let host = KeyServiceHost(
      hasConfiguration: {
        Issue.record("Disabled route must not inspect config")
        return false
      },
      makeHandler: {
        Issue.record("Disabled route must not compose")
        return { _ in .success() }
      },
      initialize: { _ in
        Issue.record("Recovery is not init")
        return ""
      })
    #expect(host.handle(.recovery(action)).errorMessage?.contains("not enabled") == true)
  }

  @Test(arguments: [KeyProductIdentity.stable, .preview])
  func liveProductsKeepRecoveryDisabled(identity: KeyProductIdentity) throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let host = KeyServiceHost.live(
      keyStore: MemoryVaultKeyStore(), configStore: .init(homeDirectoryURL: root),
      runtimeConfiguration: .init(productIdentity: identity))
    #expect(host.handle(.recovery(Self.restore)).errorMessage?.contains("not enabled") == true)
    #expect(!FileManager.default.fileExists(atPath: root.path))
  }

  @Test func configuredRuntimeIsNeverReplacedAndColdSelectedResumeDoesNotComposeIt() {
    let state = State()
    state.configured = true
    let host = makeHost(
      state: state,
      recover: { action, _ in
        #expect(action == Self.resume)
        state.incrementCalls()
        return .success("Finished")
      })
    #expect(host.handle(.recovery(Self.restore)).exitCode != EXIT_SUCCESS)
    #expect(state.calls == 0)
    #expect(host.handle(.recovery(Self.resume)) == .success("Finished"))
    #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
    #expect(host.handle(.lock) == .success())
    let composed = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success("Normal") } },
      initialize: { _ in "" },
      recover: { _, _ in
        Issue.record("Active configured runtime cannot enter recovery")
        return .success()
      })
    #expect(composed.handle(.list) == .success("Normal"))
    #expect(composed.handle(.recovery(Self.resume)).exitCode != EXIT_SUCCESS)
  }

  @Test(arguments: [false, true])
  func selectedConfigurationBlocksOldRuntimeAfterFailureOrLostResult(throwing: Bool) {
    let state = State()
    let host = makeHost(
      state: state,
      recover: { _, _ in
        state.configured = true
        if throwing { throw Stop.interrupted }
        return .failure("Interrupted")
      })
    #expect(host.handle(.recovery(Self.restore)).exitCode != EXIT_SUCCESS)
    for request in [
      KeyServiceRequest.list, .initializeVault(path: "/init"),
      .setVaultDirectory(path: "/other"), .recovery(Self.resume),
    ] {
      #expect(host.handle(request).errorMessage?.contains("restarting") == true)
    }
    #expect(host.handle(.lock) == .success())
  }

  @Test func uncertainUnselectedAttemptBlocksCompetingSetupButAllowsExplicitResume() {
    let state = State()
    let host = makeHost(
      state: state,
      recover: { action, _ in
        state.incrementCalls()
        if action.isInitialRestore { throw Stop.interrupted }
        state.configured = true
        return .success("Resumed")
      })
    #expect(host.handle(.recovery(Self.restore)).exitCode != EXIT_SUCCESS)
    for request in [
      KeyServiceRequest.initializeVault(path: "/init"),
      .shareInDirectory(request: .invitations, path: "/join"),
      .setVaultDirectory(path: "/other"), .recovery(Self.restore),
    ] {
      #expect(host.handle(request).errorMessage?.contains("saved attempt") == true)
    }
    #expect(state.calls == 1)
    #expect(host.handle(.status).helperStatus?.isUnlocked == false)
    #expect(host.handle(.recovery(Self.resume)) == .success("Resumed"))
    #expect(state.calls == 2)
  }

  @Test(arguments: [false, true])
  func successRequiresCurrentScopeAndActualConfigurationAndFinishedScopeCannotBeReused(
    disconnectDuringSelectionCheck: Bool
  ) throws {
    let state = State()
    let connection = KeyServiceConnection()
    let host = KeyServiceHost(
      hasConfiguration: {
        if disconnectDuringSelectionCheck, state.scope != nil {
          connection.invalidate()
          return true
        }
        return false
      },
      makeHandler: {
        Issue.record("No runtime")
        return { _ in .success() }
      },
      initialize: { _ in "" },
      recover: { _, scope in
        state.scope = scope
        return .success("Unsupported success")
      })
    #expect(host.handle(.recovery(Self.restore), connection: connection).exitCode != EXIT_SUCCESS)
    let scope = try #require(state.scope)
    #expect(scope.cancellation.isCancelled && !scope.authentication.hasResidentKey)
    #expect(throws: PIVRecoveryAgreementError.cancelled) { try scope.requireCurrent() }
  }

  @Test func lockCancelsBeforeWaitingForExclusiveQueueAndLateSuccessIsRefused() throws {
    let state = State()
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let finished = DispatchSemaphore(value: 0)
    let host = makeHost(
      state: state,
      recover: { _, scope in
        state.scope = scope
        entered.signal()
        #expect(release.wait(timeout: .now() + 5) == .success)
        state.configured = true
        return .success("Late response")
      })
    let box = HostBox(host)
    DispatchQueue.global().async {
      state.response = box.host.handle(.recovery(Self.restore))
      finished.signal()
    }
    defer { release.signal() }
    #expect(entered.wait(timeout: .now() + 5) == .success)
    #expect(host.handle(.lock) == .success())
    let scope = try #require(state.scope)
    #expect(scope.cancellation.isCancelled)
    #expect(host.handle(.recovery(Self.resume)).errorMessage?.contains("Another recovery") == true)
    #expect(throws: (any Error).self) { try scope.requireCurrent() }
    release.signal()
    #expect(finished.wait(timeout: .now() + 5) == .success)
    #expect(state.response?.exitCode != EXIT_SUCCESS)
    #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
  }

  @Test func disconnectCancelsActiveAndRejectsClosedConnectionWithoutAffectingOthers() throws {
    let state = State()
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let finished = DispatchGroup()
    let connection = KeyServiceConnection()
    let other = KeyServiceConnection()
    let host = makeHost(
      state: state,
      recover: { _, scope in
        state.incrementCalls()
        state.scope = scope
        entered.signal()
        #expect(release.wait(timeout: .now() + 5) == .success)
        try scope.requireCurrent()
        throw Stop.interrupted
      })
    let box = HostBox(host)
    finished.enter()
    DispatchQueue.global().async {
      _ = box.host.handle(.recovery(Self.restore), connection: connection)
      finished.leave()
    }
    defer { release.signal() }
    #expect(entered.wait(timeout: .now() + 5) == .success)
    finished.enter()
    DispatchQueue.global().async {
      #expect(
        box.host.handle(.recovery(Self.resume), connection: connection).exitCode != EXIT_SUCCESS)
      finished.leave()
    }
    connection.invalidate()
    connection.invalidate()
    #expect(try #require(state.scope).cancellation.isCancelled)
    let late = KeyRecoveryRequestScope(authentication: .init(), deadline: .now() + 30)
    connection.register(late)
    #expect(throws: PIVRecoveryAgreementError.cancelled) { try late.requireCurrent() }
    let independent = KeyRecoveryRequestScope(
      authentication: .init(), deadline: .now() + 30)
    other.register(independent)
    try independent.requireCurrent()
    release.signal()
    #expect(finished.wait(timeout: .now() + 5) == .success)
    #expect(state.calls == 1)
    #expect(host.handle(.recovery(Self.resume), connection: connection).exitCode != EXIT_SUCCESS)
    #expect(state.calls == 1)
    other.remove(independent)
    other.invalidate()
    try independent.requireCurrent()
  }

  @Test func queuedAuthenticationTicketAndExpiredDeadlineCannotBecomeFreshScope() {
    let authentication = V3DeviceWrappedVaultKeySessionStore()
    let queued = KeyRecoveryRequestScope(authentication: authentication, deadline: .now() + 30)
    authentication.invalidate()
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) { try queued.requireCurrent() }
    let expired = KeyRecoveryRequestScope(authentication: authentication, deadline: .now())
    #expect(throws: PIVRecoveryAgreementError.deadlineExceeded) { try expired.requireCurrent() }
  }

  @Test func concurrentInitialRequestsAdmitOnlyOneAttempt() {
    let state = State()
    let host = makeHost(
      state: state,
      recover: { _, _ in
        state.incrementCalls()
        state.configured = true
        return .success("Selected")
      })
    let box = HostBox(host)
    DispatchQueue.concurrentPerform(iterations: 8) { _ in
      _ = box.host.handle(.recovery(Self.restore))
    }
    #expect(state.calls == 1)
  }

  @Test func exclusiveRecoveryCannotOverlapInitEnrollmentOrConfigurationChanges() {
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let finished = DispatchGroup()
    let host = makeHost(recover: { _, _ in
      entered.signal()
      #expect(release.wait(timeout: .now() + 5) == .success)
      throw Stop.interrupted
    })
    let box = HostBox(host)
    finished.enter()
    DispatchQueue.global().async {
      _ = box.host.handle(.recovery(Self.restore))
      finished.leave()
    }
    defer { release.signal() }
    #expect(entered.wait(timeout: .now() + 5) == .success)
    for request in [
      KeyServiceRequest.initializeVault(path: "/init"),
      .shareInDirectory(request: .invitations, path: "/join"), .setVaultDirectory(path: "/other"),
    ] {
      finished.enter()
      DispatchQueue.global().async {
        #expect(box.host.handle(request).errorMessage?.contains("saved attempt") == true)
        finished.leave()
      }
    }
    release.signal()
    #expect(finished.wait(timeout: .now() + 5) == .success)
  }

  @Test(arguments: 0..<3, [false, true])
  func actualRestoreRetainsExactEvidenceWhenHostLockOrDisconnectCancels(
    phase: Int, disconnect: Bool
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try V3RecoveryRestoreServiceTests.Fixture()
    defer { f.remove() }
    let state = State()
    let connection = KeyServiceConnection()
    let box = HostBox()
    let stops: [V3RecoveryRestoreServicePhase] = [
      .preparationDurable, .publication(.manifestPublished), .selection(.configurationSelected),
    ]
    let host = KeyServiceHost(
      hasConfiguration: { try f.config.hasConfiguration() },
      makeHandler: {
        Issue.record("Do not compose after recovery")
        return { _ in .success() }
      },
      initialize: { _ in
        Issue.record("Never init an owned attempt")
        return ""
      },
      recover: { _, scope in
        state.scope = scope
        let observer = Observer { event in
          if event == stops[phase] {
            if disconnect {
              connection.invalidate()
            } else {
              #expect(box.host.handle(.lock) == .success())
            }
          }
        }
        _ = try V3RecoveryRestoreService(
          configStore: f.config, journal: f.journal(), identities: f.identities,
          checkpoints: f.checkpoints, cache: f.cache, mutationOwner: f.owner, reader: f.reader,
          agreement: f.agreement, authentication: scope.authentication, observer: observer
        ).restore(
          source: f.sourceHandle, parent: f.parentHandle, name: "restored", deviceName: "New Mac",
          observation: f.reader.read(try #require(f.reader.candidates().first)),
          cancellation: scope.cancellation, deadline: scope.deadline)
        return .success("Completed")
      })
    box.assign(host)
    #expect(host.handle(.recovery(Self.restore), connection: connection).exitCode != EXIT_SUCCESS)
    #expect(f.provider.requests == 1 && f.identities.creates.value == 1)
    #expect(f.reservations.value != nil && f.preparations.value != nil)
    #expect(try !#require(state.scope).authentication.hasResidentKey)
    if phase == 2 {
      #expect(try f.config.hasConfiguration())
      #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
    } else {
      #expect(try !f.config.hasConfiguration())
      #expect(host.handle(.initializeVault(path: "/other")).exitCode != EXIT_SUCCESS)
    }
  }

  private func makeHost(
    state: State = State(),
    recover: @escaping (KeyRecoveryRequest, KeyRecoveryRequestScope) throws -> KeyServiceResponse
  ) -> KeyServiceHost {
    KeyServiceHost(
      hasConfiguration: { state.configured },
      makeHandler: {
        Issue.record("Unexpected runtime composition")
        return { _ in .success() }
      },
      initialize: { _ in "Initialized" },
      enroll: { _, _ in
        Issue.record("Cannot enroll after uncertain restore")
        return .success()
      },
      recover: recover)
  }

  private struct Observer: V3RecoveryRestoreServicePhaseObserving {
    let action: @Sendable (V3RecoveryRestoreServicePhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreServicePhase) throws { try action(phase) }
  }
  private final class State: @unchecked Sendable {
    private let lock = NSLock()
    private var selected = false, count = 0
    private var captured: KeyRecoveryRequestScope?, result: KeyServiceResponse?
    var configured: Bool {
      get { lock.withLock { selected } }
      set { lock.withLock { selected = newValue } }
    }
    var calls: Int { lock.withLock { count } }
    func incrementCalls() { lock.withLock { count += 1 } }
    var scope: KeyRecoveryRequestScope? {
      get { lock.withLock { captured } }
      set { lock.withLock { captured = newValue } }
    }
    var response: KeyServiceResponse? {
      get { lock.withLock { result } }
      set { lock.withLock { result = newValue } }
    }
  }
  private final class HostBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: KeyServiceHost?
    init(_ host: KeyServiceHost? = nil) { value = host }
    func assign(_ host: KeyServiceHost) { lock.withLock { value = host } }
    var host: KeyServiceHost { lock.withLock { value! } }
  }
}
