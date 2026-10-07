import Foundation
import Testing

@testable import KeyCore

struct KeyRecoveryRegistrationRoutingTests {
  private static let recipient = Base64URL.encode(Data(repeating: 7, count: 32))
  private static let requests: [KeyRecoveryRegistrationRequest] = [
    .status, .prepare(tokenID: "token", recipientID: recipient),
    .resumeExport(tokenID: "token", recipientID: recipient),
    .finish(tokenID: "token", recipientID: recipient), .adopt,
    .resumeAdoption(operationID: VaultTransactionOperationID().rawValue),
  ]
  private enum Stop: Error { case interrupted }

  @Test(arguments: requests)
  func requestsRoundTripCarryPublicSelectorsAndUseBoundedFullCLIAdmission(
    action: KeyRecoveryRegistrationRequest
  ) throws {
    let request = KeyServiceRequest.recoveryRegistration(action)
    let bytes = try JSONEncoder().encode(request)
    #expect(try JSONDecoder().decode(KeyServiceRequest.self, from: bytes) == request)
    try action.validate()
    #expect(request.responseTimeoutSeconds == 120)
    #expect(request.requiresHelperShutdownAfterSuccess == action.changesCheckpoint)
    #expect(KeyXPCClientRole.fullCLI.authorizes(request))
    #expect(!KeyXPCClientRole.utilityStatus.authorizes(request))
    let fields = String(decoding: bytes, as: UTF8.self)
    #expect(
      !fields.contains("PIN") && !fields.contains("vaultKey") && !fields.contains("management"))
  }

  @Test(arguments: requests)
  func disabledRouteDoesNotInspectConfigurationOrComposeRuntime(
    action: KeyRecoveryRegistrationRequest
  ) {
    let host = KeyServiceHost(
      hasConfiguration: {
        Issue.record("Disabled setup read config")
        return true
      },
      makeHandler: {
        Issue.record("Disabled setup composed runtime")
        return { _ in .success() }
      },
      initialize: { _ in
        Issue.record("Setup is not init")
        return ""
      })
    #expect(
      host.handle(.recoveryRegistration(action)).errorMessage?.contains("not enabled") == true)
  }

  @Test(arguments: 0..<5)
  func invalidSelectorsNeverReachConfiguredSetup(variant: Int) {
    let action: KeyRecoveryRegistrationRequest
    switch variant {
    case 0: action = .prepare(tokenID: "", recipientID: Self.recipient)
    case 1: action = .finish(tokenID: "token\nother", recipientID: Self.recipient)
    case 2: action = .resumeExport(tokenID: "token", recipientID: "prefix")
    case 3:
      action = .prepare(tokenID: String(repeating: "t", count: 1_025), recipientID: Self.recipient)
    default: action = .resumeAdoption(operationID: "prefix")
    }
    let host = KeyServiceHost(
      hasConfiguration: {
        Issue.record("Invalid setup read config")
        return true
      },
      makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      registerRecovery: { _, _ in
        Issue.record("Invalid setup reached service")
        return .success()
      })
    #expect(host.handle(.recoveryRegistration(action)).exitCode != EXIT_SUCCESS)
  }

  @Test(arguments: requests)
  func setupRequiresConfigurationAndCannotInitializeIt(action: KeyRecoveryRegistrationRequest) {
    let host = KeyServiceHost(
      hasConfiguration: { false }, makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      registerRecovery: { _, _ in
        Issue.record("Unconfigured setup reached service")
        return .success()
      })
    #expect(host.handle(.recoveryRegistration(action)).exitCode != EXIT_SUCCESS)
  }

  @Test(
    arguments: [false, true],
    [KeyRecoveryRegistrationRequest.adopt, .finish(tokenID: "token", recipientID: recipient)])
  func checkpointChangingSetupRetiresRuntimeEvenAfterAnAmbiguousFailure(
    throwing: Bool, action: KeyRecoveryRegistrationRequest
  ) {
    let events = Events()
    let host = KeyServiceHost(
      hasConfiguration: { true },
      makeHandler: {
        { request in
          events.values.append(request == .lock ? "lock" : "normal")
          return .success()
        }
      }, initialize: { _ in "" },
      registerRecovery: { _, scope in
        try scope.requireCurrent()
        events.values.append("setup")
        if throwing { throw Stop.interrupted }
        return .failure("Uncertain result")
      })
    #expect(host.handle(.list).exitCode == EXIT_SUCCESS)
    #expect(host.handle(.recoveryRegistration(action)).exitCode != EXIT_SUCCESS)
    #expect(events.values == ["normal", "lock", "setup"])
    #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
    #expect(
      host.handle(.recoveryRegistration(.status)).errorMessage?.contains("restarting") == true)
  }

  @Test func disconnectedSetupScopeCannotReportLateSuccess() {
    let connection = KeyServiceConnection()
    let host = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      registerRecovery: { _, scope in
        connection.invalidate()
        #expect(throws: (any Error).self) { try scope.requireCurrent() }
        return .success("Must not escape")
      })
    #expect(
      host.handle(.recoveryRegistration(.status), connection: connection).exitCode != EXIT_SUCCESS)
  }

  private final class Events: @unchecked Sendable { var values: [String] = [] }
}
