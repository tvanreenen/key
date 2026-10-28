import Foundation
import Testing

@testable import KeyCore

struct KeyRecoverySharingRoutingTests {
  private enum Stop: Error { case interrupted }
  private let approve = KeyShareRequest.approve(
    vaultID: "vault", invitationID: "invitation", comparisonCode: "compared")

  @Test(arguments: [false, true])
  func pendingReplacementBlocksOtherSetupBeforeCompositionOrRetirement(warm: Bool) {
    var effects: [String] = []
    let host = KeyServiceHost(
      hasConfiguration: { true },
      makeHandler: {
        effects.append("compose")
        return { request in
          effects.append(request == .lock ? "lock" : "ordinary")
          return .success()
        }
      }, initialize: { _ in "" }, updateVaultDirectory: { _ in effects.append("move") },
      registerRecovery: { _, _ in
        effects.append("register")
        return .success()
      },
      rotateRecovery: { _, _ in
        effects.append("rotate")
        return .success()
      },
      requireNoPendingReplacement: { throw AppError.operationRefused("Replacement unfinished") })
    if warm { #expect(host.handle(.list).exitCode == EXIT_SUCCESS) }
    let before = effects
    for request in [
      KeyServiceRequest.setVaultDirectory(path: "/other"),
      .recoveryRegistration(.status), .recoveryRegistration(.adopt), .recoveryRotation(.rotate),
    ] {
      #expect(host.handle(request).errorMessage?.contains("Replacement unfinished") == true)
      #expect(effects == before)
    }
  }

  @Test func replacementAdmissionStillAllowsItsOwnExplicitHandoff() {
    let host = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } },
      initialize: { _ in "" },
      recoverySharing: .init { _, _, scope in
        try scope.requireCurrent()
        return .init(changesCheckpoint: false) { .success("handoff") }
      }, requireNoPendingReplacement: { Issue.record("Handoff was treated as competing setup") })
    #expect(host.handle(.share(.reviewReplacement)) == .success("handoff"))
  }

  @Test(arguments: [false, true])
  func checkpointChangeRetiresOldRuntimeAndAllowsFreshCompositionAfterUncertainty(throwing: Bool) {
    var events: [String] = []
    var generation = 0
    let host = KeyServiceHost(
      hasConfiguration: { true },
      makeHandler: {
        generation += 1
        let current = generation
        return { request in
          events.append("\(current):\(request == .lock ? "lock" : "read")")
          return .success()
        }
      }, initialize: { _ in "" },
      recoverySharing: .init { _, _, scope in
        try scope.requireCurrent()
        return .init(changesCheckpoint: true) {
          events.append("approve")
          if throwing { throw Stop.interrupted }
          return .success()
        }
      })
    #expect(host.handle(.list).exitCode == EXIT_SUCCESS)
    #expect(host.handle(.share(approve)).exitCode == (throwing ? EXIT_FAILURE : EXIT_SUCCESS))
    #expect(host.handle(.list).exitCode == EXIT_SUCCESS)
    #expect(events == ["1:read", "1:lock", "approve", "2:read"])
  }

  @Test(arguments: [false, true])
  func stoppedScopeRejectsLateSuccess(lock: Bool) {
    let connection = KeyServiceConnection()
    var host: KeyServiceHost!
    host = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } },
      initialize: { _ in "" },
      recoverySharing: .init { _, _, scope in
        .init(changesCheckpoint: false) {
          if lock {
            #expect(host.handle(.lock).exitCode == EXIT_SUCCESS)
          } else {
            connection.invalidate()
          }
          #expect(throws: (any Error).self) { try scope.requireCurrent() }
          return .success("late")
        }
      })
    #expect(host.handle(.share(.devices), connection: connection).exitCode != EXIT_SUCCESS)
  }

  @Test func disconnectedRequestNeverPreparesOrPerforms() {
    let connection = KeyServiceConnection()
    connection.invalidate()
    let host = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      recoverySharing: .init { _, _, _ in
        Issue.record("Disconnected work composed")
        return nil
      })
    #expect(host.handle(.share(.devices), connection: connection).exitCode != EXIT_SUCCESS)
  }

  @Test func permanentFallbackUsesExistingHandlerAndRefusesFolderSwitchBeforePreparation() {
    var prepared = 0
    var reads = 0
    let host = KeyServiceHost(
      hasConfiguration: { true },
      makeHandler: {
        { _ in
          reads += 1
          return .success()
        }
      },
      initialize: { _ in "" }, configuredDirectory: { URL(fileURLWithPath: "/selected") },
      recoverySharing: .init { _, _, _ in
        prepared += 1
        return nil
      })
    #expect(
      host.handle(.shareInDirectory(request: .invitations, path: "/elsewhere")).exitCode
        != EXIT_SUCCESS)
    #expect(prepared == 0 && reads == 0)
    #expect(
      host.handle(.shareInDirectory(request: .invitations, path: "/selected")).exitCode
        == EXIT_SUCCESS)
    #expect(prepared == 1 && reads == 1)
    #expect(host.handle(.share(.devices)).exitCode == EXIT_SUCCESS)
    #expect(prepared == 2 && reads == 2)
  }

  @Test(arguments: [false, true])
  func selectedJoiningAttemptCannotComposeAnOrdinaryRuntimeAfterLostReply(failure: Bool) {
    var selected = false
    let host = KeyServiceHost(
      hasConfiguration: { selected },
      makeHandler: {
        Issue.record("Uncertain selection composed runtime")
        return { _ in .success() }
      }, initialize: { _ in "" },
      recoverySharing: .init { _, _, _ in
        .init(changesCheckpoint: true) {
          selected = true
          if failure { throw Stop.interrupted }
          return .success()
        }
      })
    let response = host.handle(
      .shareInDirectory(
        request: .accept(vaultID: "vault", invitationID: "invitation", comparisonCode: "code"),
        path: "/selected"))
    #expect(response.exitCode == (failure ? EXIT_FAILURE : EXIT_SUCCESS))
    #expect(host.handle(.list).errorMessage?.contains("restarting") == true)
  }
}
