import Foundation
import Testing

@testable import KeyCore

struct KeyRecoveryRecipientRemovalRoutingTests {
  private static let id = Base64URL.encode(Data(repeating: 7, count: 32))
  private static let actions: [KeyRecoveryRecipientRemovalRequest] = [
    .review(recipientID: id),
    .remove(
      recipientID: id, confirmationToken: String(repeating: "a", count: 64),
      pendingOperationID: nil, acknowledgesProtectionLoss: true),
  ]

  @Test(arguments: actions)
  func publicRequestRoundTripsIsFullCLIOnlyAndHasNoHardwareProgress(
    action: KeyRecoveryRecipientRemovalRequest
  ) throws {
    let request = KeyServiceRequest.recoveryRecipientRemoval(action)
    let data = try JSONEncoder().encode(request)
    #expect(try JSONDecoder().decode(KeyServiceRequest.self, from: data) == request)
    try action.validate()
    #expect(
      KeyXPCClientRole.fullCLI.authorizes(request)
        && !KeyXPCClientRole.utilityStatus.authorizes(request))
    #expect(request.responseTimeoutSeconds == 120 && !request.requiresHelperShutdownAfterSuccess)
    #expect(!request.supportsRecoveryProgress)
  }

  @Test(arguments: actions)
  func disabledRouteDoesNotInspectConfigOrCompose(action: KeyRecoveryRecipientRemovalRequest) {
    let host = KeyServiceHost(
      hasConfiguration: {
        Issue.record("Disabled request read config")
        return true
      },
      makeHandler: {
        Issue.record("Disabled request composed")
        return { _ in .success() }
      }, initialize: { _ in "" })
    #expect(
      host.handle(.recoveryRecipientRemoval(action)).errorMessage?.contains("not enabled") == true)
  }

  @Test(arguments: [false, true])
  func reviewAndExecutionRetireCacheWithoutBlockingSameProfileRequests(failure: Bool) {
    var events: [String] = []
    var generation = 0
    let host = KeyServiceHost(
      hasConfiguration: { true },
      makeHandler: {
        generation += 1
        let own = generation
        return { request in
          events.append("\(own):\(request == .lock ? "lock" : "ordinary")")
          return .success()
        }
      }, initialize: { _ in "" },
      removeRecoveryRecipient: { request, _ in
        events.append("removal")
        if failure { throw AppError.operationRefused("uncertain") }
        return .success()
      })
    #expect(host.handle(.list).exitCode == EXIT_SUCCESS)
    for action in Self.actions {
      #expect(
        host.handle(.recoveryRecipientRemoval(action)).exitCode
          == (failure ? EXIT_FAILURE : EXIT_SUCCESS))
    }
    #expect(host.handle(.list).exitCode == EXIT_SUCCESS)
    #expect(events == ["1:ordinary", "1:lock", "removal", "removal", "2:ordinary"])
  }

  @Test func invalidReviewSelectorsCannotReachCapability() {
    let host = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      removeRecoveryRecipient: { _, _ in
        Issue.record("Invalid request admitted")
        return .success()
      })
    for request in [
      KeyRecoveryRecipientRemovalRequest.review(recipientID: "prefix"),
      .remove(
        recipientID: Self.id, confirmationToken: "prefix", pendingOperationID: nil,
        acknowledgesProtectionLoss: true),
      .remove(
        recipientID: Self.id, confirmationToken: String(repeating: "a", count: 64),
        pendingOperationID: "prefix", acknowledgesProtectionLoss: true),
    ] {
      #expect(host.handle(.recoveryRecipientRemoval(request)).exitCode != EXIT_SUCCESS)
    }
  }

  @Test func pendingReplacementAndConnectionCancellationBlockCompetingWork() {
    let blocked = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      removeRecoveryRecipient: { _, _ in
        Issue.record("Replacement bypassed")
        return .success()
      },
      requireNoPendingReplacement: { throw AppError.operationRefused("Replacement unfinished") })
    #expect(
      blocked.handle(.recoveryRecipientRemoval(Self.actions[0])).errorMessage?.contains(
        "Replacement unfinished") == true)
    let connection = KeyServiceConnection()
    let cancelled = KeyServiceHost(
      hasConfiguration: { true }, makeHandler: { { _ in .success() } }, initialize: { _ in "" },
      removeRecoveryRecipient: { _, scope in
        connection.invalidate()
        #expect(throws: (any Error).self) { try scope.requireCurrent() }
        return .success("late")
      })
    #expect(
      cancelled.handle(.recoveryRecipientRemoval(Self.actions[0]), connection: connection).exitCode
        != EXIT_SUCCESS)
  }
}
