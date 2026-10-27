import Foundation
import Testing

@testable import KeyCore

struct RecoveryRecipientRemovalCLITests {
  private static let id = Base64URL.encode(Data(repeating: 7, count: 32))
  private static let other = Base64URL.encode(Data(repeating: 8, count: 32))
  private static let vault = V3RecoveryRegistrationTestSupport.vaultID
  private static let digest = String(repeating: "a", count: 64)
  private let args = ["recovery", "remove-recipient", Self.id]

  @Test func parserRequiresOneCompleteRecipientAndOffersNoCredentialOrForceOptions() throws {
    #expect(try CLIParser.parse(arguments: args) == .recoveryRecipientRemoval(recipientID: Self.id))
    for input in [
      ["recovery", "remove-recipient"], ["recovery", "remove-recipient", "prefix"],
      args + [Self.other], args + ["--force"], args + ["--yes"], args + ["--pin", "secret"],
    ] {
      #expect(throws: AppError.self) { try CLIParser.parse(arguments: input) }
    }
    guard
      case .help(let help) = try CLIParser.parse(arguments: [
        "recovery", "remove-recipient", "--help",
      ])
    else {
      Issue.record("Expected command help")
      return
    }
    #expect(
      help.split(whereSeparator: \.isWhitespace).joined(separator: " ").contains(
        "REMOVE LAST RECOVERY KEY"))
    let leadingDash = Base64URL.encode(Data([0xf8] + Array(repeating: UInt8(0), count: 31)))
    #expect(leadingDash.hasPrefix("-"))
    #expect(
      try CLIParser.parse(arguments: ["recovery", "remove-recipient", "--", leadingDash])
        == .recoveryRecipientRemoval(recipientID: leadingDash))
  }

  @Test func noninteractiveInvocationSendsNoReviewOrExecution() {
    let transport = MemoryTransport { _ in
      Issue.record("No noninteractive removal")
      return .success()
    }
    let io = MemoryIO(stdinIsTTY: false)
    #expect(app(transport, io).run(arguments: args) != EXIT_SUCCESS)
    #expect(transport.requests.isEmpty && io.stderr.contains("No request was sent"))
  }

  @Test(arguments: [false, true])
  func exactReviewAndTypedConsentBecomeOneBoundExecution(last: Bool) {
    let review = review(last: last)
    let phrase = last ? "REMOVE LAST RECOVERY KEY" : "REMOVE"
    let io = MemoryIO(stdinIsTTY: true, lineInput: phrase, secureInput: "must-not-read")
    let transport = MemoryTransport { request in
      switch request {
      case .recoveryRecipientRemoval(.review(recipientID: Self.id)):
        return .recoveryRecipientRemoval(.review(review))
      case .recoveryRecipientRemoval(.remove(let id, let token, let operation, let acknowledges)):
        #expect(
          id == Self.id && token == review.confirmationToken
            && operation == review.pendingOperationID)
        #expect(acknowledges == last)
        #expect(io.stderr.contains(Self.id) && io.stderr.contains(Self.vault))
        if last { #expect(io.stderr.contains("permanently lost")) }
        return .recoveryRecipientRemoval(
          .completed(
            vaultID: Self.vault, recipientID: Self.id,
            manifestDigest: Self.digest, cleanupPending: false, alreadyRemoved: false))
      default:
        Issue.record("Unexpected request")
        return .failure("unexpected")
      }
    }
    #expect(app(transport, io).run(arguments: args) == EXIT_SUCCESS)
    #expect(transport.requests.count == 2 && !io.stdout.contains("must-not-read"))
  }

  @Test(arguments: [false, true])
  func declinedConfirmationNeverExecutesEvenWithValidReview(last: Bool) {
    let transport = MemoryTransport { _ in .recoveryRecipientRemoval(.review(review(last: last))) }
    let io = MemoryIO(stdinIsTTY: true, lineInput: last ? "REMOVE" : "no")
    #expect(app(transport, io).run(arguments: args) != EXIT_SUCCESS)
    #expect(transport.requests == [.recoveryRecipientRemoval(.review(recipientID: Self.id))])
  }

  @Test func mismatchedReviewFailsBeforeConsentAndExecution() {
    let bad = KeyRecoveryRecipientRemovalReview(
      vaultID: Self.vault, checkpointID: Self.digest,
      recipientID: Self.other, remainingRecipientIDs: [], confirmationToken: Self.digest,
      pendingOperationID: nil)
    let io = MemoryIO(stdinIsTTY: true, lineInput: "REMOVE LAST RECOVERY KEY")
    let transport = MemoryTransport { _ in .recoveryRecipientRemoval(.review(bad)) }
    #expect(app(transport, io).run(arguments: args) != EXIT_SUCCESS)
    #expect(transport.requests.count == 1 && !io.stderr.contains("Type REMOVE"))
  }

  @Test(arguments: [false, true])
  func failedOrLostExecutionReplyIsNeverRetried(lost: Bool) {
    let io = MemoryIO(stdinIsTTY: true, lineInput: "REMOVE")
    let transport = MemoryTransport { request in
      if case .recoveryRecipientRemoval(.review) = request {
        return .recoveryRecipientRemoval(.review(review(last: false)))
      }
      if lost { throw AppError.service("Lost reply") }
      return .failure("Incomplete")
    }
    #expect(app(transport, io).run(arguments: args) != EXIT_SUCCESS)
    #expect(transport.requests.count == 2 && io.stderr.contains("no automatic retry"))
  }

  @Test func alreadyRemovedReviewReportsVerifiedStatusWithoutAnotherConfirmation() {
    let io = MemoryIO(
      stdinIsTTY: true, lineInput: "must-not-read", onReadLine: { Issue.record("No new removal") })
    let transport = MemoryTransport { _ in
      .recoveryRecipientRemoval(
        .completed(
          vaultID: Self.vault,
          recipientID: Self.id, manifestDigest: Self.digest, cleanupPending: false,
          alreadyRemoved: true))
    }
    #expect(app(transport, io).run(arguments: args) == EXIT_SUCCESS)
    #expect(transport.requests.count == 1 && io.stdout.contains("already removed"))
  }

  private func review(last: Bool) -> KeyRecoveryRecipientRemovalReview {
    .init(
      vaultID: Self.vault, checkpointID: Self.digest, recipientID: Self.id,
      remainingRecipientIDs: last ? [] : [Self.other], confirmationToken: Self.digest,
      pendingOperationID: VaultTransactionOperationID().rawValue)
  }
  private func app(_ transport: MemoryTransport, _ io: MemoryIO) -> KeyCLIApplication {
    .init(transport: transport, io: io, clipboard: MemoryClipboard())
  }
}
