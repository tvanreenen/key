import Foundation
import Testing

@testable import KeyCore

struct RecoveryRegistrationCLITests {
  private static let recipient = Base64URL.encode(Data(repeating: 7, count: 32))
  private static let vault = "018f4d38-7d5a-7b20-b0f1-97d6e96c84d1"

  @Test(arguments: [false, true])
  func parserRequiresExplicitCredentialAndNewExportPath(resume: Bool) throws {
    let input = arguments(resume: resume)
    let action: KeyRecoveryRegistrationRequest =
      resume
      ? .resumeExport(tokenID: "token", recipientID: Self.recipient)
      : .prepare(tokenID: "token", recipientID: Self.recipient)
    #expect(
      try CLIParser.parse(arguments: input)
        == .recoveryRegistration(action, exportPath: "anchor.json", json: false))
    for option in ["--token", "--recipient", "--export-anchor"] {
      var missing = input
      let offset = try #require(missing.firstIndex(of: option))
      let value = missing[offset + 1]
      missing.removeSubrange(offset...(offset + 1))
      #expect(throws: AppError.self) { try CLIParser.parse(arguments: missing) }
      #expect(throws: AppError.self) { try CLIParser.parse(arguments: input + [option, value]) }
    }
    for option in ["--pin", "--puk", "--management-key", "--force", "--yes"] {
      #expect(throws: AppError.self) { try CLIParser.parse(arguments: input + [option, "no"]) }
    }
  }

  @Test(arguments: [false, true])
  func noInteractiveConsentMeansNoPreparationRequest(noninteractive: Bool) {
    let io = MemoryIO(stdinIsTTY: !noninteractive, lineInput: "wrong")
    let transport = MemoryTransport { _ in
      Issue.record("Cancelled setup reached service")
      return .success()
    }
    let app = KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard())
    #expect(app.run(arguments: arguments()) != EXIT_SUCCESS)
    #expect(transport.requests.isEmpty && io.stdout.isEmpty)
  }

  @Test(arguments: 0..<3)
  func exportWritesExactPublicBytesButNeverReplacesExistingFilesOrLinks(existing: Int) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let output = directory.appendingPathComponent("anchor.json")
    let target = directory.appendingPathComponent("other.json")
    let sentinel = Data("keep existing output".utf8)
    if existing == 1 { try sentinel.write(to: output) }
    if existing == 2 {
      try sentinel.write(to: target)
      try FileManager.default.createSymbolicLink(at: output, withDestinationURL: target)
    }
    let anchor = try V3RecoveryAnchor(
      floor: .init(vaultID: Self.vault, envelopeDigest: Data(repeating: 9, count: 32)),
      recipientID: .init(rawValue: Self.recipient), registrationID: UUID().uuidString.lowercased(),
      slot: .keyManagement)
    let io = MemoryIO(stdinIsTTY: true, lineInput: "PREPARE", secureInput: "must-not-read")
    let transport = MemoryTransport { _ in
      .init(
        exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil,
        recoveryRegistration: .export(
          operationID: VaultTransactionOperationID().rawValue, vaultID: Self.vault,
          recipientID: Self.recipient, anchor: Base64URL.encode(anchor.canonicalBytes)))
    }
    let app = KeyCLIApplication(
      transport: transport, io: io, clipboard: MemoryClipboard(), currentDirectory: { directory })
    #expect(app.run(arguments: arguments()) == (existing == 0 ? EXIT_SUCCESS : EXIT_FAILURE))
    #expect(transport.requests.count == 1)
    #expect(try Data(contentsOf: output) == (existing == 0 ? anchor.canonicalBytes : sentinel))
    #expect(!io.stdout.contains("must-not-read"))
    if existing != 0 { #expect(io.stderr.contains("not a new preparation")) }
  }

  @Test func mismatchedPayloadCannotCreateAnExportAndNeverRetries() {
    let io = MemoryIO(stdinIsTTY: true, lineInput: "PREPARE")
    let transport = MemoryTransport { _ in
      .init(
        exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil,
        recoveryRegistration: .completed(
          vaultID: Self.vault, manifestDigest: "wrong", cleanupPending: false))
    }
    let app = KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard())
    #expect(app.run(arguments: arguments()) != EXIT_SUCCESS)
    #expect(transport.requests.count == 1 && io.stdout.isEmpty)
    #expect(io.stderr.contains("does not prove nothing committed"))
  }

  @Test func statusHasNoCredentialInputAndAttentionIsNotSuccess() {
    let io = MemoryIO(
      stdinIsTTY: false, onReadLine: { Issue.record("Status must not collect approval") })
    let transport = MemoryTransport { _ in
      .init(
        exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil,
        recoveryRegistration: .status(
          state: .attentionRequired, vaultID: Self.vault, recipients: [], activationCommitted: false
        ))
    }
    #expect(
      KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard()).run(arguments: [
        "recovery", "register", "status", "--json",
      ]) == EXIT_FAILURE)
    #expect(transport.requests == [.recoveryRegistration(.status)])
    #expect(io.stdout.contains("attentionRequired"))
  }

  private func arguments(resume: Bool = false) -> [String] {
    [
      "recovery", "register", resume ? "resume-export" : "prepare", "--token", "token",
      "--recipient", Self.recipient, "--export-anchor", "anchor.json",
    ]
  }
}
