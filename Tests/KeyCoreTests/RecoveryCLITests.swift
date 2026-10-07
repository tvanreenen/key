import Foundation
import Testing

@testable import KeyCore

struct RecoveryCLITests {
  private static let recipient = Base64URL.encode(Data(repeating: 7, count: 32))
  private enum Stop: Error { case interrupted }
  private typealias Fixture = V3RecoveryRestoreServiceTests.Fixture

  @Test(arguments: [false, true])
  func parserPreservesExplicitSelectorsWithoutOpeningPaths(resume: Bool) throws {
    let expected: KeyRecoveryRequest =
      resume
      ? .resume(
        source: "./source", destination: "./destination", tokenID: "selected-token",
        recipientID: Self.recipient)
      : .restore(
        source: "./source", destination: "./destination", tokenID: "selected-token",
        recipientID: Self.recipient, deviceName: "Replacement Mac")
    #expect(try CLIParser.parse(arguments: arguments(resume: resume)) == .recovery(expected))
  }

  @Test(arguments: [false, true], ["--source", "--destination", "--token", "--recipient"])
  func missingOrDuplicateSelectorsNeverReachService(resume: Bool, option: String) throws {
    var missing = arguments(resume: resume)
    let offset = try #require(missing.firstIndex(of: option))
    let value = missing[offset + 1]
    missing.removeSubrange(offset...(offset + 1))
    assertUsage(missing)
    assertUsage(arguments(resume: resume) + [option, value])
    assertUsage(arguments(resume: resume) + ["\(option)=different"])
  }

  @Test(
    arguments: [false, true],
    [
      ("--source", ""), ("--source", "source\0path"),
      ("--source", String(repeating: "s", count: 4_097)),
      ("--destination", ""), ("--destination", "destination\0path"),
      ("--destination", String(repeating: "d", count: 4_097)),
      ("--token", ""), ("--token", "token\0id"),
      ("--token", String(repeating: "t", count: 1_025)),
      ("--recipient", ""), ("--recipient", "prefix"),
      ("--recipient", String(repeating: "0", count: 64)),
      ("--recipient", String(repeating: "A", count: 42)),
      ("--recipient", String(repeating: "A", count: 43) + "="),
    ])
  func malformedSelectorsUseUsageExitWithoutService(
    resume: Bool, replacement: (String, String)
  ) throws {
    var input = arguments(resume: resume)
    let index = try #require(input.firstIndex(of: replacement.0))
    input[index + 1] = replacement.1
    assertUsage(input)
  }

  @Test(arguments: ["", "e\u{301}", "Name\nOther", String(repeating: "n", count: 129)])
  func invalidMacNameNeverReachesService(name: String) throws {
    var input = arguments()
    let index = try #require(input.firstIndex(of: "--name"))
    input[index + 1] = name
    assertUsage(input)
  }

  @Test
  func restoreRequiresOneNameAndResumeRejectsNameAndSecretOrBypassOptions() throws {
    assertUsage(Array(arguments().dropLast(2)))
    assertUsage(arguments() + ["--name", "Another Mac"])
    assertUsage(arguments() + ["--name=Another Mac"])
    assertUsage(arguments(resume: true) + ["--name", "Replacement Mac"])
    for option in ["--pin", "--puk", "--management-key", "--vault-key", "--force", "--yes"] {
      assertUsage(arguments() + [option, "not-a-secret"])
      assertUsage(arguments(resume: true) + [option, "not-a-secret"])
    }
    assertUsage(["recovery"])
    assertUsage(["recovery", "review"])
  }

  @Test(arguments: [false, true])
  func applicationResolvesExplicitPathsOnceWithoutLoadingConfigurationOrReadingInput(resume: Bool)
    throws
  {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let config = KeyConfigStore(homeDirectoryURL: home)
    let io = MemoryIO(
      stdinIsTTY: false, pipedInput: "must-not-read", secureInput: "must-not-read",
      onReadLine: { Issue.record("Recovery CLI must not collect credentials or approval") })
    let transport = MemoryTransport { _ in .success("Selected new vault.\n") }
    var captures = 0
    let app = KeyCLIApplication(
      transport: transport, io: io, clipboard: MemoryClipboard(), configStore: config,
      currentDirectory: {
        captures += 1
        return URL(fileURLWithPath: "/explicit/base")
      })
    var input = arguments(resume: resume)
    let source = try #require(input.firstIndex(of: "--source"))
    let destination = try #require(input.firstIndex(of: "--destination"))
    input[source + 1] = "../source folder"
    input[destination + 1] = "new/../destination folder"
    #expect(app.run(arguments: input) == EXIT_SUCCESS)
    let request: KeyRecoveryRequest =
      resume
      ? .resume(
        source: "/explicit/source folder", destination: "/explicit/base/destination folder",
        tokenID: "selected-token", recipientID: Self.recipient)
      : .restore(
        source: "/explicit/source folder", destination: "/explicit/base/destination folder",
        tokenID: "selected-token", recipientID: Self.recipient, deviceName: "Replacement Mac")
    #expect(transport.requests == [.recovery(request)] && captures == 1)
    #expect(io.stdout == "Selected new vault.\n")
    #expect(io.stderr.contains("Enter PIN only in the macOS dialog"))
    #expect(!io.stderr.contains("must-not-read") && !io.stdout.contains("must-not-read"))
    #expect(!FileManager.default.fileExists(atPath: home.path))
  }

  @Test(arguments: [false, true])
  func failedOrThrownRepliesPreserveExitAndNeverRetryOrClaimCompletion(thrown: Bool) {
    let io = MemoryIO(stdinIsTTY: false)
    let transport = MemoryTransport { _ in
      if thrown { throw Stop.interrupted }
      return KeyServiceResponse(exitCode: 23, value: nil, errorMessage: "Not completed.")
    }
    let app = KeyCLIApplication(transport: transport, io: io, clipboard: MemoryClipboard())
    let result = app.run(arguments: arguments())
    #expect(result == (thrown ? EXIT_FAILURE : 23))
    #expect(transport.requests.count == 1 && io.stdout.isEmpty)
    #expect(io.stderr.contains("does not establish whether selection completed"))
    #expect(io.stderr.contains("Do not start another restore or delete state"))
    #expect(io.stderr.contains("key recovery resume"))
  }

  @Test(arguments: [KeyProductIdentity.stable, .preview])
  func actualShippingHostsRefuseCLIWithoutCreatingStateOrOpeningCard(product: KeyProductIdentity)
    throws
  {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let config = KeyConfigStore(productIdentity: product, homeDirectoryURL: home)
    let host = KeyServiceHost.live(
      keyStore: MemoryVaultKeyStore(), configStore: config,
      runtimeConfiguration: RuntimeConfiguration(productIdentity: product))
    let io = MemoryIO(stdinIsTTY: false)
    let transport = MemoryTransport { host.handle($0) }
    let app = KeyCLIApplication(
      transport: transport, io: io, clipboard: MemoryClipboard(), configStore: config)
    for resume in [false, true] {
      #expect(app.run(arguments: arguments(resume: resume)) != EXIT_SUCCESS)
    }
    #expect(transport.requests.count == 2 && io.stdout.isEmpty)
    #expect(io.stderr.contains("Recovery is not enabled in this product build"))
    #expect(!FileManager.default.fileExists(atPath: home.path))
  }

  @Test(arguments: [false, true])
  func actualCLIHostWorkflowRestoreOrExactResumeClearsOwnershipWithoutFallback(interrupted: Bool)
    throws
  {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let before = try V3RecoveryRestoreJournalTests().files(f.source.root)
    let initialHost = host(f, interrupted: interrupted)
    let initialTransport = MemoryTransport { initialHost.handle($0) }
    let initialIO = MemoryIO(stdinIsTTY: false)
    let initialApp = application(f, transport: initialTransport, io: initialIO)
    let initial = initialApp.run(arguments: fixtureArguments(f, resume: false))
    #expect((initial == EXIT_SUCCESS) == !interrupted)
    #expect(initialTransport.requests.count == 1 && f.provider.requests == 1)
    #expect(f.identities.creates.value == 1)
    if interrupted {
      #expect(
        initialIO.stdout.isEmpty && initialIO.stderr.contains("preserve state for inspection"))
      #expect(f.reservations.value != nil && f.preparations.value != nil)
      #expect(try !f.config.hasConfiguration())
      let resumedHost = host(f)
      let transport = MemoryTransport { resumedHost.handle($0) }
      let io = MemoryIO(stdinIsTTY: false)
      #expect(
        application(f, transport: transport, io: io)
          .run(arguments: fixtureArguments(f, resume: true)) == EXIT_SUCCESS)
      #expect(transport.requests.count == 1 && f.provider.requests == 2)
      #expect(io.stdout.contains("Restored 2 entries") && io.stdout.contains("no recovery key"))
    } else {
      #expect(initialIO.stdout.contains("Restored 2 entries"))
    }
    #expect(f.reservations.value == nil && f.preparations.value == nil)
    #expect(f.identities.creates.value == 1)
    #expect(try f.config.load().vaultDirectoryURL.standardizedFileURL == f.destination)
    #expect(try V3RecoveryRestoreJournalTests().files(f.source.root) == before)
    let agreements = f.provider.requests
    let finishedHost = host(f)
    let transport = MemoryTransport { finishedHost.handle($0) }
    let io = MemoryIO(stdinIsTTY: false)
    #expect(
      application(f, transport: transport, io: io)
        .run(arguments: fixtureArguments(f, resume: true)) != EXIT_SUCCESS)
    #expect(transport.requests.count == 1 && f.provider.requests == agreements)
    #expect(io.stdout.isEmpty && f.identities.creates.value == 1)
  }

  @Test
  func helpSeparatesDisabledCommandsSelectorsAuthenticationAndInterruption() throws {
    let group = try #require(CLIParser.helpText(for: "recovery"))
      .split(whereSeparator: \.isWhitespace).joined(separator: " ")
    let restore = try #require(CLIParser.helpText(for: "recovery restore"))
      .split(whereSeparator: \.isWhitespace).joined(separator: " ")
    let resume = try #require(CLIParser.helpText(for: "recovery resume"))
      .split(whereSeparator: \.isWhitespace).joined(separator: " ")
    #expect(group.contains("not enabled in Stable or ordinary Preview"))
    #expect(group.contains("Neither selector is a secret or an approval"))
    #expect(group.contains("does not set up, reset or write"))
    #expect(restore.contains("destination itself must be missing"))
    #expect(restore.contains("Recovery protection is not inherited"))
    #expect(resume.contains("never recreates missing state"))
    #expect(resume.contains("Status alone does not prove completion"))
    #expect(resume.contains("do not delete records or folders to force a retry"))
  }

  private func arguments(resume: Bool = false) -> [String] {
    [
      "recovery", resume ? "resume" : "restore", "--source", "./source",
      "--destination", "./destination", "--token", "selected-token",
      "--recipient", Self.recipient,
    ] + (resume ? [] : ["--name", "Replacement Mac"])
  }

  private func assertUsage(_ arguments: [String]) {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let transport = MemoryTransport { _ in
      Issue.record("Invalid CLI arguments must not reach the helper")
      return .success()
    }
    let io = MemoryIO(stdinIsTTY: false)
    let app = KeyCLIApplication(
      transport: transport, io: io, clipboard: MemoryClipboard(),
      configStore: KeyConfigStore(homeDirectoryURL: home))
    #expect(app.run(arguments: arguments) == KeyServiceErrorCode.invalidUsage.exitCode.rawValue)
    #expect(transport.requests.isEmpty && io.stdout.isEmpty)
    #expect(io.stderr.contains("USAGE:") || io.stderr.contains("Usage:"))
    #expect(!FileManager.default.fileExists(atPath: home.path))
  }

  private func fixtureArguments(_ f: Fixture, resume: Bool) -> [String] {
    [
      "recovery", resume ? "resume" : "restore", "--source", f.source.root.path,
      "--destination", "restored", "--token", f.card.tokenID,
      "--recipient", f.source.anchor.recipientID.rawValue,
    ] + (resume ? [] : ["--name", "Replacement Mac"])
  }

  private func application(_ f: Fixture, transport: MemoryTransport, io: MemoryIO)
    -> KeyCLIApplication
  {
    KeyCLIApplication(
      transport: transport, io: io, clipboard: MemoryClipboard(), configStore: f.config,
      currentDirectory: { f.parent })
  }

  private func host(_ f: Fixture, interrupted: Bool = false) -> KeyServiceHost {
    let workflow = V3RecoveryRestoreWorkflow(
      configStore: f.config, ownership: Ownership(f: f), reservations: f.reservations,
      preparations: f.preparations, identities: f.identities, checkpoints: f.checkpoints,
      reader: f.reader, agreement: f.agreement, mutationOwner: f.owner,
      observer: Observer(interrupted: interrupted))
    return KeyServiceHost(
      hasConfiguration: { try f.config.hasConfiguration() },
      makeHandler: {
        Issue.record("Recovery CLI must not compose an ordinary runtime")
        return { _ in .success() }
      },
      initialize: { _ in
        Issue.record("Recovery CLI must not initialize a vault")
        return ""
      }, recovery: workflow.capability)
  }

  private struct Ownership: V3RecoveryRestoreOwnershipChecking {
    let f: Fixture
    func hasPendingRestore() -> Bool { f.reservations.value != nil || f.preparations.value != nil }
  }

  private struct Observer: V3RecoveryRestoreServicePhaseObserving {
    let interrupted: Bool
    func didReach(_ phase: V3RecoveryRestoreServicePhase) throws {
      if interrupted && phase == .preparationDurable { throw Stop.interrupted }
    }
  }
}
