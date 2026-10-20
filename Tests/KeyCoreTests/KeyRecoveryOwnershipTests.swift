import Foundation
import LocalAuthentication
import Security
import Testing

@testable import KeyCore

struct KeyRecoveryOwnershipTests {
  private enum Stop: Error { case interrupted }
  private static let recipient = Base64URL.encode(Data(repeating: 7, count: 32))
  private static let restore = KeyRecoveryRequest.restore(
    source: "/backup", destination: "/new-vault", tokenID: "selected-token",
    recipientID: recipient, deviceName: "New Mac")
  private static let resume = KeyRecoveryRequest.resume(
    source: "/backup", destination: "/new-vault", tokenID: "selected-token",
    recipientID: recipient)

  @Test(
    arguments: [
      KeyProductIdentity.stable, .preview, .preview.qualificationIdentity(namespace: "ownership"),
    ], [false, true])
  func existenceQueriesAreBoundedLocalNoninteractiveAndReturnNoItems(
    identity: KeyProductIdentity, dataProtection: Bool
  ) throws {
    let configuration = RuntimeConfiguration(
      productIdentity: identity, useDataProtectionKeychain: dataProtection)
    let count = Counter()
    let inspector = V3RecoveryRestoreKeychainOwnership(configuration: configuration) { query in
      let ordinal = count.increment()
      let namespace: V3RecoveryOwnershipNamespace =
        ordinal == 1 ? .restoreReservation : .restorePreparation
      #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
      #expect(
        query[kSecAttrService as String] as? String
          == "\(configuration.vaultService).\(namespace.rawValue)")
      #expect(query[kSecAttrAccessGroup as String] as? String == identity.keychainAccessGroup)
      #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
      #expect(
        query[kSecUseDataProtectionKeychain as String] as? Bool == (dataProtection ? true : nil))
      #expect(query[kSecMatchLimit as String] as? String == kSecMatchLimitOne as String)
      #expect(
        (query[kSecUseAuthenticationContext as String] as? LAContext)?.interactionNotAllowed == true
      )
      for key in [
        kSecAttrAccount, kSecReturnData, kSecReturnAttributes, kSecReturnRef,
        kSecReturnPersistentRef, kSecValueData,
      ] { #expect(query[key as String] == nil) }
      return errSecItemNotFound
    }
    #expect(try !inspector.hasPendingRestore())
    #expect(count.value == 2)
  }

  @Test(arguments: [false, true])
  func eitherPinBlocksWithoutFetchingOrValidatingItsContents(preparationOnly: Bool) throws {
    let count = Counter()
    let inspector = V3RecoveryRestoreKeychainOwnership(
      configuration: .init(productIdentity: .preview)
    ) {
      _ in
      let ordinal = count.increment()
      return preparationOnly && ordinal == 1 ? errSecItemNotFound : errSecSuccess
    }
    #expect(try inspector.hasPendingRestore())
    #expect(count.value == (preparationOnly ? 2 : 1))
  }

  @Test(
    arguments: [
      errSecInteractionNotAllowed, errSecNotAvailable, errSecMissingEntitlement, errSecDecode,
    ], [false, true])
  func uncertaintyIsNeverTreatedAsAnEmptyNamespace(status: OSStatus, secondQuery: Bool) {
    let count = Counter()
    let inspector = V3RecoveryRestoreKeychainOwnership(
      configuration: .init(productIdentity: .preview)
    ) {
      _ in
      let ordinal = count.increment()
      return secondQuery && ordinal == 1 ? errSecItemNotFound : status
    }
    #expect(throws: V3ImmutableTransactionRecoveryAnchorError.keychainStatus(status)) {
      try inspector.hasPendingRestore()
    }
    #expect(count.value == (secondQuery ? 2 : 1))
  }

  @Test(arguments: [false, true])
  func invalidStorageNamespaceCannotReachSecurityBoundary(emptyService: Bool) {
    let identity = KeyProductIdentity(
      variant: .preview, appName: "test", appBundleIdentifier: "test", cliExecutableName: "test",
      cliSigningIdentifier: "test", helperName: "test", helperBundleIdentifier: "test",
      helperMachServiceName: "test", keychainAccessGroup: emptyService ? "group" : "",
      vaultKeyService: emptyService ? "" : "service", applicationSupportDirectoryName: "test",
      defaultVaultDirectoryName: "test")
    let inspector = V3RecoveryRestoreKeychainOwnership(
      configuration: .init(productIdentity: identity)
    ) {
      _ in
      Issue.record("Invalid configuration must not make a query")
      return errSecItemNotFound
    }
    #expect(throws: V3ImmutableTransactionRecoveryAnchorError.invalidConfiguration) {
      try inspector.hasPendingRestore()
    }
  }

  @Test(
    arguments: [false, true],
    [errSecSuccess, errSecInteractionNotAllowed, errSecMissingEntitlement])
  func coldHostRefusesCompetingSetupAndSelectedRuntimeButStillAdmitsExplicitResume(
    configured: Bool, status: OSStatus
  ) {
    let calls = Counter()
    let ownership = V3RecoveryRestoreKeychainOwnership(
      configuration: .init(productIdentity: .preview)
    ) {
      _ in status
    }
    let host = KeyServiceHost(
      hasConfiguration: { configured },
      makeHandler: {
        Issue.record("Pending or uncertain ownership must not compose a runtime")
        return { _ in .success() }
      },
      initialize: { _ in
        Issue.record("Pending or uncertain ownership must not init")
        return ""
      },
      updateVaultDirectory: { _ in Issue.record("Cannot change selection") },
      enroll: { _, _ in
        Issue.record("Cannot enroll")
        return .success()
      },
      recovery: .init(
        ownership: ownership,
        recover: { request, scope in
          #expect(request == Self.resume)
          try scope.requireCurrent()
          calls.increment()
          // Admission is not proof that any particular saved attempt is valid.
          return .failure("Exact resume must inspect its source-bound records")
        }))
    for request in [
      KeyServiceRequest.initializeVault(path: "/init"), .setVaultDirectory(path: "/other"),
      .shareInDirectory(request: .invitations, path: "/join"), .recovery(Self.restore), .list,
    ] { #expect(host.handle(request).exitCode != EXIT_SUCCESS) }
    #expect(calls.value == 0)
    if configured {
      #expect(host.handle(.status).exitCode != EXIT_SUCCESS)
    } else {
      #expect(host.handle(.status).helperStatus?.isUnlocked == false)
    }
    #expect(host.handle(.lock) == .success())
    #expect(host.handle(.recovery(Self.resume)).errorMessage?.contains("Exact resume") == true)
    #expect(calls.value == 1)
  }

  @Test func eachAdmissionRechecksOwnershipInsteadOfCachingAnEarlierEmptyResult() {
    let count = Counter()
    let ownership = V3RecoveryRestoreKeychainOwnership(
      configuration: .init(productIdentity: .preview)
    ) {
      _ in count.increment() <= 2 ? errSecItemNotFound : errSecSuccess
    }
    let host = KeyServiceHost(
      hasConfiguration: { false }, makeHandler: { { _ in .success() } },
      initialize: { _ in
        Issue.record("The second admission is not empty")
        return ""
      },
      enroll: { _, _ in .failure("Inspected without enrollment") },
      recovery: .init(
        ownership: ownership,
        recover: { _, _ in
          Issue.record("The later initial restore must be refused")
          return .success()
        }))
    #expect(
      host.handle(.shareInDirectory(request: .invitations, path: "/join")).errorMessage
        == "Inspected without enrollment")
    #expect(
      host.handle(.initializeVault(path: "/init")).errorMessage?.contains("saved recovery") == true)
    #expect(host.handle(.recovery(Self.restore)).exitCode != EXIT_SUCCESS)
    #expect(count.value == 4)
  }

  @Test(arguments: [
    V3RecoveryRestoreServicePhase.reservationDurable, .preparationDurable,
    .selection(.configurationSelected), .finalization(.reservationCleared),
    .finalization(.preparationCleared),
  ])
  func newHostUsesSurvivingOwnershipAcrossRealRestoreInterruptionAndExactResume(
    phase: V3RecoveryRestoreServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try V3RecoveryRestoreServiceTests.Fixture()
    defer { f.remove() }
    let ownership = V3RecoveryRestoreKeychainOwnership(
      configuration: .init(productIdentity: .preview)
    ) {
      query in
      let preparation =
        (query[kSecAttrService as String] as? String)?.hasSuffix(
          V3RecoveryOwnershipNamespace.restorePreparation.rawValue) == true
      return (preparation ? f.preparations.value : f.reservations.value) == nil
        ? errSecItemNotFound : errSecSuccess
    }
    func makeHost(interrupt: Bool) -> KeyServiceHost {
      KeyServiceHost(
        hasConfiguration: { try f.config.hasConfiguration() },
        makeHandler: { { _ in .success("Ordinary runtime") } },
        initialize: { _ in
          Issue.record("Must not initialize while restore is owned")
          return ""
        },
        recovery: .init(
          ownership: ownership,
          recover: { request, scope in
            let service = try V3RecoveryRestoreService(
              configStore: f.config, journal: f.journal(), identities: f.identities,
              checkpoints: f.checkpoints, cache: f.cache, mutationOwner: f.owner,
              reader: f.reader, agreement: f.agreement, authentication: scope.authentication,
              observer: Observer { if interrupt && $0 == phase { throw Stop.interrupted } })
            let observation = try f.reader.read(try #require(f.reader.candidates().first))
            if request.isInitialRestore {
              _ = try service.restore(
                source: f.sourceHandle, parent: f.parentHandle, name: "restored",
                deviceName: "New Mac",
                observation: observation, cancellation: scope.cancellation, deadline: scope.deadline
              )
            } else {
              _ = try service.resume(
                source: .init(opening: f.source.root), destination: .init(opening: f.destination),
                parent: .init(opening: f.parent), observation: observation,
                cancellation: scope.cancellation, deadline: scope.deadline)
            }
            return .success("Restored")
          }))
    }
    #expect(makeHost(interrupt: true).handle(.recovery(Self.restore)).exitCode != EXIT_SUCCESS)
    #expect(f.provider.requests == 1)
    let records = try V3RecoveryRestoreJournalTests().files(f.configRoot)
    let pins = [f.reservations.value, f.preparations.value]
    let restarted = makeHost(interrupt: false)
    if phase == .finalization(.preparationCleared) {
      #expect(try !ownership.hasPendingRestore())
      #expect(restarted.handle(.recovery(Self.resume)).exitCode != EXIT_SUCCESS)
      #expect(f.provider.requests == 1)
      // A different cold host can compose normal authority, not claim recovery success.
      #expect(makeHost(interrupt: false).handle(.list) == .success("Ordinary runtime"))
    } else {
      #expect(try ownership.hasPendingRestore())
      for request in [
        KeyServiceRequest.initializeVault(path: "/other"), .recovery(Self.restore), .list,
      ] {
        #expect(restarted.handle(request).exitCode != EXIT_SUCCESS)
      }
      #expect([f.reservations.value, f.preparations.value] == pins)
      #expect(try V3RecoveryRestoreJournalTests().files(f.configRoot) == records)
      #expect(f.provider.requests == 1)
      let result = restarted.handle(.recovery(Self.resume))
      if phase == .reservationDurable {
        #expect(result.exitCode != EXIT_SUCCESS)
        #expect(f.provider.requests == 1 && f.identities.creates.value == 0)
        #expect([f.reservations.value, f.preparations.value] == pins)
      } else {
        #expect(result == .success("Restored"))
        #expect(f.provider.requests == 2 && f.identities.creates.value == 1)
        #expect(try !ownership.hasPendingRestore())
        #expect(restarted.handle(.list).errorMessage?.contains("restarting") == true)
        #expect(makeHost(interrupt: false).handle(.list) == .success("Ordinary runtime"))
      }
    }
  }

  private struct Observer: V3RecoveryRestoreServicePhaseObserving {
    let action: @Sendable (V3RecoveryRestoreServicePhase) throws -> Void
    func didReach(_ phase: V3RecoveryRestoreServicePhase) throws { try action(phase) }
  }

  private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.withLock { count } }
    @discardableResult func increment() -> Int {
      lock.withLock {
        count += 1
        return count
      }
    }
  }
}
