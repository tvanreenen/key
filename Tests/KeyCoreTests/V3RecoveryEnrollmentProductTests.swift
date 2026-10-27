import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Exercises the existing invite/join/compare/approve/accept product services
/// over contained files with independent Mac-local state and software keys.
struct V3RecoveryEnrollmentProductTests {
  private typealias Core = V3RecoveryRegistrationTestSupport
  private typealias Disk = V3RecoveryPublicationTestSupport
  private static let now = V3RecoveryEnrollmentTestSupport.now

  @Test func completeSharingCeremonySelectsOnlyVerifiedFirstTrustAndPreservesRecovery() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let comparison = try f.compare()
    #expect(f.joiningCheckpoints.value == nil && f.selection.values.isEmpty)
    #expect(throws: V3EnrollmentAdoptionError.invalidCeremony) {
      try f.joining().accept(
        vaultID: Core.vaultID, invitationDigest: comparison.invitation.digest,
        comparisonCode: "different", at: Self.now, operationID: .init())
    }
    #expect(f.unwraps.value == 0 && f.joiningCheckpoints.value == nil)
    _ = try f.owner.approve(
      vaultID: Core.vaultID, invitationDigest: comparison.invitation.digest,
      comparisonCode: comparison.comparisonCode, at: Self.now, operationID: .init())
    let signatures = f.disk.core.owner.signatures
    let floor = f.disk.checkpoints.value
    // Lost owner reply: acknowledge the exact completed comparison, with no
    // second signature, fresh epoch, or publication.
    _ = try f.owner.approve(
      vaultID: Core.vaultID, invitationDigest: comparison.invitation.digest,
      comparisonCode: comparison.comparisonCode, at: Self.now + 601, operationID: .init())
    #expect(f.disk.core.owner.signatures == signatures && f.disk.checkpoints.value == floor)
    let result = try f.joining().accept(
      vaultID: Core.vaultID,
      invitationDigest: comparison.invitation.digest, comparisonCode: comparison.comparisonCode,
      at: Self.now + 601, operationID: .init())
    #expect(result.contains("This Mac can now use the vault"))
    #expect(f.selection.values == ["verified", Core.vaultID, "replacement-complete"])
    #expect(f.unwraps.value == 1 && f.joiningCheckpoints.value == floor)
    let context = try f.joiningUnlock.authenticatedReadContext(reason: "Software read")
    #expect(
      context.current.envelope.body.recovery.recipients == f.disk.parent.body.recovery.recipients)
    #expect(
      try V3RecoveryReadOnlyVaultRuntime(source: f.disk.store, unlockRuntime: f.joiningUnlock)
        .read(name: "fixture/secret", context: context).plaintext
        == "Software fixture secret e\u{301}\r\n")
    #expect(f.unwraps.value == 1)
  }

  @Test func stoppedJoiningSelectionRetainsExactCheckpointAndCanExplicitlyResume() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let compared = try f.compare()
    _ = try f.owner.approve(
      vaultID: Core.vaultID, invitationDigest: compared.invitation.digest,
      comparisonCode: compared.comparisonCode, at: Self.now, operationID: .init())
    let scope = KeyRecoveryRequestScope(authentication: .init(), deadline: .now() + 60)
    #expect(throws: (any Error).self) {
      try f.joining(
        validate: { try scope.requireCurrent() },
        afterSelection: {
          scope.cancellation.cancel()
        }
      ).accept(
        vaultID: Core.vaultID, invitationDigest: compared.invitation.digest,
        comparisonCode: compared.comparisonCode, at: Self.now, operationID: .init())
    }
    #expect(f.joiningCheckpoints.value == f.disk.checkpoints.value)
    #expect(!f.joiningSession.hasResidentKey)
    #expect(f.selection.values == ["verified", Core.vaultID])
    _ = try f.joining().accept(
      vaultID: Core.vaultID, invitationDigest: compared.invitation.digest,
      comparisonCode: compared.comparisonCode, at: Self.now, operationID: .init())
    #expect(f.unwraps.value == 2 && f.joiningSession.hasResidentKey)
    #expect(f.selection.values.suffix(3) == ["verified", Core.vaultID, "replacement-complete"])
  }

  @Test func disabledProfileIsRejectedBeforeCreatingJoiningCredentials() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let invitation = try f.invite()
    #expect(f.records.records.isEmpty)
    #expect(throws: V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired) {
      try f.joining(allowRecovery: false).join(
        invitationDigest: invitation,
        deviceName: "Joining Mac", at: Self.now)
    }
    #expect(f.records.records.isEmpty && f.joiningCheckpoints.value == nil)
    #expect(
      try f.ownerExchange.availableJoinRequestDigests(
        vaultID: Core.vaultID,
        invitationDigest: invitation, at: Self.now, maximumCount: 10
      ).isEmpty)
  }

  @Test func stoppedOwnerScopeBeforeApprovalPerformsNoNewPrivateOperationOrPublication() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let compared = try f.compare()
    let signatures = f.disk.core.owner.signatures
    let unwraps = f.disk.core.owner.unwraps
    f.scope.cancellation.cancel()
    #expect(throws: (any Error).self) {
      try f.owner.approve(
        vaultID: Core.vaultID, invitationDigest: compared.invitation.digest,
        comparisonCode: compared.comparisonCode, at: Self.now, operationID: .init())
    }
    #expect(f.disk.core.owner.signatures == signatures && f.disk.core.owner.unwraps == unwraps)
    #expect(
      f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes && f.disk.ownership.value == nil)
  }

  @Test func stoppingDuringOwnerUnwrapCannotContinueIntoSigningOrReservation() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    let compared = try f.compare()
    f.ownerSession.invalidate()
    let signatures = f.disk.core.owner.signatures
    f.disk.core.owner.onUnwrap = { f.scope.cancellation.cancel() }
    #expect(throws: (any Error).self) {
      try f.owner.approve(
        vaultID: Core.vaultID, invitationDigest: compared.invitation.digest,
        comparisonCode: compared.comparisonCode, at: Self.now, operationID: .init())
    }
    #expect(f.disk.core.owner.signatures == signatures && f.disk.ownership.value == nil)
    #expect(f.disk.checkpoints.value == f.disk.checkpoint.canonicalBytes)
  }

  private struct Fixture: Sendable {
    let disk: Disk.Fixture
    let scope = KeyRecoveryRequestScope(authentication: .init(), deadline: .now() + 90)
    let ownerSession = V3DeviceWrappedVaultKeySessionStore()
    let joiningSession = V3DeviceWrappedVaultKeySessionStore()
    let ownerStates = Ceremonies()
    let joiningStates = Ceremonies()
    let records = AdoptionIdentityRecordStore()
    let joiningCheckpoints: Disk.Checkpoints
    let transaction = Disk.Ownership(), registration = Disk.Ownership(), adoption = Disk.Ownership()
    let selection = Events()
    let unwraps = Core.Counter()
    init() throws {
      disk = try Disk.Fixture()
      joiningCheckpoints = Disk.Checkpoints(disk.checkpoint.canonicalBytes)
      joiningCheckpoints.value = nil
    }
    var mailbox: V3FilesystemEnrollmentMailbox {
      get throws { .init(rootHandle: try VaultRootDirectoryHandle(opening: disk.root)) }
    }
    var ownerExchange: V3EnrollmentExchangeCoordinator {
      get throws { .init(mailbox: try mailbox, stateStore: ownerStates) }
    }
    var manager: V3EnrollmentDeviceIdentityManager {
      .init(recordStore: records, keyOperations: AdoptionDeviceKeyOperations())
    }
    var joiningUnlock: V3RecoveryVaultUnlockRuntime {
      .init(
        vaultID: Core.vaultID, checkpointStore: joiningCheckpoints, source: disk.store,
        cache: disk.cache, identityLoader: manager, session: joiningSession,
        transactionOwnershipStore: transaction, registrationOwnershipStore: registration,
        adoptionOwnershipStore: adoption)
    }
    var owner: V3RecoveryEnrollmentOwnerWorkflow {
      get throws {
        let validate: @Sendable () throws -> Void = { try scope.requireCurrent() }
        let unlock = V3RecoveryVaultUnlockRuntime(
          vaultID: Core.vaultID,
          checkpointStore: disk.checkpoints, source: disk.store, cache: disk.cache,
          identityLoader: Loader(identity: disk.core.owner, validate: validate),
          session: ownerSession,
          transactionOwnershipStore: disk.ownership, registrationOwnershipStore: disk.registration,
          adoptionOwnershipStore: disk.adoption)
        return .init(
          vaultID: Core.vaultID, unlock: unlock, session: ownerSession,
          exchange: try ownerExchange, ownership: disk.ownership,
          loadIdentity: { V3ScopedEnrollmentIdentity(base: disk.core.owner, validate: validate) },
          makeService: { identity in
            .init(
              vaultID: Core.vaultID, identity: identity, session: ownerSession,
              objectStore: disk.store, checkpointStore: disk.checkpoints,
              recoveryAnchorStore: disk.ownership, registrationAnchorStore: disk.registration,
              adoptionAnchorStore: disk.adoption, ceremonyStore: ownerStates,
              cache: disk.cache, validateScope: validate)
          }, validateScope: validate)
      }
    }
    func invite() throws -> Data {
      _ = try owner.createInvitation(
        deviceName: disk.core.owner.publicIdentity.displayName, at: fixtureTime)
      return try #require(ownerExchange.availableInvitationDigests(maximumCount: 10).first)
    }
    private var fixtureTime: UInt64 { V3RecoveryEnrollmentProductTests.now }
    func compare() throws -> V3EnrollmentTranscript {
      let invitation = try invite()
      _ = try joining().join(
        invitationDigest: invitation, deviceName: "Joining Mac", at: fixtureTime)
      let request = try #require(
        ownerExchange.availableJoinRequestDigests(
          vaultID: Core.vaultID, invitationDigest: invitation, at: fixtureTime, maximumCount: 10
        ).first)
      _ = try owner.compare(
        vaultID: Core.vaultID, invitationDigest: invitation,
        joinRequestDigest: request, at: fixtureTime)
      let state = try ownerExchange.resumeDeviceWrappedOwnerApproval(
        vaultID: Core.vaultID,
        invitationDigest: invitation)
      return try #require(state.transcript)
    }
    func joining(
      allowRecovery: Bool = true,
      validate: @escaping @Sendable () throws -> Void = {},
      afterSelection: @escaping @Sendable () throws -> Void = {}
    ) throws -> V3EnrollmentWorkflowService {
      let exchange = V3EnrollmentExchangeCoordinator(
        mailbox: try mailbox, stateStore: joiningStates)
      let adopter = V3RecoveryEnrollmentProductAdoption(
        source: disk.store, checkpoints: joiningCheckpoints, ownership: transaction,
        registration: registration, adoption: adoption, ceremonies: joiningStates,
        cache: disk.cache, session: joiningSession,
        loadIdentity: { vaultID in
          guard let identity = try manager.loadIdentity(vaultID: vaultID, reason: "Software test")
          else { return nil }
          return CountingUnwrapper(base: identity, count: unwraps)
        },
        verifyRuntime: { commit, ticket in
          let context = try joiningUnlock.continuedReadContext(
            current: .init(checkpoint: commit.checkpoint, envelope: commit.envelope), ticket: ticket
          )
          _ = try V3RecoveryReadOnlyVaultRuntime(source: disk.store, unlockRuntime: joiningUnlock)
            .list(allowStale: false, context: context)
          selection.append("verified")
        },
        selectVault: { vaultID in
          selection.append(vaultID)
          try afterSelection()
        }, completeReplacement: { _ in selection.append("replacement-complete") },
        validateScope: validate)
      return V3EnrollmentWorkflowService(
        selectedVaultID: nil, source: disk.store,
        objectStore: disk.store, checkpointStore: joiningCheckpoints, exchange: exchange,
        identityManager: manager, vaultKeyStore: MemoryVaultKeyStore(), keychainMode: .local,
        selectVault: { _ in Issue.record("Legacy selection") }, verifyRuntime: { _ in },
        deviceWrappedAdoption: V3ProfiledEnrollmentAdoptionService(
          source: disk.store,
          exchange: exchange, permanent: UnexpectedAdoption(),
          recovery: allowRecovery ? adopter : nil,
          validateScope: validate),
        validateInvitation: { invitation in
          if case .recovery = try v3EnrollmentParentProfile(invitation, source: disk.store),
            !allowRecovery
          {
            throw V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired
          }
        }, validateScope: validate)
    }
  }
  private struct Loader: V3DeviceWrappedIdentityLoading {
    let identity: Core.Owner
    let validate: @Sendable () throws -> Void
    func loadDeviceIdentity(vaultID: String, reason: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? {
      try validate()
      return V3ScopedDeviceUnwrapper(base: identity, validate: validate)
    }
  }
  private struct CountingUnwrapper: V3DeviceWrappedVaultKeyUnwrapping {
    let base: any V3DeviceWrappedVaultKeyUnwrapping
    let count: Core.Counter
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ ciphertext: V3HPKEWrappedVaultKey,
      context: V3VaultKeyHPKEContext, reason: String
    ) throws -> Data {
      count.increment()
      return try base.unwrapDeviceWrappedVaultKey(ciphertext, context: context, reason: reason)
    }
  }
  private struct UnexpectedAdoption: V3EnrollmentFirstTrustAdopting {
    func adopt(
      vaultID: String, invitationDigest: Data, approvedTranscriptDigest: Data,
      at unixTime: UInt64, operationID: VaultTransactionOperationID
    ) throws -> V3DeviceEnrollmentAdoptionReport {
      Issue.record("Recovery was routed to permanent approval")
      throw V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired
    }
  }
  private final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String] = []
    var values: [String] { lock.withLock { stored } }
    func append(_ value: String) { lock.withLock { stored.append(value) } }
  }
  private final class Ceremonies: V3EnrollmentCeremonyStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Data: Data] = [:]
    func loadState(vaultID: String, invitationDigest: Data) throws -> Data? {
      lock.withLock { values[invitationDigest] }
    }
    func replaceState(_ state: Data, expectedState: Data?, vaultID: String, invitationDigest: Data)
      throws
    {
      try lock.withLock {
        guard values[invitationDigest] == expectedState else {
          throw V3EnrollmentCeremonyStateError.conflict
        }
        values[invitationDigest] = state
      }
    }
  }
}
