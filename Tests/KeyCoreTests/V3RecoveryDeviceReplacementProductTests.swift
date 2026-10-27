import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryDeviceReplacementProductTests {
  private typealias Core = V3RecoveryRegistrationTestSupport
  private typealias Disk = V3RecoveryPublicationTestSupport
  private typealias Local = V3RecoveryDeviceProductTestSupport
  private static let now = V3RecoveryEnrollmentTestSupport.now

  @Test func signedRosterHistoryProvesRevocationAcrossRotationsWithoutOpeningFutureKeys() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    try f.rotate()
    try f.ownerMutations.edit(
      name: "fixture/secret", secret: "intermediate", type: .secret, operationID: .init())
    try f.rotate()
    let revoked = try f.revoke()
    try f.ownerMutations.edit(
      name: "fixture/secret", secret: "later contents", type: .secret, operationID: .init())
    let shared = f.disk.checkpoints.value
    let target = try #require(try f.deleter.deletionTarget(vaultID: Core.vaultID))
    let result = try f.adapter(f.scope()).classifyCurrentAuthority(for: target)
    guard case .revoked(let actual, let authority) = result,
      case .ownerAuthorizedRevocation(let floor, let digest, let owner) = authority
    else {
      Issue.record("Expected anchored revocation eligibility")
      return
    }
    #expect(actual == target && floor == f.fixture.checkpoint && digest == revoked.envelope.digest)
    #expect(owner == f.fixture.owner.publicIdentity && f.unwraps.value == 1)
    #expect(
      f.local.value == f.fixture.checkpoint.canonicalBytes && f.disk.checkpoints.value == shared)
    #expect(f.records.value != nil && f.intents.value == nil)
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try f.session.load(vaultID: Core.vaultID, keyID: revoked.envelope.body.fields.keyID)
    }
  }

  @Test func confirmedCleanupAndComparedReenrollmentGiveThisMacFreshOrdinaryAccess() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.revoke()
    let invitation = try f.invite()
    let old = try #require(try f.deleter.deletionTarget(vaultID: Core.vaultID))
    let request = KeyShareRequest.join(
      invitationID: v3LowercaseHex(invitation), deviceName: "Replacement Mac")
    let handler = try f.handler(f.scope())
    let review = try #require(handler.handle(.share(request)).deviceReplacementReview)
    let shared = f.disk.checkpoints.value
    #expect(
      handler.handle(
        .share(
          .replaceCurrentDevice(
            invitationID: v3LowercaseHex(invitation),
            confirmationToken: review.confirmationToken))
      ).exitCode == EXIT_SUCCESS)
    #expect(f.records.value == nil && f.local.value == nil && f.disk.checkpoints.value == shared)
    #expect(try f.admission.state(vaultID: Core.vaultID) == .enrollmentPending)
    f.session.invalidate()
    let joining = try f.handler(f.scope())
    #expect(joining.handle(.share(request)).exitCode == EXIT_SUCCESS)
    let newIdentity = try #require(try f.manager.loadRecordedPublicIdentity(vaultID: Core.vaultID))
    #expect(newIdentity.deviceID != old.identity.deviceID)
    let requestID = try #require(
      f.ownerExchange.availableJoinRequestDigests(
        vaultID: Core.vaultID,
        invitationDigest: invitation, at: Self.now, maximumCount: 10
      ).first)
    _ = try f.ownerWorkflow.compare(
      vaultID: Core.vaultID, invitationDigest: invitation,
      joinRequestDigest: requestID, at: Self.now)
    let compared = try #require(
      f.ownerExchange.resumeDeviceWrappedOwnerApproval(
        vaultID: Core.vaultID,
        invitationDigest: invitation
      ).transcript)
    _ = try f.ownerWorkflow.approve(
      vaultID: Core.vaultID, invitationDigest: invitation,
      comparisonCode: compared.comparisonCode, at: Self.now, operationID: .init())
    let accepted = joining.handle(
      .share(
        .accept(
          vaultID: Core.vaultID,
          invitationID: v3LowercaseHex(invitation), comparisonCode: compared.comparisonCode)))
    #expect(accepted.exitCode == EXIT_SUCCESS)
    #expect(f.intents.value == nil && f.selection.ids == [Core.vaultID])
    let context = try f.unlock(f.scope()).authenticatedReadContext(
      reason: "Software ordinary access")
    #expect(
      context.current.envelope.body.fields.devices.contains(
        .init(identity: old.identity, status: .revoked)))
    #expect(
      context.current.envelope.body.fields.devices.contains(
        .init(identity: newIdentity, status: .active)))
    #expect(
      !context.current.envelope.body.fields.wrappedKeys.contains(where: {
        $0.recipientDeviceID == old.identity.deviceID
      }))
    try f.joinedMutations.add(
      name: "after/rejoin", secret: "continued", type: .secret, operationID: .init())
    f.session.invalidate()
    let reader = V3RecoveryReadOnlyVaultRuntime(
      source: f.disk.store, unlockRuntime: f.unlock(f.scope()))
    #expect(try reader.read(name: "after/rejoin", allowStale: false).plaintext == "continued")
  }

  @Test(arguments: [
    V3ReplacementEnrollmentIntentPhase.identityDeletionStarted, .identityDeleted,
    .checkpointDeleted,
  ])
  func stoppedCleanupKeepsExactProgressAndResumesWithoutOldPrivateCredentials(
    phase: V3ReplacementEnrollmentIntentPhase
  ) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.revoke()
    let invitation = try f.invite()
    let scope = f.scope()
    let handler = try f.handler(scope)
    let review = try #require(
      handler.handle(
        .share(
          .join(
            invitationID: v3LowercaseHex(invitation),
            deviceName: "Replacement Mac"))
      ).deviceReplacementReview)
    f.intents.afterPersist = { if $0 == phase { scope.cancellation.cancel() } }
    let stopped = handler.handle(
      .share(
        .replaceCurrentDevice(
          invitationID: v3LowercaseHex(invitation),
          confirmationToken: review.confirmationToken)))
    #expect(stopped.exitCode != EXIT_SUCCESS)
    let intent = try V3ReplacementEnrollmentIntent(canonicalBytes: #require(f.intents.value))
    #expect(intent.phase == phase)
    #expect((f.records.value != nil) == (phase == .identityDeletionStarted))
    #expect((f.local.value == nil) == (phase == .checkpointDeleted))
    let unwraps = f.unwraps.value
    f.intents.afterPersist = { _ in }
    f.session.invalidate()
    if phase != .checkpointDeleted {
      let fresh = try f.handler(f.scope())
      let resumedReview = try #require(
        fresh.handle(
          .share(
            .join(
              invitationID: v3LowercaseHex(invitation),
              deviceName: "Replacement Mac"))
        ).deviceReplacementReview)
      #expect(resumedReview.confirmationToken == v3LowercaseHex(intent.review.digest))
      #expect(
        fresh.handle(
          .share(
            .replaceCurrentDevice(
              invitationID: v3LowercaseHex(invitation),
              confirmationToken: resumedReview.confirmationToken))
        ).exitCode == EXIT_SUCCESS)
    }
    #expect(f.records.value == nil && f.local.value == nil && f.unwraps.value == unwraps)
    #expect(try f.admission.state(vaultID: Core.vaultID) == .enrollmentPending)
    #expect(try f.handler(f.scope()).handle(.list).exitCode != EXIT_SUCCESS)
  }

  @Test(arguments: [false, true])
  func activeIdentityOrVisibleConflictCannotAuthorizeCleanup(conflict: Bool) throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    if conflict {
      _ = try f.revoke()
      try f.fixture.addBranch()
    }
    let invitation = try f.invite()
    let response = try f.handler(f.scope()).handle(
      .share(
        .join(
          invitationID: v3LowercaseHex(invitation),
          deviceName: "Replacement Mac")))
    #expect(response.exitCode != EXIT_SUCCESS && f.records.value != nil && f.intents.value == nil)
    #expect(f.local.value == f.fixture.checkpoint.canonicalBytes)
  }

  @Test func stoppedScopeBeforeOrDuringMacApprovalCannotProduceEligibility() throws {
    let f = try Fixture()
    defer { f.disk.remove() }
    _ = try f.revoke()
    let target = try #require(try f.deleter.deletionTarget(vaultID: Core.vaultID))
    let renamed = try V3EnrollmentDeviceIdentity(
      displayName: "Different record metadata",
      signingPublicKey: target.identity.signingPublicKey,
      wrappingPublicKey: target.identity.wrappingPublicKey)
    let mismatched = try V3EnrollmentDeviceIdentityDeletionTarget(
      vaultID: Core.vaultID,
      identity: renamed, recordDigest: target.recordDigest)
    #expect(throws: V3ReplacementDeviceIdentityClassificationError.identityMismatch) {
      try f.adapter(f.scope()).classifyCurrentAuthority(for: mismatched)
    }
    let stopped = f.scope()
    stopped.cancellation.cancel()
    #expect(throws: (any Error).self) {
      try f.adapter(stopped).classifyCurrentAuthority(for: target)
    }
    #expect(f.unwraps.value == 0)
    let active = f.scope()
    f.onUnwrap = { active.cancellation.cancel() }
    #expect(throws: (any Error).self) {
      try f.adapter(active).classifyCurrentAuthority(for: target)
    }
    #expect(f.unwraps.value == 1 && f.records.value != nil && f.intents.value == nil)
    #expect(f.local.value == f.fixture.checkpoint.canonicalBytes)
  }

  private final class Fixture: @unchecked Sendable {
    let fixture: V3RecoveryRevocationTestSupport.Fixture
    let records: Local.Records
    let local: Local.Checkpoints
    let intents = Local.Intents()
    let pending = [Disk.Ownership(), Disk.Ownership(), Disk.Ownership()]
    let session = V3DeviceWrappedVaultKeySessionStore()
    let ownerSession = V3DeviceWrappedVaultKeySessionStore()
    let ownerStates = Local.Ceremonies(), joiningStates = Local.Ceremonies()
    let unwraps = Core.Counter()
    let selection = Selection()
    var onUnwrap: @Sendable () throws -> Void = {}
    var disk: Disk.Fixture { fixture.enrollment.disk }
    var manager: V3EnrollmentDeviceIdentityManager {
      .init(
        recordStore: records,
        keyOperations: AdoptionDeviceKeyOperations(signingScalar: 0x51, wrappingScalar: 0x52))
    }
    var deleter: V3EnrollmentDeviceIdentityDeleter { .init(recordStore: records) }
    var admission: V3ReplacementEnrollmentAdmission { .init(intentStore: intents) }
    init() throws {
      fixture = try .init()
      let old = fixture.enrollment.joiner
      records = Local.Records(
        try V3EnrollmentDeviceKeyRecord(
          vaultID: Core.vaultID,
          identity: old.publicIdentity, signingKeyRepresentation: old.signingKey.rawRepresentation,
          wrappingKeyRepresentation: old.wrappingKey.rawRepresentation
        ).canonicalBytes)
      local = Local.Checkpoints(fixture.checkpoint.canonicalBytes)
      try ownerSession.install(
        fixture.currentKey, vaultID: Core.vaultID, keyID: fixture.parent.body.fields.keyID)
    }
    func scope() -> KeyRecoveryRequestScope {
      .init(authentication: .init(), deadline: .now() + 90)
    }
    func validate(_ scope: KeyRecoveryRequestScope) throws {
      try scope.requireCurrent()
      for store in pending {
        guard store.value == nil else {
          throw V3RecoveryContentPublicationError.otherMutationPending
        }
      }
    }
    func identity(_ scope: KeyRecoveryRequestScope) throws -> any V3DeviceWrappedVaultKeyUnwrapping
    {
      try validate(scope)
      guard
        let identity = try manager.loadIdentity(vaultID: Core.vaultID, reason: "Software fixture")
      else {
        throw V3RecoveryVaultUnlockError.identityUnavailable
      }
      return V3ScopedDeviceUnwrapper(
        base: Counted(base: identity, count: unwraps, onUnwrap: onUnwrap),
        validate: { try self.validate(scope) })
    }
    func unlock(_ scope: KeyRecoveryRequestScope) -> V3RecoveryVaultUnlockRuntime {
      .init(
        vaultID: Core.vaultID, checkpointStore: local, source: disk.store, cache: disk.cache,
        identityLoader: Loader(load: { try self.identity(scope) }), session: session,
        transactionOwnershipStore: pending[0], registrationOwnershipStore: pending[1],
        adoptionOwnershipStore: pending[2])
    }
    func adapter(_ scope: KeyRecoveryRequestScope)
      -> V3RecoveryReplacementDeviceIdentityAuthorityAdapter
    {
      .init(
        vaultID: Core.vaultID, source: disk.store, unlock: unlock(scope),
        loadIdentity: { try self.identity(scope) }, validateScope: { try self.validate(scope) })
    }
    var ownerMutations: V3RecoveryVaultMutationService {
      .init(
        vaultID: Core.vaultID, session: ownerSession, objectStore: disk.store,
        checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
        registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
        cache: disk.cache)
    }
    var joinedMutations: V3RecoveryVaultMutationService {
      .init(
        vaultID: Core.vaultID, session: session, objectStore: disk.store,
        checkpointStore: local, recoveryAnchorStore: pending[0],
        registrationAnchorStore: pending[1],
        adoptionAnchorStore: pending[2], cache: disk.cache)
    }
    func rotate() throws {
      let service = V3RecoveryKeyRotationService(
        vaultID: Core.vaultID, identity: fixture.owner,
        session: ownerSession, objectStore: disk.store, checkpointStore: disk.checkpoints,
        recoveryAnchorStore: disk.ownership, registrationAnchorStore: disk.registration,
        adoptionAnchorStore: disk.adoption, cache: disk.cache)
      _ = try service.rotate(expectedCheckpoint: service.prepare().checkpoint, operationID: .init())
    }
    func revoke() throws -> V3RecoveryDeviceRevocationCommit {
      let service = V3RecoveryAuthorityChangeService(
        vaultID: Core.vaultID, identity: fixture.owner,
        session: ownerSession, objectStore: disk.store, checkpointStore: disk.checkpoints,
        recoveryAnchorStore: disk.ownership, registrationAnchorStore: disk.registration,
        adoptionAnchorStore: disk.adoption, cache: disk.cache)
      return try service.revoke(
        service.prepareRevocation(revoking: fixture.enrollment.joiner.publicIdentity.deviceID),
        operationID: .init())
    }
    var ownerExchange: V3EnrollmentExchangeCoordinator {
      get throws {
        .init(
          mailbox: V3FilesystemEnrollmentMailbox(
            rootHandle: try VaultRootDirectoryHandle(opening: disk.root)), stateStore: ownerStates)
      }
    }
    var ownerWorkflow: V3RecoveryEnrollmentOwnerWorkflow {
      get throws {
        let unlock = V3RecoveryVaultUnlockRuntime(
          vaultID: Core.vaultID, checkpointStore: disk.checkpoints,
          source: disk.store, cache: disk.cache,
          identityLoader: Loader(load: { self.fixture.owner }),
          session: ownerSession, transactionOwnershipStore: disk.ownership,
          registrationOwnershipStore: disk.registration, adoptionOwnershipStore: disk.adoption)
        return .init(
          vaultID: Core.vaultID, unlock: unlock, session: ownerSession, exchange: try ownerExchange,
          ownership: disk.ownership, loadIdentity: { self.fixture.owner },
          makeService: { identity in
            .init(
              vaultID: Core.vaultID, identity: identity, session: self.ownerSession,
              objectStore: self.disk.store, checkpointStore: self.disk.checkpoints,
              recoveryAnchorStore: self.disk.ownership,
              registrationAnchorStore: self.disk.registration,
              adoptionAnchorStore: self.disk.adoption, ceremonyStore: self.ownerStates,
              cache: self.disk.cache)
          })
      }
    }
    func invite() throws -> Data {
      _ = try ownerWorkflow.createInvitation(
        deviceName: fixture.owner.publicIdentity.displayName,
        at: V3RecoveryDeviceReplacementProductTests.now)
      return try #require(ownerExchange.availableInvitationDigests(maximumCount: 10).first)
    }
    func handler(_ scope: KeyRecoveryRequestScope) throws -> KeyServiceHandler {
      let validate: @Sendable () throws -> Void = { try self.validate(scope) }
      let authority = adapter(scope)
      let state = try admission.state(vaultID: Core.vaultID)
      let workflow = V3ReplacementEnrollmentWorkflow(
        vaultID: Core.vaultID,
        loadTarget: {
          try validate()
          return try self.deleter.deletionTarget(vaultID: $0)
        },
        authorityClassifier: authority, intentStore: intents,
        coordinator: V3ReplacementEnrollmentCoordinator(
          vaultID: Core.vaultID,
          mutationOwner: VaultTransactionMutationOwner(), authorityClassifier: authority,
          identityDeleter: deleter, checkpointStore: local, intentStore: intents,
          validateScope: validate), validateScope: validate)
      let exchange = V3EnrollmentExchangeCoordinator(
        mailbox: V3FilesystemEnrollmentMailbox(
          rootHandle: try VaultRootDirectoryHandle(opening: disk.root)), stateStore: joiningStates)
      let adoption = V3RecoveryEnrollmentProductAdoption(
        source: disk.store, checkpoints: local,
        ownership: pending[0], registration: pending[1], adoption: pending[2],
        ceremonies: joiningStates,
        cache: disk.cache, session: session, loadIdentity: { _ in try self.identity(scope) },
        verifyRuntime: { commit, ticket in
          let unlock = self.unlock(scope)
          let context = try unlock.continuedReadContext(
            current: .init(
              checkpoint: commit.checkpoint,
              envelope: commit.envelope), ticket: ticket)
          _ = try V3RecoveryReadOnlyVaultRuntime(source: self.disk.store, unlockRuntime: unlock)
            .list(allowStale: false, context: context)
        }, selectVault: { self.selection.ids.append($0) },
        completeReplacement: { try self.admission.consumeCompletedIntent(vaultID: $0) },
        validateScope: validate)
      let enrollment = V3EnrollmentWorkflowService(
        selectedVaultID: state == .enrollmentPending ? nil : Core.vaultID,
        replacementVaultID: state == .enrollmentPending ? Core.vaultID : nil,
        source: disk.store, objectStore: disk.store, checkpointStore: local, exchange: exchange,
        identityManager: manager, vaultKeyStore: MemoryVaultKeyStore(), keychainMode: .local,
        selectVault: { _ in Issue.record("Legacy selection") }, verifyRuntime: { _ in },
        deviceWrappedAdoption: adoption, validateScope: validate)
      return KeyServiceHandler(
        keyStore: MemoryVaultKeyStore(), entryStore: EntryStore(rootURL: disk.root),
        now: {
          Date(timeIntervalSince1970: TimeInterval(V3RecoveryDeviceReplacementProductTests.now))
        },
        mutationOwner: VaultTransactionMutationOwner(), enrollmentService: enrollment,
        validateJoinInvitation: { digest, now in
          try validate()
          guard
            try exchange.receiveInvitation(digest: digest, at: now).invitation.vaultID
              == Core.vaultID
          else {
            throw V3EnrollmentCeremonyStateError.wrongRole
          }
        }, replacementService: workflow, configuredVaultID: Core.vaultID,
        replacementAdmissionState: state)
    }
  }
  private struct Loader: V3DeviceWrappedIdentityLoading {
    let load: @Sendable () throws -> any V3DeviceWrappedVaultKeyUnwrapping
    func loadDeviceIdentity(vaultID: String, reason: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? { try load() }
  }
  private struct Counted: V3DeviceWrappedVaultKeyUnwrapping {
    let base: any V3DeviceWrappedVaultKeyUnwrapping
    let count: Core.Counter
    let onUnwrap: @Sendable () throws -> Void
    var vaultID: String { base.vaultID }
    var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
    func unwrapDeviceWrappedVaultKey(
      _ ciphertext: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext,
      reason: String
    ) throws -> Data {
      count.increment()
      let result = try base.unwrapDeviceWrappedVaultKey(
        ciphertext, context: context, reason: reason)
      try onUnwrap()
      return result
    }
  }
  private final class Selection: @unchecked Sendable { var ids: [String] = [] }
}
