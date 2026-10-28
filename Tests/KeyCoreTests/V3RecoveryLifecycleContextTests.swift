import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryLifecycleContextTests {
  private typealias Core = V3RecoveryRegistrationTestSupport
  private typealias Fixture = V3RecoveryPublicationTestSupport.Fixture
  private enum Stop: Error { case policyRefused }

  @Test(arguments: [false, true])
  func currentDoesNotRecaptureReplacedOrForeignAdmission(foreign: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let ticket = foreign
      ? V3DeviceWrappedVaultKeySessionStore().beginAuthentication()
      : session.beginAuthentication()
    if !foreign {
      session.invalidate()
      try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try context(f, session: session).current(continuing: ticket)
    }
    #expect(try session.load(vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID) == Core.nextKey)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test func operationPolicyStillRunsAfterOwnershipCleanup() throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let ticket = session.beginAuthentication()
    #expect(throws: Stop.policyRefused) {
      try context(f, session: session).installCommitted(
        f.parent, vaultKey: Core.nextKey, continuing: ticket
      ) { pending in
        #expect(pending == nil)
        throw Stop.policyRefused
      }
    }
    try session.requireCurrent(ticket)
    #expect(f.ownership.value == nil && f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func changedOwnershipOrCompetingWorkDuringPolicyPreventsInstallation(competing: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let session = try session(f)
    let ticket = session.beginAuthentication()
    let retained = try V3ImmutableTransactionRecoveryAnchor(
      operationID: f.operationID, vaultID: Core.vaultID,
      intentDigest: Data(repeating: 1, count: 32), phase: .recoverable).canonicalBytes
    #expect(throws: (any Error).self) {
      try context(f, session: session).installCommitted(
        f.parent, vaultKey: Core.nextKey, continuing: ticket
      ) { _ in
        if competing { f.registration.value = retained }
        else { f.ownership.value = retained }
      }
    }
    try session.requireCurrent(ticket)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(competing ? f.registration.value == retained : f.ownership.value == retained)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }

  private func session(_ f: Fixture) throws -> V3DeviceWrappedVaultKeySessionStore {
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.nextKey, vaultID: Core.vaultID, keyID: f.parent.body.fields.keyID)
    return session
  }

  private func context(_ f: Fixture, session: V3DeviceWrappedVaultKeySessionStore)
    -> V3RecoveryLifecycleContext
  {
    .init(
      vaultID: Core.vaultID, identity: f.core.owner.publicIdentity, session: session,
      source: f.store, checkpoints: f.checkpoints, ownership: f.ownership,
      registration: f.registration, adoption: f.adoption, limits: .standard, validateScope: {})
  }
}
