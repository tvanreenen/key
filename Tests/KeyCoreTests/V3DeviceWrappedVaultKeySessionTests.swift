import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedVaultKeySessionTests {
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c85a1"
  private static let oldKey = Data(repeating: 1, count: 32)
  private static let nextKey = Data(repeating: 2, count: 32)
  private var oldID: V3VaultKeyID {
    get throws { try V3VaultKeyID.derive(vaultKey: Self.oldKey, vaultID: Self.vaultID) }
  }
  private var nextID: V3VaultKeyID {
    get throws { try V3VaultKeyID.derive(vaultKey: Self.nextKey, vaultID: Self.vaultID) }
  }

  @Test func liveSessionCanSwitchOnlyFromItsExactPriorEpoch() throws {
    let s = try session()
    try s.replace(Self.nextKey, vaultID: Self.vaultID, keyID: nextID, expectedKeyID: oldID)
    #expect(try s.load(vaultID: Self.vaultID, keyID: nextID) == Self.nextKey)
    #expect(s.sessionStatus().isUnlocked)
  }

  @Test(arguments: [false, true])
  func invalidKeyOrWrongPriorEpochCannotReplaceOrClearValidSession(invalidKey: Bool) throws {
    let s = try session()
    if invalidKey {
      #expect(throws: V3DeviceWrappedVaultKeySessionError.invalidKey) {
        try s.replace(Self.oldKey, vaultID: Self.vaultID, keyID: nextID, expectedKeyID: oldID)
      }
    } else {
      #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
        try s.replace(Self.nextKey, vaultID: Self.vaultID, keyID: nextID, expectedKeyID: nextID)
      }
    }
    #expect(try s.load(vaultID: Self.vaultID, keyID: oldID) == Self.oldKey)
  }

  @Test func foreignVaultCannotReplaceCurrentSession() throws {
    let s = try session()
    let otherVault = "018f4d38-7d5a-7b20-b0f1-97d6e96c85a2"
    let otherID = try V3VaultKeyID.derive(vaultKey: Self.nextKey, vaultID: otherVault)
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.replace(Self.nextKey, vaultID: otherVault, keyID: otherID, expectedKeyID: oldID)
    }
    #expect(try s.load(vaultID: Self.vaultID, keyID: oldID) == Self.oldKey)
  }

  @Test(arguments: [false, true])
  func absentOrExplicitlyLockedSessionCannotBeRevived(installed: Bool) throws {
    let s = installed ? try session() : V3DeviceWrappedVaultKeySessionStore()
    if installed { s.invalidate() }
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.replace(Self.nextKey, vaultID: Self.vaultID, keyID: nextID, expectedKeyID: oldID)
    }
    #expect(!s.hasResidentKey && !s.sessionStatus().isUnlocked)
  }

  @Test func expiredSessionCannotBeRevived() async throws {
    let s = V3DeviceWrappedVaultKeySessionStore(inactivityTimeout: .milliseconds(10))
    try s.install(Self.oldKey, vaultID: Self.vaultID, keyID: oldID)
    try await Task.sleep(for: .milliseconds(40))
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.replace(Self.nextKey, vaultID: Self.vaultID, keyID: nextID, expectedKeyID: oldID)
    }
    #expect(!s.hasResidentKey && !s.sessionStatus().isUnlocked)
  }

  private func session() throws -> V3DeviceWrappedVaultKeySessionStore {
    let s = V3DeviceWrappedVaultKeySessionStore()
    try s.install(Self.oldKey, vaultID: Self.vaultID, keyID: oldID)
    return s
  }

  @Test func emptySessionStatusPollingDoesNotCancelFreshAuthentication() throws {
    let s = V3DeviceWrappedVaultKeySessionStore()
    let ticket = s.beginAuthentication()
    #expect(!s.sessionStatus().isUnlocked)
    try s.requireCurrent(ticket)
    try s.install(Self.nextKey, vaultID: Self.vaultID, keyID: nextID, authenticationTicket: ticket)
    #expect(try s.load(vaultID: Self.vaultID, keyID: nextID) == Self.nextKey)
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.requireCurrent(ticket)
    }
  }

  @Test(arguments: [false, true])
  func explicitLockCancelsAuthenticationEvenWhenSessionWasAlreadyEmpty(installed: Bool) throws {
    let s = installed ? try session() : V3DeviceWrappedVaultKeySessionStore()
    let ticket = s.beginAuthentication()
    s.invalidate()
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.install(
        Self.nextKey, vaultID: Self.vaultID, keyID: nextID, authenticationTicket: ticket)
    }
    #expect(!s.hasResidentKey)
  }

  @Test func foreignStoreOrReplacedSessionCannotAcceptOldAuthenticationTicket() throws {
    let s = try session()
    let ticket = s.beginAuthentication()
    let other = V3DeviceWrappedVaultKeySessionStore()
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try other.install(
        Self.nextKey, vaultID: Self.vaultID, keyID: nextID, authenticationTicket: ticket)
    }
    try s.replace(Self.nextKey, vaultID: Self.vaultID, keyID: nextID, expectedKeyID: oldID)
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.requireCurrent(ticket)
    }
    #expect(try s.load(vaultID: Self.vaultID, keyID: nextID) == Self.nextKey)
  }

  @Test func actualExpiryCancelsPendingAuthentication() async throws {
    let s = V3DeviceWrappedVaultKeySessionStore(inactivityTimeout: .milliseconds(10))
    try s.install(Self.oldKey, vaultID: Self.vaultID, keyID: oldID)
    let ticket = s.beginAuthentication()
    try await Task.sleep(for: .milliseconds(40))
    #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
      try s.install(
        Self.nextKey, vaultID: Self.vaultID, keyID: nextID, authenticationTicket: ticket)
    }
    #expect(!s.hasResidentKey)
  }
}
