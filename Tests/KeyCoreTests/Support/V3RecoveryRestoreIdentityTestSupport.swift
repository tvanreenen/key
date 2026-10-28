import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Software restored-Mac wrapper identity and private-operation counting.
enum V3RecoveryRestoreIdentityTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Base = V3RecoveryRestoreJournalTestSupport
  struct Identity: V3DeviceWrappedVaultKeyUnwrapping {
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let wrapping: P256.KeyAgreement.PrivateKey
    let calls = Core.Counter()
    let onUnwrap: @Sendable () throws -> Void
    init(
      owner: Base.Owner, vaultID: String = Base.vaultID, wrongPrivateKey: Bool = false,
      onUnwrap: @escaping @Sendable () throws -> Void = {}
    ) {
      self.vaultID = vaultID
      publicIdentity = owner.identity
      wrapping = wrongPrivateKey ? .init() : owner.wrapping
      self.onUnwrap = onUnwrap
    }
    func unwrapDeviceWrappedVaultKey(
      _ wrappedKey: V3HPKEWrappedVaultKey, context: V3VaultKeyHPKEContext, reason _: String
    ) throws -> Data {
      calls.increment()
      try onUnwrap()
      return try V3VaultKeyHPKE().unwrap(
        wrappedKey, recipientPrivateKey: wrapping, context: context)
    }
  }
}
