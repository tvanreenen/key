import CryptoKit
import Foundation
internal import JSONCanonicalization

/// Syntactically bound recovery context, not authenticated registration state.
/// The manifest proof/MAC and token anchor must establish origin before opening.
struct V3RecoveryHPKEContext: Equatable, Sendable {
  static let profile = "device-wrapped"
  static let profileVersion: UInt64 = 3

  let vaultID: String
  let keyID: V3VaultKeyID
  let authorityTransitionID: String
  let recoveryGenerationID: String
  let recipient: V3RecoveryRecipient

  init(
    vaultID: String, keyID: V3VaultKeyID, authorityTransitionID: String,
    recoveryGenerationID: String, recipient: V3RecoveryRecipient
  ) throws {
    guard isValidV3UUID(vaultID), isValidV3UUID(authorityTransitionID),
      isValidV3UUID(recoveryGenerationID), recipient.status == .active
    else { throw V3RecoveryRecipientError.invalidContext }
    self.vaultID = vaultID
    self.keyID = keyID
    self.authorityTransitionID = authorityTransitionID
    self.recoveryGenerationID = recoveryGenerationID
    self.recipient = recipient
  }

  var canonicalBytes: Data {
    CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-key-context")), ("version", .integer(1)),
        ("profile", .string(Self.profile)), ("profileVersion", .integer(Self.profileVersion)),
        ("vaultID", .string(vaultID)), ("keyID", .string(keyID.rawValue)),
        ("authorityTransitionID", .string(authorityTransitionID)),
        ("recoveryGenerationID", .string(recoveryGenerationID)),
        ("recipientID", .string(recipient.recipientID.rawValue)),
        ("registrationID", .string(recipient.registrationID)),
        ("slot", .string(recipient.slot.rawValue)),
        (
          "hpkeSuite",
          .object([
            ("mode", .integer(0)), ("kem", .integer(16)),
            ("kdf", .integer(1)), ("aead", .integer(2)),
          ])
        ),
      ]))
  }
}

/// CryptoKit HPKE Base wrapping with recovery-only info/AAD. No token discovery,
/// administration, caching, fallback, retry, or product caller is provided here.
struct V3RecoveryVaultKeyHPKE: Sendable {
  static func inputs(for context: V3RecoveryHPKEContext) -> V3VaultKeyHPKE.Inputs {
    func framed(_ domain: String) -> Data {
      var bytes = Data(domain.utf8)
      bytes.append(0)
      bytes.append(context.canonicalBytes)
      return bytes
    }
    return V3VaultKeyHPKE.Inputs(
      info: framed("work.tvr.key/v3/hpke-recovery-key-info/v1"),
      authenticatedData: framed("work.tvr.key/v3/hpke-recovery-key-aad/v1"))
  }

  func wrap(vaultKey: Data, context: V3RecoveryHPKEContext) throws -> V3RecoveryWrappedKey {
    try requireKeyIdentity(vaultKey, context: context)
    return try V3RecoveryWrappedKey(
      recipientID: context.recipient.recipientID, registrationID: context.recipient.registrationID,
      wrappedKey: V3VaultKeyHPKE.seal(
        vaultKey: vaultKey, recipientPublicKey: context.recipient.publicKey,
        inputs: Self.inputs(for: context)))
  }

  @available(macOS 26.0, *)
  func unwrap(
    _ wrapped: V3RecoveryWrappedKey, recipientPrivateKey: PIVHPKEReceiver,
    context: V3RecoveryHPKEContext
  ) throws -> Data {
    // Reject substituted credentials/addresses before the agreement callback.
    guard wrapped.recipientID == context.recipient.recipientID,
      wrapped.registrationID == context.recipient.registrationID,
      recipientPrivateKey.publicKey.bytes == context.recipient.publicKey
    else { throw V3RecoveryRecipientError.recipientMismatch }
    let inputs = Self.inputs(for: context)
    // Exactly one Recipient construction. Preserve provider/cancellation errors
    // for the platform boundary; neither a retry nor another wrapper is tried.
    var recipient = try HPKE.Recipient(
      privateKey: recipientPrivateKey, ciphersuite: .P256_SHA256_AES_GCM_256,
      info: inputs.info, encapsulatedKey: wrapped.wrappedKey.encapsulatedKey)
    let vaultKey = try recipient.open(
      wrapped.wrappedKey.ciphertext, authenticating: inputs.authenticatedData)
    try requireKeyIdentity(vaultKey, context: context)
    return vaultKey
  }

  private func requireKeyIdentity(_ key: Data, context: V3RecoveryHPKEContext) throws {
    guard key.count == 32 else { throw V3RecoveryRecipientError.invalidVaultKey }
    guard try V3VaultKeyID.derive(vaultKey: key, vaultID: context.vaultID) == context.keyID else {
      throw V3RecoveryRecipientError.keyIdentityMismatch
    }
  }
}
