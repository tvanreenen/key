import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryVaultKeyHPKETests {
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
  private static let transition = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
  private static let generation = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
  private static let registration = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
  private static let otherID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b7"
  private static let vaultKey = Data(0..<32)

  @Test
  func contextAndDomainInputsHaveExactFixtures() throws {
    let context = try Self.context()
    let expected =
      "{\"authorityTransitionID\":\"\(Self.transition)\",\"format\":\"key-vault-recovery-key-context\",\"hpkeSuite\":{\"aead\":2,\"kdf\":1,\"kem\":16,\"mode\":0},\"keyID\":\"YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA\",\"profile\":\"device-wrapped\",\"profileVersion\":3,\"recipientID\":\"1C44ovwuYKXCbX5whdWXuFLGjBACYSCx3E2H-cnO7yU\",\"recoveryGenerationID\":\"\(Self.generation)\",\"registrationID\":\"\(Self.registration)\",\"slot\":\"9d\",\"vaultID\":\"\(Self.vaultID)\",\"version\":1}"
    #expect(context.canonicalBytes == Data(expected.utf8))
    let inputs = V3RecoveryVaultKeyHPKE.inputs(for: context)
    #expect(inputs.info == Data(("work.tvr.key/v3/hpke-recovery-key-info/v1\0" + expected).utf8))
    #expect(
      inputs.authenticatedData
        == Data(("work.tvr.key/v3/hpke-recovery-key-aad/v1\0" + expected).utf8))
    #expect(inputs.info != inputs.authenticatedData)
    #expect(V3RecoveryHPKEContext.profileVersion == V3EpochSigningKeyContext.profileVersion)
  }

  @Test
  func independentCryptoKitReceiverAndAgreementAdapterBothOpen() throws {
    let context = try Self.context()
    let key = try Self.privateKey()
    let wrapped = try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Self.vaultKey, context: context)
    let inputs = V3RecoveryVaultKeyHPKE.inputs(for: context)
    var software = try HPKE.Recipient(
      privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256,
      info: inputs.info, encapsulatedKey: wrapped.wrappedKey.encapsulatedKey)
    #expect(
      try software.open(wrapped.wrappedKey.ciphertext, authenticating: inputs.authenticatedData)
        == Self.vaultKey)
    guard #available(macOS 26.0, *) else { return }
    let recorder = Recorder(key: key)
    #expect(
      try V3RecoveryVaultKeyHPKE().unwrap(
        wrapped, recipientPrivateKey: recorder.receiver(), context: context) == Self.vaultKey)
    #expect(recorder.calls == 1)
    let independentlyWrapped = try Self.independentWrapper(context: context, inputs: inputs)
    #expect(
      try V3RecoveryVaultKeyHPKE().unwrap(
        independentlyWrapped,
        recipientPrivateKey: recorder.receiver(), context: context) == Self.vaultKey)
    #expect(recorder.calls == 2)
  }

  @Test
  func changesToVaultEpochGenerationAndRegistrationPreventOpening() throws {
    guard #available(macOS 26.0, *) else { return }
    let context = try Self.context()
    let wrapped = try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Self.vaultKey, context: context)
    let differentRegistration = try Self.record(registration: Self.otherID)
    let variants = try [
      Self.context(vaultID: Self.otherID, keyID: context.keyID),
      Self.context(
        keyID: V3VaultKeyID.derive(
          vaultKey: Data(repeating: 0x99, count: 32), vaultID: Self.vaultID)),
      Self.context(transition: Self.otherID), Self.context(generation: Self.otherID),
      Self.context(recipient: differentRegistration),
    ]
    for alteredContext in variants {
      let recorder = Recorder(key: try Self.privateKey())
      // Match the altered wire address so registration is tested in HPKE AAD,
      // rather than stopping at the separate pre-agreement address check.
      let addressed = try V3RecoveryWrappedKey(
        recipientID: wrapped.recipientID,
        registrationID: alteredContext.recipient.registrationID, wrappedKey: wrapped.wrappedKey)
      #expect(throws: (any Error).self) {
        try V3RecoveryVaultKeyHPKE().unwrap(
          addressed, recipientPrivateKey: recorder.receiver(), context: alteredContext)
      }
      #expect(recorder.calls == 1)
    }
  }

  @Test
  func mismatchedAddressesAndPrivateCredentialsStopBeforeAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let context = try Self.context()
    let wrapped = try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Self.vaultKey, context: context)
    let recorder = Recorder(key: try Self.privateKey())
    let wrongAddresses = try [
      V3RecoveryWrappedKey(
        recipientID: wrapped.recipientID, registrationID: Self.otherID,
        wrappedKey: wrapped.wrappedKey),
      V3RecoveryWrappedKey(
        recipientID: V3RecoveryRecipientID(
          rawValue: Base64URL.encode(Data(repeating: 0, count: 32))),
        registrationID: wrapped.registrationID, wrappedKey: wrapped.wrappedKey),
    ]
    for addressed in wrongAddresses {
      #expect(throws: V3RecoveryRecipientError.recipientMismatch) {
        try V3RecoveryVaultKeyHPKE().unwrap(
          addressed, recipientPrivateKey: recorder.receiver(), context: context)
      }
    }
    #expect(recorder.calls == 0)
    let otherKey = Recorder(key: P256.KeyAgreement.PrivateKey())
    #expect(throws: V3RecoveryRecipientError.recipientMismatch) {
      try V3RecoveryVaultKeyHPKE().unwrap(
        wrapped, recipientPrivateKey: otherKey.receiver(), context: context)
    }
    #expect(otherKey.calls == 0)
  }

  @Test
  func profileSuiteAndSeparateInfoAADBindingsCannotBeSubstituted() throws {
    guard #available(macOS 26.0, *) else { return }
    let context = try Self.context()
    let inputs = V3RecoveryVaultKeyHPKE.inputs(for: context)
    let text = String(decoding: context.canonicalBytes, as: UTF8.self)
    let alteredProfile = text.replacingOccurrences(
      of: "\"profileVersion\":3", with: "\"profileVersion\":2")
    let alteredSuite = text.replacingOccurrences(of: "\"aead\":2", with: "\"aead\":1")
    let variants = [
      V3VaultKeyHPKE.Inputs(
        info: inputs.info + Data([0]), authenticatedData: inputs.authenticatedData),
      V3VaultKeyHPKE.Inputs(
        info: inputs.info, authenticatedData: inputs.authenticatedData + Data([0])),
      V3VaultKeyHPKE.Inputs(
        info: Data(("work.tvr.key/v3/hpke-recovery-key-info/v1\0" + alteredProfile).utf8),
        authenticatedData: Data(
          ("work.tvr.key/v3/hpke-recovery-key-aad/v1\0" + alteredProfile).utf8)),
      V3VaultKeyHPKE.Inputs(
        info: Data(("work.tvr.key/v3/hpke-recovery-key-info/v1\0" + alteredSuite).utf8),
        authenticatedData: Data(("work.tvr.key/v3/hpke-recovery-key-aad/v1\0" + alteredSuite).utf8)),
    ]
    for alteredInputs in variants {
      let wrapped = try Self.independentWrapper(context: context, inputs: alteredInputs)
      let recorder = Recorder(key: try Self.privateKey())
      #expect(throws: (any Error).self) {
        try V3RecoveryVaultKeyHPKE().unwrap(
          wrapped, recipientPrivateKey: recorder.receiver(), context: context)
      }
      #expect(recorder.calls == 1)
    }
  }

  @Test
  func deviceAndRecoveryDomainsAreNotInterchangeable() throws {
    let context = try Self.context()
    let key = try Self.privateKey()
    let deviceContext = try V3VaultKeyHPKEContext(
      vaultID: Self.vaultID, keyID: context.keyID,
      authorityTransitionID: Self.transition,
      recipientDeviceID: context.recipient.recipientID.rawValue)
    let recoveryWrapped = try V3RecoveryVaultKeyHPKE().wrap(
      vaultKey: Self.vaultKey, context: context)
    #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
      try V3VaultKeyHPKE().unwrap(
        recoveryWrapped.wrappedKey, recipientPrivateKey: key, context: deviceContext)
    }
    guard #available(macOS 26.0, *) else { return }
    let deviceWrapped = try V3VaultKeyHPKE().wrap(
      vaultKey: Self.vaultKey, recipientPublicKey: key.publicKey.x963Representation,
      context: deviceContext)
    let addressed = try V3RecoveryWrappedKey(
      recipientID: context.recipient.recipientID,
      registrationID: Self.registration, wrappedKey: deviceWrapped)
    let recorder = Recorder(key: key)
    #expect(throws: (any Error).self) {
      try V3RecoveryVaultKeyHPKE().unwrap(
        addressed, recipientPrivateKey: recorder.receiver(), context: context)
    }
    #expect(recorder.calls == 1)
  }

  @Test
  func wrongPayloadKeyAndChangedCiphertextFailAfterOneAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let context = try Self.context()
    let inputs = V3RecoveryVaultKeyHPKE.inputs(for: context)
    let wrongPayload = try Self.independentWrapper(
      context: context, inputs: inputs, plaintext: Data(repeating: 0x99, count: 32))
    let recorder = Recorder(key: try Self.privateKey())
    #expect(throws: V3RecoveryRecipientError.keyIdentityMismatch) {
      try V3RecoveryVaultKeyHPKE().unwrap(
        wrongPayload, recipientPrivateKey: recorder.receiver(), context: context)
    }
    #expect(recorder.calls == 1)
    let original = try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Self.vaultKey, context: context)
    var bytes = original.wrappedKey.ciphertext
    bytes[bytes.startIndex] ^= 1
    let changed = try V3RecoveryWrappedKey(
      recipientID: original.recipientID, registrationID: original.registrationID,
      wrappedKey: V3HPKEWrappedVaultKey(
        encapsulatedKey: original.wrappedKey.encapsulatedKey, ciphertext: bytes))
    let second = Recorder(key: try Self.privateKey())
    #expect(throws: (any Error).self) {
      try V3RecoveryVaultKeyHPKE().unwrap(
        changed, recipientPrivateKey: second.receiver(), context: context)
    }
    #expect(second.calls == 1)
  }

  @Test
  func cancellationErrorPropagatesWithoutRetry() throws {
    guard #available(macOS 26.0, *) else { return }
    let context = try Self.context()
    let wrapped = try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Self.vaultKey, context: context)
    let recorder = Recorder(key: try Self.privateKey(), cancel: true)
    #expect(throws: FixtureError.cancelled) {
      try V3RecoveryVaultKeyHPKE().unwrap(
        wrapped, recipientPrivateKey: recorder.receiver(), context: context)
    }
    #expect(recorder.calls == 1)
  }

  @Test
  func contextAndWrappingRequireValidAuthorityFieldsAndCorrectVaultKey() throws {
    let context = try Self.context()
    for (vaultID, transition, generation) in [
      ("invalid", Self.transition, Self.generation),
      (Self.vaultID, "invalid", Self.generation), (Self.vaultID, Self.transition, "invalid"),
    ] {
      #expect(throws: V3RecoveryRecipientError.invalidContext) {
        try Self.context(vaultID: vaultID, transition: transition, generation: generation)
      }
    }
    #expect(throws: V3RecoveryRecipientError.invalidContext) {
      try Self.context(recipient: Self.record(status: .revoked))
    }
    #expect(throws: V3RecoveryRecipientError.invalidVaultKey) {
      try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Data(repeating: 0, count: 31), context: context)
    }
    #expect(throws: V3RecoveryRecipientError.keyIdentityMismatch) {
      try V3RecoveryVaultKeyHPKE().wrap(vaultKey: Data(repeating: 0, count: 32), context: context)
    }
  }

  private static func privateKey() throws -> P256.KeyAgreement.PrivateKey {
    try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
  }

  private static func record(
    registration: String = Self.registration, status: V3RecoveryRecipientStatus = .active
  ) throws -> V3RecoveryRecipient {
    try V3RecoveryRecipient(
      registrationID: registration, publicKey: privateKey().publicKey.x963Representation,
      slot: .keyManagement, status: status)
  }

  private static func context(
    vaultID: String = Self.vaultID, keyID: V3VaultKeyID? = nil,
    transition: String = Self.transition, generation: String = Self.generation,
    recipient: V3RecoveryRecipient? = nil
  ) throws -> V3RecoveryHPKEContext {
    try V3RecoveryHPKEContext(
      vaultID: vaultID,
      keyID: keyID ?? V3VaultKeyID.derive(vaultKey: Self.vaultKey, vaultID: Self.vaultID),
      authorityTransitionID: transition, recoveryGenerationID: generation,
      recipient: recipient ?? record())
  }

  private static func independentWrapper(
    context: V3RecoveryHPKEContext, inputs: V3VaultKeyHPKE.Inputs,
    plaintext: Data = Self.vaultKey
  ) throws -> V3RecoveryWrappedKey {
    let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: context.recipient.publicKey)
    var sender = try HPKE.Sender(
      recipientKey: publicKey, ciphersuite: .P256_SHA256_AES_GCM_256, info: inputs.info)
    let ciphertext = try sender.seal(plaintext, authenticating: inputs.authenticatedData)
    return try V3RecoveryWrappedKey(
      recipientID: context.recipient.recipientID, registrationID: context.recipient.registrationID,
      wrappedKey: V3HPKEWrappedVaultKey(
        encapsulatedKey: sender.encapsulatedKey, ciphertext: ciphertext))
  }

  private enum FixtureError: Error, Equatable { case cancelled }

  private final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let key: P256.KeyAgreement.PrivateKey
    private let cancel: Bool

    init(key: P256.KeyAgreement.PrivateKey, cancel: Bool = false) {
      self.key = key
      self.cancel = cancel
    }
    var calls: Int {
      lock.lock()
      defer { lock.unlock() }
      return count
    }

    @available(macOS 26.0, *)
    func receiver() throws -> PIVHPKEReceiver {
      try PIVHPKEReceiver(publicBytes: key.publicKey.x963Representation) { bytes in
        self.lock.lock()
        self.count += 1
        self.lock.unlock()
        if self.cancel { throw FixtureError.cancelled }
        return try self.key.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: bytes)
        )
        .withUnsafeBytes { Data($0) }
      }
    }
  }
}
