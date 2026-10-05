import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3EpochSigningKeyTests {
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
  private static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
  private static let otherID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
  private static let vaultKey = Data((0..<32).map(UInt8.init))
  private static let fixturePublicKey =
    "BG_wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo"

  @Test
  func preparesAnIndependentKeyAndPreservesExactCapsuleBytes() throws {
    let context = try Self.context()
    let cipher = V3EpochSigningKeyCipher()
    let capsule = try cipher.prepare(context: context, vaultKey: Self.vaultKey)
    let other = try cipher.prepare(context: context, vaultKey: Self.vaultKey)
    #expect(capsule.publicKey.count == 65)
    #expect(capsule.protectedSigningKey.count == 60)
    #expect(capsule.publicKey != other.publicKey)
    #expect(capsule.protectedSigningKey != other.protectedSigningKey)

    let bytes = capsule.canonicalBytes
    let decoded = try V3EpochSigningKeyCapsuleCodec().parseCanonical(bytes)
    #expect(decoded == capsule)
    #expect(decoded.canonicalBytes == bytes)

    let message = Data("local capsule fixture".utf8)
    let rawSignature = try cipher.withSigningKey(decoded, context: context, vaultKey: Self.vaultKey)
    {
      try V3P256Signature.canonicalize($0.signature(for: message).rawRepresentation)
    }
    let publicKey = try P256.Signing.PublicKey(x963Representation: capsule.publicKey)
    #expect(V3P256Signature.isCanonical(rawSignature))
    #expect(
      publicKey.isValidSignature(
        try P256.Signing.ECDSASignature(rawRepresentation: rawSignature), for: message
      ))
    #expect(capsule.canonicalBytes == bytes)
  }

  @Test
  func keyLengthAndIdentityAreCheckedBeforeKeyAccess() throws {
    let context = try Self.context()
    let cipher = V3EpochSigningKeyCipher()
    #expect(throws: V3EpochSigningKeyError.invalidVaultKey) {
      try cipher.prepare(context: context, vaultKey: Data(repeating: 0, count: 31))
    }
    #expect(throws: V3EpochSigningKeyError.keyIdentityMismatch) {
      try cipher.prepare(context: context, vaultKey: Data(repeating: 0x99, count: 32))
    }
    let capsule = try cipher.prepare(context: context, vaultKey: Self.vaultKey)
    var calls = 0
    #expect(throws: V3EpochSigningKeyError.invalidVaultKey) {
      try cipher.withSigningKey(capsule, context: context, vaultKey: Data()) { _ in calls += 1 }
    }
    #expect(throws: V3EpochSigningKeyError.keyIdentityMismatch) {
      try cipher.withSigningKey(
        capsule, context: context, vaultKey: Data(repeating: 0x99, count: 32)
      ) { _ in calls += 1 }
    }
    #expect(calls == 0)
  }

  @Test
  func changedVaultTransitionOrKeyCannotOpenTheCapsule() throws {
    let capsule = try V3EpochSigningKeyCipher().prepare(
      context: Self.context(), vaultKey: Self.vaultKey
    )
    let otherKey = Data(repeating: 0x77, count: 32)
    for (context, key) in try [
      (Self.context(vaultID: Self.otherID), Self.vaultKey),
      (Self.context(transitionID: Self.otherID), Self.vaultKey),
      (Self.context(vaultKey: otherKey), otherKey),
    ] {
      #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
        try V3EpochSigningKeyCipher().withSigningKey(capsule, context: context, vaultKey: key) {
          _ in
        }
      }
    }
  }

  @Test
  func validatesCanonicalIdentifiersAndPublicPoints() throws {
    let keyID = try Self.context().keyID
    for (vaultID, transitionID) in [
      ("not-a-uuid", Self.transitionID),
      (Self.vaultID.uppercased(), Self.transitionID),
      (Self.vaultID, "not-a-uuid"),
      (Self.vaultID, Self.transitionID.uppercased()),
    ] {
      #expect(throws: V3EpochSigningKeyError.invalidContext) {
        try V3EpochSigningKeyContext(
          vaultID: vaultID, keyID: keyID, authorityTransitionID: transitionID)
      }
    }
    for publicKey in [
      Data(), Data(repeating: 0, count: 65), Data([0x04]) + Data(repeating: 0, count: 64),
    ] {
      #expect(throws: V3EpochSigningKeyError.invalidPublicKey) {
        try V3EpochSigningKeyCapsule(
          publicKey: publicKey, protectedSigningKey: Data(repeating: 0, count: 60))
      }
      #expect(throws: V3EpochSigningKeyError.invalidPublicKey) {
        try Self.context().authenticatedData(publicKey: publicKey)
      }
    }
    let key = P256.Signing.PrivateKey().publicKey
    #expect(throws: V3EpochSigningKeyError.invalidPublicKey) {
      try V3EpochSigningKeyCapsule(
        publicKey: key.compressedRepresentation, protectedSigningKey: Data(repeating: 0, count: 60))
    }
    for length in [0, 59, 61] {
      #expect(throws: V3EpochSigningKeyError.invalidCapsule) {
        try V3EpochSigningKeyCapsule(
          publicKey: key.x963Representation, protectedSigningKey: Data(repeating: 0, count: length))
      }
    }
  }

  @Test(arguments: [0, 12, 59])
  func refusesModifiedNonceCiphertextOrTag(index: Int) throws {
    let context = try Self.context()
    let original = try V3EpochSigningKeyCipher().prepare(context: context, vaultKey: Self.vaultKey)
    var bytes = original.protectedSigningKey
    bytes[index] ^= 1
    let changed = try V3EpochSigningKeyCapsule(
      publicKey: original.publicKey, protectedSigningKey: bytes)
    var calls = 0
    #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
      try V3EpochSigningKeyCipher().withSigningKey(
        changed, context: context, vaultKey: Self.vaultKey
      ) { _ in calls += 1 }
    }
    #expect(calls == 0)
  }

  @Test
  func publicKeySubstitutionFailsAuthentication() throws {
    let context = try Self.context()
    let original = try V3EpochSigningKeyCipher().prepare(context: context, vaultKey: Self.vaultKey)
    let changed = try V3EpochSigningKeyCapsule(
      publicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
      protectedSigningKey: original.protectedSigningKey
    )
    #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
      try V3EpochSigningKeyCipher().withSigningKey(
        changed, context: context, vaultKey: Self.vaultKey
      ) { _ in }
    }
  }

  @Test
  func independentlySealedFixtureOpensAndChecksPrivatePublicCorrespondence() throws {
    let context = try Self.context()
    let key = P256.Signing.PrivateKey()
    let publicKey = key.publicKey.x963Representation
    let bytes = try Self.sealFixture(
      key.rawRepresentation, aad: Self.expectedAAD(publicKey: publicKey))
    let capsule = try V3EpochSigningKeyCapsule(publicKey: publicKey, protectedSigningKey: bytes)
    let actual = try V3EpochSigningKeyCipher().withSigningKey(
      capsule, context: context, vaultKey: Self.vaultKey
    ) {
      $0.publicKey.x963Representation
    }
    #expect(actual == publicKey)

    // These local fixtures have a valid AEAD tag but a mismatched or invalid
    // private representation. The consumer must reject both before use.
    for raw in [P256.Signing.PrivateKey().rawRepresentation, Data(repeating: 0, count: 32)] {
      let mismatched = try V3EpochSigningKeyCapsule(
        publicKey: publicKey,
        protectedSigningKey: Self.sealFixture(raw, aad: Self.expectedAAD(publicKey: publicKey))
      )
      var calls = 0
      #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
        try V3EpochSigningKeyCipher().withSigningKey(
          mismatched, context: context, vaultKey: Self.vaultKey
        ) { _ in calls += 1 }
      }
      #expect(calls == 0)
    }
  }

  @Test(arguments: [
    "domain", "version", "profile", "profileVersion", "signingAlgorithm", "protectionAlgorithm",
  ])
  func differentAADDomainVersionOrAlgorithmDoesNotAuthenticate(field: String) throws {
    let key = P256.Signing.PrivateKey()
    let publicKey = key.publicKey.x963Representation
    let replacements: [String: (String, String)] = [
      "domain": ("epoch-signing-key-aad/v1", "epoch-signing-key-aad/v2"),
      "version": ("\"version\":1", "\"version\":2"),
      "profile": ("\"profile\":\"device-wrapped\"", "\"profile\":\"other\""),
      "profileVersion": ("\"profileVersion\":3", "\"profileVersion\":2"),
      "signingAlgorithm": ("P-256-ECDSA-SHA256", "P-256-ECDSA"),
      "protectionAlgorithm": ("HKDF-SHA256+AES-256-GCM", "AES-256-GCM"),
    ]
    let replacement = try #require(replacements[field])
    let aad = Data(
      String(decoding: Self.expectedAAD(publicKey: publicKey), as: UTF8.self)
        .replacingOccurrences(of: replacement.0, with: replacement.1).utf8)
    let capsule = try V3EpochSigningKeyCapsule(
      publicKey: publicKey, protectedSigningKey: Self.sealFixture(key.rawRepresentation, aad: aad)
    )
    #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
      try V3EpochSigningKeyCipher().withSigningKey(
        capsule, context: Self.context(), vaultKey: Self.vaultKey
      ) { _ in }
    }
  }

  @Test
  func generatedCapsuleOpensWithIndependentHKDFAndExactAAD() throws {
    let context = try Self.context()
    let capsule = try V3EpochSigningKeyCipher().prepare(context: context, vaultKey: Self.vaultKey)
    #expect(
      try context.authenticatedData(publicKey: capsule.publicKey)
        == Self.expectedAAD(publicKey: capsule.publicKey))
    let raw = try AES.GCM.open(
      AES.GCM.SealedBox(combined: capsule.protectedSigningKey), using: Self.fixtureWrappingKey(),
      authenticating: Self.expectedAAD(publicKey: capsule.publicKey)
    )
    #expect(raw.count == 32)
    #expect(
      try P256.Signing.PrivateKey(rawRepresentation: raw).publicKey.x963Representation
        == capsule.publicKey)
  }

  @Test
  func capsuleHasAnExactCanonicalByteFixture() throws {
    let publicKey = try #require(Base64URL.decodeCanonical(Self.fixturePublicKey))
    #expect(
      try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        .publicKey.x963Representation == publicKey)
    let protectedKey = Data((0..<60).map(UInt8.init))
    let capsule = try V3EpochSigningKeyCapsule(
      publicKey: publicKey, protectedSigningKey: protectedKey)
    let expected =
      "{\"protectedSigningKey\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7\",\"protectionAlgorithm\":\"HKDF-SHA256+AES-256-GCM\",\"publicKey\":\"BG_wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo\",\"signingAlgorithm\":\"P-256-ECDSA-SHA256\",\"version\":1}"
    #expect(capsule.canonicalBytes == Data(expected.utf8))
    #expect(try V3EpochSigningKeyCapsuleCodec().parseCanonical(Data(expected.utf8)) == capsule)
    #expect(
      try Self.context().authenticatedData(publicKey: publicKey)
        == Self.expectedAAD(publicKey: publicKey))
  }

  @Test
  func codecRejectsUnknownMissingDuplicateAndIncorrectFields() throws {
    let capsule = try V3EpochSigningKeyCipher().prepare(
      context: Self.context(), vaultKey: Self.vaultKey)
    let fields = try #require(capsule.canonicalValue.objectValue)
    let malformed: [CanonicalJSONValue] = [
      .object(fields + [("extra", .null)]),
      .object(fields.filter { $0.0 != "publicKey" }),
      .object(fields + [("publicKey", .string(Base64URL.encode(capsule.publicKey)))]),
      Self.replacing("signingAlgorithm", with: .string("other"), fields: fields),
      Self.replacing("protectionAlgorithm", with: .string("other"), fields: fields),
      Self.replacing(
        "publicKey", with: .string(Base64URL.encode(capsule.publicKey) + "="), fields: fields),
      Self.replacing("protectedSigningKey", with: .string("AA"), fields: fields),
      Self.replacing("version", with: .string("1"), fields: fields),
    ]
    for value in malformed {
      #expect(throws: (any Error).self) {
        try V3EpochSigningKeyCapsuleCodec().parseCanonical(CanonicalJSON.encode(value))
      }
      #expect(throws: (any Error).self) { try V3EpochSigningKeyCapsuleCodec().decode(value) }
    }
    #expect(throws: V3EpochSigningKeyError.unsupportedVersion(2)) {
      try V3EpochSigningKeyCapsuleCodec().parseCanonical(
        CanonicalJSON.encode(Self.replacing("version", with: .integer(2), fields: fields)))
    }
    #expect(throws: V3EpochSigningKeyError.invalidPublicKey) {
      try V3EpochSigningKeyCapsuleCodec().parseCanonical(
        CanonicalJSON.encode(
          Self.replacing(
            "publicKey", with: .string(Base64URL.encode(Data(repeating: 0, count: 65))),
            fields: fields)))
    }
  }

  @Test
  func codecBoundsAndCanonicalEncodingAreEnforced() throws {
    let capsule = try V3EpochSigningKeyCipher().prepare(
      context: Self.context(), vaultKey: Self.vaultKey)
    #expect(throws: V3EpochSigningKeyError.nonCanonicalEncoding) {
      try V3EpochSigningKeyCapsuleCodec().parseCanonical(Data(" ".utf8) + capsule.canonicalBytes)
    }
    for data in [
      Data(), Data("{\"version\":1,\"version\":1}".utf8), Data([0xFF]),
      Data(repeating: 0x20, count: V3EpochSigningKeyCapsuleCodec.maximumBytes + 1),
      Data([0xEF, 0xBB, 0xBF]) + capsule.canonicalBytes,
    ] {
      #expect(throws: V3EpochSigningKeyError.invalidEncoding) {
        try V3EpochSigningKeyCapsuleCodec().parseCanonical(data)
      }
    }
  }

  @Test
  func callerErrorsPropagateWithoutAnAutomaticRetry() throws {
    enum FixtureError: Error { case stop }
    let context = try Self.context()
    let capsule = try V3EpochSigningKeyCipher().prepare(context: context, vaultKey: Self.vaultKey)
    var calls = 0
    #expect(throws: FixtureError.stop) {
      try V3EpochSigningKeyCipher().withSigningKey(
        capsule, context: context, vaultKey: Self.vaultKey
      ) { _ -> Void in
        calls += 1
        throw FixtureError.stop
      }
    }
    #expect(calls == 1)
  }

  private static func context(
    vaultID: String = vaultID, transitionID: String = transitionID, vaultKey: Data = vaultKey
  ) throws -> V3EpochSigningKeyContext {
    try V3EpochSigningKeyContext(
      vaultID: vaultID, keyID: V3VaultKeyID.derive(vaultKey: vaultKey, vaultID: vaultID),
      authorityTransitionID: transitionID)
  }

  private static func expectedAAD(publicKey: Data) -> Data {
    Data(
      ("work.tvr.key/v3/epoch-signing-key-aad/v1\0"
        + "{\"authorityTransitionID\":\"018f4d38-7d5a-7b20-b0f1-97d6e96c44b4\",\"format\":\"key-vault-epoch-signing-key-context\",\"keyID\":\"YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA\",\"profile\":\"device-wrapped\",\"profileVersion\":3,\"protectionAlgorithm\":\"HKDF-SHA256+AES-256-GCM\",\"publicKey\":\"\(Base64URL.encode(publicKey))\",\"signingAlgorithm\":\"P-256-ECDSA-SHA256\",\"vaultID\":\"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3\",\"version\":1}")
        .utf8)
  }

  private static func fixtureWrappingKey() -> SymmetricKey {
    HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: vaultKey),
      salt: Data([
        0x01, 0x8F, 0x4D, 0x38, 0x7D, 0x5A, 0x7B, 0x20, 0xB0, 0xF1, 0x97, 0xD6, 0xE9, 0x6C, 0x44,
        0xB3,
      ]),
      info: Data("work.tvr.key/v3/epoch-signing-key-kek/v1".utf8), outputByteCount: 32
    )
  }

  private static func sealFixture(_ raw: Data, aad: Data) throws -> Data {
    // Independent use of the standard primitive with a fresh nonce. None of
    // these local generated-key fixtures involves a token or a real vault.
    try #require(
      AES.GCM.seal(
        raw, using: fixtureWrappingKey(),
        nonce: AES.GCM.Nonce(), authenticating: aad
      ).combined)
  }

  private static func replacing(
    _ name: String, with value: CanonicalJSONValue, fields: [(String, CanonicalJSONValue)]
  ) -> CanonicalJSONValue {
    .object(fields.map { $0.0 == name ? (name, value) : $0 })
  }
}
