import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Software protocol fixtures only. No token, administrative operation,
/// retained user credential, provider graph, or live vault is involved.
struct V3RecoveryManifestTests {
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
  private static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
  private static let nextTransitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
  private static let generationID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
  private static let registrationID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b7"
  private static let entryID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b8"
  private static let oldKey = Data(0..<32)
  private static let nextKey = Data(32..<64)

  @Test
  func experimentalBodyAndProjectionHaveExactCanonicalFixtures() throws {
    let signer = try Signer()
    let point =
      "BG_wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo"
    let pointBytes = try #require(Base64URL.decodeCanonical(point))
    let keyID = try V3VaultKeyID.derive(vaultKey: Self.oldKey, vaultID: Self.vaultID)
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: Self.vaultID, keyID: keyID, authorityTransitionID: Self.transitionID,
      devices: [.init(identity: signer.publicIdentity, status: .active)],
      wrappedKeys: [
        V3DeviceWrappedManifestKey(
          recipientDeviceID: signer.publicIdentity.deviceID,
          wrappedKey: V3HPKEWrappedVaultKey(encapsulatedKey: pointBytes, ciphertext: Data(0..<48)))
      ],
      entries: [
        .init(
          entryID: Self.entryID, name: "fixture/example", type: .secret,
          revision: 1, keyID: keyID,
          ciphertextDigest: Base64URL.encode(Data(repeating: 0x11, count: 32)))
      ])
    let proof = try V3RecoveryEpochTransitionProof(
      parentEnvelopeDigest: Data(0..<32),
      signature: Data(repeating: 1, count: 64))
    let body = try V3RecoveryManifestBody(
      fields: fields,
      epochSigningKey: V3EpochSigningKeyCapsule(
        publicKey: pointBytes, protectedSigningKey: Data(0..<60)),
      transitionProof: proof,
      recovery: V3RecoveryRoster(generationID: Self.generationID, recipients: [], wrappedKeys: []))
    // Fixed software public points and box-shaped bytes, not valid ciphertexts
    // or cryptographic approvals. Encoding is tested independently of opening.
    let deviceID = signer.publicIdentity.deviceID
    let signing = Base64URL.encode(signer.publicIdentity.signingPublicKey)
    let wrapping = Base64URL.encode(signer.publicIdentity.wrappingPublicKey)
    let signature =
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
    let parent = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    let expected =
      "{\"authorityTransitionID\":\"\(Self.transitionID)\",\"devices\":[{\"deviceID\":\"\(deviceID)\",\"displayName\":\"Software Mac fixture\",\"signingPublicKey\":{\"algorithm\":\"P-256-ECDSA\",\"encoding\":\"x963\",\"value\":\"\(signing)\"},\"status\":\"active\",\"wrappingPublicKey\":{\"algorithm\":\"P-256-ECDH\",\"encoding\":\"x963\",\"value\":\"\(wrapping)\"}}],\"entries\":[{\"ciphertextDigest\":\"ERERERERERERERERERERERERERERERERERERERERERE\",\"entryID\":\"\(Self.entryID)\",\"keyID\":\"YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA\",\"name\":\"fixture/example\",\"revision\":1,\"type\":\"secret\"}],\"epochAuthority\":{\"capsule\":{\"protectedSigningKey\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7\",\"protectionAlgorithm\":\"HKDF-SHA256+AES-256-GCM\",\"publicKey\":\"\(point)\",\"signingAlgorithm\":\"P-256-ECDSA-SHA256\",\"version\":1},\"transitionProof\":{\"algorithm\":\"P-256-ECDSA-SHA256\",\"parentEnvelopeDigest\":\"\(parent)\",\"signature\":\"\(signature)\",\"version\":1},\"version\":1},\"format\":\"key-vault-manifest\",\"hpkeSuite\":{\"aead\":2,\"kdf\":1,\"kem\":16,\"mode\":0},\"keyID\":\"YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA\",\"profile\":\"device-wrapped\",\"profileVersion\":3,\"recovery\":{\"generationID\":\"\(Self.generationID)\",\"recipients\":[],\"version\":1,\"wrappedKeys\":[]},\"vaultID\":\"\(Self.vaultID)\",\"version\":3,\"wrappedKeys\":[{\"ciphertext\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\",\"encapsulatedKey\":\"\(point)\",\"recipientDeviceID\":\"\(deviceID)\"}]}"
    #expect(body.canonicalBytes == Data(expected.utf8))
    #expect(
      try V3RecoveryManifestCodec().parseCanonicalBody(Data(expected.utf8)) == .recovery(body))
    let unsigned = expected.replacingOccurrences(of: "\"signature\":\"\(signature)\",", with: "")
    let expectedInput =
      "work.tvr.key/v3/epoch-transition-authorization/v1\0{\"manifest\":\(unsigned),\"parents\":[\"\(parent)\"]}"
    #expect(
      try V3RecoveryEpochBoundary.signatureInput(body: body, parents: [Data(0..<32)])
        == Data(expectedInput.utf8))
  }

  @Test
  func experimentalSchemaTracksExactRecordsWithoutChangingShippingSchema() throws {
    let fixture = try Fixture()
    let body = try fixture.boundary().body
    let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(
        "docs/schemas")
    let schema = try #require(
      JSONSerialization.jsonObject(
        with: Data(
          contentsOf:
            directory.appendingPathComponent("v3-recovery-manifest-body.schema.json")))
        as? [String: Any])
    let definitions = try #require(schema["$defs"] as? [String: [String: Any]])
    func exact(_ record: [String: Any], _ value: CanonicalJSONValue) throws {
      let fields = try #require(value.objectValue)
      #expect(record["additionalProperties"] as? Bool == false)
      #expect(Set(try #require(record["required"] as? [String])) == Set(fields.map(\.0)))
      #expect(
        Set(try #require(record["properties"] as? [String: Any]).keys) == Set(fields.map(\.0)))
    }
    try exact(schema, body.canonicalValue)
    let authority = try Self.member("epochAuthority", in: body.canonicalValue)
    try exact(try #require(definitions["epochAuthority"]), authority)
    try exact(try #require(definitions["capsule"]), body.epochSigningKey.canonicalValue)
    try exact(
      try #require(definitions["transitionProof"]),
      try #require(body.transitionProof).canonicalValue)
    try exact(try #require(definitions["recovery"]), body.recovery.canonicalValue)
    try exact(try #require(definitions["recipient"]), body.recovery.recipients[0].canonicalValue)
    try exact(
      try #require(definitions["recoveryPublicKey"]),
      Self.member("publicKey", in: body.recovery.recipients[0].canonicalValue))
    try exact(
      try #require(definitions["recoveryWrappedKey"]), body.recovery.wrappedKeys[0].canonicalValue)
    let legacy = try #require(
      JSONSerialization.jsonObject(
        with: Data(
          contentsOf:
            directory.appendingPathComponent("v3-manifest-body.schema.json"))) as? [String: Any])
    #expect(
      (legacy["properties"] as? [String: [String: Any]])?["profileVersion"]?["const"] as? Int == 2)
    #expect(
      (schema["properties"] as? [String: [String: Any]])?["profileVersion"]?["const"] as? Int == 3)
  }

  @Test
  func explicitDispatchPreservesShippingProfileAndOldReaderRefusal() throws {
    let fixture = try Fixture()
    let old = V3DeviceWrappedManifestBody(fields: fixture.origin.body.fields)
    #expect(try V3RecoveryManifestCodec().parseCanonicalBody(old.canonicalBytes) == .permanent(old))
    #expect(
      try V3RecoveryManifestCodec().parseCanonicalBody(fixture.origin.body.canonicalBytes)
        == .recovery(fixture.origin.body))
    #expect(throws: V3DeviceWrappedManifestError.unsupportedProfileVersion(3)) {
      try V3DeviceWrappedManifestCodec().parseCanonicalBody(fixture.origin.body.canonicalBytes)
    }
    #expect(throws: V3DeviceWrappedUnlockError.unsupportedProfileVersion(3)) {
      try V3DeviceWrappedManifestEnvelopeCodec().parse(fixture.origin.canonicalBytes)
    }
    let metadata = try V3DeviceWrappedManifestEnvelopeCodec().metadata(
      fixture.origin.canonicalBytes)
    #expect(metadata.canonicalContentBytes == fixture.origin.canonicalContentBytes)
    var future = try #require(fixture.origin.body.canonicalValue.objectValue)
    future = future.map { ($0.0, $0.0 == "profileVersion" ? .integer(4) : $0.1) }
    future.append(("futureField", .null))
    #expect(throws: V3RecoveryManifestError.unsupportedProfileVersion(4)) {
      try V3RecoveryManifestCodec().decodeBody(.object(future))
    }
  }

  @Test
  func deviceContextsReuseHPKEWithDistinctExplicitProfileBytes() throws {
    let fixture = try Fixture()
    let body = fixture.origin.body
    let context = try body.deviceContext(recipientDeviceID: fixture.signer.publicIdentity.deviceID)
    let old = try V3VaultKeyHPKEContext(
      vaultID: Self.vaultID, keyID: body.fields.keyID,
      authorityTransitionID: Self.transitionID, recipientDeviceID: context.recipientDeviceID)
    #expect(context.wrappingProfile == .recovery)
    #expect(old.wrappingProfile == .permanent)
    #expect(V3DeviceWrappingProfile.recovery.rawValue == V3RecoveryManifestBody.profileVersion)
    #expect(
      V3DeviceWrappingProfile.permanent.rawValue == V3DeviceWrappedManifestBody.profileVersion)
    #expect(
      String(decoding: context.canonicalBytes, as: UTF8.self)
        == String(decoding: old.canonicalBytes, as: UTF8.self)
        .replacingOccurrences(of: "\"profileVersion\":2", with: "\"profileVersion\":3"))
    #expect(V3VaultKeyHPKE.inputs(for: context) != V3VaultKeyHPKE.inputs(for: old))
    let wrapped = try #require(body.fields.wrappedKeys.first).wrappedKey
    #expect(
      try V3VaultKeyHPKE().unwrap(
        wrapped, recipientPrivateKey: fixture.signer.wrappingKey, context: context) == Self.oldKey)
    #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
      try V3VaultKeyHPKE().unwrap(
        wrapped, recipientPrivateKey: fixture.signer.wrappingKey, context: old)
    }
    let oldWrapped = try V3VaultKeyHPKE().wrap(
      vaultKey: Self.oldKey, recipientPublicKey: fixture.signer.publicIdentity.wrappingPublicKey,
      context: old)
    #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
      try V3VaultKeyHPKE().unwrap(
        oldWrapped, recipientPrivateKey: fixture.signer.wrappingKey, context: context)
    }
  }

  @Test
  func proofProjectionOmitsExactlyItsSignatureAndHasIndependentFraming() throws {
    let fixture = try Fixture()
    let boundary = try fixture.boundary()
    let proof = try #require(boundary.body.transitionProof)
    let expectedProof = CanonicalJSONValue.object([
      ("algorithm", .string("P-256-ECDSA-SHA256")),
      ("parentEnvelopeDigest", .string(Base64URL.encode(fixture.origin.digest))),
      ("version", .integer(1)),
    ])
    #expect(CanonicalJSON.encode(proof.unsignedValue) == CanonicalJSON.encode(expectedProof))
    let root = boundary.body.canonicalValue
    let authority = try Self.member("epochAuthority", in: root)
    let independentlyProjected = Self.replacing(
      "epochAuthority", in: root,
      with: Self.replacing("transitionProof", in: authority, with: expectedProof))
    let content = CanonicalJSONValue.object([
      ("manifest", independentlyProjected),
      ("parents", .array([.string(Base64URL.encode(fixture.origin.digest))])),
    ])
    let expected =
      Data("work.tvr.key/v3/epoch-transition-authorization/v1\0".utf8)
      + CanonicalJSON.encode(content)
    #expect(
      try V3RecoveryEpochBoundary.signatureInput(body: boundary.body, parents: boundary.parents)
        == expected)
    #expect(!String(decoding: expected, as: UTF8.self).contains("\"signature\""))
    #expect(throws: V3RecoveryManifestError.invalidBoundary) {
      try V3RecoveryEpochBoundary.signatureInput(body: boundary.body, parents: [])
    }
    #expect(throws: V3RecoveryManifestError.invalidBoundary) {
      try V3RecoveryEpochBoundary.signatureInput(body: fixture.origin.body, parents: [])
    }
  }

  @Test
  func preparedBoundaryAuthenticatesBothSignaturesAndCurrentCapsule() throws {
    let fixture = try Fixture()
    let boundary = try fixture.boundary()
    #expect(fixture.signer.calls == 1)
    #expect(boundary.authorizations.count == 1)
    try V3RecoveryEpochBoundary().verifyBoundary(boundary, parent: fixture.origin)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(fixture.origin, vaultKey: Self.oldKey)
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(boundary, vaultKey: Self.nextKey)
    #expect(
      boundary.body.epochSigningKey.publicKey != fixture.origin.body.epochSigningKey.publicKey)
    #expect(throws: V3RecoveryManifestError.invalidVaultKey) {
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(boundary, vaultKey: Self.oldKey)
    }
    guard #available(macOS 26.0, *) else { return }
    let record = try #require(boundary.body.recovery.recipients.first)
    let context = try V3RecoveryHPKEContext(
      vaultID: Self.vaultID, keyID: boundary.body.fields.keyID,
      authorityTransitionID: Self.nextTransitionID, recoveryGenerationID: Self.generationID,
      recipient: record)
    let key = fixture.token
    let receiver = try PIVHPKEReceiver(
      publicBytes: key.publicKey.x963Representation,
      agree: {
        try key.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: $0)
        )
        .withUnsafeBytes { Data($0) }
      })
    #expect(
      try V3RecoveryVaultKeyHPKE().unwrap(
        try #require(boundary.body.recovery.wrappedKeys.first), recipientPrivateKey: receiver,
        context: context) == Self.nextKey)
  }

  @Test
  func missingOrMismatchedApprovalsAreRejectedSeparately() throws {
    let fixture = try Fixture()
    let boundary = try fixture.boundary()
    let proof = try #require(boundary.body.transitionProof)
    let missingDevice = try V3RecoveryEpochBoundary().encode(
      body: boundary.body, parents: boundary.parents, vaultKey: Self.nextKey, authorizations: [])
    #expect(throws: V3RecoveryManifestError.invalidDeviceAuthorization) {
      try V3RecoveryEpochBoundary().verifyBoundary(missingDevice, parent: fixture.origin)
    }
    let unknownDevice = try V3RecoveryEpochBoundary().encode(
      body: boundary.body, parents: boundary.parents, vaultKey: Self.nextKey,
      authorizations: [
        .init(
          signerDeviceID: Base64URL.encode(Data(repeating: 0, count: 32)),
          signature: boundary.authorizations[0].signature)
      ])
    #expect(throws: V3RecoveryManifestError.invalidDeviceAuthorization) {
      try V3RecoveryEpochBoundary().verifyBoundary(unknownDevice, parent: fixture.origin)
    }
    let noProof = try Self.rebody(boundary.body, proof: nil)
    #expect(throws: (any Error).self) {
      try V3RecoveryEpochBoundary().verifyBoundary(fixture.resign(noProof), parent: fixture.origin)
    }
    // A well-formed but unrelated software signature, with the Mac signature
    // recomputed, exercises the independent epoch-signature check.
    let differentSignature = try V3P256Signature.canonicalize(
      P256.Signing.PrivateKey().signature(for: Data("mismatch fixture".utf8)).rawRepresentation)
    let wrongProof = try V3RecoveryEpochTransitionProof(
      parentEnvelopeDigest: proof.parentEnvelopeDigest, signature: differentSignature)
    let mismatched = try fixture.resign(Self.rebody(boundary.body, proof: wrongProof))
    #expect(throws: V3RecoveryManifestError.invalidEpochAuthorization) {
      try V3RecoveryEpochBoundary().verifyBoundary(mismatched, parent: fixture.origin)
    }
    var signature = try #require(Base64URL.decodeCanonical(boundary.authorizations[0].signature))
    signature[signature.startIndex] ^= 1
    let wrongDevice = try V3RecoveryEpochBoundary().encode(
      body: boundary.body, parents: boundary.parents, vaultKey: Self.nextKey,
      authorizations: [
        .init(
          signerDeviceID: fixture.signer.publicIdentity.deviceID,
          signature: Base64URL.encode(signature))
      ])
    #expect(throws: V3RecoveryManifestError.invalidDeviceAuthorization) {
      try V3RecoveryEpochBoundary().verifyBoundary(wrongDevice, parent: fixture.origin)
    }
  }

  @Test
  func epochProofCommitsCompleteCandidateMetadataAndUsesParentAuthority() throws {
    let fixture = try Fixture()
    let boundary = try fixture.boundary()
    let value = boundary.body.canonicalValue
    let authority = try Self.member("epochAuthority", in: value)
    let capsule = try Self.member("capsule", in: authority)
    let recovery = try Self.member("recovery", in: value)
    let wrappers = try #require(Self.member("wrappedKeys", in: value).arrayValue)
    let entries = try #require(Self.member("entries", in: value).arrayValue)
    let devices = try #require(Self.member("devices", in: value).arrayValue)
    let changed = [
      Self.replacing(
        "epochAuthority", in: value,
        with: Self.replacing(
          "capsule", in: authority,
          with: Self.replacing(
            "protectedSigningKey", in: capsule,
            with: .string(Base64URL.encode(Data(repeating: 0x55, count: 60)))))),
      Self.replacing(
        "epochAuthority", in: value,
        with: Self.replacing(
          "capsule", in: authority,
          with: Self.replacing(
            "publicKey", in: capsule,
            with: .string(
              Base64URL.encode(
                try P256.Signing.PrivateKey(rawRepresentation: Self.scalar(8)).publicKey
                  .x963Representation))))),
      Self.replacing(
        "recovery", in: value,
        with: Self.replacing(
          "generationID", in: recovery,
          with: .string(Self.registrationID))),
      Self.replacing(
        "wrappedKeys", in: value,
        with: .array([
          Self.replacing(
            "ciphertext", in: wrappers[0],
            with: .string(Base64URL.encode(Data(repeating: 0x55, count: 48))))
        ])),
      Self.replacing(
        "entries", in: value,
        with: .array([
          Self.replacing(
            "ciphertextDigest", in: entries[0],
            with: .string(Base64URL.encode(Data(repeating: 0x55, count: 32))))
        ])),
      Self.replacing(
        "devices", in: value,
        with: .array([
          Self.replacing("displayName", in: devices[0], with: .string("Changed fixture"))
        ])),
    ]
    for candidateValue in changed {
      guard case .recovery(let body) = try V3RecoveryManifestCodec().decodeBody(candidateValue)
      else {
        Issue.record("Expected recovery fixture")
        continue
      }
      let edited = try fixture.resign(body)
      #expect(throws: V3RecoveryManifestError.invalidEpochAuthorization) {
        try V3RecoveryEpochBoundary().verifyBoundary(edited, parent: fixture.origin)
      }
    }
    // The verifier receives an altered public parent, but its exact digest is
    // different from the signed parent commitment. It cannot substitute it.
    let replacementParent = try V3RecoveryEpochBoundary().encode(
      body: Self.rebody(fixture.origin.body, capsule: boundary.body.epochSigningKey, proof: nil),
      parents: [], vaultKey: Self.oldKey, authorizations: [])
    #expect(throws: (any Error).self) {
      try V3RecoveryEpochBoundary().verifyBoundary(boundary, parent: replacementParent)
    }
  }

  @Test
  func publicSignatureChecksDoNotClaimMACOrHistoricalDecryption() throws {
    let fixture = try Fixture()
    let boundary = try fixture.boundary()
    let root = try CanonicalJSON.parse(boundary.canonicalBytes)
    let authentication = try Self.member("authentication", in: root)
    let changed = Self.replacing(
      "authentication", in: root,
      with: Self.replacing(
        "tag", in: authentication, with: .string(Base64URL.encode(Data(repeating: 0, count: 32)))))
    let invalidMAC = try V3RecoveryManifestCodec().parseEnvelope(CanonicalJSON.encode(changed))
    try V3RecoveryEpochBoundary().verifyBoundary(invalidMAC, parent: fixture.origin)
    #expect(throws: V3RecoveryManifestError.authenticationFailed) {
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(invalidMAC, vaultKey: Self.nextKey)
    }
  }

  @Test
  func editsAndMergesPreserveExactEpochAuthorityAndProofBytes() throws {
    let fixture = try Fixture()
    let root = try fixture.boundary()
    let fields = root.body.fields
    let empty = try V3DeviceWrappedManifestFields(
      vaultID: fields.vaultID, keyID: fields.keyID,
      authorityTransitionID: fields.authorityTransitionID,
      devices: fields.devices, wrappedKeys: fields.wrappedKeys, entries: [])
    let editedBody = try V3RecoveryManifestBody(
      fields: empty, epochSigningKey: root.body.epochSigningKey,
      transitionProof: root.body.transitionProof, recovery: root.body.recovery)
    let edited = try V3RecoveryEpochBoundary().encode(
      body: editedBody, parents: [root.digest], vaultKey: Self.nextKey, authorizations: [])
    try V3RecoveryEpochBoundary().verifySameEpochMetadata(edited, parents: [root])
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(edited, vaultKey: Self.nextKey)
    let merged = try V3RecoveryEpochBoundary().encode(
      body: editedBody,
      parents: [root.digest, edited.digest].sorted(by: { $0.lexicographicallyPrecedes($1) }),
      vaultKey: Self.nextKey, authorizations: [])
    try V3RecoveryEpochBoundary().verifySameEpochMetadata(merged, parents: [edited, root])
    let withoutProof = try V3RecoveryEpochBoundary().encode(
      body: Self.rebody(editedBody, proof: nil), parents: [root.digest], vaultKey: Self.nextKey,
      authorizations: [])
    #expect(throws: V3RecoveryManifestError.invalidBoundary) {
      try V3RecoveryEpochBoundary().verifySameEpochMetadata(withoutProof, parents: [root])
    }
    #expect(throws: V3RecoveryManifestError.invalidBoundary) {
      try V3RecoveryEpochBoundary().verifySameEpochMetadata(
        merged, parents: [fixture.origin, edited])
    }
  }

  @Test
  func exactCodecsRejectExtraMissingDuplicateAndMalformedProofFields() throws {
    let fixture = try Fixture()
    let boundary = try fixture.boundary()
    let root = boundary.body.canonicalValue
    let authority = try Self.member("epochAuthority", in: root)
    let proof = try Self.member("transitionProof", in: authority)
    let device = try #require(Self.member("devices", in: root).arrayValue?.first)
    func variants(_ value: CanonicalJSONValue) throws -> [CanonicalJSONValue] {
      let fields = try #require(value.objectValue)
      return [
        .object(fields + [("extra", .null)]), .object(Array(fields.dropFirst())),
        .object(fields + [fields[0]]),
      ]
    }
    var invalid = try variants(root)
    invalid += try variants(authority).map { Self.replacing("epochAuthority", in: root, with: $0) }
    invalid += try variants(proof).map {
      Self.replacing(
        "epochAuthority", in: root, with: Self.replacing("transitionProof", in: authority, with: $0)
      )
    }
    invalid += try variants(device).map { Self.replacing("devices", in: root, with: .array([$0])) }
    for (name, value) in [
      ("version", CanonicalJSONValue.integer(2)), ("algorithm", .string("unsupported")),
      ("parentEnvelopeDigest", .string(Base64URL.encode(Data(repeating: 0, count: 31)))),
      ("signature", .string(Base64URL.encode(Data(repeating: 0xff, count: 64)))),
      ("signature", .string(Base64URL.encode(Data(repeating: 1, count: 63)))),
    ] {
      invalid.append(
        Self.replacing(
          "epochAuthority", in: root,
          with: Self.replacing(
            "transitionProof", in: authority, with: Self.replacing(name, in: proof, with: value))))
    }
    for value in invalid {
      #expect(throws: (any Error).self) { try V3RecoveryManifestCodec().decodeBody(value) }
      #expect(throws: (any Error).self) {
        try V3RecoveryManifestCodec().parseCanonicalBody(CanonicalJSON.encode(value))
      }
    }
    let legacy = V3DeviceWrappedManifestBody(fields: fixture.origin.body.fields)
    for value in try variants(legacy.canonicalValue) {
      #expect(throws: (any Error).self) { try V3DeviceWrappedManifestCodec().decodeBody(value) }
    }
  }

  @Test
  func canonicalAndInputBudgetsFailClosedBeforeDomainUse() throws {
    let fixture = try Fixture()
    let bytes = fixture.origin.body.canonicalBytes
    for count in 0..<bytes.count {
      #expect(throws: (any Error).self) {
        try V3RecoveryManifestCodec().parseCanonicalBody(Data(bytes.prefix(count)))
      }
    }
    #expect(throws: V3RecoveryManifestError.nonCanonicalEncoding) {
      try V3RecoveryManifestCodec().parseCanonicalBody(bytes + Data([10]))
    }
    for bytes in [
      Data([0xff]), Data([0xef, 0xbb, 0xbf]) + bytes, Data("null".utf8), bytes + Data([0]),
    ] {
      #expect(throws: (any Error).self) { try V3RecoveryManifestCodec().parseCanonicalBody(bytes) }
    }
    let oversized = Data(repeating: 0x20, count: V3RecoveryManifestCodec.maximumBytes + 1)
    #expect(throws: V3RecoveryManifestError.resourceLimit) {
      try V3RecoveryManifestCodec().parseCanonicalBody(oversized)
    }
    #expect(throws: V3RecoveryManifestError.resourceLimit) {
      try V3RecoveryManifestCodec().parseEnvelope(oversized)
    }
    let inconsistent = V3RecoveryManifestEnvelope(
      parents: [Data(repeating: 1, count: 32)], body: fixture.origin.body,
      authenticationTag: fixture.origin.authenticationTag, authorizations: [],
      canonicalBytes: fixture.origin.canonicalBytes,
      canonicalContentBytes: fixture.origin.canonicalContentBytes)
    #expect(throws: V3RecoveryManifestError.invalidStructure) {
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(inconsistent, vaultKey: Self.oldKey)
    }
  }

  @Test
  func invalidPreparationAndCancellationDoNotRetryTheMacSigner() throws {
    let fixture = try Fixture()
    #expect(throws: V3RecoveryManifestError.invalidBoundary) {
      try V3RecoveryEpochBoundary().authorize(
        candidate: fixture.origin.body, parent: fixture.origin,
        currentVaultKey: Self.oldKey, nextVaultKey: Self.oldKey, signer: fixture.signer,
        reason: "fixture")
    }
    #expect(fixture.signer.calls == 0)
    #expect(throws: V3RecoveryManifestError.invalidVaultKey) {
      try V3RecoveryEpochBoundary().authorize(
        candidate: fixture.next, parent: fixture.origin,
        currentVaultKey: Self.oldKey, nextVaultKey: Data(repeating: 0, count: 32),
        signer: fixture.signer, reason: "fixture")
    }
    #expect(fixture.signer.calls == 0)
    let corrupt = try V3EpochSigningKeyCapsule(
      publicKey: fixture.next.epochSigningKey.publicKey,
      protectedSigningKey: Data(repeating: 0, count: 60))
    #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
      try V3RecoveryEpochBoundary().authorize(
        candidate: Self.rebody(fixture.next, capsule: corrupt, proof: nil),
        parent: fixture.origin, currentVaultKey: Self.oldKey, nextVaultKey: Self.nextKey,
        signer: fixture.signer, reason: "fixture")
    }
    #expect(fixture.signer.calls == 0)
    fixture.signer.cancel = true
    #expect(throws: FixtureError.cancelled) { try fixture.boundary() }
    #expect(fixture.signer.calls == 1)
  }

  @Test
  func crossRoleCredentialReuseIsRejected() throws {
    let fixture = try Fixture()
    let body = fixture.origin.body
    let reused = try V3EpochSigningKeyCapsule(
      publicKey: fixture.signer.publicIdentity.signingPublicKey,
      protectedSigningKey: body.epochSigningKey.protectedSigningKey)
    #expect(throws: V3RecoveryManifestError.invalidStructure) {
      try Self.rebody(body, capsule: reused, proof: nil)
    }
    let record = try V3RecoveryRecipient(
      registrationID: Self.registrationID,
      publicKey: fixture.signer.publicIdentity.wrappingPublicKey, slot: .keyManagement,
      status: .revoked)
    let roster = try V3RecoveryRoster(
      generationID: Self.generationID, recipients: [record], wrappedKeys: [])
    #expect(throws: V3RecoveryManifestError.invalidStructure) {
      try V3RecoveryManifestBody(
        fields: body.fields, epochSigningKey: body.epochSigningKey,
        transitionProof: nil, recovery: roster)
    }
  }

  private static func scalar(_ value: UInt8) -> Data {
    Data(repeating: 0, count: 31) + Data([value])
  }

  private static func rebody(
    _ body: V3RecoveryManifestBody, capsule: V3EpochSigningKeyCapsule? = nil,
    proof: V3RecoveryEpochTransitionProof?
  ) throws -> V3RecoveryManifestBody {
    try V3RecoveryManifestBody(
      fields: body.fields, epochSigningKey: capsule ?? body.epochSigningKey,
      transitionProof: proof, recovery: body.recovery)
  }

  private static func member(_ name: String, in value: CanonicalJSONValue) throws
    -> CanonicalJSONValue
  {
    try #require(value.objectValue?.first(where: { $0.0 == name })?.1)
  }

  private static func replacing(
    _ name: String, in value: CanonicalJSONValue, with replacement: CanonicalJSONValue
  ) -> CanonicalJSONValue {
    .object((value.objectValue ?? []).map { ($0.0, $0.0 == name ? replacement : $0.1) })
  }

  private enum FixtureError: Error { case cancelled }

  private final class Signer: V3EnrollmentMessageSigning, @unchecked Sendable {
    let vaultID = V3RecoveryManifestTests.vaultID
    let signingKey: P256.Signing.PrivateKey
    let wrappingKey: P256.KeyAgreement.PrivateKey
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let lock = NSLock()
    private var callCount = 0
    private var cancellation = false
    var calls: Int { lock.withLock { callCount } }
    var cancel: Bool {
      get { lock.withLock { cancellation } }
      set { lock.withLock { cancellation = newValue } }
    }

    init() throws {
      signingKey = try P256.Signing.PrivateKey(rawRepresentation: V3RecoveryManifestTests.scalar(1))
      wrappingKey = try P256.KeyAgreement.PrivateKey(
        rawRepresentation: V3RecoveryManifestTests.scalar(2))
      publicIdentity = try V3EnrollmentDeviceIdentity(
        displayName: "Software Mac fixture",
        signingPublicKey: signingKey.publicKey.x963Representation,
        wrappingPublicKey: wrappingKey.publicKey.x963Representation)
    }

    func signature(for input: Data, reason _: String) throws -> Data {
      let cancelled = lock.withLock {
        callCount += 1
        return cancellation
      }
      if cancelled { throw FixtureError.cancelled }
      return try signingKey.signature(for: input).rawRepresentation
    }
  }

  private struct Fixture {
    let signer: Signer
    let token: P256.KeyAgreement.PrivateKey
    let origin: V3RecoveryManifestEnvelope
    let next: V3RecoveryManifestBody

    init() throws {
      signer = try Signer()
      token = try P256.KeyAgreement.PrivateKey(rawRepresentation: V3RecoveryManifestTests.scalar(3))
      let initial = try Self.prepare(
        key: V3RecoveryManifestTests.oldKey,
        transition: V3RecoveryManifestTests.transitionID, signer: signer, token: token)
      origin = try V3RecoveryEpochBoundary().encode(
        body: initial, parents: [],
        vaultKey: V3RecoveryManifestTests.oldKey, authorizations: [])
      next = try Self.prepare(
        key: V3RecoveryManifestTests.nextKey,
        transition: V3RecoveryManifestTests.nextTransitionID, signer: signer, token: token)
    }

    func boundary() throws -> V3RecoveryManifestEnvelope {
      try V3RecoveryEpochBoundary().authorize(
        candidate: next, parent: origin,
        currentVaultKey: V3RecoveryManifestTests.oldKey,
        nextVaultKey: V3RecoveryManifestTests.nextKey,
        signer: signer, reason: "Software fixture boundary")
    }

    func resign(_ body: V3RecoveryManifestBody) throws -> V3RecoveryManifestEnvelope {
      let content = CanonicalJSON.encode(
        .object([
          ("manifest", body.canonicalValue),
          ("parents", .array([.string(Base64URL.encode(origin.digest))])),
        ]))
      let signature = try V3P256Signature.canonicalize(
        signer.signingKey.signature(
          for: V3ManifestAuthenticator.authenticationInput(for: content)
        ).rawRepresentation)
      return try V3RecoveryEpochBoundary().encode(
        body: body, parents: [origin.digest],
        vaultKey: V3RecoveryManifestTests.nextKey,
        authorizations: [
          .init(
            signerDeviceID: signer.publicIdentity.deviceID, signature: Base64URL.encode(signature))
        ])
    }

    private static func prepare(
      key: Data, transition: String, signer: Signer, token: P256.KeyAgreement.PrivateKey
    ) throws -> V3RecoveryManifestBody {
      let vaultID = V3RecoveryManifestTests.vaultID
      let keyID = try V3VaultKeyID.derive(vaultKey: key, vaultID: vaultID)
      let context = try V3VaultKeyHPKEContext(
        vaultID: vaultID, keyID: keyID,
        authorityTransitionID: transition, recipientDeviceID: signer.publicIdentity.deviceID,
        wrappingProfile: .recovery)
      let deviceWrapper = try V3DeviceWrappedManifestKey(
        recipientDeviceID: signer.publicIdentity.deviceID,
        wrappedKey: V3VaultKeyHPKE().wrap(
          vaultKey: key,
          recipientPublicKey: signer.publicIdentity.wrappingPublicKey, context: context))
      let entry = try V3EntryCipher().seal(
        "Software fixture value",
        context: V3EntryAuthenticationContext(
          vaultID: vaultID, entryID: V3RecoveryManifestTests.entryID, name: "fixture/example",
          type: .secret, keyID: keyID, revision: 1), vaultKey: key)
      let fields = try V3DeviceWrappedManifestFields(
        vaultID: vaultID, keyID: keyID,
        authorityTransitionID: transition,
        devices: [.init(identity: signer.publicIdentity, status: .active)],
        wrappedKeys: [deviceWrapper],
        entries: [
          .init(
            entryID: V3RecoveryManifestTests.entryID,
            name: "fixture/example", type: .secret, revision: 1, keyID: keyID,
            ciphertextDigest: entry.ciphertextDigest)
        ])
      let recipient = try V3RecoveryRecipient(
        registrationID: V3RecoveryManifestTests.registrationID,
        publicKey: token.publicKey.x963Representation, slot: .keyManagement, status: .active)
      let recoveryContext = try V3RecoveryHPKEContext(
        vaultID: vaultID, keyID: keyID,
        authorityTransitionID: transition,
        recoveryGenerationID: V3RecoveryManifestTests.generationID,
        recipient: recipient)
      let roster = try V3RecoveryRoster(
        generationID: V3RecoveryManifestTests.generationID,
        recipients: [recipient],
        wrappedKeys: [V3RecoveryVaultKeyHPKE().wrap(vaultKey: key, context: recoveryContext)])
      let capsule = try V3EpochSigningKeyCipher().prepare(
        context: V3EpochSigningKeyContext(
          vaultID: vaultID, keyID: keyID, authorityTransitionID: transition), vaultKey: key)
      return try V3RecoveryManifestBody(
        fields: fields, epochSigningKey: capsule, transitionProof: nil, recovery: roster)
    }
  }
}
