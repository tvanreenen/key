import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Design evidence using shipping profile-2 builders and real cryptography.
/// This is not a recovery verifier, a new profile, or hardware qualification.
struct PIVRecoveryAuthorityDesignTests {
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84b3"
  private static let entryID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84b4"

  @Test
  func signedBoundariesCommitInterveningHistoryWithoutHistoricalKeys() throws {
    let fixture = try Fixture()

    // This check receives no vault key. It proves only hash linkage and
    // active-parent signature commitments, not old MACs or resealing.
    #expect(try Self.hasPublicCommitments(fixture.path))
    #expect(fixture.path.filter { !$0.authorizations.isEmpty }.count == 2)
    #expect(
      fixture.path.last?.body.devices.first(where: {
        $0.identity == fixture.originalOwner.publicIdentity
      })?.status == .revoked)
  }

  @Test
  func changingAnEarlierEnvelopeBreaksTheSignedParentCommitment() throws {
    let fixture = try Fixture()
    var path = fixture.path
    path[1] = try Self.replacingTag(path[1], with: Data(repeating: 0, count: 32))

    #expect(try !Self.hasPublicCommitments(path))
    // The transition's signature itself is still valid over its unchanged
    // content. It is the exact parent digest that rejects the splice.
    #expect(
      try Self.hasActiveParentSignature(
        path[2], parent: fixture.path[1]
      ))
  }

  @Test
  func oneSoftwareHPKEOpeningAuthenticatesTheFinalEpochAndCurrentEntry() throws {
    let fixture = try Fixture()
    let token = P256.KeyAgreement.PrivateKey()
    let epochRoot = fixture.path[4]
    let context = try V3VaultKeyHPKEContext(
      vaultID: Self.vaultID,
      keyID: epochRoot.body.keyID,
      authorityTransitionID: epochRoot.body.authorityTransitionID,
      recipientDeviceID: Base64URL.encode(
        Data(
          SHA256.hash(
            data: token.publicKey.x963Representation
          )))
    )
    // A stand-alone test wrapper demonstrates the primitive. It is not
    // an authenticated recovery recipient in the shipping profile.
    let wrapped = try V3VaultKeyHPKE().wrap(
      vaultKey: fixture.keys[2],
      recipientPublicKey: token.publicKey.x963Representation,
      context: context
    )
    let opened = try V3VaultKeyHPKE().unwrap(
      wrapped, recipientPrivateKey: token, context: context
    )

    #expect(try Self.hasPublicCommitments(fixture.path))
    for manifest in fixture.path[4...] {
      #expect(
        try V3ManifestAuthenticator.isValidAuthenticationTag(
          manifest.authenticationTag,
          canonicalContent: manifest.canonicalContentBytes,
          vaultID: Self.vaultID,
          vaultKey: opened
        ))
    }
    #expect(
      try V3EntryCipher().openTrusted(
        fixture.finalEntry.canonicalBytes,
        vaultID: Self.vaultID,
        manifestEntry: try #require(fixture.path.last?.body.entries.first),
        vaultKey: opened
      ) == "current value")
    #expect(
      try !V3ManifestAuthenticator.isValidAuthenticationTag(
        fixture.path[1].authenticationTag,
        canonicalContent: fixture.path[1].canonicalContentBytes,
        vaultID: Self.vaultID,
        vaultKey: opened
      ))
  }

  @Test
  func signatureCommitmentsDoNotProveHistoricalMACValidity() throws {
    let fixture = try Fixture()
    let invalid = try Self.replacingTag(
      fixture.path[2], with: Data(repeating: 0, count: 32)
    )

    #expect(try Self.hasActiveParentSignature(invalid, parent: fixture.path[1]))
    #expect(
      try !V3ManifestAuthenticator.isValidAuthenticationTag(
        invalid.authenticationTag,
        canonicalContent: invalid.canonicalContentBytes,
        vaultID: Self.vaultID,
        vaultKey: fixture.keys[1]
      ))
    // This deliberate negative control is why a public commitment must
    // never be promoted to the existing MAC-verified checkpoint type.
  }

  @Test
  func revokedSignerCannotAuthorizeAnotherBoundary() throws {
    let fixture = try Fixture()
    let parent = fixture.path[4]
    let unauthorized = try Self.envelope(
      body: parent.body,
      parent: Self.digest(parent),
      key: fixture.keys[2],
      signer: fixture.originalOwner
    )

    #expect(try !Self.hasActiveParentSignature(unauthorized, parent: parent))
  }

  @Test
  func completeRotationValidationAcceptsPreservedPlaintext() throws {
    let fixture = try Fixture()
    let validated = try Self.validateRotation(
      fixture.path[2], entry: fixture.entryObjects[2], nextKey: fixture.keys[1],
      fixture: fixture
    )

    #expect(validated.candidate == fixture.path[2])
    #expect(validated.stagedEntries.count == 1)
  }

  @Test
  func publicCommitmentsAndCurrentAuthenticationDoNotProvePreservedPlaintext() throws {
    let fixture = try Fixture()
    let replacementKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    // Construction receives public parent data, a generated signing capability,
    // and a fresh key. Neither the original vault key nor its plaintext is an input.
    let replacement = try Self.syntheticReplacement(
      parent: fixture.path[1], devices: fixture.path[2].body.devices,
      signer: fixture.originalOwner, nextKey: replacementKey
    )

    #expect(try Self.hasPublicCommitments(Array(fixture.path.prefix(2)) + [replacement.manifest]))
    #expect(
      try V3ManifestAuthenticator.isValidAuthenticationTag(
        replacement.manifest.authenticationTag,
        canonicalContent: replacement.manifest.canonicalContentBytes,
        vaultID: Self.vaultID, vaultKey: replacementKey
      ))
    #expect(
      try V3EntryCipher().openTrusted(
        replacement.entry.canonicalBytes, vaultID: Self.vaultID,
        manifestEntry: try #require(replacement.manifest.body.entries.first),
        vaultKey: replacementKey
      ) == "replacement example")
    #expect(throws: V3DeviceWrappedKeyRotationValidationError.invalidStagedEntry) {
      try Self.validateRotation(
        replacement.manifest, entry: replacement.entry, nextKey: replacementKey,
        fixture: fixture
      )
    }
  }

  private static func validateRotation(
    _ candidate: V3DeviceWrappedManifestEnvelope, entry: V3EncryptedEntry,
    nextKey: Data, fixture: Fixture
  ) throws -> V3DeviceWrappedValidatedKeyRotation {
    let parent = fixture.path[1]
    let checkpoint = try V3ManifestCheckpoint(vaultID: Self.vaultID, envelopeDigest: digest(parent))
    let trusted = V3DeviceWrappedTrustedCheckpoint(checkpoint: checkpoint, envelope: parent)
    let input = V3DeviceWrappedKeyRotationValidationInput(
      expectedCheckpoint: checkpoint, body: candidate.body,
      manifestData: candidate.canonicalBytes, manifestDigest: digest(candidate),
      stagedEntries: [entry]
    )
    return try V3DeviceWrappedKeyRotationValidator().validate(
      input, parent: trusted,
      currentEntries: [
        V3EntryObjectKey(
          entryID: Self.entryID,
          digest: Data(SHA256.hash(data: fixture.entryObjects[1].canonicalBytes))):
          fixture.entryObjects[1]
      ],
      currentVaultKey: fixture.keys[0], nextVaultKey: nextKey,
      expectedOwner: fixture.originalOwner.publicIdentity,
      validateRoster: { authenticatedParent, authenticatedCandidate in
        // Use the production enrollment preflight, not a test-only roster bypass.
        let classified = try V3DeviceWrappedEnrollmentTransitionValidator()
          .preflightOwnerAuthorizedKeyTransition(
            manifestData: authenticatedCandidate.canonicalBytes,
            manifestDigest: digest(authenticatedCandidate),
            parent: .init(checkpoint: checkpoint, envelope: authenticatedParent),
            currentVaultKey: fixture.keys[0]
          )
        guard classified.kind == .enrollment,
          classified.candidate == authenticatedCandidate
        else { throw V3DeviceWrappedKeyRotationValidationError.invalidTransition }
      }
    )
  }

  @Test
  func draftEpochSigningKeyIsBoundToItsVaultKeyAndPublicContext() throws {
    let fixture = try Fixture()
    let body = fixture.path[1].body
    let authority = try DraftEpochAuthority(body: body, vaultKey: fixture.keys[0])
    let opened = try authority.open(body: body, vaultKey: fixture.keys[0])

    #expect(opened.publicKey.x963Representation == authority.publicKey)
    #expect(throws: (any Error).self) {
      try authority.open(body: body, vaultKey: fixture.keys[1])
    }
    #expect(throws: (any Error).self) {
      try authority.open(body: fixture.path[2].body, vaultKey: fixture.keys[0])
    }
    #expect(throws: (any Error).self) {
      try authority.open(
        body: body, vaultKey: fixture.keys[0],
        expectedPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation
      )
    }
    let next = try DraftEpochAuthority(body: fixture.path[2].body, vaultKey: fixture.keys[1])
    #expect(next.publicKey != authority.publicKey)
    #expect(throws: (any Error).self) {
      try next.open(body: fixture.path[2].body, vaultKey: fixture.keys[0])
    }
  }

  @Test
  func draftBoundaryRequiresBothSeparateAuthorizations() throws {
    let fixture = try Fixture()
    let oldAuthority = try DraftEpochAuthority(
      body: fixture.path[1].body, vaultKey: fixture.keys[0])
    let nextAuthority = try DraftEpochAuthority(
      body: fixture.path[2].body, vaultKey: fixture.keys[1])
    let epochSigner = try oldAuthority.open(body: fixture.path[1].body, vaultKey: fixture.keys[0])
    let projection = try Self.draftProjection(fixture.path[2], authority: nextAuthority)
    let epochSignature = try Self.draftEpochSignature(projection, key: epochSigner)
    let deviceSignature = try Self.draftDeviceSignature(
      projection, epochSignature: epochSignature, signer: fixture.originalOwner)
    let verify: (Data?, Data?) throws -> Bool = { epoch, device in
      try Self.verifyDraftBoundary(
        projection, epochSignature: epoch, deviceSignature: device,
        signerDeviceID: fixture.originalOwner.publicIdentity.deviceID,
        parent: fixture.path[1], parentEpochPublicKey: oldAuthority.publicKey
      )
    }

    #expect(try verify(epochSignature, deviceSignature))
    #expect(try !verify(nil, deviceSignature))
    #expect(try !verify(epochSignature, nil))
    let unrelatedEpoch = try Self.draftEpochSignature(projection, key: P256.Signing.PrivateKey())
    let deviceOverUnrelated = try Self.draftDeviceSignature(
      projection, epochSignature: unrelatedEpoch, signer: fixture.originalOwner)
    #expect(try !verify(unrelatedEpoch, deviceOverUnrelated))
    let unrelatedDevice = try V3P256Signature.canonicalize(
      P256.Signing.PrivateKey().signature(
        for: Self.draftDeviceInput(projection, epochSignature: epochSignature)
      ).rawRepresentation)
    #expect(try !verify(epochSignature, unrelatedDevice))
  }

  @Test
  func draftEpochSignatureBindsTheCompleteProjectionAndItsDomain() throws {
    let fixture = try Fixture()
    let epochSigner = P256.Signing.PrivateKey()
    let nextAuthority = try DraftEpochAuthority(
      body: fixture.path[2].body, vaultKey: fixture.keys[1])
    let projection = try Self.draftProjection(fixture.path[2], authority: nextAuthority)
    let signature = try Self.draftEpochSignature(projection, key: epochSigner)
    let signatureObject = try P256.Signing.ECDSASignature(rawRepresentation: signature)
    #expect(
      epochSigner.publicKey.isValidSignature(signatureObject, for: Self.draftEpochInput(projection))
    )
    #expect(
      !epochSigner.publicKey.isValidSignature(
        signatureObject, for: CanonicalJSON.encode(projection)))

    // Every top-level manifest field is covered, not just the next public key.
    let content = try #require(projection.objectValue)
    let manifest = try #require(content.first { $0.0 == "manifest" }?.1.objectValue)
    for (field, _) in manifest {
      let changedManifest = CanonicalJSONValue.object(
        manifest.map {
          ($0.0, $0.0 == field ? .null : $0.1)
        })
      let changed = CanonicalJSONValue.object(
        content.map {
          ($0.0, $0.0 == "manifest" ? changedManifest : $0.1)
        })
      #expect(
        !epochSigner.publicKey.isValidSignature(signatureObject, for: Self.draftEpochInput(changed))
      )
    }
    let changedParents = CanonicalJSONValue.object(
      content.map {
        ($0.0, $0.0 == "parents" ? .array([]) : $0.1)
      })
    #expect(
      !epochSigner.publicKey.isValidSignature(
        signatureObject, for: Self.draftEpochInput(changedParents)))
  }

  @Test
  func draftBodyProofPreservesTheExistingFutureProfileRefusal() throws {
    let fixture = try Fixture()
    let nextAuthority = try DraftEpochAuthority(
      body: fixture.path[2].body, vaultKey: fixture.keys[1])
    let projection = try Self.draftProjection(fixture.path[2], authority: nextAuthority)
    let epochSignature = try Self.draftEpochSignature(projection, key: P256.Signing.PrivateKey())
    let content = try Self.draftFinalContent(projection, epochSignature: epochSignature)
    let bytes = try Self.envelopeBytes(
      content: content, key: fixture.keys[1], signer: fixture.originalOwner)
    let metadata = try V3DeviceWrappedManifestEnvelopeCodec().metadata(bytes)
    #expect(metadata.authorizations.count == 1)
    #expect(throws: V3DeviceWrappedUnlockError.unsupportedProfileVersion(3)) {
      try V3DeviceWrappedManifestEnvelopeCodec().parse(bytes)
    }
    let parent = fixture.path[1]
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Self.vaultID, envelopeDigest: Self.digest(parent))
    #expect(
      try V3DeviceWrappedEnrollmentTransitionValidator().isOwnerAuthorizedDirectChildEnvelope(
        manifestData: bytes, manifestDigest: Data(SHA256.hash(data: bytes)),
        parent: .init(checkpoint: checkpoint, envelope: parent), currentVaultKey: fixture.keys[0]
      ))
    // The legacy guard recognizes only the Mac signature and requires upgrade.
    // It does not verify or trust this draft proof or perform adoption.
  }

  @Test
  func draftDualAuthorizationDoesNotEstablishHistoricalPlaintextEquality() throws {
    let fixture = try Fixture()
    let replacementKey = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
    let replacement = try Self.syntheticReplacement(
      parent: fixture.path[1], devices: fixture.path[2].body.devices,
      signer: fixture.originalOwner, nextKey: replacementKey
    )
    let oldAuthority = try DraftEpochAuthority(
      body: fixture.path[1].body, vaultKey: fixture.keys[0])
    let epochSigner = try oldAuthority.open(body: fixture.path[1].body, vaultKey: fixture.keys[0])
    let nextAuthority = try DraftEpochAuthority(
      body: replacement.manifest.body, vaultKey: replacementKey)
    let projection = try Self.draftProjection(replacement.manifest, authority: nextAuthority)
    let epochSignature = try Self.draftEpochSignature(projection, key: epochSigner)
    let deviceSignature = try Self.draftDeviceSignature(
      projection, epochSignature: epochSignature, signer: fixture.originalOwner)
    #expect(
      try Self.verifyDraftBoundary(
        projection, epochSignature: epochSignature, deviceSignature: deviceSignature,
        signerDeviceID: fixture.originalOwner.publicIdentity.deviceID,
        parent: fixture.path[1], parentEpochPublicKey: oldAuthority.publicKey
      ))
    #expect(throws: V3DeviceWrappedKeyRotationValidationError.invalidStagedEntry) {
      try Self.validateRotation(
        replacement.manifest, entry: replacement.entry, nextKey: replacementKey, fixture: fixture
      )
    }
  }

  // These deliberately test-only domains and provisional fields are not wire
  // fixtures, production codecs, a trusted history type, or an integrated profile.
  private static func draftProjection(
    _ candidate: V3DeviceWrappedManifestEnvelope, authority: DraftEpochAuthority
  ) throws -> CanonicalJSONValue {
    let manifest = try #require(candidate.body.canonicalValue.objectValue)
    let fields = manifest.map { ($0.0, $0.0 == "profileVersion" ? .integer(3) : $0.1) }
    return .object([
      ("parents", .array(candidate.parents.map { .string(Base64URL.encode($0)) })),
      ("manifest", .object(fields + [("epochAuthority", authority.canonicalValue)])),
    ])
  }

  private static func draftEpochInput(_ projection: CanonicalJSONValue) -> Data {
    Data("work.tvr.key/test-only/epoch-transition-proof/v1\u{0}".utf8)
      + CanonicalJSON.encode(projection)
  }

  private static func draftEpochSignature(
    _ projection: CanonicalJSONValue, key: P256.Signing.PrivateKey
  ) throws -> Data {
    try V3P256Signature.canonicalize(
      key.signature(for: draftEpochInput(projection)).rawRepresentation)
  }

  private static func draftFinalContent(
    _ projection: CanonicalJSONValue, epochSignature: Data
  ) throws -> CanonicalJSONValue {
    let content = try #require(projection.objectValue)
    let manifest = try #require(content.first { $0.0 == "manifest" }?.1.objectValue)
    let authority = try #require(manifest.first { $0.0 == "epochAuthority" }?.1.objectValue)
    let finalized = CanonicalJSONValue.object(
      authority + [
        ("transitionSignature", .string(Base64URL.encode(epochSignature)))
      ])
    let body = CanonicalJSONValue.object(
      manifest.map {
        ($0.0, $0.0 == "epochAuthority" ? finalized : $0.1)
      })
    return .object(content.map { ($0.0, $0.0 == "manifest" ? body : $0.1) })
  }

  private static func draftDeviceInput(
    _ projection: CanonicalJSONValue, epochSignature: Data
  ) throws -> Data {
    V3ManifestAuthenticator.authenticationInput(
      for: CanonicalJSON.encode(try draftFinalContent(projection, epochSignature: epochSignature))
    )
  }

  private static func draftDeviceSignature(
    _ projection: CanonicalJSONValue, epochSignature: Data, signer: Device
  ) throws -> Data {
    try V3P256Signature.canonicalize(
      signer.signature(
        for: draftDeviceInput(projection, epochSignature: epochSignature), reason: "Design test."))
  }

  private static func verifyDraftBoundary(
    _ projection: CanonicalJSONValue, epochSignature: Data?, deviceSignature: Data?,
    signerDeviceID: String, parent: V3DeviceWrappedManifestEnvelope, parentEpochPublicKey: Data
  ) throws -> Bool {
    guard let epochSignature, let deviceSignature,
      V3P256Signature.isCanonical(epochSignature),
      V3P256Signature.isCanonical(deviceSignature),
      let owner = parent.body.devices.first(where: {
        $0.identity.deviceID == signerDeviceID && $0.status == .active
      }),
      let content = projection.objectValue,
      let parents = content.first(where: { $0.0 == "parents" })?.1.arrayValue,
      parents.count == 1, parents.first?.stringValue == Base64URL.encode(digest(parent))
    else { return false }
    let epochValid = try P256.Signing.PublicKey(x963Representation: parentEpochPublicKey)
      .isValidSignature(
        P256.Signing.ECDSASignature(rawRepresentation: epochSignature),
        for: draftEpochInput(projection))
    let deviceValid = try P256.Signing.PublicKey(
      x963Representation: owner.identity.signingPublicKey
    )
    .isValidSignature(
      P256.Signing.ECDSASignature(rawRepresentation: deviceSignature),
      for: draftDeviceInput(projection, epochSignature: epochSignature))
    return epochValid && deviceValid
  }

  private struct DraftEpochAuthority {
    let publicKey: Data
    let protectedSigningKey: Data

    init(body: V3DeviceWrappedManifestBody, vaultKey: Data) throws {
      let key = P256.Signing.PrivateKey()
      publicKey = key.publicKey.x963Representation
      let context = Self.context(body: body, publicKey: publicKey)
      let box = try AES.GCM.seal(
        key.rawRepresentation,
        using: Self.wrappingKey(vaultKey: vaultKey),
        authenticating: context)
      protectedSigningKey = try #require(box.combined)
    }

    var canonicalValue: CanonicalJSONValue {
      .object([
        ("publicKey", .string(Base64URL.encode(publicKey))),
        ("protectedSigningKey", .string(Base64URL.encode(protectedSigningKey))),
      ])
    }

    func open(
      body: V3DeviceWrappedManifestBody, vaultKey: Data, expectedPublicKey: Data? = nil
    ) throws -> P256.Signing.PrivateKey {
      let expected = expectedPublicKey ?? publicKey
      let context = Self.context(body: body, publicKey: expected)
      let raw = try AES.GCM.open(
        AES.GCM.SealedBox(combined: protectedSigningKey),
        using: Self.wrappingKey(vaultKey: vaultKey), authenticating: context)
      let key = try P256.Signing.PrivateKey(rawRepresentation: raw)
      guard key.publicKey.x963Representation == expected else {
        throw V3P256SignatureError.invalidRawRepresentation
      }
      return key
    }

    private static func context(body: V3DeviceWrappedManifestBody, publicKey: Data) -> Data {
      CanonicalJSON.encode(
        .object([
          ("domain", .string("work.tvr.key/test-only/epoch-signing-key-aad/v1")),
          ("profileVersion", .integer(3)),
          ("vaultID", .string(body.vaultID)), ("keyID", .string(body.keyID.rawValue)),
          ("authorityTransitionID", .string(body.authorityTransitionID)),
          ("publicKey", .string(Base64URL.encode(publicKey))),
        ]))
    }

    private static func wrappingKey(vaultKey: Data) -> SymmetricKey {
      HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: vaultKey),
        salt: Data(),
        info: Data("work.tvr.key/test-only/epoch-signing-key-kek/v1".utf8),
        outputByteCount: 32)
    }
  }

  private static func syntheticReplacement(
    parent: V3DeviceWrappedManifestEnvelope, devices: [V3DeviceWrappedManifestDevice],
    signer: Device, nextKey: Data
  ) throws -> (manifest: V3DeviceWrappedManifestEnvelope, entry: V3EncryptedEntry) {
    let old = try #require(parent.body.entries.first)
    let keyID = try V3VaultKeyID.derive(vaultKey: nextKey, vaultID: parent.body.vaultID)
    let transitionID = UUID().uuidString.lowercased()
    let context = try V3EntryAuthenticationContext(
      vaultID: parent.body.vaultID, entryID: old.entryID, name: old.name,
      type: old.type, keyID: keyID, revision: old.revision
    )
    let entry = try V3EntryCipher().seal("replacement example", context: context, vaultKey: nextKey)
    let wrappers = try devices.filter { $0.status == .active }.map { device in
      let context = try V3VaultKeyHPKEContext(
        vaultID: parent.body.vaultID, keyID: keyID, authorityTransitionID: transitionID,
        recipientDeviceID: device.identity.deviceID
      )
      return try V3DeviceWrappedManifestKey(
        recipientDeviceID: device.identity.deviceID,
        wrappedKey: try V3VaultKeyHPKE().wrap(
          vaultKey: nextKey, recipientPublicKey: device.identity.wrappingPublicKey, context: context
        )
      )
    }
    let body = try V3DeviceWrappedManifestBody(
      vaultID: parent.body.vaultID, keyID: keyID, authorityTransitionID: transitionID,
      devices: devices, wrappedKeys: wrappers,
      entries: [
        .init(
          entryID: old.entryID, name: old.name, type: old.type, revision: old.revision,
          keyID: keyID, ciphertextDigest: entry.ciphertextDigest)
      ]
    )
    return (try envelope(body: body, parent: digest(parent), key: nextKey, signer: signer), entry)
  }

  private static func hasPublicCommitments(
    _ path: [V3DeviceWrappedManifestEnvelope]
  ) throws -> Bool {
    guard !path.isEmpty else { return false }
    for (parent, child) in zip(path, path.dropFirst()) {
      guard child.parents == [digest(parent)],
        child.body.vaultID == parent.body.vaultID
      else { return false }
      if child.body.keyID == parent.body.keyID {
        guard child.authorizations.isEmpty,
          child.body.authorityTransitionID == parent.body.authorityTransitionID,
          child.body.devices == parent.body.devices,
          child.body.wrappedKeys == parent.body.wrappedKeys
        else { return false }
      } else {
        guard try hasActiveParentSignature(child, parent: parent) else { return false }
      }
    }
    return true
  }

  private static func hasActiveParentSignature(
    _ child: V3DeviceWrappedManifestEnvelope,
    parent: V3DeviceWrappedManifestEnvelope
  ) throws -> Bool {
    guard child.authorizations.count == 1,
      let authorization = child.authorizations.first,
      let owner = parent.body.devices.first(where: {
        $0.identity.deviceID == authorization.signerDeviceID && $0.status == .active
      }),
      let signatureBytes = Base64URL.decodeCanonical(authorization.signature)
    else { return false }
    return try P256.Signing.PublicKey(
      x963Representation: owner.identity.signingPublicKey
    ).isValidSignature(
      P256.Signing.ECDSASignature(rawRepresentation: signatureBytes),
      for: V3ManifestAuthenticator.authenticationInput(for: child.canonicalContentBytes)
    )
  }

  private static func digest(_ envelope: V3DeviceWrappedManifestEnvelope) -> Data {
    Data(SHA256.hash(data: envelope.canonicalBytes))
  }

  private static func replacingTag(
    _ envelope: V3DeviceWrappedManifestEnvelope, with tag: Data
  ) throws -> V3DeviceWrappedManifestEnvelope {
    let value = try CanonicalJSON.parse(envelope.canonicalBytes)
    let root = try #require(value.objectValue)
    return try V3DeviceWrappedManifestEnvelopeCodec().parse(
      CanonicalJSON.encode(
        .object(
          root.map { name, value in
            (
              name,
              name == "authentication"
                ? .object([
                  ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                  ("tag", .string(Base64URL.encode(tag))),
                ]) : value
            )
          }
        )))
  }

  private static func envelope(
    body: V3DeviceWrappedManifestBody, parent: Data, key: Data,
    signer: Device? = nil
  ) throws -> V3DeviceWrappedManifestEnvelope {
    let content = CanonicalJSONValue.object([
      ("parents", .array([.string(Base64URL.encode(parent))])),
      ("manifest", body.canonicalValue),
    ])
    return try V3DeviceWrappedManifestEnvelopeCodec().parse(
      envelopeBytes(content: content, key: key, signer: signer)
    )
  }

  private static func envelopeBytes(
    content: CanonicalJSONValue, key: Data, signer: Device? = nil
  ) throws -> Data {
    let canonical = CanonicalJSON.encode(content)
    let tag = try V3ManifestAuthenticator.authenticationTag(
      canonicalContent: canonical, vaultID: Self.vaultID, vaultKey: key
    )
    var authorizations: [CanonicalJSONValue] = []
    if let signer {
      let signature = try V3P256Signature.canonicalize(
        signer.signature(
          for: V3ManifestAuthenticator.authenticationInput(for: canonical),
          reason: "Software-only design evidence."
        ))
      authorizations = [
        .object([
          ("algorithm", .string("P-256-ECDSA-SHA256")),
          ("signerDeviceID", .string(signer.publicIdentity.deviceID)),
          ("signature", .string(Base64URL.encode(signature))),
        ])
      ]
    }
    return CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-manifest-envelope")),
        ("version", .integer(3)),
        ("content", content),
        (
          "authentication",
          .object([
            ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
            ("tag", .string(Base64URL.encode(tag))),
          ])
        ),
        ("authorizations", .array(authorizations)),
      ]))
  }

  private struct Fixture {
    let originalOwner: Device
    let keys = (0..<3).map { _ in SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) } }
    let path: [V3DeviceWrappedManifestEnvelope]
    let entryObjects: [V3EncryptedEntry]
    let finalEntry: V3EncryptedEntry

    init() throws {
      originalOwner = try Device(name: "Original Mac")
      let newOwner = try Device(name: "Replacement Mac")
      let genesis = try V3DeviceWrappedGenesisBuilder().buildPublicationCandidate(
        vaultID: PIVRecoveryAuthorityDesignTests.vaultID,
        authorityTransitionID: UUID().uuidString.lowercased(),
        entryIDs: [PIVRecoveryAuthorityDesignTests.entryID],
        snapshotEntries: [.init(name: "example", type: .secret, plaintext: "initial value")],
        vaultKey: keys[0], ownerIdentity: originalOwner.publicIdentity
      )
      var manifests = [
        try V3DeviceWrappedManifestEnvelopeCodec().parse(genesis.genesis.manifestData)
      ]
      var encrypted = try #require(genesis.entries.first).encryptedEntry
      var objects = [encrypted]
      for epoch in 0..<3 {
        if epoch > 0 {
          let parent = try #require(manifests.last)
          let checkpoint = try V3ManifestCheckpoint(
            vaultID: PIVRecoveryAuthorityDesignTests.vaultID,
            envelopeDigest: PIVRecoveryAuthorityDesignTests.digest(parent)
          )
          let devices = [
            V3DeviceWrappedManifestDevice(
              identity: originalOwner.publicIdentity,
              status: epoch == 2 ? .revoked : .active),
            V3DeviceWrappedManifestDevice(identity: newOwner.publicIdentity, status: .active),
          ].sorted { $0.identity.deviceID < $1.identity.deviceID }
          let entryKey = V3EntryObjectKey(
            entryID: PIVRecoveryAuthorityDesignTests.entryID,
            digest: Data(SHA256.hash(data: encrypted.canonicalBytes))
          )
          let candidate = try V3DeviceWrappedKeyRotationBuilder().build(
            from: .init(checkpoint: checkpoint, envelope: parent),
            currentEntries: [entryKey: encrypted], currentVaultKey: keys[epoch - 1],
            nextVaultKey: keys[epoch], authorityTransitionID: UUID().uuidString.lowercased(),
            resultingDevices: devices, owner: epoch == 1 ? originalOwner : newOwner,
            authorizationReason: "Software-only design evidence."
          )
          manifests.append(try V3DeviceWrappedManifestEnvelopeCodec().parse(candidate.manifestData))
          encrypted = try #require(candidate.stagedEntries.first)
          objects.append(encrypted)
        }
        let parent = try #require(manifests.last)
        let context = try V3EntryAuthenticationContext(
          vaultID: PIVRecoveryAuthorityDesignTests.vaultID,
          entryID: PIVRecoveryAuthorityDesignTests.entryID,
          name: "example", type: .secret, keyID: parent.body.keyID,
          revision: UInt64(epoch + 2)
        )
        encrypted = try V3EntryCipher().seal(
          epoch == 2 ? "current value" : "intermediate value", context: context,
          vaultKey: keys[epoch]
        )
        let body = try V3DeviceWrappedManifestBody(
          vaultID: parent.body.vaultID, keyID: parent.body.keyID,
          authorityTransitionID: parent.body.authorityTransitionID,
          devices: parent.body.devices, wrappedKeys: parent.body.wrappedKeys,
          entries: [
            .init(
              entryID: context.entryID, name: context.name, type: context.type,
              revision: context.revision, keyID: context.keyID,
              ciphertextDigest: encrypted.ciphertextDigest)
          ]
        )
        manifests.append(
          try PIVRecoveryAuthorityDesignTests.envelope(
            body: body, parent: PIVRecoveryAuthorityDesignTests.digest(parent), key: keys[epoch]
          ))
        objects.append(encrypted)
      }
      path = manifests
      entryObjects = objects
      finalEntry = encrypted
    }
  }

  private struct Device: V3EnrollmentMessageSigning {
    let vaultID = PIVRecoveryAuthorityDesignTests.vaultID
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let signingKey = P256.Signing.PrivateKey()

    init(name: String) throws {
      publicIdentity = try V3EnrollmentDeviceIdentity(
        displayName: name, signingPublicKey: signingKey.publicKey.x963Representation,
        wrappingPublicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation
      )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
      try signingKey.signature(for: input).rawRepresentation
    }
  }
}
