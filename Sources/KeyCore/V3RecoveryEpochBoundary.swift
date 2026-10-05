import CryptoKit
import Foundation
internal import JSONCanonicalization

/// Cryptographic transcript checks for one exact profile-3 boundary, not a
/// history/roster/reseal validator. Its caller must establish parent authority
/// from an anchor. Success does not produce a trusted checkpoint or snapshot.
struct V3RecoveryEpochBoundary: Sendable {
  private static let domain = "work.tvr.key/v3/epoch-transition-authorization/v1"

  /// The only omitted value is epochAuthority.transitionProof.signature.
  /// Typed, exact codecs reject other fields before this construction path.
  static func signatureInput(body: V3RecoveryManifestBody, parents: [Data]) throws -> Data {
    guard let proof = body.transitionProof, parents == [proof.parentEnvelopeDigest] else {
      throw V3RecoveryManifestError.invalidBoundary
    }
    return signatureInput(body: body, parentDigest: proof.parentEnvelopeDigest)
  }

  private static func signatureInput(body: V3RecoveryManifestBody, parentDigest: Data) -> Data {
    let proof: CanonicalJSONValue = .object([
      ("version", .integer(V3RecoveryEpochTransitionProof.version)),
      ("algorithm", .string(V3EpochSigningKeyCapsule.signingAlgorithm)),
      ("parentEnvelopeDigest", .string(Base64URL.encode(parentDigest))),
    ])
    let content = canonicalContent(body: body.canonicalValue(proof: proof), parents: [parentDigest])
    var bytes = Data(Self.domain.utf8)
    bytes.append(0)
    bytes.append(CanonicalJSON.encode(content))
    return bytes
  }

  /// Pure construction after the service has prepared and fully checked its
  /// candidate. No publication, prompts, token calls or administrative policy.
  /// The existing Mac signer is explicit; fixture signers use software keys.
  /// Production publication must additionally verify MACs, wrappers, roster
  /// policy, independent fresh epochs and complete same-plaintext resealing.
  func authorize(
    candidate: V3RecoveryManifestBody, parent: V3RecoveryManifestEnvelope,
    currentVaultKey: Data, nextVaultKey: Data,
    signer: any V3EnrollmentMessageSigning, reason: String
  ) throws -> V3RecoveryManifestEnvelope {
    try requireParsed(parent)
    guard candidate.transitionProof == nil, !reason.isEmpty,
      signer.vaultID == parent.body.fields.vaultID,
      parent.body.fields.devices.contains(where: {
        $0.status == .active && $0.identity == signer.publicIdentity
      })
    else { throw V3RecoveryManifestError.invalidDeviceAuthorization }
    try requireNewEpoch(candidate, parent: parent.body)
    try verifyCurrentAuthentication(parent, vaultKey: currentVaultKey)
    try requireKey(nextVaultKey, body: candidate)
    // Check the new capsule before invoking either signing operation.
    try V3EpochSigningKeyCipher().withSigningKey(
      candidate.epochSigningKey, context: epochContext(candidate), vaultKey: nextVaultKey
    ) { _ in () }
    let input = Self.signatureInput(body: candidate, parentDigest: parent.digest)
    let epochSignature = try V3EpochSigningKeyCipher().withSigningKey(
      parent.body.epochSigningKey, context: epochContext(parent.body), vaultKey: currentVaultKey
    ) { key in try V3P256Signature.canonicalize(key.signature(for: input).rawRepresentation) }
    let body = try V3RecoveryManifestBody(
      fields: candidate.fields, epochSigningKey: candidate.epochSigningKey,
      transitionProof: V3RecoveryEpochTransitionProof(
        parentEnvelopeDigest: parent.digest, signature: epochSignature),
      recovery: candidate.recovery)
    let content = CanonicalJSON.encode(
      Self.canonicalContent(body: body.canonicalValue, parents: [parent.digest]))
    let signature = try V3P256Signature.canonicalize(
      signer.signature(
        for: V3ManifestAuthenticator.authenticationInput(for: content), reason: reason))
    let envelope = try encode(
      body: body, parents: [parent.digest], vaultKey: nextVaultKey,
      authorizations: [
        V3ManifestAuthorization(
          signerDeviceID: signer.publicIdentity.deviceID, signature: Base64URL.encode(signature))
      ])
    try verifyBoundary(envelope, parent: parent)
    try verifyCurrentAuthentication(envelope, vaultKey: nextVaultKey)
    return envelope
  }

  func verifyBoundary(
    _ candidate: V3RecoveryManifestEnvelope, parent: V3RecoveryManifestEnvelope
  ) throws {
    try requireParsed(parent)
    try requireParsed(candidate)
    try requireNewEpoch(candidate.body, parent: parent.body)
    guard candidate.parents == [parent.digest],
      candidate.body.transitionProof?.parentEnvelopeDigest == parent.digest,
      candidate.authorizations.count == 1,
      let authorization = candidate.authorizations.first,
      let owner = parent.body.fields.devices.first(where: {
        $0.identity.deviceID == authorization.signerDeviceID && $0.status == .active
      }),
      let deviceSignature = Base64URL.decodeCanonical(authorization.signature)
    else { throw V3RecoveryManifestError.invalidDeviceAuthorization }
    try verifySignature(
      deviceSignature, publicKey: owner.identity.signingPublicKey,
      input: V3ManifestAuthenticator.authenticationInput(for: candidate.canonicalContentBytes),
      error: .invalidDeviceAuthorization)
    guard let proof = candidate.body.transitionProof else {
      throw V3RecoveryManifestError.invalidEpochAuthorization
    }
    // Parent-supplied public authority, never the candidate's replacement key.
    try verifySignature(
      proof.signature, publicKey: parent.body.epochSigningKey.publicKey,
      input: Self.signatureInput(body: candidate.body, parents: candidate.parents),
      error: .invalidEpochAuthorization)
  }

  /// Current manifest MAC and capsule correspondence only. Entries, ancestry,
  /// recipient policy, freshness and restorable-state construction are elsewhere.
  func verifyCurrentAuthentication(_ envelope: V3RecoveryManifestEnvelope, vaultKey: Data) throws {
    try requireParsed(envelope)
    try requireKey(vaultKey, body: envelope.body)
    guard
      try V3ManifestAuthenticator.isValidAuthenticationTag(
        envelope.authenticationTag, canonicalContent: envelope.canonicalContentBytes,
        vaultID: envelope.body.fields.vaultID, vaultKey: vaultKey)
    else { throw V3RecoveryManifestError.authenticationFailed }
    try V3EpochSigningKeyCipher().withSigningKey(
      envelope.body.epochSigningKey, context: epochContext(envelope.body), vaultKey: vaultKey
    ) { _ in () }
  }

  /// Public metadata checks for edits/merges within one epoch, not historical
  /// MAC verification. Every parent must carry the identical authority record.
  func verifySameEpochMetadata(
    _ child: V3RecoveryManifestEnvelope, parents: [V3RecoveryManifestEnvelope]
  ) throws {
    try requireParsed(child)
    guard !parents.isEmpty, child.authorizations.isEmpty,
      child.parents == parents.map(\.digest).sorted(by: { $0.lexicographicallyPrecedes($1) })
    else { throw V3RecoveryManifestError.invalidBoundary }
    for parent in parents {
      try requireParsed(parent)
      let a = child.body
      let b = parent.body
      guard a.fields.vaultID == b.fields.vaultID, a.fields.keyID == b.fields.keyID,
        a.fields.authorityTransitionID == b.fields.authorityTransitionID,
        a.fields.devices == b.fields.devices, a.fields.wrappedKeys == b.fields.wrappedKeys,
        a.epochSigningKey == b.epochSigningKey, a.transitionProof == b.transitionProof,
        a.recovery == b.recovery
      else { throw V3RecoveryManifestError.invalidBoundary }
    }
  }

  /// Exact serialization shared by origin, edits and authorized boundaries.
  /// This is not an origin-validation or same-epoch-policy API.
  func encode(
    body: V3RecoveryManifestBody, parents: [Data], vaultKey: Data,
    authorizations: [V3ManifestAuthorization]
  ) throws -> V3RecoveryManifestEnvelope {
    try requireKey(vaultKey, body: body)
    let content = Self.canonicalContent(body: body.canonicalValue, parents: parents)
    let tag = try V3ManifestAuthenticator.authenticationTag(
      canonicalContent: CanonicalJSON.encode(content), vaultID: body.fields.vaultID,
      vaultKey: vaultKey)
    let data = CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-manifest-envelope")), ("version", .integer(3)),
        ("content", content),
        (
          "authentication",
          .object([
            ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
            ("tag", .string(Base64URL.encode(tag))),
          ])
        ),
        (
          "authorizations",
          .array(
            authorizations.map {
              .object([
                ("algorithm", .string(V3EpochSigningKeyCapsule.signingAlgorithm)),
                ("signerDeviceID", .string($0.signerDeviceID)),
                ("signature", .string($0.signature)),
              ])
            })
        ),
      ]))
    return try V3RecoveryManifestCodec().parseEnvelope(data)
  }

  private static func canonicalContent(body: CanonicalJSONValue, parents: [Data])
    -> CanonicalJSONValue
  {
    .object([
      ("manifest", body), ("parents", .array(parents.map { .string(Base64URL.encode($0)) })),
    ])
  }

  private func requireParsed(_ envelope: V3RecoveryManifestEnvelope) throws {
    guard try V3RecoveryManifestCodec().parseEnvelope(envelope.canonicalBytes) == envelope else {
      throw V3RecoveryManifestError.invalidStructure
    }
  }

  private func requireNewEpoch(_ candidate: V3RecoveryManifestBody, parent: V3RecoveryManifestBody)
    throws
  {
    guard candidate.fields.vaultID == parent.fields.vaultID,
      candidate.fields.keyID != parent.fields.keyID,
      candidate.fields.authorityTransitionID != parent.fields.authorityTransitionID,
      candidate.epochSigningKey.publicKey != parent.epochSigningKey.publicKey,
      candidate.epochSigningKey.protectedSigningKey != parent.epochSigningKey.protectedSigningKey
    else { throw V3RecoveryManifestError.invalidBoundary }
  }

  private func requireKey(_ key: Data, body: V3RecoveryManifestBody) throws {
    guard key.count == 32,
      try V3VaultKeyID.derive(vaultKey: key, vaultID: body.fields.vaultID) == body.fields.keyID
    else { throw V3RecoveryManifestError.invalidVaultKey }
  }

  private func epochContext(_ body: V3RecoveryManifestBody) throws -> V3EpochSigningKeyContext {
    try V3EpochSigningKeyContext(
      vaultID: body.fields.vaultID, keyID: body.fields.keyID,
      authorityTransitionID: body.fields.authorityTransitionID)
  }

  private func verifySignature(
    _ bytes: Data, publicKey: Data, input: Data, error: V3RecoveryManifestError
  ) throws {
    guard V3P256Signature.isCanonical(bytes),
      let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
      let signature = try? P256.Signing.ECDSASignature(rawRepresentation: bytes),
      key.isValidSignature(signature, for: SHA256.hash(data: input))
    else { throw error }
  }
}
