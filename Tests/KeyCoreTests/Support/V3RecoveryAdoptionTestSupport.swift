import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Permanent-profile source and recovery-adoption construction for software tests.
enum V3RecoveryAdoptionTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  struct Fixture {
    let owner: Core.Owner
    let member: Core.Owner
    let revoked: Core.Owner
    let base: V3DeviceWrappedTrustedCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    init(empty: Bool = false) throws {
      owner = try Core.Owner()
      member = try Core.Owner()
      revoked = try Core.Owner()
      let publication = try V3DeviceWrappedGenesisBuilder().buildPublicationCandidate(
        vaultID: Core.vaultID, authorityTransitionID: "018f4d38-7d5a-7b20-b0f1-97d6e96c84b4",
        entryIDs: empty
          ? [] : ["018f4d38-7d5a-7b20-b0f1-97d6e96c84b7", "018f4d38-7d5a-7b20-b0f1-97d6e96c84b8"],
        snapshotEntries: empty
          ? []
          : [
            V3GenesisSourceEntry(
              name: "account/密碼", type: .secret, plaintext: "Adoption fixture secret"),
            V3GenesisSourceEntry(name: "otp", type: .totp, plaintext: "JBSWY3DPEHPK3PXP"),
          ],
        vaultKey: Core.oldKey, ownerIdentity: owner.publicIdentity)
      let devices = [
        V3DeviceWrappedManifestDevice(identity: owner.publicIdentity, status: .active),
        V3DeviceWrappedManifestDevice(identity: member.publicIdentity, status: .active),
        V3DeviceWrappedManifestDevice(identity: revoked.publicIdentity, status: .revoked),
      ]
      .sorted { $0.identity.deviceID < $1.identity.deviceID }
      let original = publication.genesis.body
      var current = publication.entries.map(\.encryptedEntry)
      if let index = current.firstIndex(where: { $0.context.type == .secret }) {
        let entry = current[index]
        current[index] = try V3EntryCipher().seal(
          "Adoption fixture secret",
          context: V3EntryAuthenticationContext(
            vaultID: Core.vaultID,
            entryID: entry.context.entryID, name: entry.context.name, type: .secret,
            keyID: original.keyID, revision: 7), vaultKey: Core.oldKey)
      }
      let wrappers = try devices.compactMap { device -> V3DeviceWrappedManifestKey? in
        guard device.status == .active else { return nil }
        return try V3DeviceWrappedManifestKey(
          recipientDeviceID: device.identity.deviceID,
          wrappedKey: V3VaultKeyHPKE().wrap(
            vaultKey: Core.oldKey,
            recipientPublicKey: device.identity.wrappingPublicKey,
            context: V3VaultKeyHPKEContext(
              vaultID: Core.vaultID, keyID: original.keyID,
              authorityTransitionID: original.authorityTransitionID,
              recipientDeviceID: device.identity.deviceID)))
      }
      let body = try V3DeviceWrappedManifestBody(
        vaultID: Core.vaultID, keyID: original.keyID,
        authorityTransitionID: original.authorityTransitionID, devices: devices,
        wrappedKeys: wrappers,
        entries: current.map { V3ResealedEntry(encryptedEntry: $0).manifestEntry })
      let content = CanonicalJSONValue.object([
        ("manifest", body.canonicalValue), ("parents", .array([])),
      ])
      let data = CanonicalJSON.encode(
        .object([
          ("format", .string("key-vault-manifest-envelope")), ("version", .integer(3)),
          ("content", content),
          (
            "authentication",
            .object([
              ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
              (
                "tag",
                .string(
                  Base64URL.encode(
                    try V3ManifestAuthenticator.authenticationTag(
                      canonicalContent: CanonicalJSON.encode(content), vaultID: Core.vaultID,
                      vaultKey: Core.oldKey)))
              ),
            ])
          ),
          ("authorizations", .array([])),
        ]))
      base = V3DeviceWrappedTrustedCheckpoint(
        checkpoint: try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: Data(SHA256.hash(data: data))),
        envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(data))
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(
        current)
    }
    func build(limits: V3ManifestRepositoryLimits = .standard) throws
      -> V3RecoveryProfileAdoptionCandidate
    {
      try V3RecoveryProfileAdoptionBuilder(limits: limits).build(
        from: base, currentEntries: entries,
        currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey, owner: owner,
        reason: "Adopt fixture")
    }
    func validate(_ candidate: V3RecoveryProfileAdoptionCandidate, nextKey: Data = Core.nextKey)
      throws
    {
      try V3RecoveryProfileAdoptionValidator().validate(
        candidate, parent: base, currentEntries: entries,
        currentVaultKey: Core.oldKey, nextVaultKey: nextKey, expectedOwner: owner.publicIdentity)
    }
    func validateForPublication(_ candidate: V3RecoveryProfileAdoptionCandidate) throws {
      try V3RecoveryProfileAdoptionValidator().validateForPublication(
        candidate, parent: base,
        currentEntries: entries, currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
        identity: owner, reason: "Check fixture adoption")
    }
    func resign(
      _ original: V3RecoveryProfileAdoptionCandidate, body: V3RecoveryManifestBody,
      staged: [V3EncryptedEntry], signer: Core.Owner? = nil
    ) throws -> V3RecoveryProfileAdoptionCandidate {
      let signer = signer ?? owner
      let boundary = V3RecoveryEpochBoundary()
      let unsigned = try boundary.encode(
        body: body, parents: original.envelope.parents,
        vaultKey: Core.nextKey, authorizations: [])
      let signature = try V3P256Signature.canonicalize(
        signer.signature(
          for: V3ManifestAuthenticator.authenticationInput(for: unsigned.canonicalContentBytes),
          reason: "Sign changed software fixture"))
      return V3RecoveryProfileAdoptionCandidate(
        expectedCheckpoint: original.expectedCheckpoint,
        envelope: try boundary.encode(
          body: body, parents: original.envelope.parents,
          vaultKey: Core.nextKey,
          authorizations: [
            V3ManifestAuthorization(
              signerDeviceID: signer.publicIdentity.deviceID, signature: Base64URL.encode(signature)
            )
          ]),
        stagedEntries: staged)
    }
  }
}
