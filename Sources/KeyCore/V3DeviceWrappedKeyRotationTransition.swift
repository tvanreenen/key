import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3DeviceWrappedKeyRotationError: Error, Equatable {
    case invalidTrustedCheckpoint
    case invalidCurrentVaultKey
    case invalidNextVaultKey
    case invalidOwner
    case incompleteEntrySnapshot
    case invalidEntry
    case invalidCandidate
}

/// Common cryptographic output for an owner-authorized membership change.
///
/// The raw current and next keys are intentionally absent. Callers retain
/// ownership of their bounded in-memory lifetime and add transition-specific
/// evidence such as an enrollment transcript or a revocation plan.
struct V3DeviceWrappedKeyRotationCandidate: Equatable, Sendable {
    let expectedCheckpoint: V3ManifestCheckpoint
    let body: V3DeviceWrappedManifestBody
    let manifestData: Data
    let manifestDigest: Data
    let stagedEntries: [V3EncryptedEntry]
}

/// Pure cryptographic construction shared by enrollment and revocation.
///
/// A caller must first prove its exact roster transition. This type then
/// rotates the key, reseals the complete current snapshot, creates one wrapper
/// per resulting active device, and signs the exact candidate with an active
/// owner from the authenticated parent.
struct V3DeviceWrappedKeyRotationBuilder: Sendable {
    private static let envelopeFormat = "key-vault-manifest-envelope"
    private static let envelopeVersion: UInt64 = 3
    private static let authenticationAlgorithm =
        "HKDF-SHA256+HMAC-SHA256"
    private static let authorizationAlgorithm = "P-256-ECDSA-SHA256"

    private let entryCipher = V3EntryCipher()
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let hpke = V3VaultKeyHPKE()

    func build(
        from base: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        authorityTransitionID: String,
        resultingDevices: [V3DeviceWrappedManifestDevice],
        owner: any V3EnrollmentMessageSigning,
        authorizationReason: String
    ) throws -> V3DeviceWrappedKeyRotationCandidate {
        let parent = try validate(
            base: base,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            authorityTransitionID: authorityTransitionID,
            resultingDevices: resultingDevices,
            owner: owner,
            authorizationReason: authorizationReason
        )
        let nextKeyID = try V3VaultKeyID.derive(
            vaultKey: nextVaultKey,
            vaultID: parent.body.vaultID
        )
        let wrappedKeys = try resultingDevices.compactMap {
            device -> V3DeviceWrappedManifestKey? in
            guard device.status == .active else { return nil }
            let context = try V3VaultKeyHPKEContext(
                vaultID: parent.body.vaultID,
                keyID: nextKeyID,
                authorityTransitionID: authorityTransitionID,
                recipientDeviceID: device.identity.deviceID
            )
            return try V3DeviceWrappedManifestKey(
                recipientDeviceID: device.identity.deviceID,
                wrappedKey: hpke.wrap(
                    vaultKey: nextVaultKey,
                    recipientPublicKey: device.identity.wrappingPublicKey,
                    context: context
                )
            )
        }
        let resealed = try resealEntries(
            parent.body.entries,
            currentEntries: currentEntries,
            vaultID: parent.body.vaultID,
            nextKeyID: nextKeyID,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey
        )
        let body: V3DeviceWrappedManifestBody
        do {
            body = try V3DeviceWrappedManifestBody(
                vaultID: parent.body.vaultID,
                keyID: nextKeyID,
                authorityTransitionID: authorityTransitionID,
                devices: resultingDevices,
                wrappedKeys: wrappedKeys,
                entries: resealed.map(\.manifestEntry)
            )
        } catch {
            throw V3DeviceWrappedKeyRotationError.invalidCandidate
        }

        let content = CanonicalJSONValue.object([
            ("parents", .array([.string(Base64URL.encode(
                base.checkpoint.envelopeDigest
            ))])),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: body.vaultID,
            vaultKey: nextVaultKey
        )
        let authorizationInput = V3ManifestAuthenticator.authenticationInput(
            for: canonicalContent
        )
        let signature: Data
        do {
            signature = try V3P256Signature.canonicalize(
                owner.signature(
                    for: authorizationInput,
                    reason: authorizationReason
                )
            )
        } catch {
            throw V3DeviceWrappedKeyRotationError.invalidOwner
        }
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string(Self.envelopeFormat)),
            ("version", .integer(Self.envelopeVersion)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string(Self.authenticationAlgorithm)),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([.object([
                ("algorithm", .string(Self.authorizationAlgorithm)),
                ("signerDeviceID", .string(owner.publicIdentity.deviceID)),
                ("signature", .string(Base64URL.encode(signature))),
            ])])),
        ]))
        try validateCandidate(
            manifestData,
            expectedBody: body,
            expectedParent: base.checkpoint.envelopeDigest,
            ownerIdentity: owner.publicIdentity,
            authorizationInput: authorizationInput,
            nextVaultKey: nextVaultKey
        )
        return V3DeviceWrappedKeyRotationCandidate(
            expectedCheckpoint: base.checkpoint,
            body: body,
            manifestData: manifestData,
            manifestDigest: Data(SHA256.hash(data: manifestData)),
            stagedEntries: resealed.map(\.encryptedEntry)
        )
    }

    private func validate(
        base: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey: Data,
        nextVaultKey: Data,
        authorityTransitionID: String,
        resultingDevices: [V3DeviceWrappedManifestDevice],
        owner: any V3EnrollmentMessageSigning,
        authorizationReason: String
    ) throws -> V3DeviceWrappedManifestEnvelope {
        guard base.checkpoint.vaultID == base.envelope.body.vaultID,
              base.checkpoint.envelopeDigest
                == Data(SHA256.hash(data: base.envelope.canonicalBytes)),
              let parent = try? envelopeCodec.parse(
                  base.envelope.canonicalBytes
              ),
              parent == base.envelope
        else {
            throw V3DeviceWrappedKeyRotationError.invalidTrustedCheckpoint
        }
        guard currentVaultKey.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: currentVaultKey,
                  vaultID: parent.body.vaultID
              )) == parent.body.keyID,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  parent.authenticationTag,
                  canonicalContent: parent.canonicalContentBytes,
                  vaultID: parent.body.vaultID,
                  vaultKey: currentVaultKey
              )) == true
        else {
            throw V3DeviceWrappedKeyRotationError.invalidCurrentVaultKey
        }
        guard nextVaultKey.count == 32,
              nextVaultKey != currentVaultKey,
              (try? V3VaultKeyID.derive(
                  vaultKey: nextVaultKey,
                  vaultID: parent.body.vaultID
              )) != parent.body.keyID,
              isValidV3UUID(authorityTransitionID),
              authorityTransitionID != parent.body.authorityTransitionID
        else {
            throw V3DeviceWrappedKeyRotationError.invalidNextVaultKey
        }
        guard !authorizationReason.isEmpty,
              owner.vaultID == parent.body.vaultID,
              let parentOwner = parent.body.devices.first(where: {
                  $0.identity.deviceID == owner.publicIdentity.deviceID
              }),
              parentOwner.identity == owner.publicIdentity,
              parentOwner.status == .active,
              resultingDevices.contains(where: {
                  $0.identity == owner.publicIdentity
                      && $0.status == .active
              })
        else {
            throw V3DeviceWrappedKeyRotationError.invalidOwner
        }
        return parent
    }

    private func resealEntries(
        _ manifestEntries: [V3ManifestEntry],
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        vaultID: String,
        nextKeyID: V3VaultKeyID,
        currentVaultKey: Data,
        nextVaultKey: Data
    ) throws -> [V3DeviceWrappedRotatedEntry] {
        var expected = Set<V3EntryObjectKey>()
        for entry in manifestEntries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32 else {
                throw V3DeviceWrappedKeyRotationError.invalidEntry
            }
            expected.insert(V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            ))
        }
        guard Set(currentEntries.keys) == expected else {
            throw V3DeviceWrappedKeyRotationError.incompleteEntrySnapshot
        }

        var result: [V3DeviceWrappedRotatedEntry] = []
        result.reserveCapacity(manifestEntries.count)
        for entry in manifestEntries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), let encrypted = currentEntries[V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            )] else {
                throw V3DeviceWrappedKeyRotationError
                    .incompleteEntrySnapshot
            }
            do {
                let plaintext = try entryCipher.openTrusted(
                    encrypted.canonicalBytes,
                    vaultID: vaultID,
                    manifestEntry: entry,
                    vaultKey: currentVaultKey
                )
                let resealed = try entryCipher.seal(
                    plaintext,
                    context: V3EntryAuthenticationContext(
                        vaultID: vaultID,
                        entryID: entry.entryID,
                        name: entry.name,
                        type: entry.type,
                        keyID: nextKeyID,
                        revision: entry.revision
                    ),
                    vaultKey: nextVaultKey
                )
                result.append(V3DeviceWrappedRotatedEntry(
                    manifestEntry: V3ManifestEntry(
                        entryID: entry.entryID,
                        name: entry.name,
                        type: entry.type,
                        revision: entry.revision,
                        keyID: nextKeyID,
                        ciphertextDigest: resealed.ciphertextDigest
                    ),
                    encryptedEntry: resealed
                ))
            } catch {
                throw V3DeviceWrappedKeyRotationError.invalidEntry
            }
        }
        return result.sorted {
            v3ManifestEntryPrecedes($0.manifestEntry, $1.manifestEntry)
        }
    }

    private func validateCandidate(
        _ manifestData: Data,
        expectedBody: V3DeviceWrappedManifestBody,
        expectedParent: Data,
        ownerIdentity: V3EnrollmentDeviceIdentity,
        authorizationInput: Data,
        nextVaultKey: Data
    ) throws {
        do {
            let parsed = try envelopeCodec.parse(manifestData)
            guard parsed.parents == [expectedParent],
                  parsed.body == expectedBody,
                  parsed.authorizations.count == 1,
                  parsed.authorizations[0].signerDeviceID
                    == ownerIdentity.deviceID,
                  (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                      parsed.authenticationTag,
                      canonicalContent: parsed.canonicalContentBytes,
                      vaultID: expectedBody.vaultID,
                      vaultKey: nextVaultKey
                  )) == true,
                  let signatureBytes = Base64URL.decodeCanonical(
                      parsed.authorizations[0].signature
                  ),
                  V3P256Signature.isCanonical(signatureBytes)
            else {
                throw V3DeviceWrappedKeyRotationError.invalidCandidate
            }
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: ownerIdentity.signingPublicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: signatureBytes
            )
            guard publicKey.isValidSignature(
                signature,
                for: SHA256.hash(data: authorizationInput)
            ) else {
                throw V3DeviceWrappedKeyRotationError.invalidCandidate
            }
        } catch let error as V3DeviceWrappedKeyRotationError {
            throw error
        } catch {
            throw V3DeviceWrappedKeyRotationError.invalidCandidate
        }
    }
}

private struct V3DeviceWrappedRotatedEntry: Sendable {
    let manifestEntry: V3ManifestEntry
    let encryptedEntry: V3EncryptedEntry
}
