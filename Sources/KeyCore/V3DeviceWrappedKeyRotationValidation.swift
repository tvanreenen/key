import CryptoKit
import Foundation

enum V3DeviceWrappedKeyRotationValidationError: Error, Equatable {
    case invalidTrustedCheckpoint
    case invalidCurrentVaultKey
    case invalidNextVaultKey
    case invalidTransition
    case invalidOwnerAuthorization
    case authenticationCancelled
    case localWrapperInvalid
    case invalidCurrentEntry
    case invalidStagedEntry
    case objectTooLarge
}

struct V3DeviceWrappedKeyRotationValidationInput: Sendable {
    let expectedCheckpoint: V3ManifestCheckpoint
    let body: V3DeviceWrappedManifestBody
    let manifestData: Data
    let manifestDigest: Data
    let stagedEntries: [V3EncryptedEntry]
}

extension V3DeviceWrappedEnrollmentTransitionCandidate {
    var keyRotationValidationInput:
        V3DeviceWrappedKeyRotationValidationInput
    {
        V3DeviceWrappedKeyRotationValidationInput(
            expectedCheckpoint: expectedCheckpoint,
            body: body,
            manifestData: manifestData,
            manifestDigest: manifestDigest,
            stagedEntries: stagedEntries
        )
    }
}

extension V3DeviceWrappedRevocationTransitionCandidate {
    var keyRotationValidationInput:
        V3DeviceWrappedKeyRotationValidationInput
    {
        V3DeviceWrappedKeyRotationValidationInput(
            expectedCheckpoint: plan.expectedCheckpoint,
            body: body,
            manifestData: manifestData,
            manifestDigest: manifestDigest,
            stagedEntries: stagedEntries
        )
    }
}

struct V3DeviceWrappedValidatedKeyRotation: Sendable {
    let parent: V3DeviceWrappedManifestEnvelope
    let candidate: V3DeviceWrappedManifestEnvelope
    let manifestDigest: Data
    let stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
}

/// Shared independent verification for an owner-authorized key epoch.
///
/// The transition-specific roster closure runs after both envelopes and the
/// parent-owner signature are authenticated, but before any entry plaintext is
/// opened. Enrollment and revocation therefore share the cryptographic proof
/// without weakening their distinct membership rules.
struct V3DeviceWrappedKeyRotationValidator: Sendable {
    private let limits: V3ManifestRepositoryLimits
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()

    init(limits: V3ManifestRepositoryLimits = .standard) {
        self.limits = limits
    }

    func validate(
        _ input: V3DeviceWrappedKeyRotationValidationInput,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        expectedOwner: V3EnrollmentDeviceIdentity,
        validateRoster: (
            V3DeviceWrappedManifestEnvelope,
            V3DeviceWrappedManifestEnvelope
        ) throws -> Void
    ) throws -> V3DeviceWrappedValidatedKeyRotation {
        guard input.manifestData.count <= limits.maximumManifestBytes,
              input.stagedEntries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3DeviceWrappedKeyRotationValidationError.objectTooLarge
        }
        guard input.manifestDigest.count == 32 else {
            throw V3DeviceWrappedKeyRotationValidationError.invalidTransition
        }

        let authenticatedParent = try validateParent(
            parent,
            expectedCheckpoint: input.expectedCheckpoint,
            currentVaultKey: currentVaultKey
        )
        let authenticatedCandidate = try validateCandidate(
            input,
            parent: authenticatedParent,
            nextVaultKey: nextVaultKey
        )
        try validateOwnerAuthorization(
            authenticatedCandidate,
            parent: authenticatedParent,
            expectedOwner: expectedOwner
        )
        try validateRoster(authenticatedParent, authenticatedCandidate)
        let staged = try validateEntries(
            parent: authenticatedParent,
            candidate: authenticatedCandidate,
            currentEntries: currentEntries,
            stagedEntries: input.stagedEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey
        )
        return V3DeviceWrappedValidatedKeyRotation(
            parent: authenticatedParent,
            candidate: authenticatedCandidate,
            manifestDigest: input.manifestDigest,
            stagedEntries: staged
        )
    }

    func validateLocalWrapper(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        nextVaultKey: Data,
        reason: String
    ) throws {
        let deviceID = identity.publicIdentity.deviceID
        guard !reason.isEmpty,
              identity.vaultID == candidate.body.vaultID,
              let device = candidate.body.devices.first(where: {
                  $0.identity.deviceID == deviceID
              }),
              device.identity == identity.publicIdentity,
              device.role == .owner,
              device.status == .active,
              let wrapped = candidate.body.wrappedKeys.first(where: {
                  $0.recipientDeviceID == deviceID
              }),
              let context = try? V3VaultKeyHPKEContext(
                  vaultID: candidate.body.vaultID,
                  keyID: candidate.body.keyID,
                  authorityTransitionID:
                    candidate.body.authorityTransitionID,
                  recipientDeviceID: deviceID
              )
        else {
            throw V3DeviceWrappedKeyRotationValidationError
                .localWrapperInvalid
        }
        let opened: Data
        do {
            opened = try identity.unwrapDeviceWrappedVaultKey(
                wrapped.wrappedKey,
                context: context,
                reason: reason
            )
        } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
            throw V3DeviceWrappedKeyRotationValidationError
                .authenticationCancelled
        } catch {
            throw V3DeviceWrappedKeyRotationValidationError
                .localWrapperInvalid
        }
        guard opened == nextVaultKey else {
            throw V3DeviceWrappedKeyRotationValidationError
                .localWrapperInvalid
        }
    }

    private func validateParent(
        _ parent: V3DeviceWrappedTrustedCheckpoint,
        expectedCheckpoint: V3ManifestCheckpoint,
        currentVaultKey: Data
    ) throws -> V3DeviceWrappedManifestEnvelope {
        guard parent.checkpoint == expectedCheckpoint,
              expectedCheckpoint.vaultID == parent.envelope.body.vaultID,
              expectedCheckpoint.envelopeDigest
                == Data(SHA256.hash(data: parent.envelope.canonicalBytes)),
              let reparsed = try? envelopeCodec.parse(
                  parent.envelope.canonicalBytes
              ),
              reparsed == parent.envelope
        else {
            throw V3DeviceWrappedKeyRotationValidationError
                .invalidTrustedCheckpoint
        }
        guard currentVaultKey.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: currentVaultKey,
                  vaultID: reparsed.body.vaultID
              )) == reparsed.body.keyID,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  reparsed.authenticationTag,
                  canonicalContent: reparsed.canonicalContentBytes,
                  vaultID: reparsed.body.vaultID,
                  vaultKey: currentVaultKey
              )) == true
        else {
            throw V3DeviceWrappedKeyRotationValidationError
                .invalidCurrentVaultKey
        }
        return reparsed
    }

    private func validateCandidate(
        _ input: V3DeviceWrappedKeyRotationValidationInput,
        parent: V3DeviceWrappedManifestEnvelope,
        nextVaultKey: Data
    ) throws -> V3DeviceWrappedManifestEnvelope {
        guard Data(SHA256.hash(data: input.manifestData))
                == input.manifestDigest,
              let candidate = try? envelopeCodec.parse(input.manifestData),
              candidate.body == input.body,
              candidate.parents
                == [input.expectedCheckpoint.envelopeDigest],
              candidate.body.vaultID == parent.body.vaultID
        else {
            throw V3DeviceWrappedKeyRotationValidationError.invalidTransition
        }
        guard nextVaultKey.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: nextVaultKey,
                  vaultID: candidate.body.vaultID
              )) == candidate.body.keyID,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  candidate.authenticationTag,
                  canonicalContent: candidate.canonicalContentBytes,
                  vaultID: candidate.body.vaultID,
                  vaultKey: nextVaultKey
              )) == true
        else {
            throw V3DeviceWrappedKeyRotationValidationError
                .invalidNextVaultKey
        }
        return candidate
    }

    private func validateOwnerAuthorization(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        parent: V3DeviceWrappedManifestEnvelope,
        expectedOwner: V3EnrollmentDeviceIdentity
    ) throws {
        guard candidate.authorizations.count == 1,
              let authorization = candidate.authorizations.first,
              authorization.signerDeviceID == expectedOwner.deviceID,
              let owner = parent.body.devices.first(where: {
                  $0.identity.deviceID == authorization.signerDeviceID
              }),
              owner.identity == expectedOwner,
              owner.role == .owner,
              owner.status == .active,
              let signatureBytes = Base64URL.decodeCanonical(
                  authorization.signature
              ),
              V3P256Signature.isCanonical(signatureBytes),
              let publicKey = try? P256.Signing.PublicKey(
                  x963Representation: owner.identity.signingPublicKey
              ),
              let signature = try? P256.Signing.ECDSASignature(
                  rawRepresentation: signatureBytes
              ),
              publicKey.isValidSignature(
                  signature,
                  for: SHA256.hash(data:
                      V3ManifestAuthenticator.authenticationInput(
                          for: candidate.canonicalContentBytes
                      )
                  )
              )
        else {
            throw V3DeviceWrappedKeyRotationValidationError
                .invalidOwnerAuthorization
        }
    }

    private func validateEntries(
        parent: V3DeviceWrappedManifestEnvelope,
        candidate: V3DeviceWrappedManifestEnvelope,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        stagedEntries: [V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        guard parent.body.entries.count == candidate.body.entries.count,
              parent.body.entries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3DeviceWrappedKeyRotationValidationError.objectTooLarge
        }
        let parentByID = Dictionary(uniqueKeysWithValues:
            parent.body.entries.map { ($0.entryID, $0) }
        )
        let candidateByID = Dictionary(uniqueKeysWithValues:
            candidate.body.entries.map { ($0.entryID, $0) }
        )
        guard parentByID.keys == candidateByID.keys,
              parent.body.entries.allSatisfy({ old in
                  guard let new = candidateByID[old.entryID] else {
                      return false
                  }
                  return new.name == old.name
                      && new.type == old.type
                      && new.revision == old.revision
                      && new.keyID == candidate.body.keyID
                      && new.ciphertextDigest != old.ciphertextDigest
              })
        else {
            throw V3DeviceWrappedKeyRotationValidationError.invalidTransition
        }

        let expectedCurrent = try entryMap(parent.body.entries)
        guard Set(currentEntries.keys) == Set(expectedCurrent.keys) else {
            throw V3DeviceWrappedKeyRotationValidationError
                .invalidCurrentEntry
        }
        let staged = try stagedEntryMap(stagedEntries)
        let expectedStaged = try entryMap(candidate.body.entries)
        guard Set(staged.keys) == Set(expectedStaged.keys) else {
            throw V3DeviceWrappedKeyRotationValidationError
                .invalidStagedEntry
        }

        var currentBytes = 0
        var stagedBytes = 0
        for old in parent.body.entries {
            guard let new = candidateByID[old.entryID],
                  let oldKey = try? entryObjectKey(old),
                  let newKey = try? entryObjectKey(new),
                  let current = currentEntries[oldKey],
                  let resealed = staged[newKey]
            else {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidStagedEntry
            }
            currentBytes = try boundedTotal(
                currentBytes,
                adding: current.canonicalBytes.count
            )
            stagedBytes = try boundedTotal(
                stagedBytes,
                adding: resealed.canonicalBytes.count
            )
            let oldPlaintext: Data
            do {
                oldPlaintext = try entryCipher.openPlaintextDataTrusted(
                    current.canonicalBytes,
                    vaultID: parent.body.vaultID,
                    manifestEntry: old,
                    vaultKey: currentVaultKey
                )
            } catch {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidCurrentEntry
            }
            let newPlaintext: Data
            do {
                newPlaintext = try entryCipher.openPlaintextDataTrusted(
                    resealed.canonicalBytes,
                    vaultID: candidate.body.vaultID,
                    manifestEntry: new,
                    vaultKey: nextVaultKey
                )
            } catch {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidStagedEntry
            }
            guard newPlaintext == oldPlaintext else {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidStagedEntry
            }
        }
        return staged
    }

    private func entryMap(
        _ entries: [V3ManifestEntry]
    ) throws -> [V3EntryObjectKey: V3ManifestEntry] {
        var result: [V3EntryObjectKey: V3ManifestEntry] = [:]
        for entry in entries {
            let key = try entryObjectKey(entry)
            guard result.updateValue(entry, forKey: key) == nil else {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidTransition
            }
        }
        return result
    }

    private func stagedEntryMap(
        _ entries: [V3EncryptedEntry]
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        for entry in entries {
            guard entry.canonicalBytes.count <= limits.maximumEntryBytes else {
                throw V3DeviceWrappedKeyRotationValidationError.objectTooLarge
            }
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32 else {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidStagedEntry
            }
            let key = V3EntryObjectKey(
                entryID: entry.context.entryID,
                digest: digest
            )
            guard result.updateValue(entry, forKey: key) == nil else {
                throw V3DeviceWrappedKeyRotationValidationError
                    .invalidStagedEntry
            }
        }
        return result
    }

    private func entryObjectKey(
        _ entry: V3ManifestEntry
    ) throws -> V3EntryObjectKey {
        guard let digest = Base64URL.decodeCanonical(
            entry.ciphertextDigest
        ), digest.count == 32 else {
            throw V3DeviceWrappedKeyRotationValidationError.invalidTransition
        }
        return V3EntryObjectKey(entryID: entry.entryID, digest: digest)
    }

    private func boundedTotal(
        _ total: Int,
        adding count: Int
    ) throws -> Int {
        guard count <= limits.maximumEntryBytes,
              count <= limits.maximumTotalEntryBytes - total
        else {
            throw V3DeviceWrappedKeyRotationValidationError.objectTooLarge
        }
        return total + count
    }
}
