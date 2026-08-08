import CryptoKit
import Foundation

enum V3DeviceWrappedEnrollmentValidationError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidTrustedCheckpoint
    case invalidCurrentVaultKey
    case invalidNextVaultKey
    case invalidCeremony
    case invalidTransition
    case invalidOwnerAuthorization
    case authenticationCancelled
    case localWrapperInvalid
    case invalidCurrentEntry
    case invalidStagedEntry
    case objectTooLarge

    var errorDescription: String? {
        switch self {
        case .invalidTrustedCheckpoint:
            "The enrollment transition does not extend the exact authenticated checkpoint."
        case .invalidCurrentVaultKey:
            "The current vault key does not authenticate the enrollment parent."
        case .invalidNextVaultKey:
            "The rotated vault key does not authenticate the enrollment candidate."
        case .invalidCeremony:
            "The enrollment transition does not match the exact compared device ceremony."
        case .invalidTransition:
            "The enrollment candidate is not one exact key-rotating roster addition."
        case .invalidOwnerAuthorization:
            "The enrollment transition lacks a valid active-owner authorization."
        case .authenticationCancelled:
            "Device authentication was cancelled while checking the new local vault-key wrapper."
        case .localWrapperInvalid:
            "The inviting device cannot open its new vault-key wrapper."
        case .invalidCurrentEntry:
            "A current entry does not match the authenticated parent snapshot."
        case .invalidStagedEntry:
            "A re-encrypted entry does not match the complete enrollment snapshot."
        case .objectTooLarge:
            "The enrollment transition exceeds a repository resource limit."
        }
    }
}

struct V3DeviceWrappedValidatedEnrollmentTransition: Sendable {
    let parent: V3DeviceWrappedManifestEnvelope
    let candidate: V3DeviceWrappedManifestEnvelope
    let manifestDigest: Data
    let stagedEntries: [V3EntryObjectKey: V3EncryptedEntry]
}

/// Independently verifies an unpublished permanent-profile roster addition.
///
/// The builder is not an authority boundary. Initial publication uses this
/// validator to prove that the exact checkpoint moves to one owner-approved
/// key epoch containing the same complete plaintext snapshot and exactly one
/// additional active device. Durable recovery can reuse the structural proof
/// only after the exact candidate was anchored while the ceremony was valid.
struct V3DeviceWrappedEnrollmentTransitionValidator: Sendable {
    private let limits: V3ManifestRepositoryLimits
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()
    private let messageAuthenticator = V3EnrollmentMessageAuthenticator()

    init(limits: V3ManifestRepositoryLimits = .standard) {
        self.limits = limits
    }

    func validate(
        _ transition: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        state: V3EnrollmentCeremonyState,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        at unixTime: UInt64,
        unwrapReason: String
    ) throws -> V3DeviceWrappedValidatedEnrollmentTransition {
        let transcript = try validateCeremony(
            state,
            transition: transition,
            parent: parent.envelope,
            localIdentity: localIdentity,
            at: unixTime
        )
        let validated = try validateAnchored(
            transition,
            parent: parent,
            currentEntries: currentEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            expectedOwner: transcript.invitation.invitingDevice,
            expectedAddition: (
                transcript.joinRequest.joiningDevice,
                transcript.invitation.invitedRole
            )
        )
        try validateLocalWrapper(
            validated.candidate,
            identity: localIdentity,
            nextVaultKey: nextVaultKey,
            reason: unwrapReason
        )
        return validated
    }

    /// Revalidates an exact candidate selected by a device-local recovery
    /// anchor. The anchor is created only after `validate` succeeds, so this
    /// path deliberately proves the immutable transition without reopening an
    /// expired ceremony or trusting synchronized transaction metadata.
    func validateAnchored(
        _ transition: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        expectedOwner: V3EnrollmentDeviceIdentity
    ) throws -> V3DeviceWrappedValidatedEnrollmentTransition {
        try validateAnchored(
            transition,
            parent: parent,
            currentEntries: currentEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            expectedOwner: expectedOwner,
            expectedAddition: nil
        )
    }

    private func validateAnchored(
        _ transition: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        currentVaultKey: Data,
        nextVaultKey: Data,
        expectedOwner: V3EnrollmentDeviceIdentity,
        expectedAddition: (
            identity: V3EnrollmentDeviceIdentity,
            role: V3DeviceRole
        )?
    ) throws -> V3DeviceWrappedValidatedEnrollmentTransition {
        guard transition.manifestData.count <= limits.maximumManifestBytes,
              transition.stagedEntries.count
                <= limits.maximumReferencedEntryObjects
        else {
            throw V3DeviceWrappedEnrollmentValidationError.objectTooLarge
        }
        guard transition.manifestDigest.count == 32 else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }

        let authenticatedParent = try validateParent(
            parent,
            expectedCheckpoint: transition.expectedCheckpoint,
            currentVaultKey: currentVaultKey
        )
        let authenticatedCandidate = try validateCandidate(
            transition,
            parent: authenticatedParent,
            nextVaultKey: nextVaultKey
        )
        try validateRosterTransition(
            from: authenticatedParent,
            to: authenticatedCandidate,
            expectedAddition: expectedAddition
        )
        try validateOwnerAuthorization(
            authenticatedCandidate,
            parent: authenticatedParent,
            expectedOwner: expectedOwner
        )
        let staged = try validateEntries(
            parent: authenticatedParent,
            candidate: authenticatedCandidate,
            currentEntries: currentEntries,
            stagedEntries: transition.stagedEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey
        )
        return V3DeviceWrappedValidatedEnrollmentTransition(
            parent: authenticatedParent,
            candidate: authenticatedCandidate,
            manifestDigest: transition.manifestDigest,
            stagedEntries: staged
        )
    }

    private func validateCeremony(
        _ state: V3EnrollmentCeremonyState,
        transition: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedManifestEnvelope,
        localIdentity: any V3DeviceWrappedVaultKeyUnwrapping,
        at unixTime: UInt64
    ) throws -> V3EnrollmentTranscript {
        guard transition.transcriptDigest.count == 32,
              state.role == .inviter,
              state.phase == .awaitingComparison,
              let signedJoinRequest = state.signedJoinRequest,
              let transcript = state.transcript,
              transcript.digest == transition.transcriptDigest,
              transcript.invitation.vaultID == parent.body.vaultID,
              transcript.invitation.parentManifestDigest
                == transition.expectedCheckpoint.envelopeDigest,
              localIdentity.vaultID == parent.body.vaultID,
              localIdentity.publicIdentity
                == transcript.invitation.invitingDevice
        else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidCeremony
        }
        do {
            _ = try messageAuthenticator.verify(state.signedInvitation)
            _ = try messageAuthenticator.verify(signedJoinRequest)
            try transcript.invitation.requireUnexpired(at: unixTime)
        } catch {
            throw V3DeviceWrappedEnrollmentValidationError.invalidCeremony
        }
        return transcript
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
            throw V3DeviceWrappedEnrollmentValidationError
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
            throw V3DeviceWrappedEnrollmentValidationError
                .invalidCurrentVaultKey
        }
        return reparsed
    }

    private func validateCandidate(
        _ transition: V3DeviceWrappedEnrollmentTransitionCandidate,
        parent: V3DeviceWrappedManifestEnvelope,
        nextVaultKey: Data
    ) throws -> V3DeviceWrappedManifestEnvelope {
        guard Data(SHA256.hash(data: transition.manifestData))
                == transition.manifestDigest,
              let candidate = try? envelopeCodec.parse(
                  transition.manifestData
              ),
              candidate.body == transition.body,
              candidate.parents
                == [transition.expectedCheckpoint.envelopeDigest],
              candidate.body.vaultID == parent.body.vaultID
        else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
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
            throw V3DeviceWrappedEnrollmentValidationError
                .invalidNextVaultKey
        }
        return candidate
    }

    private func validateRosterTransition(
        from parent: V3DeviceWrappedManifestEnvelope,
        to candidate: V3DeviceWrappedManifestEnvelope,
        expectedAddition: (
            identity: V3EnrollmentDeviceIdentity,
            role: V3DeviceRole
        )?
    ) throws {
        let parentBody = parent.body
        let candidateBody = candidate.body
        let parentByID = Dictionary(uniqueKeysWithValues:
            parentBody.devices.map { ($0.identity.deviceID, $0) }
        )
        let added = candidateBody.devices.filter {
            parentByID[$0.identity.deviceID] == nil
        }
        guard candidateBody.keyID != parentBody.keyID,
              candidateBody.authorityTransitionID
                != parentBody.authorityTransitionID,
              candidateBody.devices.count == parentBody.devices.count + 1,
              added.count == 1,
              added[0].status == .active,
              expectedAddition.map({ added[0].identity == $0.identity })
                ?? true,
              expectedAddition.map({ added[0].role == $0.role }) ?? true,
              parentBody.devices.allSatisfy({ device in
                  candidateBody.devices.first(where: {
                      $0.identity.deviceID == device.identity.deviceID
                  }) == device
              })
        else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }
    }

    private func validateOwnerAuthorization(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        parent: V3DeviceWrappedManifestEnvelope,
        expectedOwner: V3EnrollmentDeviceIdentity
    ) throws {
        guard candidate.authorizations.count == 1,
              let authorization = candidate.authorizations.first,
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
            throw V3DeviceWrappedEnrollmentValidationError
                .invalidOwnerAuthorization
        }
    }

    private func validateLocalWrapper(
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
            throw V3DeviceWrappedEnrollmentValidationError
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
            throw V3DeviceWrappedEnrollmentValidationError
                .authenticationCancelled
        } catch {
            throw V3DeviceWrappedEnrollmentValidationError
                .localWrapperInvalid
        }
        guard opened == nextVaultKey else {
            throw V3DeviceWrappedEnrollmentValidationError
                .localWrapperInvalid
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
            throw V3DeviceWrappedEnrollmentValidationError.objectTooLarge
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
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }

        let expectedCurrent = try entryMap(parent.body.entries)
        guard Set(currentEntries.keys) == Set(expectedCurrent.keys) else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidCurrentEntry
        }
        let staged = try stagedEntryMap(stagedEntries)
        let expectedStaged = try entryMap(candidate.body.entries)
        guard Set(staged.keys) == Set(expectedStaged.keys) else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidStagedEntry
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
                throw V3DeviceWrappedEnrollmentValidationError
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
                throw V3DeviceWrappedEnrollmentValidationError
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
                throw V3DeviceWrappedEnrollmentValidationError
                    .invalidStagedEntry
            }
            guard newPlaintext == oldPlaintext else {
                throw V3DeviceWrappedEnrollmentValidationError
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
                throw V3DeviceWrappedEnrollmentValidationError
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
                throw V3DeviceWrappedEnrollmentValidationError.objectTooLarge
            }
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32 else {
                throw V3DeviceWrappedEnrollmentValidationError
                    .invalidStagedEntry
            }
            let key = V3EntryObjectKey(
                entryID: entry.context.entryID,
                digest: digest
            )
            guard result.updateValue(entry, forKey: key) == nil else {
                throw V3DeviceWrappedEnrollmentValidationError
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
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
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
            throw V3DeviceWrappedEnrollmentValidationError.objectTooLarge
        }
        return total + count
    }
}
