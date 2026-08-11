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

/// An untrusted candidate whose exact parent, roster shape, and active-owner
/// signature have been verified before invoking a local key wrapper.
///
/// This is authority to attempt the addressed unwrap, not authority to advance
/// the checkpoint. The candidate HMAC and complete resealed entry snapshot
/// still require validation with the recovered key.
struct V3DeviceWrappedOwnerAuthorizedEnrollmentTransition:
    Equatable,
    Sendable
{
    let candidate: V3DeviceWrappedManifestEnvelope
    let manifestDigest: Data
    let authorizingOwner: V3EnrollmentDeviceIdentity
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
    private let keyRotationValidator: V3DeviceWrappedKeyRotationValidator
    private let messageAuthenticator = V3EnrollmentMessageAuthenticator()

    init(limits: V3ManifestRepositoryLimits = .standard) {
        self.limits = limits
        keyRotationValidator = V3DeviceWrappedKeyRotationValidator(
            limits: limits
        )
    }

    /// Proves that one provider-supplied enrollment candidate is an exact,
    /// owner-authorized child of the authenticated parent before catch-up asks
    /// the Secure Enclave to open this device's addressed wrapper.
    ///
    /// The returned candidate remains untrusted until `validateAnchored`
    /// authenticates it with the opened next key and compares every resealed
    /// entry with the parent snapshot.
    func preflightOwnerAuthorizedCandidate(
        manifestData: Data,
        manifestDigest: Data,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey: Data
    ) throws -> V3DeviceWrappedOwnerAuthorizedEnrollmentTransition {
        guard manifestData.count <= limits.maximumManifestBytes,
              manifestDigest.count == 32,
              Data(SHA256.hash(data: manifestData)) == manifestDigest
        else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }
        let authenticatedParent = try validateParent(
            parent,
            expectedCheckpoint: parent.checkpoint,
            currentVaultKey: currentVaultKey
        )
        let candidate: V3DeviceWrappedManifestEnvelope
        do {
            candidate = try envelopeCodec.parse(manifestData)
        } catch let error as V3DeviceWrappedUnlockError {
            switch error {
            case .unsupportedEnvelopeVersion,
                    .unsupportedProfileVersion:
                throw error
            case .invalidManifest, .checkpointMismatch,
                    .deviceIdentityMismatch, .deviceNotEnrolled,
                    .deviceRevoked, .wrapperMissing,
                    .authenticationCancelled, .keyUnwrapFailed,
                    .authenticationFailed:
                throw V3DeviceWrappedEnrollmentValidationError
                    .invalidTransition
            }
        } catch {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }
        guard candidate.parents == [parent.checkpoint.envelopeDigest],
              candidate.body.vaultID == authenticatedParent.body.vaultID
        else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }
        try validateRosterTransition(
            from: authenticatedParent,
            to: candidate,
            expectedAddition: nil
        )
        let owner = try authorizingOwner(
            of: candidate,
            parent: authenticatedParent
        )
        return V3DeviceWrappedOwnerAuthorizedEnrollmentTransition(
            candidate: candidate,
            manifestDigest: manifestDigest,
            authorizingOwner: owner
        )
    }

    /// Authenticates the supported outer envelope of a direct child whose
    /// manifest-body profile is newer than this client understands.
    ///
    /// A valid active-owner signature is enough to require an upgrade before
    /// this client publishes a competing child. It is not authority to open or
    /// advance to the unknown profile.
    func isOwnerAuthorizedDirectChildEnvelope(
        manifestData: Data,
        manifestDigest: Data,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey: Data
    ) throws -> Bool {
        guard manifestData.count <= limits.maximumManifestBytes,
              manifestDigest.count == 32,
              Data(SHA256.hash(data: manifestData)) == manifestDigest
        else {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }
        let authenticatedParent = try validateParent(
            parent,
            expectedCheckpoint: parent.checkpoint,
            currentVaultKey: currentVaultKey
        )
        let metadata: V3DeviceWrappedManifestEnvelopeMetadata
        do {
            metadata = try envelopeCodec.metadata(manifestData)
        } catch {
            throw V3DeviceWrappedEnrollmentValidationError.invalidTransition
        }
        guard metadata.parents == [parent.checkpoint.envelopeDigest] else {
            return false
        }
        _ = try authorizingOwner(
            authorizations: metadata.authorizations,
            canonicalContentBytes: metadata.canonicalContentBytes,
            parent: authenticatedParent
        )
        return true
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
        do {
            try keyRotationValidator.validateLocalWrapper(
                validated.candidate,
                identity: localIdentity,
                nextVaultKey: nextVaultKey,
                reason: unwrapReason
            )
        } catch let error as V3DeviceWrappedKeyRotationValidationError {
            throw enrollmentError(for: error)
        }
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
        let rotation: V3DeviceWrappedValidatedKeyRotation
        do {
            rotation = try keyRotationValidator.validate(
                transition.keyRotationValidationInput,
                parent: parent,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                expectedOwner: expectedOwner
            ) { authenticatedParent, authenticatedCandidate in
                try validateRosterTransition(
                    from: authenticatedParent,
                    to: authenticatedCandidate,
                    expectedAddition: expectedAddition
                )
            }
        } catch let error as V3DeviceWrappedKeyRotationValidationError {
            throw enrollmentError(for: error)
        }
        return V3DeviceWrappedValidatedEnrollmentTransition(
            parent: rotation.parent,
            candidate: rotation.candidate,
            manifestDigest: rotation.manifestDigest,
            stagedEntries: rotation.stagedEntries
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

    private func authorizingOwner(
        of candidate: V3DeviceWrappedManifestEnvelope,
        parent: V3DeviceWrappedManifestEnvelope
    ) throws -> V3EnrollmentDeviceIdentity {
        try authorizingOwner(
            authorizations: candidate.authorizations,
            canonicalContentBytes: candidate.canonicalContentBytes,
            parent: parent
        )
    }

    private func authorizingOwner(
        authorizations: [V3ManifestAuthorization],
        canonicalContentBytes: Data,
        parent: V3DeviceWrappedManifestEnvelope
    ) throws -> V3EnrollmentDeviceIdentity {
        guard authorizations.count == 1,
              let authorization = authorizations.first,
              let owner = parent.body.devices.first(where: {
                  $0.identity.deviceID == authorization.signerDeviceID
              }),
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
                          for: canonicalContentBytes
                      )
                  )
              )
        else {
            throw V3DeviceWrappedEnrollmentValidationError
                .invalidOwnerAuthorization
        }
        return owner.identity
    }

    private func enrollmentError(
        for error: V3DeviceWrappedKeyRotationValidationError
    ) -> V3DeviceWrappedEnrollmentValidationError {
        switch error {
        case .invalidTrustedCheckpoint:
            .invalidTrustedCheckpoint
        case .invalidCurrentVaultKey:
            .invalidCurrentVaultKey
        case .invalidNextVaultKey:
            .invalidNextVaultKey
        case .invalidTransition:
            .invalidTransition
        case .invalidOwnerAuthorization:
            .invalidOwnerAuthorization
        case .authenticationCancelled:
            .authenticationCancelled
        case .localWrapperInvalid:
            .localWrapperInvalid
        case .invalidCurrentEntry:
            .invalidCurrentEntry
        case .invalidStagedEntry:
            .invalidStagedEntry
        case .objectTooLarge:
            .objectTooLarge
        }
    }
}
