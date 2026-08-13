import CryptoKit
import Foundation

enum V3DeviceWrappedEnrollmentAdoptionError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidCeremony
    case approvalUnavailable
    case upgradeRequired
    case ambiguousApproval
    case invalidApproval
    case identityUnavailable
    case authenticationCancelled
    case invalidWrappedKey
    case conflictingCheckpoint
    case selectionFailed

    var errorDescription: String? {
        switch self {
        case .invalidCeremony:
            "Joining this vault requires the exact enrollment comparison approved on both Macs."
        case .approvalUnavailable:
            "The approved vault state is not available from the file provider yet."
        case .upgradeRequired:
            "The approved vault state requires a newer version of Key. Upgrade this Mac before accepting the enrollment."
        case .ambiguousApproval:
            "More than one vault state matches this enrollment ceremony. Wait for synchronization to settle and try again."
        case .invalidApproval:
            "The available vault state does not authenticate the exact approved enrollment ceremony."
        case .identityUnavailable:
            "This Mac no longer has the Secure Enclave identity that created the enrollment request."
        case .authenticationCancelled:
            "Device authentication was cancelled while opening this Mac's vault-key wrapper."
        case .invalidWrappedKey:
            "The approved vault state does not contain a valid vault key for this Mac."
        case .conflictingCheckpoint:
            "This Mac already trusts a different version 3 vault state. The checkpoint was not replaced."
        case .selectionFailed:
            "The verified shared vault could not be selected on this Mac."
        }
    }
}

struct V3DeviceWrappedEnrollmentAdoptionReport: Equatable, Sendable {
    let vaultID: String
    let deviceName: String

    var rendered: String {
        [
            "Enrollment completed.",
            "This Mac (\(deviceName)) is now an active device in version 3 vault '\(vaultID)'.",
            "Its Secure Enclave identity can open only this Mac's wrapped copy of the current vault key.",
            "The raw vault key remains only in the running helper session."
        ].joined(separator: "\n") + "\n"
    }
}

protocol V3DeviceWrappedEnrollmentAdoptionServicing: Sendable {
    func adopt(
        vaultID: String,
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedEnrollmentAdoptionReport
}

/// Establishes permanent-profile first trust on the joining Mac.
///
/// Provider bytes are filtered by the exact locally compared transcript before
/// Secure Enclave use. The service then authenticates the owner transition,
/// opens only this device's wrapper, verifies the complete encrypted snapshot,
/// and selects the vault only after all device-local trust is usable.
struct V3DeviceWrappedEnrollmentAdoptionService:
    V3DeviceWrappedEnrollmentAdoptionServicing,
    Sendable
{
    typealias IdentityLoader = @Sendable (
        _ vaultID: String,
        _ reason: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)?
    typealias VaultSelector = @Sendable (_ vaultID: String) throws -> Void
    typealias RuntimeVerifier = @Sendable (
        _ vaultID: String,
        _ session: V3DeviceWrappedVaultKeySessionStore
    ) throws -> Void

    private let source: any V3ImmutableObjectReading
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let cache: any V3CheckpointManifestCaching
    private let exchange: V3EnrollmentExchangeCoordinator
    private let loadIdentity: IdentityLoader
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let selectVault: VaultSelector
    private let verifyRuntime: RuntimeVerifier
    private let limits: V3ManifestRepositoryLimits

    init(
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        exchange: V3EnrollmentExchangeCoordinator,
        loadIdentity: @escaping IdentityLoader,
        session: V3DeviceWrappedVaultKeySessionStore,
        selectVault: @escaping VaultSelector,
        verifyRuntime: @escaping RuntimeVerifier,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.source = source
        self.checkpointStore = checkpointStore
        self.cache = cache
        self.exchange = exchange
        self.loadIdentity = loadIdentity
        self.session = session
        self.selectVault = selectVault
        self.verifyRuntime = verifyRuntime
        self.limits = limits
    }

    func adopt(
        vaultID: String,
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        at unixTime: UInt64,
        operationID _: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedEnrollmentAdoptionReport {
        guard isValidV3UUID(vaultID),
              invitationDigest.count == 32,
              approvedTranscriptDigest.count == 32
        else {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidCeremony
        }
        let state = try exchange.resumeJoinerAdoption(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        guard state.role == .joiner,
              let transcript = state.transcript,
              transcript.digest == approvedTranscriptDigest,
              transcript.invitation.vaultID == vaultID,
              let signedRequest = state.signedJoinRequest
        else {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidCeremony
        }
        do {
            _ = try V3EnrollmentMessageAuthenticator().verify(
                state.signedInvitation
            )
            _ = try V3EnrollmentMessageAuthenticator().verify(signedRequest)
        } catch {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidCeremony
        }
        guard let identity = try loadIdentity(
            vaultID,
            "Use this Mac's Secure Enclave identity to join the approved vault."
        ), identity.publicIdentity == transcript.joinRequest.joiningDevice
        else {
            throw V3DeviceWrappedEnrollmentAdoptionError.identityUnavailable
        }

        let verified = try V3DeviceWrappedEnrollmentFirstTrustVerifier(
            source: source,
            limits: limits
        ).verify(
            transcript: transcript,
            identity: identity,
            reason: "Open the vault key approved for this Mac."
        )

        if state.phase != .consumed {
            _ = try exchange.markConsumed(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                transcriptDigest: approvedTranscriptDigest,
                at: unixTime
            )
        }

        try installExactCheckpoint(verified.checkpoint)
        try cache.store(verified.manifestData, for: verified.checkpoint)
        try session.install(
            verified.vaultKey,
            vaultID: vaultID,
            keyID: verified.envelope.body.keyID
        )

        var selected = false
        defer {
            if !selected {
                session.invalidate()
            }
        }
        try verifyRuntime(vaultID, session)
        try requireExactCheckpoint(verified.checkpoint)
        do {
            try selectVault(vaultID)
        } catch {
            throw V3DeviceWrappedEnrollmentAdoptionError.selectionFailed
        }
        selected = true
        return V3DeviceWrappedEnrollmentAdoptionReport(
            vaultID: vaultID,
            deviceName: identity.publicIdentity.displayName
        )
    }

    private func installExactCheckpoint(
        _ checkpoint: V3ManifestCheckpoint
    ) throws {
        if let existing = try checkpointStore.loadCheckpoint(
            vaultID: checkpoint.vaultID
        ) {
            guard existing == checkpoint.canonicalBytes else {
                throw V3DeviceWrappedEnrollmentAdoptionError
                    .conflictingCheckpoint
            }
            return
        }
        do {
            try checkpointStore.replaceCheckpoint(
                checkpoint.canonicalBytes,
                expectedCheckpoint: nil,
                vaultID: checkpoint.vaultID
            )
        } catch {
            guard try checkpointStore.loadCheckpoint(
                vaultID: checkpoint.vaultID
            ) == checkpoint.canonicalBytes else {
                throw V3DeviceWrappedEnrollmentAdoptionError
                    .conflictingCheckpoint
            }
        }
    }

    private func requireExactCheckpoint(
        _ checkpoint: V3ManifestCheckpoint
    ) throws {
        guard try checkpointStore.loadCheckpoint(vaultID: checkpoint.vaultID)
                == checkpoint.canonicalBytes
        else {
            throw V3DeviceWrappedEnrollmentAdoptionError
                .conflictingCheckpoint
        }
    }
}

private struct V3DeviceWrappedEnrollmentFirstTrust: Sendable {
    let checkpoint: V3ManifestCheckpoint
    let manifestData: Data
    let envelope: V3DeviceWrappedManifestEnvelope
    let vaultKey: Data
}

/// Pure first-trust verification. It performs no local trust writes and keeps
/// the recovered key scoped to the returned value.
private struct V3DeviceWrappedEnrollmentFirstTrustVerifier: Sendable {
    let source: any V3ImmutableObjectReading
    let limits: V3ManifestRepositoryLimits
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()

    func verify(
        transcript: V3EnrollmentTranscript,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        reason: String
    ) throws -> V3DeviceWrappedEnrollmentFirstTrust {
        guard identity.vaultID == transcript.invitation.vaultID,
              identity.publicIdentity == transcript.joinRequest.joiningDevice
        else {
            throw V3DeviceWrappedEnrollmentAdoptionError.identityUnavailable
        }
        let candidates = try matchingCandidates(transcript: transcript)
        guard candidates.count == 1, let candidate = candidates.first else {
            throw candidates.isEmpty
                ? V3DeviceWrappedEnrollmentAdoptionError.approvalUnavailable
                : V3DeviceWrappedEnrollmentAdoptionError.ambiguousApproval
        }
        let parent = try loadParent(transcript: transcript)
        try validateTransition(
            from: parent,
            to: candidate.envelope,
            transcript: transcript
        )

        let checkpoint = try V3ManifestCheckpoint(
            vaultID: transcript.invitation.vaultID,
            envelopeDigest: candidate.digest
        )
        let validationSession = V3DeviceWrappedVaultKeySessionStore()
        defer { validationSession.invalidate() }
        do {
            _ = try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: checkpoint,
                manifestData: candidate.data,
                identity: identity,
                session: validationSession,
                reason: reason
            )
        } catch V3DeviceWrappedUnlockError.authenticationCancelled {
            throw V3DeviceWrappedEnrollmentAdoptionError
                .authenticationCancelled
        } catch {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidWrappedKey
        }
        let vaultKey: Data
        do {
            vaultKey = try validationSession.load(
                vaultID: checkpoint.vaultID,
                keyID: candidate.envelope.body.keyID
            )
        } catch {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidWrappedKey
        }
        try validateEntries(
            candidate.envelope,
            checkpoint: checkpoint,
            vaultKey: vaultKey
        )
        return V3DeviceWrappedEnrollmentFirstTrust(
            checkpoint: checkpoint,
            manifestData: candidate.data,
            envelope: candidate.envelope,
            vaultKey: vaultKey
        )
    }

    private func matchingCandidates(
        transcript: V3EnrollmentTranscript
    ) throws -> [Candidate] {
        let digests: [Data]
        switch try source.manifestDigests(
            maximumCount: limits.maximumManifestObjects
        ) {
        case let .available(available, _):
            digests = available
        case .unavailable:
            throw V3DeviceWrappedEnrollmentAdoptionError.approvalUnavailable
        case .invalid, .limitExceeded:
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
        }

        var candidates: [Candidate] = []
        var totalBytes = 0
        var sawUnsupportedVersion = false
        for digest in digests {
            let result = try source.readManifest(
                digest: digest,
                maximumBytes: limits.maximumManifestBytes
            )
            guard case let .available(data) = result else { continue }
            guard data.count <= limits.maximumTotalManifestBytes - totalBytes
            else {
                throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
            }
            totalBytes += data.count
            guard Data(SHA256.hash(data: data)) == digest else {
                continue
            }
            let envelope: V3DeviceWrappedManifestEnvelope
            do {
                envelope = try envelopeCodec.parse(data)
            } catch V3DeviceWrappedUnlockError.unsupportedEnvelopeVersion,
                    V3DeviceWrappedUnlockError.unsupportedProfileVersion {
                sawUnsupportedVersion = true
                continue
            } catch {
                continue
            }
            guard superficiallyMatches(
                      envelope,
                      transcript: transcript
                  ),
                  validOwnerSignature(envelope, transcript: transcript)
            else {
                continue
            }
            candidates.append(Candidate(
                digest: digest,
                data: data,
                envelope: envelope
            ))
            if candidates.count > 1 { break }
        }
        if candidates.isEmpty, sawUnsupportedVersion {
            throw V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired
        }
        return candidates
    }

    private func superficiallyMatches(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        transcript: V3EnrollmentTranscript
    ) -> Bool {
        let owner = transcript.invitation.invitingDevice
        let joiner = transcript.joinRequest.joiningDevice
        return candidate.parents
                == [transcript.invitation.parentManifestDigest]
            && candidate.body.vaultID == transcript.invitation.vaultID
            && candidate.body.devices.contains(where: {
                $0.identity == owner && $0.status == .active
            })
            && candidate.body.devices.contains(where: {
                $0.identity == joiner && $0.status == .active
            })
            && candidate.body.wrappedKeys.filter({
                $0.recipientDeviceID == joiner.deviceID
            }).count == 1
            && candidate.authorizations.count == 1
            && candidate.authorizations[0].signerDeviceID == owner.deviceID
    }

    private func validOwnerSignature(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        transcript: V3EnrollmentTranscript
    ) -> Bool {
        guard let authorization = candidate.authorizations.first,
              let signatureBytes = Base64URL.decodeCanonical(
                  authorization.signature
              ),
              V3P256Signature.isCanonical(signatureBytes),
              let publicKey = try? P256.Signing.PublicKey(
                  x963Representation:
                    transcript.invitation.invitingDevice.signingPublicKey
              ),
              let signature = try? P256.Signing.ECDSASignature(
                  rawRepresentation: signatureBytes
              )
        else {
            return false
        }
        return publicKey.isValidSignature(
            signature,
            for: SHA256.hash(data:
                V3ManifestAuthenticator.authenticationInput(
                    for: candidate.canonicalContentBytes
                )
            )
        )
    }

    private func loadParent(
        transcript: V3EnrollmentTranscript
    ) throws -> V3DeviceWrappedManifestEnvelope {
        let digest = transcript.invitation.parentManifestDigest
        switch try source.readManifest(
            digest: digest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case let .available(data):
            guard Data(SHA256.hash(data: data)) == digest else {
                throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
            }
            let parent: V3DeviceWrappedManifestEnvelope
            do {
                parent = try envelopeCodec.parse(data)
            } catch V3DeviceWrappedUnlockError.unsupportedEnvelopeVersion,
                    V3DeviceWrappedUnlockError.unsupportedProfileVersion {
                throw V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired
            } catch {
                throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
            }
            guard parent.body.vaultID == transcript.invitation.vaultID else {
                throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
            }
            return parent
        case .unavailable:
            throw V3DeviceWrappedEnrollmentAdoptionError.approvalUnavailable
        case .invalid, .tooLarge:
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
        }
    }

    private func validateTransition(
        from parent: V3DeviceWrappedManifestEnvelope,
        to candidate: V3DeviceWrappedManifestEnvelope,
        transcript: V3EnrollmentTranscript
    ) throws {
        let owner = transcript.invitation.invitingDevice
        let joiner = transcript.joinRequest.joiningDevice
        let parentByID = Dictionary(uniqueKeysWithValues:
            parent.body.devices.map { ($0.identity.deviceID, $0) }
        )
        let additions = candidate.body.devices.filter {
            parentByID[$0.identity.deviceID] == nil
        }
        let parentEntries = parent.body.entries.map {
            EntryIdentity(
                entryID: $0.entryID,
                name: $0.name,
                type: $0.type,
                revision: $0.revision
            )
        }
        let candidateEntries = candidate.body.entries.map {
            EntryIdentity(
                entryID: $0.entryID,
                name: $0.name,
                type: $0.type,
                revision: $0.revision
            )
        }
        guard parent.parents.count <= 1,
              candidate.body.authorityTransitionID
                == (try? v3EnrollmentAuthorityTransitionID(
                    transcriptDigest: transcript.digest
                )),
              parent.body.keyID != candidate.body.keyID,
              parent.body.authorityTransitionID
                != candidate.body.authorityTransitionID,
              parent.body.devices.contains(where: {
                  $0.identity == owner && $0.status == .active
              }),
              candidate.body.devices.count == parent.body.devices.count + 1,
              additions.count == 1,
              additions[0].identity == joiner,
              additions[0].status == .active,
              parent.body.devices.allSatisfy({ device in
                  candidate.body.devices.first(where: {
                      $0.identity.deviceID == device.identity.deviceID
                  }) == device
              }),
              parentEntries == candidateEntries
        else {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
        }
    }

    private func validateEntries(
        _ envelope: V3DeviceWrappedManifestEnvelope,
        checkpoint: V3ManifestCheckpoint,
        vaultKey: Data
    ) throws {
        let trusted = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: checkpoint,
            envelope: envelope
        )
        let entries: [V3EntryObjectKey: V3EncryptedEntry]
        do {
            entries = try V3DeviceWrappedEntrySnapshotLoader(
                source: source,
                limits: limits
            ).load(trusted)
        } catch let error as V3ImmutableTransactionError {
            switch error {
            case .referencedEntryUnavailable:
                throw V3DeviceWrappedEnrollmentAdoptionError
                    .approvalUnavailable
            default:
                throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
            }
        } catch {
            throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
        }
        for entry in envelope.body.entries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), let encrypted = entries[V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            )], (try? entryCipher.openTrusted(
                encrypted.canonicalBytes,
                vaultID: checkpoint.vaultID,
                manifestEntry: entry,
                vaultKey: vaultKey
            )) != nil
            else {
                throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
            }
        }
    }

    private struct Candidate: Sendable {
        let digest: Data
        let data: Data
        let envelope: V3DeviceWrappedManifestEnvelope
    }

    private struct EntryIdentity: Equatable {
        let entryID: String
        let name: String
        let type: SecretEntryType
        let revision: UInt64
    }
}
