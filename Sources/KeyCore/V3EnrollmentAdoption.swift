import CryptoKit
import Foundation

enum V3EnrollmentAdoptionError: Error, Equatable, LocalizedError {
    case invalidCeremony
    case approvalUnavailable
    case ambiguousApproval
    case invalidApproval
    case identityUnavailable
    case invalidWrappedKey
    case conflictingVaultKey
    case conflictingCheckpoint
    case selectionFailed

    var errorDescription: String? {
        switch self {
        case .invalidCeremony:
            "Joining this vault requires the exact enrollment comparison that was approved on both devices."
        case .approvalUnavailable:
            "The approved shared vault state is not available from the file provider yet."
        case .ambiguousApproval:
            "More than one shared vault state matches this enrollment ceremony. Wait for synchronization to settle and try again."
        case .invalidApproval:
            "The shared vault state does not authenticate the exact approved enrollment ceremony."
        case .identityUnavailable:
            "This Mac no longer has the Secure Enclave identity that created the enrollment request."
        case .invalidWrappedKey:
            "The approved shared vault does not contain a valid vault key for this Mac."
        case .conflictingVaultKey:
            "This Mac already stores a different vault key. The existing key was not replaced."
        case .conflictingCheckpoint:
            "This Mac already trusts a different version 3 vault state. The checkpoint was not replaced."
        case .selectionFailed:
            "The verified shared vault could not be selected on this Mac."
        }
    }
}

struct V3EnrollmentAdoptionReport: Equatable, Sendable {
    let vaultID: String
    let deviceName: String
    let role: V3DeviceRole

    var rendered: String {
        [
            "Enrollment completed.",
            "This Mac (\(deviceName)) is now an active \(role.rawValue) of version 3 vault '\(vaultID)'.",
            "The approved vault key is stored locally and the exact shared manifest is trusted on this Mac.",
            "Ordinary version 3 vault commands are now available on this Mac."
        ].joined(separator: "\n") + "\n"
    }
}

enum V3EnrollmentAdoptionPhase: Equatable, Sendable {
    case approvalVerified
    case ceremonyConsumed
    case vaultKeyInstalled
    case checkpointInstalled
    case runtimeVerified
}

protocol V3EnrollmentAdoptionPhaseObserving: Sendable {
    func didReach(
        _ phase: V3EnrollmentAdoptionPhase,
        operationID: VaultTransactionOperationID
    ) throws
}

private struct V3NoopEnrollmentAdoptionPhaseObserver:
    V3EnrollmentAdoptionPhaseObserving
{
    func didReach(
        _: V3EnrollmentAdoptionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

protocol V3EnrollmentAdoptionServicing {
    func adopt(
        vaultID: String,
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> V3EnrollmentAdoptionReport
}

/// Establishes first trust on the joining device without trusting provider
/// metadata or selecting partially installed state.
///
/// Every durable local step is insert-only or exact-idempotent. The selected
/// `vault_id` remains the final commit point, so a crash before selection keeps
/// the shipping version 2 runtime authoritative and a retry can only finish
/// the same authenticated ceremony.
struct V3EnrollmentAdoptionService: V3EnrollmentAdoptionServicing {
    typealias VaultSelector = (_ vaultID: String) throws -> Void
    typealias RuntimeVerifier = (_ vaultID: String) throws -> Void

    private let source: any V3ImmutableObjectReading
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let exchange: V3EnrollmentExchangeCoordinator
    private let identityManager: V3EnrollmentDeviceIdentityManager
    private let vaultKeyStore: any VaultKeyStoring
    private let keychainMode: KeychainMode
    private let selectVault: VaultSelector
    private let verifyRuntime: RuntimeVerifier
    private let limits: V3ManifestRepositoryLimits
    private let phaseObserver: any V3EnrollmentAdoptionPhaseObserving

    init(
        source: any V3ImmutableObjectReading,
        checkpointStore: any V3ManifestCheckpointStoring,
        exchange: V3EnrollmentExchangeCoordinator,
        identityManager: V3EnrollmentDeviceIdentityManager,
        vaultKeyStore: any VaultKeyStoring,
        keychainMode: KeychainMode,
        selectVault: @escaping VaultSelector,
        verifyRuntime: @escaping RuntimeVerifier,
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3EnrollmentAdoptionPhaseObserving =
            V3NoopEnrollmentAdoptionPhaseObserver()
    ) {
        self.source = source
        self.checkpointStore = checkpointStore
        self.exchange = exchange
        self.identityManager = identityManager
        self.vaultKeyStore = vaultKeyStore
        self.keychainMode = keychainMode
        self.selectVault = selectVault
        self.verifyRuntime = verifyRuntime
        self.limits = limits
        self.phaseObserver = phaseObserver
    }

    func adopt(
        vaultID: String,
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> V3EnrollmentAdoptionReport {
        guard approvedTranscriptDigest.count == 32 else {
            throw V3EnrollmentAdoptionError.invalidCeremony
        }
        let state = try exchange.resumeJoinerAdoption(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        guard let transcript = state.transcript,
            transcript.digest == approvedTranscriptDigest,
            let signedJoinRequest = state.signedJoinRequest
        else {
            throw V3EnrollmentAdoptionError.invalidCeremony
        }
        let messageAuthenticator = V3EnrollmentMessageAuthenticator()
        _ = try messageAuthenticator.verify(state.signedInvitation)
        _ = try messageAuthenticator.verify(signedJoinRequest)

        guard let identity = try identityManager.loadIdentity(
            vaultID: vaultID,
            reason: "Use this Mac's Secure Enclave identity to join the approved vault."
        ), identity.publicIdentity == transcript.joinRequest.joiningDevice
        else {
            throw V3EnrollmentAdoptionError.identityUnavailable
        }

        let firstTrust = try V3EnrollmentFirstTrustVerifier(
            source: source,
            limits: limits
        ).verify(
            transcript: transcript,
            identity: identity,
            reason: "Unlock the vault key approved for this Mac."
        )
        try phaseObserver.didReach(
            .approvalVerified,
            operationID: operationID
        )

        if state.phase != .consumed {
            _ = try exchange.markConsumed(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                transcriptDigest: approvedTranscriptDigest,
                at: unixTime
            )
        }
        try phaseObserver.didReach(
            .ceremonyConsumed,
            operationID: operationID
        )

        try installExactVaultKey(firstTrust.vaultKey)
        try phaseObserver.didReach(
            .vaultKeyInstalled,
            operationID: operationID
        )

        let checkpoint = try V3ManifestCheckpoint(
            verifiedManifest: firstTrust.manifest
        )
        try installExactCheckpoint(checkpoint, vaultID: vaultID)
        try phaseObserver.didReach(
            .checkpointInstalled,
            operationID: operationID
        )

        try verifyRuntime(vaultID)
        try phaseObserver.didReach(
            .runtimeVerified,
            operationID: operationID
        )
        do {
            try selectVault(vaultID)
        } catch {
            throw V3EnrollmentAdoptionError.selectionFailed
        }

        return V3EnrollmentAdoptionReport(
            vaultID: vaultID,
            deviceName: identity.publicIdentity.displayName,
            role: .member
        )
    }

    private func installExactVaultKey(_ vaultKey: Data) throws {
        if try vaultKeyStore.keyExists(mode: keychainMode) {
            let existing = try vaultKeyStore.loadKey(
                mode: keychainMode,
                reason: "Confirm the vault key already stored on this Mac.",
                createIfMissing: false
            )
            guard existing == vaultKey else {
                throw V3EnrollmentAdoptionError.conflictingVaultKey
            }
            return
        }
        try vaultKeyStore.storeKey(
            vaultKey,
            mode: keychainMode,
            overwriteExisting: false
        )
    }

    private func installExactCheckpoint(
        _ checkpoint: V3ManifestCheckpoint,
        vaultID: String
    ) throws {
        if let existing = try checkpointStore.loadCheckpoint(
            vaultID: vaultID
        ) {
            guard existing == checkpoint.canonicalBytes else {
                throw V3EnrollmentAdoptionError.conflictingCheckpoint
            }
            return
        }
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: nil,
            vaultID: vaultID
        )
    }
}

private struct V3EnrollmentFirstTrust: Sendable {
    let manifest: V3VerifiedManifest
    let vaultKey: Data
}

/// Finds the single immutable transition bound to the compared transcript,
/// then authenticates it with the key wrapped to this exact device.
private struct V3EnrollmentFirstTrustVerifier: Sendable {
    let source: any V3ImmutableObjectReading
    let limits: V3ManifestRepositoryLimits
    private let authenticator = V3ManifestAuthenticator()

    func verify(
        transcript: V3EnrollmentTranscript,
        identity: any V3EnrollmentVaultKeyUnwrapping,
        reason: String
    ) throws -> V3EnrollmentFirstTrust {
        guard identity.vaultID == transcript.invitation.vaultID,
            identity.publicIdentity == transcript.joinRequest.joiningDevice
        else {
            throw V3EnrollmentAdoptionError.identityUnavailable
        }
        let candidates = try matchingCandidates(transcript: transcript)
        guard candidates.count == 1, let candidate = candidates.first else {
            if candidates.isEmpty {
                throw V3EnrollmentAdoptionError.approvalUnavailable
            }
            throw V3EnrollmentAdoptionError.ambiguousApproval
        }
        let body = candidate.envelope.content.manifest
        guard let wrapped = body.wrappedKeys.first(where: {
            $0.deviceID == identity.publicIdentity.deviceID
        }), let ciphertext = Base64URL.decodeCanonical(wrapped.ciphertext)
        else {
            throw V3EnrollmentAdoptionError.invalidWrappedKey
        }
        let context = try V3EnrollmentVaultKeyWrapContext(
            vaultID: body.vaultID,
            keyID: body.keyID,
            recipientDeviceID: identity.publicIdentity.deviceID,
            transcriptDigest: transcript.digest
        )
        let vaultKey: Data
        do {
            vaultKey = try identity.unwrapVaultKey(
                ciphertext,
                context: context,
                reason: reason
            )
        } catch {
            throw V3EnrollmentAdoptionError.invalidWrappedKey
        }
        guard (try? V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: body.vaultID
        )) == body.keyID else {
            throw V3EnrollmentAdoptionError.invalidWrappedKey
        }

        let parentData = try requireManifest(
            digest: transcript.invitation.parentManifestDigest
        )
        let parent: V3VerifiedManifest
        do {
            let parsedParent = try authenticator.parse(parentData)
            if parsedParent.content.manifest.mode == .local {
                parent = try authenticator.reopenCheckpointAncestor(
                    parentData,
                    expectedVaultID: transcript.invitation.vaultID,
                    expectedDigest: transcript.invitation
                        .parentManifestDigest
                )
            } else {
                let authenticated = try authenticator
                    .authenticateForRepositoryDiscovery(
                        parentData,
                        vaultKey: vaultKey
                    )
                guard authenticated.envelopeDigest
                        == transcript.invitation.parentManifestDigest
                else {
                    throw V3EnrollmentAdoptionError.invalidApproval
                }
                parent = V3VerifiedManifest(
                    envelope: authenticated.envelope,
                    envelopeDigest: authenticated.envelopeDigest
                )
            }
            let verified = try authenticator.verifyOwnerApprovedEnrollment(
                candidate.data,
                vaultKey: vaultKey,
                parent: parent,
                transcript: transcript
            )
            guard verified.envelopeDigest == candidate.digest else {
                throw V3EnrollmentAdoptionError.invalidApproval
            }
            return V3EnrollmentFirstTrust(
                manifest: verified,
                vaultKey: vaultKey
            )
        } catch let error as V3EnrollmentAdoptionError {
            throw error
        } catch {
            throw V3EnrollmentAdoptionError.invalidApproval
        }
    }

    private func matchingCandidates(
        transcript: V3EnrollmentTranscript
    ) throws -> [Candidate] {
        let digests: [Data]
        switch try source.manifestDigests(
            maximumCount: limits.maximumManifestObjects
        ) {
        case .available(let listed, _):
            digests = listed
        case .unavailable:
            throw V3EnrollmentAdoptionError.approvalUnavailable
        case .invalid, .limitExceeded:
            throw V3EnrollmentAdoptionError.invalidApproval
        }

        let expectedInviter = manifestDevice(
            transcript.invitation.invitingDevice,
            role: .owner
        )
        let expectedJoiner = manifestDevice(
            transcript.joinRequest.joiningDevice,
            role: .member
        )
        let parent = Base64URL.encode(
            transcript.invitation.parentManifestDigest
        )
        var matches: [Candidate] = []
        var totalManifestBytes = 0
        for digest in digests {
            let result = try source.readManifest(
                digest: digest,
                maximumBytes: limits.maximumManifestBytes
            )
            guard case .available(let data) = result else {
                continue
            }
            guard data.count
                    <= limits.maximumTotalManifestBytes - totalManifestBytes
            else {
                throw V3EnrollmentAdoptionError.invalidApproval
            }
            totalManifestBytes += data.count
            guard Data(SHA256.hash(data: data)) == digest,
                let envelope = try? authenticator.parse(data)
            else {
                continue
            }
            let body = envelope.content.manifest
            guard envelope.content.parents == [parent],
                body.vaultID == transcript.invitation.vaultID,
                body.mode == .shared,
                body.devices.contains(expectedInviter),
                body.devices.contains(expectedJoiner),
                body.wrappedKeys.filter({
                    $0.deviceID == expectedJoiner.deviceID
                }).count == 1,
                envelope.authorizations.count == 1,
                envelope.authorizations[0].signerDeviceID
                    == transcript.invitation.invitingDevice.deviceID
            else {
                continue
            }
            guard (try? authenticator.verifyEnrollmentAuthorization(
                    envelope,
                    transcript: transcript
                )) != nil
            else {
                continue
            }
            matches.append(Candidate(
                digest: digest,
                data: data,
                envelope: envelope
            ))
            guard matches.count <= 1 else {
                break
            }
        }
        return matches
    }

    private func requireManifest(digest: Data) throws -> Data {
        switch try source.readManifest(
            digest: digest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case .available(let data)
            where Data(SHA256.hash(data: data)) == digest:
            return data
        case .unavailable:
            throw V3EnrollmentAdoptionError.approvalUnavailable
        case .available, .invalid, .tooLarge:
            throw V3EnrollmentAdoptionError.invalidApproval
        }
    }

    private func manifestDevice(
        _ identity: V3EnrollmentDeviceIdentity,
        role: V3DeviceRole
    ) -> V3ManifestDevice {
        V3ManifestDevice(
            deviceID: identity.deviceID,
            displayName: identity.displayName,
            role: role,
            status: .active,
            signingPublicKey: V3DevicePublicKey(
                value: Base64URL.encode(identity.signingPublicKey)
            ),
            wrappingPublicKey: V3DevicePublicKey(
                value: Base64URL.encode(identity.wrappingPublicKey)
            )
        )
    }

    private struct Candidate: Sendable {
        let digest: Data
        let data: Data
        let envelope: V3ManifestEnvelope
    }
}
