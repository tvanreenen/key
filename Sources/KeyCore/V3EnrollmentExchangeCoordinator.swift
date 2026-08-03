import Foundation

/// Coordinates authenticated enrollment messages without granting authority.
///
/// Shared files are treated only as bounded transport. Device-local state is
/// the source of ceremony ownership, replay status, and exact retry bytes.
struct V3EnrollmentExchangeCoordinator: Sendable {
    private let mailbox: any V3EnrollmentMailboxStoring
    private let stateStore: any V3EnrollmentCeremonyStateStoring
    private let authenticator: V3EnrollmentMessageAuthenticator

    init(
        mailbox: any V3EnrollmentMailboxStoring,
        stateStore: any V3EnrollmentCeremonyStateStoring,
        authenticator: V3EnrollmentMessageAuthenticator =
            V3EnrollmentMessageAuthenticator()
    ) {
        self.mailbox = mailbox
        self.stateStore = stateStore
        self.authenticator = authenticator
    }

    /// Lists bounded invitation candidates without trusting their contents.
    func availableInvitationDigests(
        maximumCount: Int
    ) throws -> [Data] {
        switch try mailbox.invitationDigests(
            maximumCount: maximumCount
        ) {
        case .available(let digests, _):
            return digests
        case .unavailable:
            return []
        case .invalid:
            throw V3EnrollmentCeremonyStateError.listingInvalid
        case .limitExceeded:
            throw V3EnrollmentCeremonyStateError.listingLimitExceeded
        }
    }

    /// Persists exact retry bytes before publishing an invitation.
    func beginInviting(
        _ signedInvitation: V3SignedEnrollmentInvitation,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        let verified = try authenticator.verify(signedInvitation)
        try verified.invitation.requireUnexpired(at: unixTime)
        let proposed = try V3EnrollmentCeremonyState(
            vaultID: verified.invitation.vaultID,
            invitationDigest: verified.invitation.digest,
            role: .inviter,
            phase: .awaitingJoinRequest,
            signedInvitation: signedInvitation,
            signedJoinRequest: nil
        )
        let state = try installOrResume(proposed)
        try mailbox.publishInvitation(
            state.signedInvitation.canonicalBytes
        )
        return state
    }

    /// Authenticates one exact invitation selected by its payload digest.
    func receiveInvitation(
        digest: Data,
        at unixTime: UInt64
    ) throws -> V3VerifiedEnrollmentInvitation {
        guard digest.count == 32 else {
            throw V3EnrollmentMailboxError.invalidDigest
        }
        let bytes = try requireMessage(
            mailbox.readInvitation(digest: digest)
        )
        let signed = try parseInvitation(bytes)
        guard signed.invitation.digest == digest else {
            throw V3EnrollmentMailboxError.digestMismatch
        }
        let verified = try authenticator.verify(signed)
        try verified.invitation.requireUnexpired(at: unixTime)
        return verified
    }

    /// Persists a complete join-side transcript before publishing its answer.
    func beginJoining(
        _ signedJoinRequest: V3SignedEnrollmentJoinRequest,
        answering verifiedInvitation: V3VerifiedEnrollmentInvitation,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        let verifiedInvitation = try authenticator.verify(
            verifiedInvitation.signedInvitation
        )
        let invitation = verifiedInvitation.invitation
        try invitation.requireUnexpired(at: unixTime)
        let verifiedJoinRequest = try authenticator.verify(
            signedJoinRequest
        )
        _ = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: verifiedJoinRequest.joinRequest
        )
        let proposed = try V3EnrollmentCeremonyState(
            vaultID: invitation.vaultID,
            invitationDigest: invitation.digest,
            role: .joiner,
            phase: .awaitingComparison,
            signedInvitation: verifiedInvitation.signedInvitation,
            signedJoinRequest: signedJoinRequest
        )
        let state = try installOrResume(proposed)
        guard let storedJoinRequest = state.signedJoinRequest else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        try mailbox.publishJoinRequest(
            storedJoinRequest.canonicalBytes,
            invitationDigest: state.invitationDigest
        )
        return state
    }

    /// Republishes the exact join request already owned by this device.
    ///
    /// This is intentionally checked before a caller creates a new nonce or
    /// signature. A transient provider failure after device-local persistence
    /// can therefore resume with identical bytes instead of conflicting with
    /// the durable ceremony state.
    func resumeJoining(
        answering verifiedInvitation: V3VerifiedEnrollmentInvitation,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState? {
        let verifiedInvitation = try authenticator.verify(
            verifiedInvitation.signedInvitation
        )
        let invitation = verifiedInvitation.invitation
        guard let loaded = try loadValidatedState(
            vaultID: invitation.vaultID,
            invitationDigest: invitation.digest
        ) else {
            return nil
        }
        let state = loaded.state
        guard state.role == .joiner,
              state.phase == .awaitingComparison,
              state.signedInvitation == verifiedInvitation.signedInvitation,
              let signedJoinRequest = state.signedJoinRequest
        else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        try invitation.requireUnexpired(at: unixTime)
        try mailbox.publishJoinRequest(
            signedJoinRequest.canonicalBytes,
            invitationDigest: invitation.digest
        )
        return state
    }

    /// Lists only bounded digest-shaped candidates for an active local invite.
    func availableJoinRequestDigests(
        vaultID: String,
        invitationDigest: Data,
        at unixTime: UInt64,
        maximumCount: Int
    ) throws -> [Data] {
        let loaded = try requireActiveState(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        guard loaded.state.role == .inviter else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        switch try mailbox.joinRequestDigests(
            invitationDigest: invitationDigest,
            maximumCount: maximumCount
        ) {
        case .available(let digests, _):
            return digests
        case .unavailable:
            return []
        case .invalid:
            throw V3EnrollmentCeremonyStateError.listingInvalid
        case .limitExceeded:
            throw V3EnrollmentCeremonyStateError.listingLimitExceeded
        }
    }

    /// Selects and durably pins one exact authenticated join response.
    func receiveJoinRequest(
        vaultID: String,
        invitationDigest: Data,
        joinRequestDigest: Data,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        guard joinRequestDigest.count == 32 else {
            throw V3EnrollmentMailboxError.invalidDigest
        }
        let loaded = try requireActiveState(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        let state = loaded.state
        guard state.role == .inviter else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        if let existing = state.signedJoinRequest {
            guard existing.joinRequest.digest == joinRequestDigest else {
                throw V3EnrollmentCeremonyStateError.conflict
            }
            return state
        }

        let bytes = try requireMessage(
            mailbox.readJoinRequest(
                invitationDigest: invitationDigest,
                joinRequestDigest: joinRequestDigest
            )
        )
        let signedJoinRequest = try parseJoinRequest(bytes)
        guard signedJoinRequest.joinRequest.digest == joinRequestDigest,
            signedJoinRequest.joinRequest.invitationDigest
                == invitationDigest
        else {
            throw V3EnrollmentMailboxError.digestMismatch
        }
        let verifiedJoinRequest = try authenticator.verify(
            signedJoinRequest
        )
        _ = try V3EnrollmentTranscript(
            invitation: state.signedInvitation.invitation,
            joinRequest: verifiedJoinRequest.joinRequest
        )
        let updated = try V3EnrollmentCeremonyState(
            vaultID: state.vaultID,
            invitationDigest: state.invitationDigest,
            role: .inviter,
            phase: .awaitingComparison,
            signedInvitation: state.signedInvitation,
            signedJoinRequest: signedJoinRequest
        )
        try stateStore.replaceState(
            updated.canonicalBytes,
            expectedState: loaded.bytes,
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        return updated
    }

    /// Reopens only authenticated, unexpired, non-consumed local state.
    func resume(
        vaultID: String,
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        try requireActiveState(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        ).state
    }

    /// Reopens joining-side state for the final adoption transaction.
    ///
    /// A consumed state is an exact, device-local retry marker: comparison
    /// and first-trust verification already completed, but the helper may
    /// still need to finish checkpoint or configuration installation after a
    /// crash. New adoption attempts remain subject to invitation expiry.
    func resumeJoinerAdoption(
        vaultID: String,
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        guard let loaded = try loadValidatedState(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        ) else {
            throw V3EnrollmentCeremonyStateError.notFound
        }
        let state = loaded.state
        guard state.role == .joiner else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        switch state.phase {
        case .awaitingComparison:
            try state.signedInvitation.invitation.requireUnexpired(
                at: unixTime
            )
        case .consumed:
            break
        case .awaitingJoinRequest, .publishingApproval:
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        return state
    }

    /// Persists the exact randomized owner approval before any shared
    /// manifest publication. Repeating the same preparation is idempotent;
    /// a different candidate for the same transcript is a conflict.
    func prepareOwnerApproval(
        vaultID: String,
        invitationDigest: Data,
        approval: V3EnrollmentPreparedOwnerApproval,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        let loaded = try loadValidatedState(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        guard let loaded else {
            throw V3EnrollmentCeremonyStateError.notFound
        }
        let state = loaded.state
        guard state.role == .inviter else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        guard state.phase != .consumed else {
            throw V3EnrollmentCeremonyStateError.replayed
        }
        guard state.transcript?.digest == approval.transcriptDigest else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        if state.phase == .publishingApproval {
            guard state.ownerApproval == approval else {
                throw V3EnrollmentCeremonyStateError.conflict
            }
            return state
        }
        guard state.phase == .awaitingComparison,
              state.ownerApproval == nil
        else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        try state.signedInvitation.invitation.requireUnexpired(
            at: unixTime
        )
        let prepared = try V3EnrollmentCeremonyState(
            vaultID: state.vaultID,
            invitationDigest: state.invitationDigest,
            role: state.role,
            phase: .publishingApproval,
            signedInvitation: state.signedInvitation,
            signedJoinRequest: state.signedJoinRequest,
            ownerApproval: approval
        )
        try stateStore.replaceState(
            prepared.canonicalBytes,
            expectedState: loaded.bytes,
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        return prepared
    }

    /// Reopens inviter state for ENR-504. Once an exact approval has been
    /// prepared, retries may finish publication after the invitation expires;
    /// no new candidate or approval can be created at that point.
    func resumeOwnerApproval(
        vaultID: String,
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        guard let loaded = try loadValidatedState(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        ) else {
            throw V3EnrollmentCeremonyStateError.notFound
        }
        let state = loaded.state
        guard state.role == .inviter else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        switch state.phase {
        case .awaitingComparison:
            try state.signedInvitation.invitation.requireUnexpired(
                at: unixTime
            )
        case .publishingApproval:
            guard state.ownerApproval != nil else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        case .awaitingJoinRequest:
            throw V3EnrollmentCeremonyStateError.invalidState
        case .consumed:
            throw V3EnrollmentCeremonyStateError.replayed
        }
        return state
    }

    /// Marks the exact compared transcript as consumed using a CAS guard.
    ///
    /// This is non-authoritative bookkeeping for ENR-504 and ENR-505. Calling
    /// it again for the same transcript is idempotent; every other ceremony
    /// operation rejects the consumed record as replayed.
    func markConsumed(
        vaultID: String,
        invitationDigest: Data,
        transcriptDigest: Data,
        at unixTime: UInt64
    ) throws -> V3EnrollmentCeremonyState {
        guard transcriptDigest.count == 32 else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        let loaded = try loadValidatedState(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        guard let loaded else {
            throw V3EnrollmentCeremonyStateError.notFound
        }
        let state = loaded.state
        guard let transcript = state.transcript,
            transcript.digest == transcriptDigest
        else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        if state.phase == .consumed {
            return state
        }
        switch state.role {
        case .inviter:
            guard state.phase == .publishingApproval,
                  state.ownerApproval != nil
            else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        case .joiner:
            try state.signedInvitation.invitation.requireUnexpired(
                at: unixTime
            )
            guard state.phase == .awaitingComparison else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        }
        let consumed = try V3EnrollmentCeremonyState(
            vaultID: state.vaultID,
            invitationDigest: state.invitationDigest,
            role: state.role,
            phase: .consumed,
            signedInvitation: state.signedInvitation,
            signedJoinRequest: state.signedJoinRequest,
            ownerApproval: state.ownerApproval
        )
        try stateStore.replaceState(
            consumed.canonicalBytes,
            expectedState: loaded.bytes,
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        return consumed
    }

    private func installOrResume(
        _ proposed: V3EnrollmentCeremonyState
    ) throws -> V3EnrollmentCeremonyState {
        if let loaded = try loadValidatedState(
            vaultID: proposed.vaultID,
            invitationDigest: proposed.invitationDigest
        ) {
            let existing = loaded.state
            guard existing.phase != .consumed else {
                throw V3EnrollmentCeremonyStateError.replayed
            }
            guard existing.role == proposed.role,
                existing.signedInvitation == proposed.signedInvitation
            else {
                throw V3EnrollmentCeremonyStateError.conflict
            }
            if proposed.role == .joiner {
                guard
                    existing.signedJoinRequest
                        == proposed.signedJoinRequest
                else {
                    throw V3EnrollmentCeremonyStateError.conflict
                }
            }
            return existing
        }

        try stateStore.replaceState(
            proposed.canonicalBytes,
            expectedState: nil,
            vaultID: proposed.vaultID,
            invitationDigest: proposed.invitationDigest
        )
        return proposed
    }

    private func requireActiveState(
        vaultID: String,
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> (bytes: Data, state: V3EnrollmentCeremonyState) {
        guard
            let loaded = try loadValidatedState(
                vaultID: vaultID,
                invitationDigest: invitationDigest
            )
        else {
            throw V3EnrollmentCeremonyStateError.notFound
        }
        guard loaded.state.phase != .consumed else {
            throw V3EnrollmentCeremonyStateError.replayed
        }
        try loaded.state.signedInvitation.invitation.requireUnexpired(
            at: unixTime
        )
        return loaded
    }

    private func loadValidatedState(
        vaultID: String,
        invitationDigest: Data
    ) throws -> (bytes: Data, state: V3EnrollmentCeremonyState)? {
        guard isValidV3UUID(vaultID), invitationDigest.count == 32 else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        guard
            let bytes = try stateStore.loadState(
                vaultID: vaultID,
                invitationDigest: invitationDigest
            )
        else {
            return nil
        }
        let state: V3EnrollmentCeremonyState
        do {
            state = try V3EnrollmentCeremonyState(canonicalBytes: bytes)
            guard state.vaultID == vaultID,
                state.invitationDigest == invitationDigest
            else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
            _ = try authenticator.verify(state.signedInvitation)
            if let signedJoinRequest = state.signedJoinRequest {
                _ = try authenticator.verify(signedJoinRequest)
            }
        } catch {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        return (bytes, state)
    }

    private func requireMessage(
        _ read: V3RepositoryObjectRead
    ) throws -> Data {
        switch read {
        case .available(let data):
            return data
        case .unavailable:
            throw V3EnrollmentCeremonyStateError.messageUnavailable
        case .invalid:
            throw V3EnrollmentCeremonyStateError.invalidMessage
        case .tooLarge:
            throw V3EnrollmentCeremonyStateError.messageTooLarge
        }
    }

    private func parseInvitation(
        _ bytes: Data
    ) throws -> V3SignedEnrollmentInvitation {
        do {
            return try V3SignedEnrollmentInvitation(
                canonicalBytes: bytes
            )
        } catch {
            try preserveUpgradeRequired(error)
            throw V3EnrollmentCeremonyStateError.invalidMessage
        }
    }

    private func parseJoinRequest(
        _ bytes: Data
    ) throws -> V3SignedEnrollmentJoinRequest {
        do {
            return try V3SignedEnrollmentJoinRequest(
                canonicalBytes: bytes
            )
        } catch {
            try preserveUpgradeRequired(error)
            throw V3EnrollmentCeremonyStateError.invalidMessage
        }
    }
}

private func preserveUpgradeRequired(_ error: any Error) throws {
    if case .unsupportedVersion = error as? V3EnrollmentAuthenticationError {
        throw error
    }
    switch error as? V3EnrollmentProtocolError {
    case .unsupportedMessageVersion, .unsupportedVaultFormatVersion:
        throw error
    default:
        return
    }
}
