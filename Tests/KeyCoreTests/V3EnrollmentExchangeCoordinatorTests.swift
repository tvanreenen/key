import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3EnrollmentExchangeCoordinatorTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let activeTime: UInt64 = 1_800_000_000

    @Test
    func inviterPersistsExactBytesBeforePublishingAndResumesRetry() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let mailbox = MemoryEnrollmentMailbox()
        mailbox.failInvitationPublish = true
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: stateStore
        )

        #expect(throws: EnrollmentExchangeTestError.publishFailed) {
            try coordinator.beginInviting(
                fixture.signedInvitation,
                at: Self.activeTime
            )
        }

        let loaded = try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest
        )
        let persisted = try #require(loaded)
        let state = try V3EnrollmentCeremonyState(
            canonicalBytes: persisted
        )
        #expect(
            state.signedInvitation.canonicalBytes
                == fixture.signedInvitation.canonicalBytes
        )

        mailbox.failInvitationPublish = false
        let resumed = try coordinator.beginInviting(
            fixture.signedInvitation,
            at: Self.activeTime
        )
        #expect(resumed == state)
        #expect(
            mailbox.invitations[fixture.invitation.digest]
                == fixture.signedInvitation.canonicalBytes
        )
    }

    @Test
    func joiningPersistsBeforePublishingAndResumesTheExactAnswer() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let mailbox = MemoryEnrollmentMailbox()
        mailbox.failJoinRequestPublish = true
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: stateStore
        )

        #expect(throws: EnrollmentExchangeTestError.publishFailed) {
            try coordinator.beginJoining(
                fixture.signedJoinRequest,
                answering: fixture.verifiedInvitation,
                at: Self.activeTime
            )
        }

        let loaded = try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest
        )
        let persisted = try #require(loaded)
        let state = try V3EnrollmentCeremonyState(
            canonicalBytes: persisted
        )
        #expect(
            state.signedJoinRequest?.canonicalBytes
                == fixture.signedJoinRequest.canonicalBytes
        )

        mailbox.failJoinRequestPublish = false
        let resumed = try #require(try coordinator.resumeJoining(
            answering: fixture.verifiedInvitation,
            at: Self.activeTime
        ))
        #expect(resumed == state)
        #expect(
            mailbox.joinRequests[fixture.invitation.digest]?[
                fixture.joinRequest.digest
            ] == fixture.signedJoinRequest.canonicalBytes
        )
    }

    @Test
    func invitationReadAuthenticatesTheDigestBytesSignatureAndExpiry() throws {
        let fixture = try Fixture()
        let mailbox = MemoryEnrollmentMailbox()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: MemoryCeremonyStateStore()
        )

        #expect(throws: V3EnrollmentCeremonyStateError.messageUnavailable) {
            try coordinator.receiveInvitation(
                digest: fixture.invitation.digest,
                at: Self.activeTime
            )
        }

        mailbox.invitations[fixture.invitation.digest] = Data("invalid".utf8)
        #expect(throws: V3EnrollmentCeremonyStateError.invalidMessage) {
            try coordinator.receiveInvitation(
                digest: fixture.invitation.digest,
                at: Self.activeTime
            )
        }

        let wrongDigest = Data(repeating: 0xD1, count: 32)
        mailbox.invitations[wrongDigest] =
            fixture.signedInvitation.canonicalBytes
        #expect(throws: V3EnrollmentMailboxError.digestMismatch) {
            try coordinator.receiveInvitation(
                digest: wrongDigest,
                at: Self.activeTime
            )
        }

        mailbox.invitations[fixture.invitation.digest] =
            fixture.signedInvitation.canonicalBytes
        #expect(throws: V3EnrollmentProtocolError.expired) {
            try coordinator.receiveInvitation(
                digest: fixture.invitation.digest,
                at: fixture.invitation.expiresAt + 1
            )
        }
        #expect(
            try coordinator.receiveInvitation(
                digest: fixture.invitation.digest,
                at: Self.activeTime
            ) == fixture.verifiedInvitation
        )
    }

    @Test
    func invitationDiscoveryIsBoundedAndUnauthoritative() throws {
        let fixture = try Fixture()
        let mailbox = MemoryEnrollmentMailbox()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: MemoryCeremonyStateStore()
        )

        mailbox.invitationListing = .unavailable
        #expect(
            try coordinator.availableInvitationDigests(
                maximumCount: 10
            ).isEmpty
        )

        mailbox.invitationListing = .available(
            digests: [fixture.invitation.digest],
            objectCount: 3
        )
        #expect(
            try coordinator.availableInvitationDigests(
                maximumCount: 10
            ) == [fixture.invitation.digest]
        )

        mailbox.invitationListing = .limitExceeded
        #expect(
            throws: V3EnrollmentCeremonyStateError.listingLimitExceeded
        ) {
            try coordinator.availableInvitationDigests(maximumCount: 10)
        }
    }

    @Test
    func futureMailboxEnvelopesRequireAnUpgrade() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let mailbox = MemoryEnrollmentMailbox()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: stateStore
        )
        let futureInvitation = enrollmentExchangeReplacingLast(
            enrollmentExchangeReplacing(
                fixture.signedInvitation.canonicalBytes,
                "\"format\":\"key-vault-enrollment-signed-invitation\",\"invitation\":",
                with:
                    "\"format\":\"key-vault-enrollment-signed-invitation\",\"futureField\":true,\"invitation\":"
            ),
            "\"version\":2}",
            with: "\"version\":3}"
        )
        mailbox.invitations[fixture.invitation.digest] = futureInvitation

        #expect(
            throws: V3EnrollmentAuthenticationError.unsupportedVersion(3)
        ) {
            try coordinator.receiveInvitation(
                digest: fixture.invitation.digest,
                at: Self.activeTime
            )
        }

        _ = try coordinator.beginInviting(
            fixture.signedInvitation,
            at: Self.activeTime
        )
        let futureJoinRequest = enrollmentExchangeReplacingLast(
            enrollmentExchangeReplacing(
                fixture.signedJoinRequest.canonicalBytes,
                "\"format\":\"key-vault-enrollment-signed-join-request\",\"joinRequest\":",
                with:
                    "\"format\":\"key-vault-enrollment-signed-join-request\",\"futureField\":true,\"joinRequest\":"
            ),
            "\"version\":2}",
            with: "\"version\":3}"
        )
        mailbox.joinRequests[fixture.invitation.digest] = [
            fixture.joinRequest.digest: futureJoinRequest
        ]

        #expect(
            throws: V3EnrollmentAuthenticationError.unsupportedVersion(3)
        ) {
            try coordinator.receiveJoinRequest(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                joinRequestDigest: fixture.joinRequest.digest,
                at: Self.activeTime
            )
        }
    }

    @Test
    func inviterListsOnlyWithinTheBoundedLocalCeremony() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let mailbox = MemoryEnrollmentMailbox()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: stateStore
        )
        _ = try coordinator.beginInviting(
            fixture.signedInvitation,
            at: Self.activeTime
        )

        mailbox.joinRequestListing = .unavailable
        #expect(
            try coordinator.availableJoinRequestDigests(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: Self.activeTime,
                maximumCount: 10
            ).isEmpty
        )

        mailbox.joinRequestListing = .limitExceeded
        #expect(
            throws: V3EnrollmentCeremonyStateError.listingLimitExceeded
        ) {
            try coordinator.availableJoinRequestDigests(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: Self.activeTime,
                maximumCount: 10
            )
        }

        mailbox.joinRequestListing = .invalid
        #expect(throws: V3EnrollmentCeremonyStateError.listingInvalid) {
            try coordinator.availableJoinRequestDigests(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: Self.activeTime,
                maximumCount: 10
            )
        }
    }

    @Test
    func inviterPinsOneAuthenticatedResponseAndRejectsAlternates() throws {
        let fixture = try Fixture()
        let alternate = try fixture.signedJoinRequest(
            joiningNonce: Data(repeating: 0xB2, count: 32)
        )
        let stateStore = MemoryCeremonyStateStore()
        let mailbox = MemoryEnrollmentMailbox()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: stateStore
        )
        _ = try coordinator.beginInviting(
            fixture.signedInvitation,
            at: Self.activeTime
        )
        mailbox.joinRequests[fixture.invitation.digest] = [
            fixture.joinRequest.digest:
                fixture.signedJoinRequest.canonicalBytes,
            alternate.joinRequest.digest: alternate.canonicalBytes,
        ]

        let pinned = try coordinator.receiveJoinRequest(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            joinRequestDigest: fixture.joinRequest.digest,
            at: Self.activeTime
        )
        #expect(pinned.phase == .awaitingComparison)
        #expect(pinned.signedJoinRequest == fixture.signedJoinRequest)

        #expect(throws: V3EnrollmentCeremonyStateError.conflict) {
            try coordinator.receiveJoinRequest(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                joinRequestDigest: alternate.joinRequest.digest,
                at: Self.activeTime
            )
        }
        #expect(
            try coordinator.receiveJoinRequest(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                joinRequestDigest: fixture.joinRequest.digest,
                at: Self.activeTime
            ) == pinned
        )
    }

    @Test
    func wrongContextAndCorruptLocalStateFailClosed() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: MemoryEnrollmentMailbox(),
            stateStore: stateStore
        )

        #expect(throws: V3EnrollmentCeremonyStateError.notFound) {
            try coordinator.resume(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: Self.activeTime
            )
        }

        stateStore.forceSet(
            Data("corrupt".utf8),
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest
        )
        #expect(throws: V3EnrollmentCeremonyStateError.invalidState) {
            try coordinator.resume(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: Self.activeTime
            )
        }
    }

    @Test
    func expiryNeverAdvancesOrDeletesLocalState() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: MemoryEnrollmentMailbox(),
            stateStore: stateStore
        )
        _ = try coordinator.beginInviting(
            fixture.signedInvitation,
            at: Self.activeTime
        )
        let before = try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest
        )

        #expect(throws: V3EnrollmentProtocolError.expired) {
            try coordinator.resume(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: fixture.invitation.expiresAt + 1
            )
        }
        #expect(
            try stateStore.loadState(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest
            ) == before
        )
    }

    @Test
    func finalJoinerAdoptionCanResumeAfterInvitationExpiry() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: MemoryEnrollmentMailbox(),
            stateStore: stateStore
        )
        let awaitingComparison = try coordinator.beginJoining(
            fixture.signedJoinRequest,
            answering: fixture.verifiedInvitation,
            at: Self.activeTime
        )

        #expect(
            try coordinator.resumeJoinerAdoption(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: fixture.invitation.expiresAt + 1
            ) == awaitingComparison
        )
        #expect(throws: V3EnrollmentProtocolError.expired) {
            try coordinator.resume(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: fixture.invitation.expiresAt + 1
            )
        }
    }

    @Test
    func consumedTranscriptIsIdempotentButCannotBeReplayed() throws {
        let fixture = try Fixture()
        let stateStore = MemoryCeremonyStateStore()
        let mailbox = MemoryEnrollmentMailbox()
        let coordinator = V3EnrollmentExchangeCoordinator(
            mailbox: mailbox,
            stateStore: stateStore
        )
        _ = try coordinator.beginJoining(
            fixture.signedJoinRequest,
            answering: fixture.verifiedInvitation,
            at: Self.activeTime
        )
        let transcript = try V3EnrollmentTranscript(
            invitation: fixture.invitation,
            joinRequest: fixture.joinRequest
        )

        let consumed = try coordinator.markConsumed(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            transcriptDigest: transcript.digest,
            at: Self.activeTime
        )
        #expect(consumed.phase == .consumed)
        #expect(
            try coordinator.markConsumed(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                transcriptDigest: transcript.digest,
                at: fixture.invitation.expiresAt + 1
            ) == consumed
        )

        #expect(throws: V3EnrollmentCeremonyStateError.replayed) {
            try coordinator.resume(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                at: Self.activeTime
            )
        }
        #expect(throws: V3EnrollmentCeremonyStateError.replayed) {
            try coordinator.beginJoining(
                fixture.signedJoinRequest,
                answering: fixture.verifiedInvitation,
                at: Self.activeTime
            )
        }
    }

    @Test
    func localStateIsCanonicalStrictAndTranscriptBound() throws {
        let fixture = try Fixture()
        let state = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            role: .joiner,
            phase: .awaitingComparison,
            signedInvitation: fixture.signedInvitation,
            signedJoinRequest: fixture.signedJoinRequest
        )

        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: state.canonicalBytes
            ) == state
        )

        let extended = enrollmentExchangeReplacing(
            state.canonicalBytes,
            "\"version\":1}",
            with: "\"unexpected\":true,\"version\":1}"
        )
        #expect(throws: V3EnrollmentCeremonyStateError.invalidState) {
            try V3EnrollmentCeremonyState(canonicalBytes: extended)
        }

        let invalidPhase = enrollmentExchangeReplacing(
            state.canonicalBytes,
            "\"phase\":\"awaitingComparison\"",
            with: "\"phase\":\"awaitingJoinRequest\""
        )
        #expect(throws: V3EnrollmentCeremonyStateError.invalidState) {
            try V3EnrollmentCeremonyState(canonicalBytes: invalidPhase)
        }

        #expect(throws: V3EnrollmentCeremonyStateError.invalidState) {
            try V3EnrollmentCeremonyState(
                canonicalBytes: Data(
                    repeating: 0x41,
                    count: V3EnrollmentCeremonyState.maximumBytes + 1
                )
            )
        }
    }

    private struct Fixture {
        let inviter: EnrollmentExchangeSoftwareSigner
        let joiner: EnrollmentExchangeSoftwareSigner
        let invitation: V3EnrollmentInvitation
        let signedInvitation: V3SignedEnrollmentInvitation
        let verifiedInvitation: V3VerifiedEnrollmentInvitation
        let joinRequest: V3EnrollmentJoinRequest
        let signedJoinRequest: V3SignedEnrollmentJoinRequest

        init() throws {
            inviter = try EnrollmentExchangeSoftwareSigner(
                vaultID: V3EnrollmentExchangeCoordinatorTests.vaultID,
                displayName: "Office Mac",
                signingScalar: 1,
                wrappingScalar: 2
            )
            joiner = try EnrollmentExchangeSoftwareSigner(
                vaultID: V3EnrollmentExchangeCoordinatorTests.vaultID,
                displayName: "Travel Mac",
                signingScalar: 3,
                wrappingScalar: 4
            )
            invitation = try V3EnrollmentInvitation(
                vaultID: V3EnrollmentExchangeCoordinatorTests.vaultID,
                parentManifestDigest: Data(repeating: 0x91, count: 32),
                invitingDevice: inviter.publicIdentity,
                nonce: Data(repeating: 0xA1, count: 32),
                expiresAt: 1_900_000_000
            )
            let authenticator = V3EnrollmentMessageAuthenticator()
            signedInvitation = try authenticator.sign(
                invitation,
                using: inviter,
                reason: "Approve invitation"
            )
            verifiedInvitation = try authenticator.verify(signedInvitation)
            joinRequest = try V3EnrollmentJoinRequest(
                invitationDigest: invitation.digest,
                joiningDevice: joiner.publicIdentity,
                nonce: Data(repeating: 0xB1, count: 32)
            )
            signedJoinRequest = try authenticator.sign(
                joinRequest,
                answering: verifiedInvitation,
                using: joiner,
                reason: "Approve join request"
            )
        }

        func signedJoinRequest(
            joiningNonce: Data
        ) throws -> V3SignedEnrollmentJoinRequest {
            let request = try V3EnrollmentJoinRequest(
                invitationDigest: invitation.digest,
                joiningDevice: joiner.publicIdentity,
                nonce: joiningNonce
            )
            return try V3EnrollmentMessageAuthenticator().sign(
                request,
                answering: verifiedInvitation,
                using: joiner,
                reason: "Approve alternate join request"
            )
        }
    }
}

private enum EnrollmentExchangeTestError: Error {
    case publishFailed
}

private final class MemoryEnrollmentMailbox:
    V3EnrollmentMailboxStoring,
    @unchecked Sendable
{
    var invitations: [Data: Data] = [:]
    var joinRequests: [Data: [Data: Data]] = [:]
    var invitationListing: V3EnrollmentMailboxListing?
    var joinRequestListing: V3EnrollmentMailboxListing?
    var failInvitationPublish = false
    var failJoinRequestPublish = false

    func invitationDigests(
        maximumCount _: Int
    ) throws -> V3EnrollmentMailboxListing {
        if let invitationListing {
            return invitationListing
        }
        return .available(
            digests: invitations.keys.sorted(
                by: { $0.lexicographicallyPrecedes($1) }
            ),
            objectCount: invitations.count
        )
    }

    func readInvitation(digest: Data) throws -> V3RepositoryObjectRead {
        invitations[digest].map(V3RepositoryObjectRead.available)
            ?? .unavailable
    }

    func publishInvitation(_ canonicalBytes: Data) throws {
        if failInvitationPublish {
            throw EnrollmentExchangeTestError.publishFailed
        }
        let signed = try V3SignedEnrollmentInvitation(
            canonicalBytes: canonicalBytes
        )
        invitations[signed.invitation.digest] = canonicalBytes
    }

    func joinRequestDigests(
        invitationDigest: Data,
        maximumCount _: Int
    ) throws -> V3EnrollmentMailboxListing {
        if let joinRequestListing {
            return joinRequestListing
        }
        let messages = joinRequests[invitationDigest] ?? [:]
        return .available(
            digests: messages.keys.sorted(
                by: { $0.lexicographicallyPrecedes($1) }
            ),
            objectCount: messages.count
        )
    }

    func readJoinRequest(
        invitationDigest: Data,
        joinRequestDigest: Data
    ) throws -> V3RepositoryObjectRead {
        joinRequests[invitationDigest]?[joinRequestDigest]
            .map(V3RepositoryObjectRead.available) ?? .unavailable
    }

    func publishJoinRequest(
        _ canonicalBytes: Data,
        invitationDigest: Data
    ) throws {
        if failJoinRequestPublish {
            throw EnrollmentExchangeTestError.publishFailed
        }
        let signed = try V3SignedEnrollmentJoinRequest(
            canonicalBytes: canonicalBytes
        )
        joinRequests[invitationDigest, default: [:]][
            signed.joinRequest.digest
        ] = canonicalBytes
    }
}

private final class MemoryCeremonyStateStore:
    V3EnrollmentCeremonyStateStoring,
    @unchecked Sendable
{
    private struct Key: Hashable {
        let vaultID: String
        let invitationDigest: Data
    }

    // On macOS 15+, Synchronization.Mutex can replace this compatibility lock.
    private let lock = NSLock()
    private var states: [Key: Data] = [:]

    func loadState(
        vaultID: String,
        invitationDigest: Data
    ) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return states[
            Key(vaultID: vaultID, invitationDigest: invitationDigest)
        ]
    }

    func replaceState(
        _ state: Data,
        expectedState: Data?,
        vaultID: String,
        invitationDigest: Data
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        let key = Key(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        guard states[key] == expectedState else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        states[key] = state
    }

    func forceSet(
        _ state: Data,
        vaultID: String,
        invitationDigest: Data
    ) {
        lock.lock()
        defer { lock.unlock() }
        states[
            Key(vaultID: vaultID, invitationDigest: invitationDigest)
        ] = state
    }
}

private struct EnrollmentExchangeSoftwareSigner:
    V3EnrollmentMessageSigning,
    Sendable
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let privateKey: P256.Signing.PrivateKey

    init(
        vaultID: String,
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        privateKey = try P256.Signing.PrivateKey(
            rawRepresentation: enrollmentPrivateKeyBytes(signingScalar)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: enrollmentPrivateKeyBytes(wrappingScalar)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: privateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try privateKey.signature(for: input).rawRepresentation
    }
}

private func enrollmentPrivateKeyBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}

private func enrollmentExchangeReplacing(
    _ data: Data,
    _ original: String,
    with replacement: String
) -> Data {
    Data(
        String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: original, with: replacement)
            .utf8
    )
}

private func enrollmentExchangeReplacingLast(
    _ data: Data,
    _ original: String,
    with replacement: String
) -> Data {
    var value = String(decoding: data, as: UTF8.self)
    if let range = value.range(of: original, options: .backwards) {
        value.replaceSubrange(range, with: replacement)
    }
    return Data(value.utf8)
}
