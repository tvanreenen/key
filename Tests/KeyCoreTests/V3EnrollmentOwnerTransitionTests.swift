import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3EnrollmentOwnerTransitionTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    fileprivate static let vaultKey = Data((0..<32).map(UInt8.init))
    fileprivate static let activeTime: UInt64 = 1_900_000_000

    @Test
    func wrappedVaultKeyRoundTripsOnlyInTheExactContext() throws {
        let fixture = try Fixture()
        let recipient = fixture.joiner.wrappingPrivateKey
        let context = try V3EnrollmentVaultKeyWrapContext(
            vaultID: Self.vaultID,
            keyID: fixture.keyID,
            recipientDeviceID: fixture.joiner.publicIdentity.deviceID,
            transcriptDigest: fixture.transcript.digest
        )
        let ciphertext = try V3EnrollmentVaultKeyWrapper().wrap(
            vaultKey: Self.vaultKey,
            recipientPublicKey:
                recipient.publicKey.x963Representation,
            context: context
        )

        #expect(
            try openWrappedVaultKey(
                ciphertext,
                recipient: recipient,
                context: context
            ) == Self.vaultKey
        )
        let wrongContext = try V3EnrollmentVaultKeyWrapContext(
            vaultID: Self.vaultID,
            keyID: fixture.keyID,
            recipientDeviceID: fixture.joiner.publicIdentity.deviceID,
            transcriptDigest: Data(repeating: 0x99, count: 32)
        )
        #expect(throws: (any Error).self) {
            try openWrappedVaultKey(
                ciphertext,
                recipient: recipient,
                context: wrongContext
            )
        }
    }

    @Test
    func buildsOnlyTheExactComparedLocalToSharedTransition() throws {
        let fixture = try Fixture()
        let candidate = try V3EnrollmentOwnerTransitionBuilder().build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the compared device."
        )
        let body = candidate.verifiedManifest.envelope.content.manifest

        #expect(body.mode == .shared)
        #expect(body.keyID == fixture.keyID)
        #expect(body.entries == fixture.parent.envelope.content.manifest.entries)
        #expect(body.devices.count == 2)
        #expect(body.devices.filter { $0.role == .owner }.count == 1)
        #expect(body.wrappedKeys.map(\.deviceID) == body.devices.map(\.deviceID))
        #expect(candidate.transcriptDigest == fixture.transcript.digest)
        #expect(
            candidate.approval.candidateManifestDigest
                == candidate.verifiedManifest.envelopeDigest)

        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                candidate.manifestData,
                vaultKey: Self.vaultKey,
                trustAnchor: .verifiedParents([fixture.parent])
            )
        }
    }

    @Test
    func addsOneComparedDeviceToAnExistingSharedVault() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let shared = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the second device."
        )
        let third = try SoftwareEnrollmentSigner(
            vaultID: Self.vaultID,
            displayName: "Travel Mac",
            signingScalar: 0x41,
            wrappingScalar: 0x42
        )
        let enrollment = try AdditionalEnrollmentFixture(
            parent: shared.verifiedManifest,
            inviter: fixture.inviter,
            joiner: third,
            role: .owner
        )

        let candidate = try builder.build(
            state: enrollment.inviterState,
            parent: shared.verifiedManifest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the third device."
        )
        let parentBody = shared.verifiedManifest.envelope.content.manifest
        let body = candidate.verifiedManifest.envelope.content.manifest

        #expect(body.devices.count == parentBody.devices.count + 1)
        #expect(body.devices.contains(where: {
            $0.deviceID == third.publicIdentity.deviceID
                && $0.role == .owner
                && $0.status == .active
        }))
        #expect(parentBody.devices.allSatisfy(body.devices.contains))
        #expect(body.wrappedKeys.count == parentBody.wrappedKeys.count + 1)
        #expect(parentBody.wrappedKeys.allSatisfy(body.wrappedKeys.contains))
        #expect(candidate.approval.wrappedKeys.count == 1)
        #expect(
            candidate.approval.wrappedKeys[0].deviceID
                == third.publicIdentity.deviceID
        )
        #expect(body.entries == parentBody.entries)

        let wrapped = try #require(candidate.approval.wrappedKeys.first)
        let ciphertext = try #require(
            Base64URL.decodeCanonical(wrapped.ciphertext)
        )
        let context = try V3EnrollmentVaultKeyWrapContext(
            vaultID: Self.vaultID,
            keyID: fixture.keyID,
            recipientDeviceID: third.publicIdentity.deviceID,
            transcriptDigest: enrollment.transcript.digest
        )
        #expect(
            try openWrappedVaultKey(
                ciphertext,
                recipient: third.wrappingPrivateKey,
                context: context
            ) == Self.vaultKey
        )

        let preparedState = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: enrollment.invitation.digest,
            role: .inviter,
            phase: .publishingApproval,
            signedInvitation: enrollment.signedInvitation,
            signedJoinRequest: enrollment.signedJoinRequest,
            ownerApproval: candidate.approval
        )
        let rebuilt = try builder.rebuild(
            state: preparedState,
            parent: shared.verifiedManifest,
            vaultKey: Self.vaultKey,
            approval: candidate.approval
        )
        #expect(rebuilt == candidate)
    }

    @Test
    func sharedEnrollmentRejectsMembersAndExistingDevices() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let shared = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the second device."
        )
        let third = try SoftwareEnrollmentSigner(
            vaultID: Self.vaultID,
            displayName: "Travel Mac",
            signingScalar: 0x41,
            wrappingScalar: 0x42
        )
        let memberEnrollment = try AdditionalEnrollmentFixture(
            parent: shared.verifiedManifest,
            inviter: fixture.joiner,
            joiner: third,
            role: .member
        )
        #expect(
            throws: V3EnrollmentOwnerTransitionError
                .inviterIdentityMismatch
        ) {
            try builder.build(
                state: memberEnrollment.inviterState,
                parent: shared.verifiedManifest,
                vaultKey: Self.vaultKey,
                inviterIdentity: fixture.joiner,
                authorizationReason: "A member cannot approve enrollment."
            )
        }

        let duplicateEnrollment = try AdditionalEnrollmentFixture(
            parent: shared.verifiedManifest,
            inviter: fixture.inviter,
            joiner: fixture.joiner,
            role: .member
        )
        #expect(
            throws: V3EnrollmentOwnerTransitionError
                .joiningIdentityConflict
        ) {
            try builder.build(
                state: duplicateEnrollment.inviterState,
                parent: shared.verifiedManifest,
                vaultKey: Self.vaultKey,
                inviterIdentity: fixture.inviter,
                authorizationReason: "Do not enroll an existing device."
            )
        }
    }

    @Test
    func ordinaryCandidateBuilderPreservesSharedAuthorityExactly() throws {
        let fixture = try Fixture()
        let shared = try V3EnrollmentOwnerTransitionBuilder().build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the compared device."
        )
        let child = try V3ManifestCandidateBuilder().build(
            content: V3ManifestContent(
                parents: [Base64URL.encode(
                    shared.verifiedManifest.envelopeDigest
                )],
                manifest: shared.verifiedManifest.envelope.content.manifest
            ),
            vaultKey: Self.vaultKey,
            trustAnchor: .verifiedParents([
                shared.verifiedManifest
            ])
        )

        #expect(
            child.verified.envelope.content.manifest
                == shared.verifiedManifest.envelope.content.manifest
        )
        #expect(child.verified.envelope.authorizations.isEmpty)
    }

    @Test
    func preparedApprovalRebuildsTheExactCandidateWithoutResigning() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let candidate = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the compared device."
        )
        let preparedState = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            role: .inviter,
            phase: .publishingApproval,
            signedInvitation: fixture.signedInvitation,
            signedJoinRequest: fixture.signedJoinRequest,
            ownerApproval: candidate.approval
        )

        let rebuilt = try builder.rebuild(
            state: preparedState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            approval: candidate.approval
        )

        #expect(rebuilt.manifestData == candidate.manifestData)
        #expect(rebuilt.verifiedManifest == candidate.verifiedManifest)
        #expect(
            try V3EnrollmentPreparedOwnerApproval(
                canonicalBytes: candidate.approval.canonicalBytes
            ) == candidate.approval
        )
    }

    @Test
    func publishesManifestBeforeCheckpointAndConsumesApprovalLast() throws {
        let fixture = try Fixture()
        let stateStore = MemoryOwnerApprovalStateStore(
            state: fixture.inviterState
        )
        let exchange = V3EnrollmentExchangeCoordinator(
            mailbox: EmptyEnrollmentMailbox(),
            stateStore: stateStore
        )
        let proof = fixture.proof(head: fixture.parent)
        let observer = SequenceOwnerApprovalObserver([
            fixture.observation(proof: proof),
            fixture.observation(proof: proof),
        ])
        let objectStore = MemoryOwnerApprovalObjectStore()
        let checkpointStore = MemoryOwnerApprovalCheckpointStore(
            checkpoint: proof.checkpoint.canonicalBytes
        )
        let phases = RecordingOwnerApprovalPhases()
        let coordinator = V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectOwnerApprovalMutationOwner(),
            ancestryObserver: observer,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            exchange: exchange,
            phaseObserver: phases
        )

        let trusted = try coordinator.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            approvedTranscriptDigest: fixture.transcript.digest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            at: Self.activeTime,
            authorizationReason: "Approve the compared device."
        )

        #expect(trusted.envelope.content.manifest.mode == .shared)
        #expect(checkpointStore.checkpoint == trusted.checkpoint.canonicalBytes)
        #expect(
            objectStore.events == [
                "stage-manifest", "read-staged-manifest",
                "publish-manifest", "read-manifest",
            ])
        #expect(
            phases.phases == [
                .approvalPrepared, .manifestStaged,
                .repositoryStateRechecked, .manifestPublished,
                .checkpointAdvanced, .ceremonyConsumed,
            ])
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: stateStore.state
            ).phase == .consumed
        )
    }

    @Test
    func retryAfterCheckpointAdvancementOnlyConsumesTheExactApproval() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let candidate = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the compared device."
        )
        let preparedState = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            role: .inviter,
            phase: .publishingApproval,
            signedInvitation: fixture.signedInvitation,
            signedJoinRequest: fixture.signedJoinRequest,
            ownerApproval: candidate.approval
        )
        let stateStore = MemoryOwnerApprovalStateStore(
            state: preparedState
        )
        let proof = V3ManifestAncestryProof(
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: candidate.verifiedManifest
            ),
            manifests: [fixture.parent, candidate.verifiedManifest],
            heads: [candidate.verifiedManifest]
        )
        let objectStore = MemoryOwnerApprovalObjectStore()
        let checkpointStore = MemoryOwnerApprovalCheckpointStore(
            checkpoint: proof.checkpoint.canonicalBytes
        )
        let coordinator = V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectOwnerApprovalMutationOwner(),
            ancestryObserver: SequenceOwnerApprovalObserver([
                fixture.observation(proof: proof)
            ]),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: EmptyEnrollmentMailbox(),
                stateStore: stateStore
            )
        )

        let trusted = try coordinator.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            approvedTranscriptDigest: fixture.transcript.digest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            at: fixture.invitation.expiresAt + 1,
            authorizationReason: "This retry must not sign again."
        )

        #expect(trusted.verifiedManifest == candidate.verifiedManifest)
        #expect(objectStore.events.isEmpty)
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: stateStore.state
            ).phase == .consumed
        )
    }

    @Test
    func retryConsumesApprovalAfterASecondCheckpointAdvance() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let candidate = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the compared device."
        )
        let descendant = try fixture.descendant(of: candidate)
        let preparedState = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            role: .inviter,
            phase: .publishingApproval,
            signedInvitation: fixture.signedInvitation,
            signedJoinRequest: fixture.signedJoinRequest,
            ownerApproval: candidate.approval
        )
        let stateStore = MemoryOwnerApprovalStateStore(
            state: preparedState
        )
        let proof = V3ManifestAncestryProof(
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: descendant
            ),
            manifests: [
                fixture.parent, candidate.verifiedManifest, descendant,
            ],
            heads: [descendant]
        )
        let objectStore = MemoryOwnerApprovalObjectStore()
        let coordinator = V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectOwnerApprovalMutationOwner(),
            ancestryObserver: SequenceOwnerApprovalObserver([
                fixture.observation(proof: proof)
            ]),
            objectStore: objectStore,
            checkpointStore: MemoryOwnerApprovalCheckpointStore(
                checkpoint: proof.checkpoint.canonicalBytes
            ),
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: EmptyEnrollmentMailbox(),
                stateStore: stateStore
            )
        )

        let trusted = try coordinator.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            approvedTranscriptDigest: fixture.transcript.digest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            at: fixture.invitation.expiresAt + 1,
            authorizationReason: "This retry must not sign again."
        )

        #expect(trusted.verifiedManifest == descendant)
        #expect(objectStore.events.isEmpty)
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: stateStore.state
            ).phase == .consumed
        )
    }

    @Test
    func retryDoesNotCountAnExactPublishedCandidateTwice() throws {
        let fixture = try Fixture()
        let candidate = try V3EnrollmentOwnerTransitionBuilder().build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the compared device."
        )
        let preparedState = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            role: .inviter,
            phase: .publishingApproval,
            signedInvitation: fixture.signedInvitation,
            signedJoinRequest: fixture.signedJoinRequest,
            ownerApproval: candidate.approval
        )
        let stateStore = MemoryOwnerApprovalStateStore(
            state: preparedState
        )
        let proof = fixture.proof(head: fixture.parent)
        let saturatedObservation = V3ManifestAncestryObservation(
            proof: proof,
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount:
                    V3ManifestRepositoryLimits.standard
                    .maximumManifestObjects,
                maximumHistoryDepth: 0,
                totalManifestBytes:
                    V3ManifestRepositoryLimits.standard
                    .maximumTotalManifestBytes,
                referencedEntryObjectCount: 0,
                totalEntryBytes: 0
            )
        )
        let objectStore = MemoryOwnerApprovalObjectStore(
            publishedManifest: candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest
        )
        let checkpointStore = MemoryOwnerApprovalCheckpointStore(
            checkpoint: proof.checkpoint.canonicalBytes
        )
        let coordinator = V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectOwnerApprovalMutationOwner(),
            ancestryObserver: SequenceOwnerApprovalObserver([
                saturatedObservation, saturatedObservation,
            ]),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: EmptyEnrollmentMailbox(),
                stateStore: stateStore
            )
        )

        let trusted = try coordinator.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            approvedTranscriptDigest: fixture.transcript.digest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            at: Self.activeTime,
            authorizationReason: "This retry must not sign again."
        )

        #expect(checkpointStore.checkpoint == trusted.checkpoint.canonicalBytes)
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: stateStore.state
            ).phase == .consumed
        )
    }

    @Test
    func sharedEnrollmentRetryAdvancesPastAnAlreadyPublishedCandidate() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let shared = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the second device."
        )
        let third = try SoftwareEnrollmentSigner(
            vaultID: Self.vaultID,
            displayName: "Travel Mac",
            signingScalar: 0x41,
            wrappingScalar: 0x42
        )
        let enrollment = try AdditionalEnrollmentFixture(
            parent: shared.verifiedManifest,
            inviter: fixture.inviter,
            joiner: third,
            role: .member
        )
        let candidate = try builder.build(
            state: enrollment.inviterState,
            parent: shared.verifiedManifest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the third device."
        )
        let preparedState = try V3EnrollmentCeremonyState(
            vaultID: Self.vaultID,
            invitationDigest: enrollment.invitation.digest,
            role: .inviter,
            phase: .publishingApproval,
            signedInvitation: enrollment.signedInvitation,
            signedJoinRequest: enrollment.signedJoinRequest,
            ownerApproval: candidate.approval
        )
        let stateStore = MemoryOwnerApprovalStateStore(
            state: preparedState
        )
        let proof = V3ManifestAncestryProof(
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: shared.verifiedManifest
            ),
            manifests: [
                shared.verifiedManifest,
                candidate.verifiedManifest,
            ],
            heads: [candidate.verifiedManifest]
        )
        let observation = fixture.observation(proof: proof)
        let objectStore = MemoryOwnerApprovalObjectStore(
            publishedManifest: candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest
        )
        let checkpointStore = MemoryOwnerApprovalCheckpointStore(
            checkpoint: proof.checkpoint.canonicalBytes
        )
        let coordinator = V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectOwnerApprovalMutationOwner(),
            ancestryObserver: SequenceOwnerApprovalObserver([
                observation, observation,
            ]),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: EmptyEnrollmentMailbox(),
                stateStore: stateStore
            )
        )

        let trusted = try coordinator.approve(
            vaultID: Self.vaultID,
            invitationDigest: enrollment.invitation.digest,
            approvedTranscriptDigest: enrollment.transcript.digest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            at: enrollment.invitation.expiresAt + 1,
            authorizationReason: "This retry must not sign again."
        )

        #expect(trusted.verifiedManifest == candidate.verifiedManifest)
        #expect(checkpointStore.checkpoint == trusted.checkpoint.canonicalBytes)
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: stateStore.state
            ).phase == .consumed
        )
    }

    @Test
    func sharedEnrollmentCanApproveTheAuthenticatedHeadBeyondCheckpoint() throws {
        let fixture = try Fixture()
        let builder = V3EnrollmentOwnerTransitionBuilder()
        let shared = try builder.build(
            state: fixture.inviterState,
            parent: fixture.parent,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            authorizationReason: "Approve the second device."
        )
        let authenticatedHead = try V3ManifestCandidateBuilder().build(
            content: V3ManifestContent(
                parents: [Base64URL.encode(
                    shared.verifiedManifest.envelopeDigest
                )],
                manifest: shared.verifiedManifest.envelope.content.manifest
            ),
            vaultKey: Self.vaultKey,
            trustAnchor: .verifiedParents([shared.verifiedManifest])
        ).verified
        let third = try SoftwareEnrollmentSigner(
            vaultID: Self.vaultID,
            displayName: "Travel Mac",
            signingScalar: 0x41,
            wrappingScalar: 0x42
        )
        let enrollment = try AdditionalEnrollmentFixture(
            parent: authenticatedHead,
            inviter: fixture.inviter,
            joiner: third,
            role: .member
        )
        let stateStore = MemoryOwnerApprovalStateStore(
            state: enrollment.inviterState
        )
        let proof = V3ManifestAncestryProof(
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: shared.verifiedManifest
            ),
            manifests: [shared.verifiedManifest, authenticatedHead],
            heads: [authenticatedHead]
        )
        let observation = fixture.observation(proof: proof)
        let checkpointStore = MemoryOwnerApprovalCheckpointStore(
            checkpoint: proof.checkpoint.canonicalBytes
        )
        let coordinator = V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectOwnerApprovalMutationOwner(),
            ancestryObserver: SequenceOwnerApprovalObserver([
                observation, observation,
            ]),
            objectStore: MemoryOwnerApprovalObjectStore(),
            checkpointStore: checkpointStore,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: EmptyEnrollmentMailbox(),
                stateStore: stateStore
            )
        )

        let trusted = try coordinator.approve(
            vaultID: Self.vaultID,
            invitationDigest: enrollment.invitation.digest,
            approvedTranscriptDigest: enrollment.transcript.digest,
            vaultKey: Self.vaultKey,
            inviterIdentity: fixture.inviter,
            at: Self.activeTime,
            authorizationReason: "Approve the authenticated current head."
        )

        #expect(
            trusted.envelope.content.parents
                == [Base64URL.encode(authenticatedHead.envelopeDigest)]
        )
        #expect(checkpointStore.checkpoint == trusted.checkpoint.canonicalBytes)
    }
}

private struct Fixture {
    let keyID: V3VaultKeyID
    let parent: V3VerifiedManifest
    let inviter: SoftwareEnrollmentSigner
    let joiner: SoftwareEnrollmentSigner
    let invitation: V3EnrollmentInvitation
    let signedInvitation: V3SignedEnrollmentInvitation
    let signedJoinRequest: V3SignedEnrollmentJoinRequest
    let transcript: V3EnrollmentTranscript
    let inviterState: V3EnrollmentCeremonyState

    init() throws {
        keyID = try V3VaultKeyID.derive(
            vaultKey: V3EnrollmentOwnerTransitionTests.vaultKey,
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID
        )
        parent = try V3LocalGenesisBuilder().build(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            entryIDs: [],
            sourceEntries: [],
            vaultKey: V3EnrollmentOwnerTransitionTests.vaultKey
        ).verifiedManifest
        inviter = try SoftwareEnrollmentSigner(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            displayName: "Existing Mac",
            signingScalar: 0x21,
            wrappingScalar: 0x22
        )
        joiner = try SoftwareEnrollmentSigner(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            displayName: "New Mac",
            signingScalar: 0x31,
            wrappingScalar: 0x32
        )
        invitation = try V3EnrollmentInvitation(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            vaultFormatVersion: 3,
            parentManifestDigest: parent.envelopeDigest,
            invitingDevice: inviter.publicIdentity,
            invitedRole: .member,
            nonce: Data(repeating: 0x41, count: 32),
            expiresAt: V3EnrollmentOwnerTransitionTests.activeTime + 300
        )
        let authenticator = V3EnrollmentMessageAuthenticator()
        signedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Create invitation."
        )
        let verifiedInvitation = try authenticator.verify(signedInvitation)
        let joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0x42, count: 32)
        )
        signedJoinRequest = try authenticator.sign(
            joinRequest,
            answering: verifiedInvitation,
            using: joiner,
            reason: "Join vault."
        )
        transcript = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: joinRequest
        )
        inviterState = try V3EnrollmentCeremonyState(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            invitationDigest: invitation.digest,
            role: .inviter,
            phase: .awaitingComparison,
            signedInvitation: signedInvitation,
            signedJoinRequest: signedJoinRequest
        )
    }

    func proof(head: V3VerifiedManifest) -> V3ManifestAncestryProof {
        V3ManifestAncestryProof(
            checkpoint: try! V3ManifestCheckpoint(
                verifiedManifest: head
            ),
            manifests: [parent],
            heads: [head]
        )
    }

    func observation(
        proof: V3ManifestAncestryProof
    ) -> V3ManifestAncestryObservation {
        V3ManifestAncestryObservation(
            proof: proof,
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount: proof.manifests.count,
                maximumHistoryDepth: 0,
                totalManifestBytes: proof.manifests.reduce(0) {
                    $0 + $1.envelope.canonicalBytes.count
                },
                referencedEntryObjectCount: 0,
                totalEntryBytes: 0
            )
        )
    }

    func descendant(
        of candidate: V3EnrollmentOwnerTransitionCandidate
    ) throws -> V3VerifiedManifest {
        let candidateValue = try CanonicalJSON.parse(
            candidate.manifestData
        )
        guard let envelope = candidateValue.objectValue,
            let candidateContent = envelope.first(where: {
                $0.0 == "content"
            })?.1.objectValue,
            let manifest = candidateContent.first(where: {
                $0.0 == "manifest"
            })?.1
        else {
            throw V3EnrollmentOwnerTransitionError.invalidAuthorization
        }
        let content: CanonicalJSONValue = .object([
            (
                "parents",
                .array([
                    .string(
                        Base64URL.encode(
                            candidate.verifiedManifest.envelopeDigest
                        ))
                ])
            ),
            ("manifest", manifest),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            vaultKey: V3EnrollmentOwnerTransitionTests.vaultKey
        )
        let data = CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-manifest-envelope")),
                ("version", .integer(3)),
                ("content", content),
                (
                    "authentication",
                    .object([
                        (
                            "algorithm",
                            .string("HKDF-SHA256+HMAC-SHA256")
                        ),
                        ("tag", .string(Base64URL.encode(tag))),
                    ])
                ),
                ("authorizations", .array([])),
            ]))
        return try V3ManifestAuthenticator().verify(
            data,
            vaultKey: V3EnrollmentOwnerTransitionTests.vaultKey,
            trustAnchor: .verifiedParents([
                candidate.verifiedManifest
            ])
        )
    }
}

private struct AdditionalEnrollmentFixture {
    let invitation: V3EnrollmentInvitation
    let signedInvitation: V3SignedEnrollmentInvitation
    let signedJoinRequest: V3SignedEnrollmentJoinRequest
    let transcript: V3EnrollmentTranscript
    let inviterState: V3EnrollmentCeremonyState

    init(
        parent: V3VerifiedManifest,
        inviter: SoftwareEnrollmentSigner,
        joiner: SoftwareEnrollmentSigner,
        role: V3DeviceRole
    ) throws {
        invitation = try V3EnrollmentInvitation(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            parentManifestDigest: parent.envelopeDigest,
            invitingDevice: inviter.publicIdentity,
            invitedRole: role,
            nonce: Data(repeating: 0x51, count: 32),
            expiresAt: V3EnrollmentOwnerTransitionTests.activeTime + 300
        )
        let authenticator = V3EnrollmentMessageAuthenticator()
        signedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Create another invitation."
        )
        let verifiedInvitation = try authenticator.verify(signedInvitation)
        let request = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0x52, count: 32)
        )
        signedJoinRequest = try authenticator.sign(
            request,
            answering: verifiedInvitation,
            using: joiner,
            reason: "Join the shared vault."
        )
        transcript = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: request
        )
        inviterState = try V3EnrollmentCeremonyState(
            vaultID: V3EnrollmentOwnerTransitionTests.vaultID,
            invitationDigest: invitation.digest,
            role: .inviter,
            phase: .awaitingComparison,
            signedInvitation: signedInvitation,
            signedJoinRequest: signedJoinRequest
        )
    }
}

private struct SoftwareEnrollmentSigner: V3EnrollmentMessageSigning {
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let signingPrivateKey: P256.Signing.PrivateKey
    let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    init(
        vaultID: String,
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        signingPrivateKey = try P256.Signing.PrivateKey(
            rawRepresentation: privateKeyBytes(signingScalar)
        )
        wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: privateKeyBytes(wrappingScalar)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey:
                signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey:
                wrappingPrivateKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingPrivateKey.signature(for: input).rawRepresentation
    }
}

private func privateKeyBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}

private func wrappingDomainInput(
    _ domain: String,
    context: V3EnrollmentVaultKeyWrapContext
) -> Data {
    var result = Data(domain.utf8)
    result.append(0)
    result.append(context.canonicalBytes)
    return result
}

private func openWrappedVaultKey(
    _ bytes: Data,
    recipient: P256.KeyAgreement.PrivateKey,
    context: V3EnrollmentVaultKeyWrapContext
) throws -> Data {
    let framed = try V3EnrollmentWrappedVaultKeyCiphertext(
        combinedBytes: bytes
    )
    let ephemeral = try P256.KeyAgreement.PublicKey(
        x963Representation: framed.ephemeralPublicKey
    )
    let shared = try recipient.sharedSecretFromKeyAgreement(with: ephemeral)
    let key = shared.x963DerivedSymmetricKey(
        using: SHA256.self,
        sharedInfo: wrappingDomainInput(
            "work.tvr.key/v3/enrollment-wrapped-key-kek/v1",
            context: context
        ),
        outputByteCount: 32
    )
    let sealed = try AES.GCM.SealedBox(
        nonce: AES.GCM.Nonce(data: framed.nonce),
        ciphertext: framed.ciphertext,
        tag: framed.tag
    )
    return try AES.GCM.open(
        sealed,
        using: key,
        authenticating: wrappingDomainInput(
            "work.tvr.key/v3/enrollment-wrapped-key/v1",
            context: context
        )
    )
}

private final class MemoryOwnerApprovalStateStore:
    V3EnrollmentCeremonyStateStoring,
    @unchecked Sendable
{
    var state: Data

    init(state: V3EnrollmentCeremonyState) {
        self.state = state.canonicalBytes
    }

    func loadState(vaultID _: String, invitationDigest _: Data) throws -> Data? {
        state
    }

    func replaceState(
        _ state: Data,
        expectedState: Data?,
        vaultID _: String,
        invitationDigest _: Data
    ) throws {
        guard self.state == expectedState else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        self.state = state
    }
}

private struct EmptyEnrollmentMailbox: V3EnrollmentMailboxStoring {
    func invitationDigests(maximumCount _: Int) throws -> V3EnrollmentMailboxListing {
        .available(digests: [], objectCount: 0)
    }
    func readInvitation(digest _: Data) throws -> V3RepositoryObjectRead { .unavailable }
    func publishInvitation(_: Data) throws {}
    func joinRequestDigests(
        invitationDigest _: Data,
        maximumCount _: Int
    ) throws -> V3EnrollmentMailboxListing {
        .available(digests: [], objectCount: 0)
    }
    func readJoinRequest(
        invitationDigest _: Data,
        joinRequestDigest _: Data
    ) throws -> V3RepositoryObjectRead { .unavailable }
    func publishJoinRequest(_: Data, invitationDigest _: Data) throws {}
}

private final class SequenceOwnerApprovalObserver:
    V3ManifestAncestryObserving,
    @unchecked Sendable
{
    private var observations: [V3ManifestAncestryObservation]

    init(_ observations: [V3ManifestAncestryObservation]) {
        self.observations = observations
    }

    func observeAncestry() throws -> V3ManifestAncestryObservation {
        guard !observations.isEmpty else {
            throw V3EnrollmentOwnerApprovalError.invalidRepositoryState
        }
        return observations.removeFirst()
    }
}

private final class MemoryOwnerApprovalObjectStore:
    V3ImmutableObjectPublishing,
    @unchecked Sendable
{
    var events: [String] = []
    private var staged: Data?
    private var published: [Data: Data] = [:]

    init(publishedManifest: Data? = nil, digest: Data? = nil) {
        if let publishedManifest, let digest {
            published[digest] = publishedManifest
        }
    }

    func manifestDigests(maximumCount _: Int) throws -> V3RepositoryDirectoryListing {
        .available(digests: Array(published.keys), objectCount: published.count)
    }
    func readManifest(digest: Data, maximumBytes _: Int) throws -> V3RepositoryObjectRead {
        events.append("read-manifest")
        return published[digest].map(V3RepositoryObjectRead.available) ?? .unavailable
    }
    func readEntry(entryID _: String, digest _: Data, maximumBytes _: Int) throws
        -> V3RepositoryObjectRead
    { .unavailable }
    func readStagedEntry(
        entryID _: String, digest _: Data, operationID _: VaultTransactionOperationID,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead { .unavailable }
    func readStagedManifest(
        digest _: Data, operationID _: VaultTransactionOperationID, maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        events.append("read-staged-manifest")
        return staged.map(V3RepositoryObjectRead.available) ?? .unavailable
    }
    func stageEntry(
        _: Data, entryID _: String, digest _: Data, operationID _: VaultTransactionOperationID
    ) throws {}
    func stageManifest(_ data: Data, digest _: Data, operationID _: VaultTransactionOperationID)
        throws
    {
        events.append("stage-manifest")
        staged = data
    }
    func publishStagedEntry(
        _: Data, entryID _: String, digest _: Data, operationID _: VaultTransactionOperationID
    ) throws {}
    func publishStagedManifest(
        _ data: Data, digest: Data, operationID _: VaultTransactionOperationID
    )
        throws
    {
        events.append("publish-manifest")
        published[digest] = data
    }
    func removeStagedEntry(
        _: Data, entryID _: String, digest _: Data, operationID _: VaultTransactionOperationID
    ) throws {}
    func removeStagedManifest(
        _ data: Data, digest _: Data, operationID _: VaultTransactionOperationID
    ) throws {
        if staged == data { staged = nil }
    }
    func removeEmptyTransactionDirectories(
        operationID _: VaultTransactionOperationID, entryIDs _: [String]
    ) throws {}
}

private final class MemoryOwnerApprovalCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    var checkpoint: Data

    init(checkpoint: Data) { self.checkpoint = checkpoint }

    func loadCheckpoint(vaultID _: String) throws -> Data? { checkpoint }
    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID _: String
    ) throws {
        guard self.checkpoint == expectedCheckpoint else {
            throw V3ManifestCheckpointStoreError.conflict
        }
        self.checkpoint = checkpoint
    }
}

private struct DirectOwnerApprovalMutationOwner: VaultTransactionMutationOwning {
    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        try mutation(
            VaultTransactionMutationContext(
                operationID: try VaultTransactionOperationID(
                    validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
                ),
                kind: kind
            ))
    }
}

private final class RecordingOwnerApprovalPhases:
    V3EnrollmentOwnerApprovalPhaseObserving,
    @unchecked Sendable
{
    var phases: [V3EnrollmentOwnerApprovalPhase] = []
    func didReach(
        _ phase: V3EnrollmentOwnerApprovalPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        phases.append(phase)
    }
}
