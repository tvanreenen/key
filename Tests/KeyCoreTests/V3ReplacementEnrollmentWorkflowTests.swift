import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3ReplacementEnrollmentWorkflowTests {
    @Test
    func reviewRequiresAuthenticatedRevocation() throws {
        let fixture = try Fixture()

        #expect(try fixture.workflow.review() == fixture.review)
        #expect(fixture.authority.classifyCount == 1)

        fixture.authority.classification = .active(
            fixture.target,
            authority: fixture.review.authority
        )
        #expect(
            throws: V3ReplacementEnrollmentWorkflowError.deviceStillActive
        ) {
            _ = try fixture.workflow.review()
        }

        fixture.authority.classification = .unrecognized(
            fixture.target,
            authority: fixture.review.authority
        )
        #expect(
            throws: V3ReplacementEnrollmentWorkflowError
                .identityUnrecognized
        ) {
            _ = try fixture.workflow.review()
        }
    }

    @Test
    func confirmedCurrentReviewBeginsCoordinatedCleanup() throws {
        let fixture = try Fixture()

        let result = try fixture.workflow.replace(
            confirmedReviewDigest: fixture.review.digest
        )

        #expect(result == fixture.completed)
        #expect(fixture.coordinator.begunReviews == [fixture.review])
        #expect(fixture.coordinator.resumeCount == 0)
        #expect(fixture.authority.classifyCount == 1)
    }

    @Test
    func preparedIntentUsesNewlyReviewedAuthority() throws {
        let fixture = try Fixture()
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: fixture.review
        ).canonicalBytes
        let newerCheckpoint = try V3ManifestCheckpoint(
            vaultID: Fixture.vaultID,
            envelopeDigest: Data(repeating: 0x44, count: 32)
        )
        let newerReview = try V3ReplacementEnrollmentReview(
            classification: .revoked(
                fixture.target,
                authority: .trustedCheckpoint(newerCheckpoint)
            )
        )
        fixture.authority.classification = .revoked(
            fixture.target,
            authority: newerReview.authority
        )
        fixture.coordinator.result = V3ReplacementEnrollmentIntent(
            review: newerReview,
            phase: .checkpointDeleted
        )

        let result = try fixture.workflow.replace(
            confirmedReviewDigest: newerReview.digest
        )

        #expect(result.review == newerReview)
        #expect(fixture.coordinator.begunReviews == [newerReview])
        #expect(fixture.authority.classifyCount == 1)
    }

    @Test
    func destructiveRetryUsesStoredReviewWithoutDeletedIdentity() throws {
        let fixture = try Fixture()
        let interrupted = V3ReplacementEnrollmentIntent(
            review: fixture.review,
            phase: .identityDeletionStarted
        )
        fixture.intents.storage = interrupted.canonicalBytes
        fixture.targets.target = nil
        fixture.coordinator.result = fixture.completed

        let result = try fixture.workflow.replace(
            confirmedReviewDigest: fixture.review.digest
        )

        #expect(result == fixture.completed)
        #expect(fixture.coordinator.resumeCount == 1)
        #expect(fixture.coordinator.begunReviews.isEmpty)
        #expect(fixture.authority.classifyCount == 0)
    }

    @Test
    func destructiveRetryRecoversStoredReviewWithoutDeletedIdentity() throws {
        let fixture = try Fixture()
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: fixture.review,
            phase: .identityDeleted
        ).canonicalBytes
        fixture.targets.target = nil

        let review = try fixture.workflow.review()

        #expect(review == fixture.review)
        #expect(fixture.authority.classifyCount == 0)
    }

    @Test
    func preparedIntentStillReobservesCurrentAuthorityForReview() throws {
        let fixture = try Fixture()
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: fixture.review
        ).canonicalBytes
        let newerCheckpoint = try V3ManifestCheckpoint(
            vaultID: Fixture.vaultID,
            envelopeDigest: Data(repeating: 0x55, count: 32)
        )
        let newerReview = try V3ReplacementEnrollmentReview(
            classification: .revoked(
                fixture.target,
                authority: .trustedCheckpoint(newerCheckpoint)
            )
        )
        fixture.authority.classification = .revoked(
            fixture.target,
            authority: newerReview.authority
        )

        let review = try fixture.workflow.review()

        #expect(review == newerReview)
        #expect(fixture.authority.classifyCount == 1)
    }

    @Test
    func destructiveRetryChecksConfirmationBeforeResuming() throws {
        let fixture = try Fixture()
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: fixture.review,
            phase: .identityDeleted
        ).canonicalBytes
        fixture.targets.target = nil

        #expect(
            throws: V3ReplacementEnrollmentWorkflowError
                .invalidConfirmation
        ) {
            _ = try fixture.workflow.replace(
                confirmedReviewDigest: Data(repeating: 0xFF, count: 32)
            )
        }
        #expect(fixture.coordinator.resumeCount == 0)
    }

    @Test
    func missingIdentityAndIntentCannotStartReplacement() throws {
        let fixture = try Fixture()
        fixture.targets.target = nil

        #expect(
            throws: V3ReplacementEnrollmentWorkflowError.noLocalIdentity
        ) {
            _ = try fixture.workflow.replace(
                confirmedReviewDigest: fixture.review.digest
            )
        }
        #expect(fixture.coordinator.begunReviews.isEmpty)
        #expect(fixture.coordinator.resumeCount == 0)
    }

    @Test
    func helperJoinExposesExactReviewThenConfirmsCleanup() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let owner = WorkflowMutationOwner()
        let session = WorkflowVaultSession()
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: owner,
            validateJoinInvitation: { digest, _ in
                #expect(digest == Data(repeating: 0x11, count: 32))
            },
            replacementService: service,
            vaultSession: session,
            configuredVaultID: Fixture.vaultID
        )

        let reviewResponse = handler.handle(
            .share(.join(
                invitationID: String(repeating: "11", count: 32),
                deviceName: "Replacement Mac"
            ))
        )
        let projected = try #require(
            reviewResponse.deviceReplacementReview
        )
        #expect(projected.vaultID == Fixture.vaultID)
        #expect(projected.checkpointID == String(repeating: "33", count: 32))
        #expect(projected.confirmationToken == v3LowercaseHex(
            v3ReplacementEnrollmentConfirmationDigest(
                reviewDigest: fixture.review.digest,
                invitationDigest: Data(repeating: 0x11, count: 32)
            )
        ))
        #expect(projected.replacedDevice.deviceID
            == fixture.target.identity.deviceID)
        #expect(projected.replacedDevice.status == .revoked)
        #expect(projected.authorityKind == .trustedCheckpoint)
        #expect(projected.authorizingDevice == nil)
        #expect(projected.revocationManifestID == nil)
        #expect(owner.kinds == [.catchUpVault])

        let replaceResponse = handler.handle(
            .share(.replaceCurrentDevice(
                invitationID: String(repeating: "11", count: 32),
                confirmationToken: projected.confirmationToken
            ))
        )

        #expect(replaceResponse.exitCode == EXIT_SUCCESS)
        #expect(service.confirmations == [fixture.review.digest])
        #expect(session.lockCount == 1)
        #expect(owner.kinds == [.catchUpVault])
    }

    @Test
    func helperJoinValidatesTheInvitationBeforeOfferingCleanup() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            validateJoinInvitation: { _, _ in
                throw V3EnrollmentMailboxError.invalidMessage
            },
            replacementService: service,
            configuredVaultID: Fixture.vaultID
        )

        let response = handler.handle(.share(.join(
            invitationID: String(repeating: "11", count: 32),
            deviceName: "Replacement Mac"
        )))

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(response.errorMessage?.contains("mailbox message") == true)
        #expect(service.reviewCount == 0)
    }

    @Test
    func helperRevalidatesInvitationBeforeCleanupAfterPromptExpiry() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let expiresAt: UInt64 = 1_900_000_000
        let clock = WorkflowClock(unixTime: expiresAt)
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let owner = WorkflowMutationOwner()
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            now: {
                Date(timeIntervalSince1970: TimeInterval(clock.unixTime))
            },
            mutationOwner: owner,
            validateJoinInvitation: { _, unixTime in
                guard unixTime <= expiresAt else {
                    throw V3EnrollmentProtocolError.expired
                }
            },
            replacementService: service,
            configuredVaultID: Fixture.vaultID
        )
        let request = KeyServiceRequest.share(.join(
            invitationID: String(repeating: "11", count: 32),
            deviceName: "Replacement Mac"
        ))

        let reviewResponse = handler.handle(request)
        #expect(reviewResponse.deviceReplacementReview != nil)
        #expect(service.reviewCount == 1)

        clock.unixTime = expiresAt + 1
        let expiredResponse = handler.handle(request)

        #expect(expiredResponse.exitCode == EXIT_FAILURE)
        #expect(expiredResponse.errorMessage?.contains("expired") == true)
        #expect(service.reviewCount == 1)
        #expect(service.confirmations.isEmpty)
        #expect(owner.kinds == [.catchUpVault, .catchUpVault])
    }

    @Test
    func helperRejectsInvitationSubstitutionAtCleanupBoundary() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            validateJoinInvitation: { _, _ in },
            replacementService: service,
            configuredVaultID: Fixture.vaultID
        )
        let selectedInvitationID = String(repeating: "11", count: 32)
        let substitutedInvitationID = String(repeating: "22", count: 32)
        let reviewResponse = handler.handle(.share(.join(
            invitationID: selectedInvitationID,
            deviceName: "Replacement Mac"
        )))
        let review = try #require(
            reviewResponse.deviceReplacementReview
        )

        let response = handler.handle(.share(.replaceCurrentDevice(
            invitationID: substitutedInvitationID,
            confirmationToken: review.confirmationToken
        )))

        #expect(response.errorCode == .invalidUsage)
        #expect(service.confirmations.isEmpty)
    }

    @Test
    func helperRejectsInvitationExpiryAtCleanupBoundary() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let expiresAt: UInt64 = 1_900_000_000
        let clock = WorkflowClock(unixTime: expiresAt)
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            now: {
                Date(timeIntervalSince1970: TimeInterval(clock.unixTime))
            },
            mutationOwner: WorkflowMutationOwner(),
            validateJoinInvitation: { _, unixTime in
                guard unixTime <= expiresAt else {
                    throw V3EnrollmentProtocolError.expired
                }
            },
            replacementService: service,
            configuredVaultID: Fixture.vaultID
        )
        let invitationID = String(repeating: "11", count: 32)
        let reviewResponse = handler.handle(.share(.join(
            invitationID: invitationID,
            deviceName: "Replacement Mac"
        )))
        let review = try #require(
            reviewResponse.deviceReplacementReview
        )
        clock.unixTime = expiresAt + 1

        let response = handler.handle(.share(.replaceCurrentDevice(
            invitationID: invitationID,
            confirmationToken: review.confirmationToken
        )))

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(response.errorMessage?.contains("expired") == true)
        #expect(service.confirmations.isEmpty)
    }

    @Test
    func destructiveCleanupResumeDoesNotRequireInvitationAvailability()
        throws
    {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            validateJoinInvitation: { _, _ in
                throw V3EnrollmentProtocolError.expired
            },
            replacementService: service,
            configuredVaultID: Fixture.vaultID,
            replacementAdmissionState: .cleanupPending
        )

        let response = handler.handle(.share(.replaceCurrentDevice(
            invitationID: String(repeating: "11", count: 32),
            confirmationToken: v3LowercaseHex(fixture.review.digest)
        )))

        #expect(response.exitCode == EXIT_SUCCESS)
        #expect(service.confirmations == [fixture.review.digest])
    }

    @Test
    func preparedCleanupStillRequiresInvitationAvailability() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            validateJoinInvitation: { _, _ in
                throw V3EnrollmentProtocolError.expired
            },
            replacementService: service,
            configuredVaultID: Fixture.vaultID,
            replacementAdmissionState: .cleanupPrepared
        )

        let response = handler.handle(.share(.replaceCurrentDevice(
            invitationID: String(repeating: "11", count: 32),
            confirmationToken: v3LowercaseHex(fixture.review.digest)
        )))

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(response.errorMessage?.contains("expired") == true)
        #expect(service.confirmations.isEmpty)
    }

    @Test
    func helperRejectsNoncanonicalReplacementTokenBeforeCleanup() throws {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            replacementService: service
        )

        let response = handler.handle(
            .share(.replaceCurrentDevice(
                invitationID: String(repeating: "11", count: 32),
                confirmationToken: String(repeating: "A", count: 64)
            ))
        )

        #expect(response.errorCode == .invalidUsage)
        #expect(service.confirmations.isEmpty)
    }

    @Test
    func admissionClassifiesResumableCleanupAndConsumesExactIntent() throws {
        let fixture = try Fixture()
        let admission = V3ReplacementEnrollmentAdmission(
            intentStore: fixture.intents
        )
        #expect(try admission.state(vaultID: Fixture.vaultID) == .inactive)
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: fixture.review,
            phase: .prepared
        ).canonicalBytes
        #expect(
            try admission.state(vaultID: Fixture.vaultID)
                == .cleanupPrepared
        )
        for phase in [
            V3ReplacementEnrollmentIntentPhase.identityDeletionStarted,
            .identityDeleted,
        ] {
            fixture.intents.storage = V3ReplacementEnrollmentIntent(
                review: fixture.review,
                phase: phase
            ).canonicalBytes
            #expect(
                try admission.state(vaultID: Fixture.vaultID)
                    == .cleanupPending
            )
        }

        fixture.intents.storage = fixture.completed.canonicalBytes
        #expect(
            try admission.state(vaultID: Fixture.vaultID)
                == .enrollmentPending
        )

        try admission.consumeCompletedIntent(vaultID: Fixture.vaultID)

        #expect(fixture.intents.storage == nil)
        #expect(
            try admission.state(vaultID: Fixture.vaultID) == .inactive
        )
        try admission.consumeCompletedIntent(vaultID: Fixture.vaultID)
    }

    @Test
    func interruptedCleanupFencesVaultWorkButKeepsResumeAvailable()
        throws
    {
        let fixture = try Fixture()
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let service = WorkflowService(
            review: fixture.review,
            result: fixture.completed
        )
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            validateJoinInvitation: { _, _ in
                throw V3EnrollmentProtocolError.expired
            },
            replacementService: service,
            configuredVaultID: Fixture.vaultID,
            replacementAdmissionState: .cleanupPending
        )

        let blocked = handler.handle(.list)
        #expect(blocked.errorMessage?.contains(
            "replacement cleanup is still in progress"
        ) == true)

        let malformedJoin = handler.handle(.share(.join(
            invitationID: String(repeating: "A", count: 64),
            deviceName: "Replacement Mac"
        )))
        #expect(malformedJoin.errorCode == .invalidUsage)

        let join = handler.handle(.share(.join(
            invitationID: String(repeating: "11", count: 32),
            deviceName: "Replacement Mac"
        )))
        let joinReview = try #require(join.deviceReplacementReview)
        #expect(joinReview.confirmationToken == v3LowercaseHex(
            fixture.review.digest
        ))

        let review = handler.handle(.share(.reviewReplacement))
        let projected = try #require(review.deviceReplacementReview)
        #expect(projected.confirmationToken == v3LowercaseHex(
            fixture.review.digest
        ))
        let resumed = handler.handle(.share(.replaceCurrentDevice(
            invitationID: String(repeating: "11", count: 32),
            confirmationToken: projected.confirmationToken
        )))
        #expect(resumed.exitCode == EXIT_SUCCESS)
        #expect(service.confirmations == [fixture.review.digest])
    }

    @Test
    func completedReplacementFencesVaultWorkButKeepsEnrollmentRetryable()
        throws
    {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: WorkflowMutationOwner(),
            replacementAdmissionState: .enrollmentPending
        )

        let invitations = handler.handle(.share(.invitations))
        #expect(invitations.errorMessage?.contains(
            "sharing is unavailable"
        ) == true)

        let invitationID = String(repeating: "11", count: 32)
        let comparisonCode = "000000"
        let acceptance = {
            handler.handle(.share(.accept(
                vaultID: Fixture.vaultID,
                invitationID: invitationID,
                comparisonCode: comparisonCode
            )))
        }
        #expect(acceptance().errorMessage?.contains(
            "sharing is unavailable"
        ) == true)

        let blocked = handler.handle(.list)
        #expect(blocked.exitCode == EXIT_FAILURE)
        #expect(blocked.errorMessage?.contains(
            "replacement enrollment is still in progress"
        ) == true)
        #expect(handler.handle(.status).exitCode == EXIT_SUCCESS)

        #expect(acceptance().errorMessage?.contains(
            "sharing is unavailable"
        ) == true)
    }

    private final class Fixture {
        static let vaultID =
            "018f4d38-7d5a-7b20-b0f1-97d6e96cc4b3"

        let target: V3EnrollmentDeviceIdentityDeletionTarget
        let review: V3ReplacementEnrollmentReview
        let completed: V3ReplacementEnrollmentIntent
        let targets: WorkflowTargetSource
        let authority: WorkflowAuthority
        let intents = WorkflowIntentStore()
        let coordinator: WorkflowCoordinator

        var workflow: V3ReplacementEnrollmentWorkflow {
            V3ReplacementEnrollmentWorkflow(
                vaultID: Self.vaultID,
                loadTarget: { [targets] _ in targets.target },
                authorityClassifier: authority,
                intentStore: intents,
                coordinator: coordinator
            )
        }

        init() throws {
            let signing = P256.Signing.PrivateKey()
            let wrapping = P256.KeyAgreement.PrivateKey()
            let identity = try V3EnrollmentDeviceIdentity(
                displayName: "Revoked Mac",
                signingPublicKey: signing.publicKey.x963Representation,
                wrappingPublicKey: wrapping.publicKey.x963Representation
            )
            let record = try V3EnrollmentDeviceKeyRecord(
                vaultID: Self.vaultID,
                identity: identity,
                signingKeyRepresentation: Data([0x01]),
                wrappingKeyRepresentation: Data([0x02])
            )
            target = try V3EnrollmentDeviceIdentityDeletionTarget(
                recordData: record.canonicalBytes
            )
            let checkpoint = try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: Data(repeating: 0x33, count: 32)
            )
            review = try V3ReplacementEnrollmentReview(
                classification: .revoked(
                    target,
                    authority: .trustedCheckpoint(checkpoint)
                )
            )
            completed = V3ReplacementEnrollmentIntent(
                review: review,
                phase: .checkpointDeleted
            )
            targets = WorkflowTargetSource(target: target)
            authority = WorkflowAuthority(classification: .revoked(
                target,
                authority: review.authority
            ))
            coordinator = WorkflowCoordinator(result: completed)
        }
    }
}

private final class WorkflowTargetSource: @unchecked Sendable {
    var target: V3EnrollmentDeviceIdentityDeletionTarget?

    init(target: V3EnrollmentDeviceIdentityDeletionTarget?) {
        self.target = target
    }
}

private final class WorkflowClock: @unchecked Sendable {
    var unixTime: UInt64

    init(unixTime: UInt64) {
        self.unixTime = unixTime
    }
}

private final class WorkflowAuthority:
    V3ReplacementDeviceIdentityAuthorityClassifying,
    @unchecked Sendable
{
    var classification: V3ReplacementDeviceIdentityClassification
    private(set) var classifyCount = 0

    init(classification: V3ReplacementDeviceIdentityClassification) {
        self.classification = classification
    }

    func classifyCurrentAuthority(
        for _: V3EnrollmentDeviceIdentityDeletionTarget
    ) throws -> V3ReplacementDeviceIdentityClassification {
        classifyCount += 1
        return classification
    }
}

private final class WorkflowIntentStore:
    V3ReplacementEnrollmentIntentStoring,
    @unchecked Sendable
{
    var storage: Data?

    func loadReplacementIntent(vaultID _: String) throws -> Data? {
        storage
    }

    func replaceReplacementIntent(
        _ intent: Data?,
        expectedIntent _: Data?,
        vaultID _: String
    ) throws {
        storage = intent
    }
}

private final class WorkflowCoordinator:
    V3ReplacementEnrollmentCoordinating,
    @unchecked Sendable
{
    var result: V3ReplacementEnrollmentIntent
    private(set) var begunReviews: [V3ReplacementEnrollmentReview] = []
    private(set) var resumeCount = 0

    init(result: V3ReplacementEnrollmentIntent) {
        self.result = result
    }

    func begin(
        review: V3ReplacementEnrollmentReview,
        confirmedReviewDigest: Data
    ) throws -> V3ReplacementEnrollmentIntent {
        guard review.digest == confirmedReviewDigest else {
            throw V3ReplacementEnrollmentCoordinatorError
                .invalidConfirmation
        }
        begunReviews.append(review)
        return result
    }

    func resume() throws -> V3ReplacementEnrollmentIntent {
        resumeCount += 1
        return result
    }
}

private final class WorkflowService:
    V3ReplacementEnrollmentWorkflowServicing,
    @unchecked Sendable
{
    let reviewValue: V3ReplacementEnrollmentReview
    let result: V3ReplacementEnrollmentIntent
    private let lock = NSLock()
    private var confirmationStorage: [Data] = []
    private var reviewCountStorage = 0

    var confirmations: [Data] {
        lock.withLock { confirmationStorage }
    }

    var reviewCount: Int {
        lock.withLock { reviewCountStorage }
    }

    init(
        review: V3ReplacementEnrollmentReview,
        result: V3ReplacementEnrollmentIntent
    ) {
        reviewValue = review
        self.result = result
    }

    func review() throws -> V3ReplacementEnrollmentReview {
        lock.withLock { reviewCountStorage += 1 }
        return reviewValue
    }

    func replace(
        confirmedReviewDigest: Data
    ) throws -> V3ReplacementEnrollmentIntent {
        lock.withLock {
            confirmationStorage.append(confirmedReviewDigest)
        }
        return result
    }
}

private final class WorkflowMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var storage: [VaultTransactionMutationKind] = []

    var kinds: [VaultTransactionMutationKind] {
        lock.withLock { storage }
    }

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        lock.withLock {
            storage.append(kind)
        }
        return try mutation(
            VaultTransactionMutationContext(
                operationID: VaultTransactionOperationID(),
                kind: kind
            )
        )
    }
}

private final class WorkflowVaultSession:
    VaultSessionServicing,
    @unchecked Sendable
{
    private let lockValue = NSLock()
    private var locks = 0

    var lockCount: Int {
        lockValue.withLock { locks }
    }

    func lock() {
        lockValue.withLock { locks += 1 }
    }

    func sessionStatus(at _: Date?) -> KeyHelperStatus {
        .locked(inactivityTimeoutSeconds: 15 * 60)
    }
}
