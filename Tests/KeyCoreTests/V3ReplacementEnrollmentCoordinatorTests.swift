import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3ReplacementEnrollmentCoordinatorTests {
    @Test
    func confirmedReviewRevalidatesAndCompletesOrderedCleanup() throws {
        let fixture = try Fixture()

        let result = try fixture.coordinator.begin(
            review: fixture.review,
            confirmedReviewDigest: fixture.review.digest
        )

        #expect(result.phase == .checkpointDeleted)
        #expect(fixture.records.record == nil)
        #expect(fixture.checkpoints.checkpoint == nil)
        #expect(fixture.authority.classifyCount == 1)
        #expect(fixture.owner.kinds == [.enrollDevice])
        #expect(try fixture.storedIntent()?.phase == .checkpointDeleted)
        #expect(fixture.events.values == [
            "authority",
            "intent-prepared",
            "intent-identityDeletionStarted",
            "identity-deleted",
            "intent-identityDeleted",
            "checkpoint-deleted",
            "intent-checkpointDeleted",
        ])
    }

    @Test
    func wrongConfirmationCannotCreateIntentOrDeleteState() throws {
        let fixture = try Fixture()

        #expect(
            throws: V3ReplacementEnrollmentCoordinatorError
                .invalidConfirmation
        ) {
            _ = try fixture.coordinator.begin(
                review: fixture.review,
                confirmedReviewDigest: Data(repeating: 0xFF, count: 32)
            )
        }

        #expect(fixture.intents.storage == nil)
        #expect(fixture.records.record != nil)
        #expect(fixture.checkpoints.checkpoint != nil)
        #expect(fixture.authority.classifyCount == 0)
        #expect(fixture.owner.kinds.isEmpty)
    }

    @Test
    func changedAuthorityFailsBeforePersistingOrDeletingAnything() throws {
        let fixture = try Fixture()
        fixture.authority.classification = .active(
            fixture.target,
            authority: fixture.review.authority
        )

        #expect(
            throws: V3ReplacementEnrollmentCoordinatorError
                .reviewedStateChanged
        ) {
            _ = try fixture.coordinator.begin(
                review: fixture.review,
                confirmedReviewDigest: fixture.review.digest
            )
        }

        #expect(fixture.intents.storage == nil)
        #expect(fixture.records.record != nil)
        #expect(fixture.checkpoints.checkpoint != nil)
        #expect(fixture.events.values == ["authority"])
    }

    @Test
    func retryUsesDurableAuthorityAfterIdentityDeletionInterruptedPhaseUpdate()
        throws
    {
        let fixture = try Fixture()
        fixture.records.interruptAfterNextDeletion = true

        #expect(throws: ReplacementCoordinatorTestError.interrupted) {
            _ = try fixture.coordinator.begin(
                review: fixture.review,
                confirmedReviewDigest: fixture.review.digest
            )
        }
        #expect(fixture.records.record == nil)
        #expect(
            try fixture.storedIntent()?.phase
                == .identityDeletionStarted
        )
        #expect(fixture.authority.classifyCount == 1)

        let result = try fixture.coordinator.resume()

        #expect(result.phase == .checkpointDeleted)
        #expect(fixture.checkpoints.checkpoint == nil)
        #expect(fixture.authority.classifyCount == 1)
        #expect(fixture.owner.kinds == [.enrollDevice, .enrollDevice])
    }

    @Test
    func retryRepeatsCheckpointDeletionWithoutReauthorizing() throws {
        let fixture = try Fixture()
        fixture.checkpoints.interruptAfterNextDeletion = true

        #expect(throws: ReplacementCoordinatorTestError.interrupted) {
            _ = try fixture.coordinator.begin(
                review: fixture.review,
                confirmedReviewDigest: fixture.review.digest
            )
        }
        #expect(fixture.records.record == nil)
        #expect(fixture.checkpoints.checkpoint == nil)
        #expect(try fixture.storedIntent()?.phase == .identityDeleted)
        #expect(fixture.authority.classifyCount == 1)

        let result = try fixture.coordinator.resume()

        #expect(result.phase == .checkpointDeleted)
        #expect(fixture.authority.classifyCount == 1)
        #expect(fixture.checkpoints.deleteCount == 2)
    }

    @Test
    func differentDurableReplacementCannotBeOverwritten() throws {
        let fixture = try Fixture()
        let other = try Fixture(
            identityName: "Different revoked Mac",
            signing: 0x41,
            wrapping: 0x42,
            checkpointByte: 0x43
        )
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: other.review
        ).canonicalBytes

        #expect(
            throws: V3ReplacementEnrollmentCoordinatorError
                .replacementAlreadyInProgress
        ) {
            _ = try fixture.coordinator.begin(
                review: fixture.review,
                confirmedReviewDigest: fixture.review.digest
            )
        }

        #expect(fixture.authority.classifyCount == 0)
        #expect(fixture.records.record != nil)
        #expect(fixture.checkpoints.checkpoint != nil)
    }

    @Test
    func newlyConfirmedAuthorityCanReplaceOnlyAnUntouchedPreparedIntent()
        throws
    {
        let fixture = try Fixture()
        fixture.intents.storage = V3ReplacementEnrollmentIntent(
            review: fixture.review
        ).canonicalBytes
        let advancedCheckpoint = try V3ManifestCheckpoint(
            vaultID: Fixture.vaultID,
            envelopeDigest: Data(repeating: 0x55, count: 32)
        )
        let advancedReview = try V3ReplacementEnrollmentReview(
            classification: .revoked(
                fixture.target,
                authority: .trustedCheckpoint(advancedCheckpoint)
            )
        )
        fixture.authority.classification = .revoked(
            fixture.target,
            authority: .trustedCheckpoint(advancedCheckpoint)
        )
        fixture.checkpoints.checkpoint = advancedCheckpoint.canonicalBytes

        let result = try fixture.coordinator.begin(
            review: advancedReview,
            confirmedReviewDigest: advancedReview.digest
        )

        #expect(result.review == advancedReview)
        #expect(result.phase == .checkpointDeleted)

        let interrupted = try Fixture()
        interrupted.intents.storage = V3ReplacementEnrollmentIntent(
            review: interrupted.review
        ).canonicalBytes
        interrupted.records.record = nil
        #expect(
            throws: V3ReplacementEnrollmentCoordinatorError
                .replacementAlreadyInProgress
        ) {
            _ = try interrupted.coordinator.begin(
                review: advancedReview,
                confirmedReviewDigest: advancedReview.digest
            )
        }
    }

    @Test
    func completedIntentReturnsIdempotentlyAndMissingIntentCannotResume()
        throws
    {
        let fixture = try Fixture()
        _ = try fixture.coordinator.begin(
            review: fixture.review,
            confirmedReviewDigest: fixture.review.digest
        )
        let authorityCount = fixture.authority.classifyCount
        let deleteCount = fixture.checkpoints.deleteCount

        let repeated = try fixture.coordinator.resume()

        #expect(repeated.phase == .checkpointDeleted)
        #expect(fixture.authority.classifyCount == authorityCount)
        #expect(fixture.checkpoints.deleteCount == deleteCount)

        let empty = try Fixture()
        empty.intents.storage = nil
        #expect(
            throws: V3ReplacementEnrollmentCoordinatorError
                .noReplacementInProgress
        ) {
            _ = try empty.coordinator.resume()
        }
    }

    private final class Fixture {
        static let vaultID =
            "018f4d38-7d5a-7b20-b0f1-97d6e96c94d3"

        let events = ReplacementCoordinatorEvents()
        let target: V3EnrollmentDeviceIdentityDeletionTarget
        let review: V3ReplacementEnrollmentReview
        let records: ReplacementCoordinatorRecordStore
        let checkpoints: ReplacementCoordinatorCheckpointStore
        let intents: ReplacementCoordinatorIntentStore
        let authority: ReplacementCoordinatorAuthority
        let owner = ReplacementCoordinatorMutationOwner()

        var coordinator: V3ReplacementEnrollmentCoordinator {
            V3ReplacementEnrollmentCoordinator(
                vaultID: Self.vaultID,
                mutationOwner: owner,
                authorityClassifier: authority,
                identityDeleter: V3EnrollmentDeviceIdentityDeleter(
                    recordStore: records
                ),
                checkpointStore: checkpoints,
                intentStore: intents
            )
        }

        init(
            identityName: String = "Revoked Mac",
            signing: UInt8 = 0x11,
            wrapping: UInt8 = 0x12,
            checkpointByte: UInt8 = 0x21
        ) throws {
            let identity = try Self.identity(
                name: identityName,
                signing: signing,
                wrapping: wrapping
            )
            let record = try V3EnrollmentDeviceKeyRecord(
                vaultID: Self.vaultID,
                identity: identity,
                signingKeyRepresentation: Data([0x01]),
                wrappingKeyRepresentation: Data([0x02])
            ).canonicalBytes
            target = try V3EnrollmentDeviceIdentityDeletionTarget(
                recordData: record
            )
            let checkpoint = try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: Data(repeating: checkpointByte, count: 32)
            )
            review = try V3ReplacementEnrollmentReview(
                classification: .revoked(
                    target,
                    authority: .trustedCheckpoint(checkpoint)
                )
            )
            records = ReplacementCoordinatorRecordStore(
                record: record,
                events: events
            )
            checkpoints = ReplacementCoordinatorCheckpointStore(
                checkpoint: checkpoint.canonicalBytes,
                events: events
            )
            intents = ReplacementCoordinatorIntentStore(events: events)
            authority = ReplacementCoordinatorAuthority(
                classification: .revoked(
                    target,
                    authority: .trustedCheckpoint(checkpoint)
                ),
                events: events
            )
        }

        func storedIntent() throws -> V3ReplacementEnrollmentIntent? {
            guard let storage = intents.storage else { return nil }
            return try V3ReplacementEnrollmentIntent(
                canonicalBytes: storage
            )
        }

        private static func identity(
            name: String,
            signing: UInt8,
            wrapping: UInt8
        ) throws -> V3EnrollmentDeviceIdentity {
            let signingKey = try P256.Signing.PrivateKey(
                rawRepresentation: scalar(signing)
            )
            let wrappingKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: scalar(wrapping)
            )
            return try V3EnrollmentDeviceIdentity(
                displayName: name,
                signingPublicKey:
                    signingKey.publicKey.x963Representation,
                wrappingPublicKey:
                    wrappingKey.publicKey.x963Representation
            )
        }

        private static func scalar(_ value: UInt8) -> Data {
            Data(SHA256.hash(data: Data([value])))
        }
    }
}

private enum ReplacementCoordinatorTestError: Error {
    case interrupted
}

private final class ReplacementCoordinatorEvents: @unchecked Sendable {
    var values: [String] = []
}

private final class ReplacementCoordinatorAuthority:
    V3ReplacementDeviceIdentityAuthorityClassifying,
    @unchecked Sendable
{
    var classification: V3ReplacementDeviceIdentityClassification
    private(set) var classifyCount = 0
    private let events: ReplacementCoordinatorEvents

    init(
        classification: V3ReplacementDeviceIdentityClassification,
        events: ReplacementCoordinatorEvents
    ) {
        self.classification = classification
        self.events = events
    }

    func classifyCurrentAuthority(
        for _: V3EnrollmentDeviceIdentityDeletionTarget
    ) throws -> V3ReplacementDeviceIdentityClassification {
        classifyCount += 1
        events.values.append("authority")
        return classification
    }
}

private final class ReplacementCoordinatorRecordStore:
    V3EnrollmentDeviceKeyRecordStoring,
    V3EnrollmentDeviceKeyRecordDeleting,
    @unchecked Sendable
{
    var record: Data?
    var interruptAfterNextDeletion = false
    private let events: ReplacementCoordinatorEvents

    init(record: Data, events: ReplacementCoordinatorEvents) {
        self.record = record
        self.events = events
    }

    func loadRecord(vaultID _: String) throws -> Data? { record }

    func insertRecord(_ record: Data, vaultID _: String) throws {
        self.record = record
    }

    func deleteRecord(
        expectedRecordDigest: Data,
        vaultID _: String
    ) throws {
        if let record {
            guard Data(SHA256.hash(data: record)) == expectedRecordDigest else {
                throw V3EnrollmentDeviceIdentityStoreError.conflict
            }
            self.record = nil
        }
        events.values.append("identity-deleted")
        if interruptAfterNextDeletion {
            interruptAfterNextDeletion = false
            throw ReplacementCoordinatorTestError.interrupted
        }
    }
}

private final class ReplacementCoordinatorCheckpointStore:
    V3ManifestCheckpointDeleting,
    @unchecked Sendable
{
    var checkpoint: Data?
    var interruptAfterNextDeletion = false
    private(set) var deleteCount = 0
    private let events: ReplacementCoordinatorEvents

    init(checkpoint: Data, events: ReplacementCoordinatorEvents) {
        self.checkpoint = checkpoint
        self.events = events
    }

    func deleteCheckpoint(
        expectedCheckpoint: Data,
        vaultID _: String
    ) throws {
        deleteCount += 1
        if let checkpoint {
            guard checkpoint == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            self.checkpoint = nil
        }
        events.values.append("checkpoint-deleted")
        if interruptAfterNextDeletion {
            interruptAfterNextDeletion = false
            throw ReplacementCoordinatorTestError.interrupted
        }
    }
}

private final class ReplacementCoordinatorIntentStore:
    V3ReplacementEnrollmentIntentStoring,
    @unchecked Sendable
{
    var storage: Data?
    private let events: ReplacementCoordinatorEvents

    init(events: ReplacementCoordinatorEvents) {
        self.events = events
    }

    func loadReplacementIntent(vaultID _: String) throws -> Data? {
        storage
    }

    func replaceReplacementIntent(
        _ intent: Data?,
        expectedIntent: Data?,
        vaultID _: String
    ) throws {
        guard storage == expectedIntent else {
            throw V3ReplacementEnrollmentIntentError.conflict
        }
        storage = intent
        guard let intent else { return }
        let phase = try V3ReplacementEnrollmentIntent(
            canonicalBytes: intent
        ).phase
        events.values.append("intent-\(phase.rawValue)")
    }
}

private final class ReplacementCoordinatorMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private(set) var kinds: [VaultTransactionMutationKind] = []

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        kinds.append(kind)
        return try mutation(VaultTransactionMutationContext(
            operationID: VaultTransactionOperationID(),
            kind: kind
        ))
    }
}
