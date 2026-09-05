import CryptoKit
import Foundation
import Testing

@testable import KeyCore

private final class TestEnrollmentSelector: @unchecked Sendable {
    let select: (String) throws -> Void
    init(_ select: @escaping (String) throws -> Void) { self.select = select }
}

@Suite(.serialized)
struct V3DeviceWrappedEnrollmentTransitionPublisherTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let genesisTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let enrollmentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
    private static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
    private static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b7"
    )
    private static let seedOperationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b8"
    )
    private static let currentKey = Data(0..<32)
    private static let nextKey = Data(repeating: 0x41, count: 32)
    private static let approvalTime: UInt64 = 4_102_444_800

    @Test
    func publishesTheCompleteNewEpochBeforeAdvancingTheCheckpoint() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let observer = RecordingObserver()

        let trusted = try fixture.publisher(observer: observer).publish(
            fixture.candidate,
            parent: fixture.base,
            currentEntries: fixture.currentEntries,
            currentVaultKey: Self.currentKey,
            nextVaultKey: Self.nextKey,
            state: fixture.ceremony,
            localIdentity: fixture.owner,
            at: Self.approvalTime,
            unwrapReason: "Verify the owner's rotated-key wrapper."
        )

        #expect(observer.phases == [
            .recoveryAnchorPrepared,
            .recoveryIntentPersisted,
            .recoveryArmed,
            .entryStaged(index: 0),
            .manifestStaged,
            .repositoryStateRechecked,
            .entryPublished(index: 0),
            .publishedEntriesValidated,
            .manifestPublished,
            .publishedManifestValidated,
            .checkpointAdvanced,
            .cleanupCompleted,
        ])
        #expect(trusted.envelope.body == fixture.candidate.body)
        #expect(
            fixture.checkpointStore.checkpoint
                == trusted.checkpoint.canonicalBytes
        )
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(fixture.cache.storedManifest == fixture.candidate.manifestData)
        try fixture.requireCandidateObjectsPublished()
    }

    @Test
    func completionFailureRetainsRecoveryUntilTheCallbackSucceeds() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(observer: RecordingObserver())

        #expect(throws: PublicationTestError.commitFailed) {
            _ = try publisher.publish(
                fixture.candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: fixture.ceremony,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the owner's rotated-key wrapper.",
                afterCheckpointAdvance: { _, _ in
                    throw PublicationTestError.commitFailed
                }
            )
        }
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)

        let recorder = EnrollmentCommitRecorder()
        let recovered = try publisher.recoverInterruptedTransaction(
            vaultID: Self.vaultID,
            expectedTranscriptDigest: fixture.candidate.transcriptDigest,
            localIdentity: fixture.owner,
            unwrapReason: "Resume the exact approved enrollment.",
            afterCheckpointAdvance: { trusted, vaultKey in
                recorder.record(trusted: trusted, vaultKey: vaultKey)
            }
        )

        #expect(recovered.outcome == .alreadyCompleted(
            operationID: Self.operationID
        ))
        #expect(recorder.count == 1)
        #expect(recorder.vaultKey == Self.nextKey)
        #expect(recorder.checkpoint?.envelope.body == fixture.candidate.body)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
    }

    @Test
    func recoveryRequiresTheExactApprovedCeremony() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            observer: InterruptingObserver(target: .recoveryArmed)
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try fixture.publish(using: publisher)
        }
        let recorder = EnrollmentCommitRecorder()

        #expect(
            throws: V3ImmutableTransactionRecoveryError.invalidIntent(
                operationID: Self.operationID.rawValue
            )
        ) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                expectedTranscriptDigest: Data(repeating: 0x9a, count: 32),
                localIdentity: fixture.owner,
                unwrapReason: "Do not resume another enrollment ceremony.",
                afterCheckpointAdvance: { trusted, vaultKey in
                    recorder.record(trusted: trusted, vaultKey: vaultKey)
                }
            )
        }

        #expect(recorder.count == 0)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)
        #expect(
            fixture.checkpointStore.checkpoint
                == fixture.base.checkpoint.canonicalBytes
        )
    }

    @Test
    func everyInterruptionRecoversToTheCompleteOldOrNewEpoch() throws {
        let cases: [(
            phase: V3ImmutableTransactionPhase,
            expectsNewCheckpoint: Bool
        )] = [
            (.recoveryAnchorPrepared, false),
            (.recoveryIntentPersisted, false),
            (.recoveryArmed, false),
            (.entryStaged(index: 0), false),
            (.manifestStaged, true),
            (.repositoryStateRechecked, true),
            (.entryPublished(index: 0), true),
            (.publishedEntriesValidated, true),
            (.manifestPublished, true),
            (.publishedManifestValidated, true),
            (.checkpointAdvanced, true),
            (.cleanupCompleted, true),
        ]

        for testCase in cases {
            let fixture = try Fixture()
            defer { fixture.removeRoot() }
            let publisher = fixture.publisher(
                observer: InterruptingObserver(target: testCase.phase)
            )
            #expect(throws: PublicationTestError.interrupted) {
                _ = try publisher.publish(
                    fixture.candidate,
                    parent: fixture.base,
                    currentEntries: fixture.currentEntries,
                    currentVaultKey: Self.currentKey,
                    nextVaultKey: Self.nextKey,
                    state: fixture.ceremony,
                    localIdentity: fixture.owner,
                    at: Self.approvalTime,
                    unwrapReason: "Verify the owner's rotated-key wrapper."
                )
            }

            let recovered = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                expectedTranscriptDigest: fixture.candidate.transcriptDigest,
                localIdentity: fixture.owner,
                unwrapReason: "Resume the exact approved enrollment."
            )
            let expected = testCase.expectsNewCheckpoint
                ? try V3ManifestCheckpoint(
                    vaultID: Self.vaultID,
                    envelopeDigest: fixture.candidate.manifestDigest
                )
                : fixture.base.checkpoint
            #expect(fixture.checkpointStore.checkpoint == expected.canonicalBytes)
            #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
            if testCase.expectsNewCheckpoint {
                #expect(recovered.outcome != .abandoned(
                    operationID: Self.operationID
                ))
                if recovered.outcome != .nothingToRecover {
                    #expect(recovered.vaultKey == Self.nextKey)
                    #expect(
                        recovered.trustedCheckpoint?.checkpoint == expected
                    )
                }
                try fixture.requireCandidateObjectsPublished()
            } else {
                #expect(recovered.outcome == .abandoned(
                    operationID: Self.operationID
                ))
                #expect(recovered.vaultKey == nil)
                #expect(recovered.trustedCheckpoint == nil)
            }
        }
    }

    @Test
    func checkpointChangeCleansStagingWithoutPublishingTheCandidate() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let replacement = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 0xAA, count: 32)
        )
        let observer = CheckpointChangingObserver(
            target: .manifestStaged,
            store: fixture.checkpointStore,
            expected: fixture.base.checkpoint,
            replacement: replacement
        )

        #expect(throws: V3ImmutableTransactionError.expectedHeadsChanged) {
            _ = try fixture.publisher(observer: observer).publish(
                fixture.candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: fixture.ceremony,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the owner's rotated-key wrapper."
            )
        }

        #expect(fixture.checkpointStore.checkpoint == replacement.canonicalBytes)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(try fixture.candidateManifestIsUnavailable())
    }

    @Test
    func repositoryWideEntryLimitStopsBeforeRecoveryIsArmed() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let limits = Self.limits(maximumReferencedEntryObjects: 1)

        #expect(throws: V3ImmutableTransactionError.objectTooLarge) {
            _ = try fixture.publish(using: fixture.publisher(
                observer: RecordingObserver(),
                limits: limits
            ))
        }
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(try fixture.candidateManifestIsUnavailable())
    }

    @Test
    func repositoryUsageChangeAfterStagingStopsPublication() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let initial = try fixture.repositoryObservation()
        let extraKey = V3EntryObjectKey(
            entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b9",
            digest: Data(repeating: 0x7A, count: 32)
        )
        let changed = V3DeviceWrappedRepositoryObservation(
            checkpoint: initial.checkpoint,
            heads: initial.heads,
            manifestDigests: initial.manifestDigests,
            parentsByManifestDigest: initial.parentsByManifestDigest,
            referencedEntryObjects:
                initial.referencedEntryObjects.union([extraKey]),
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount:
                    initial.resourceUsage.manifestObjectCount,
                maximumHistoryDepth:
                    initial.resourceUsage.maximumHistoryDepth,
                totalManifestBytes:
                    initial.resourceUsage.totalManifestBytes,
                referencedEntryObjectCount:
                    initial.resourceUsage.referencedEntryObjectCount + 1,
                totalEntryBytes:
                    initial.resourceUsage.totalEntryBytes + 1
            )
        )
        let repositoryObserver = SequencedRepositoryObserver([
            initial,
            changed,
        ])

        #expect(throws: V3ImmutableTransactionError.objectTooLarge) {
            _ = try fixture.publish(using: fixture.publisher(
                observer: RecordingObserver(),
                repositoryObserver: repositoryObserver,
                limits: Self.limits(maximumReferencedEntryObjects: 2)
            ))
        }
        #expect(repositoryObserver.observationCount == 2)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(try fixture.candidateManifestIsUnavailable())
    }

    @Test
    func recoveryAcceptsAHeadDescendingFromThePublishedCandidate() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let interrupted = fixture.publisher(
            observer: InterruptingObserver(target: .checkpointAdvanced)
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try fixture.publish(using: interrupted)
        }

        let published = try fixture.repositoryObservation()
        let descendantDigest = Data(repeating: 0x7B, count: 32)
        var manifestDigests = published.manifestDigests
        manifestDigests.insert(descendantDigest)
        var parents = published.parentsByManifestDigest
        parents[descendantDigest] = [fixture.candidate.manifestDigest]
        let advanced = V3DeviceWrappedRepositoryObservation(
            checkpoint: published.checkpoint,
            heads: [descendantDigest],
            manifestDigests: manifestDigests,
            parentsByManifestDigest: parents,
            referencedEntryObjects: published.referencedEntryObjects,
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount:
                    published.resourceUsage.manifestObjectCount + 1,
                maximumHistoryDepth:
                    published.resourceUsage.maximumHistoryDepth + 1,
                totalManifestBytes:
                    published.resourceUsage.totalManifestBytes + 1,
                referencedEntryObjectCount:
                    published.resourceUsage.referencedEntryObjectCount,
                totalEntryBytes: published.resourceUsage.totalEntryBytes
            )
        )

        let recovered = try fixture.publisher(
            observer: RecordingObserver(),
            repositoryObserver: ClosureRepositoryObserver { _, _ in advanced }
        ).recoverInterruptedTransaction(
            vaultID: Self.vaultID,
            expectedTranscriptDigest: fixture.candidate.transcriptDigest,
            localIdentity: fixture.owner,
            unwrapReason: "Resume the exact approved enrollment."
        )

        #expect(recovered.outcome == .alreadyCompleted(
            operationID: Self.operationID
        ))
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
    }

    @Test
    func recoveryRejectsASubstitutedStagedManifest() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            observer: InterruptingObserver(target: .manifestStaged)
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try publisher.publish(
                fixture.candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: fixture.ceremony,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the owner's rotated-key wrapper."
            )
        }
        try Data("{}".utf8).write(
            to: fixture.stagedManifestURL,
            options: .atomic
        )

        #expect(
            throws: V3ImmutableTransactionRecoveryError.invalidRecoveryState(
                operationID: Self.operationID.rawValue
            )
        ) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                expectedTranscriptDigest: fixture.candidate.transcriptDigest,
                localIdentity: fixture.owner,
                unwrapReason: "Resume the exact approved enrollment."
            )
        }
        #expect(
            fixture.checkpointStore.checkpoint
                == fixture.base.checkpoint.canonicalBytes
        )
    }

    @Test
    func recoveryMapsADelayedPublishedEntryToTemporaryUnavailable() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            observer: InterruptingObserver(target: .checkpointAdvanced)
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try fixture.publish(using: publisher)
        }
        let entry = try #require(fixture.candidate.stagedEntries.first)
        let digest = try #require(Base64URL.decodeCanonical(
            entry.ciphertextDigest
        ))
        let delayedStore = FaultInjectingArtifactStore(
            base: fixture.store,
            fault: .entryUnavailableOnSecondRead(
                entryID: entry.context.entryID,
                digest: digest
            )
        )

        #expect(
            throws: V3ImmutableTransactionRecoveryError
                .transactionDirectoryUnavailable
        ) {
            _ = try fixture.publisher(
                observer: RecordingObserver(),
                objectStore: delayedStore
            ).recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                expectedTranscriptDigest: fixture.candidate.transcriptDigest,
                localIdentity: fixture.owner,
                unwrapReason: "Resume the exact approved enrollment."
            )
        }
    }

    @Test
    func recoveryMapsASubstitutedPublishedManifestToInvalidState() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            observer: InterruptingObserver(target: .checkpointAdvanced)
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try fixture.publish(using: publisher)
        }
        let substitutedStore = FaultInjectingArtifactStore(
            base: fixture.store,
            fault: .manifestInvalidOnSecondRead(
                digest: fixture.candidate.manifestDigest
            )
        )

        #expect(
            throws: V3ImmutableTransactionRecoveryError.invalidRecoveryState(
                operationID: Self.operationID.rawValue
            )
        ) {
            _ = try fixture.publisher(
                observer: RecordingObserver(),
                objectStore: substitutedStore
            ).recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                expectedTranscriptDigest: fixture.candidate.transcriptDigest,
                localIdentity: fixture.owner,
                unwrapReason: "Resume the exact approved enrollment."
            )
        }
    }

    @Test
    func durableRecoveryMetadataContainsNoRawVaultKey() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let publisher = fixture.publisher(
            observer: InterruptingObserver(target: .recoveryIntentPersisted)
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try publisher.publish(
                fixture.candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: fixture.ceremony,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the owner's rotated-key wrapper."
            )
        }
        let intent = try #require(try fixture.recoveryIntent())
        let anchor = try #require(
            fixture.anchorStore.anchor(vaultID: Self.vaultID)
        )
        for rawKey in [Self.currentKey, Self.nextKey] {
            #expect(intent.range(of: rawKey) == nil)
            #expect(anchor.range(of: rawKey) == nil)
            #expect(!String(decoding: intent, as: UTF8.self).contains(
                Base64URL.encode(rawKey)
            ))
        }
    }

    @Test
    func ownerApprovalRotatesTheKeyAndConsumesTheCeremony() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let stateStore = ApprovalMemoryCeremonyStateStore()
        try stateStore.replaceState(
            fixture.ceremony.canonicalBytes,
            expectedState: nil,
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        )
        let exchange = V3EnrollmentExchangeCoordinator(
            mailbox: ApprovalNoopMailbox(),
            stateStore: stateStore
        )
        let session = V3DeviceWrappedVaultKeySessionStore()
        let service = V3DeviceWrappedEnrollmentOwnerApprovalService(
            vaultID: Self.vaultID,
            stateLoader: ApprovalStateLoader(
                trusted: fixture.base,
                vaultKey: Self.currentKey
            ),
            source: fixture.store,
            objectStore: fixture.store,
            checkpointStore: fixture.checkpointStore,
            recoveryAnchorStore: fixture.anchorStore,
            cache: fixture.cache,
            exchange: exchange,
            loadIdentity: { _, _ in fixture.owner },
            session: session,
            makeVaultKey: { Self.nextKey }
        )
        let workflow = V3DeviceWrappedEnrollmentOwnerWorkflow(
            vaultID: Self.vaultID,
            stateLoader: ApprovalStateLoader(
                trusted: fixture.base,
                vaultKey: Self.currentKey
            ),
            exchange: exchange,
            loadIdentity: { _, _ in fixture.owner },
            loadPublicIdentity: { _ in fixture.owner.publicIdentity },
            approvalService: service
        )
        let transcript = try #require(fixture.ceremony.transcript)

        #expect(throws: V3EnrollmentAdoptionError.invalidCeremony) {
            _ = try workflow.approve(
                vaultID: Self.vaultID,
                invitationDigest: fixture.ceremony.invitationDigest,
                comparisonCode: "0000-0000-0000-0000-0000",
                at: Self.approvalTime,
                operationID: Self.operationID
            )
        }
        #expect(try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        ) == fixture.ceremony.canonicalBytes)

        let rendered = try workflow.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest,
            comparisonCode: transcript.comparisonCode,
            at: Self.approvalTime,
            operationID: Self.operationID
        )

        #expect(rendered.contains("Enrollment approved."))
        let checkpointData = try #require(fixture.checkpointStore.checkpoint)
        let checkpoint = try V3ManifestCheckpoint(
            canonicalBytes: checkpointData
        )
        let manifestData: Data
        switch try fixture.store.readManifest(
            digest: checkpoint.envelopeDigest,
            maximumBytes: V3ManifestRepositoryLimits.standard
                .maximumManifestBytes
        ) {
        case let .available(data):
            manifestData = data
        case .unavailable, .invalid, .tooLarge:
            Issue.record("Approved manifest is unavailable.")
            return
        }
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            manifestData
        )
        #expect(envelope.body.authorityTransitionID
            == (try v3EnrollmentAuthorityTransitionID(
                transcriptDigest: transcript.digest
            )))
        #expect(envelope.body.devices.count == 2)
        #expect(envelope.body.devices.contains(where: {
            $0.identity == fixture.joiner.publicIdentity
        }))
        #expect(try session.load(
            vaultID: Self.vaultID,
            keyID: envelope.body.keyID
        ) == Self.nextKey)
        let consumedData = try #require(try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        ))
        let consumed = try V3EnrollmentCeremonyState(
            canonicalBytes: consumedData
        )
        #expect(consumed.phase == .consumed)
        #expect(consumed.ownerApproval == nil)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
    }

    @Test
    func ownerApprovalRecoversWhenCeremonyConsumptionInitiallyFails() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let stateStore = ApprovalMemoryCeremonyStateStore()
        try stateStore.replaceState(
            fixture.ceremony.canonicalBytes,
            expectedState: nil,
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        )
        stateStore.setFailConsumedReplacement(true)
        let exchange = V3EnrollmentExchangeCoordinator(
            mailbox: ApprovalNoopMailbox(),
            stateStore: stateStore
        )
        let session = V3DeviceWrappedVaultKeySessionStore()
        let service = V3DeviceWrappedEnrollmentOwnerApprovalService(
            vaultID: Self.vaultID,
            stateLoader: ApprovalStateLoader(
                trusted: fixture.base,
                vaultKey: Self.currentKey
            ),
            source: fixture.store,
            objectStore: fixture.store,
            checkpointStore: fixture.checkpointStore,
            recoveryAnchorStore: fixture.anchorStore,
            cache: fixture.cache,
            exchange: exchange,
            loadIdentity: { _, _ in fixture.owner },
            session: session,
            makeVaultKey: { Self.nextKey }
        )
        let transcript = try #require(fixture.ceremony.transcript)

        #expect(throws: ApprovalTestError.consumptionFailed) {
            _ = try service.approve(
                invitationDigest: fixture.ceremony.invitationDigest,
                approvedTranscriptDigest: transcript.digest,
                at: Self.approvalTime,
                operationID: Self.operationID
            )
        }
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)

        stateStore.setFailConsumedReplacement(false)
        let recovered = try service.approve(
            invitationDigest: fixture.ceremony.invitationDigest,
            approvedTranscriptDigest: transcript.digest,
            at: Self.approvalTime + 10_000,
            operationID: Self.operationID
        )

        #expect(recovered.envelope.body.devices.count == 2)
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        let consumedData = try #require(try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        ))
        #expect(try V3EnrollmentCeremonyState(
            canonicalBytes: consumedData
        ).phase == .consumed)
    }

    @Test
    func consumedOwnerApprovalCanFinishInterruptedCleanup() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let stateStore = ApprovalMemoryCeremonyStateStore()
        try stateStore.replaceState(
            fixture.ceremony.canonicalBytes,
            expectedState: nil,
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        )
        let exchange = V3EnrollmentExchangeCoordinator(
            mailbox: ApprovalNoopMailbox(),
            stateStore: stateStore
        )
        let session = V3DeviceWrappedVaultKeySessionStore()
        let stateLoader = ApprovalStateLoader(
            trusted: fixture.base,
            vaultKey: Self.currentKey
        )
        let service = V3DeviceWrappedEnrollmentOwnerApprovalService(
            vaultID: Self.vaultID,
            stateLoader: stateLoader,
            source: fixture.store,
            objectStore: fixture.store,
            checkpointStore: fixture.checkpointStore,
            recoveryAnchorStore: fixture.anchorStore,
            cache: fixture.cache,
            exchange: exchange,
            loadIdentity: { _, _ in fixture.owner },
            session: session,
            makeVaultKey: { Self.nextKey }
        )
        let workflow = V3DeviceWrappedEnrollmentOwnerWorkflow(
            vaultID: Self.vaultID,
            stateLoader: stateLoader,
            exchange: exchange,
            loadIdentity: { _, _ in fixture.owner },
            loadPublicIdentity: { _ in fixture.owner.publicIdentity },
            approvalService: service
        )
        let transcript = try #require(fixture.ceremony.transcript)
        fixture.anchorStore.failNextRemoval()

        _ = try workflow.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest,
            comparisonCode: transcript.comparisonCode,
            at: Self.approvalTime,
            operationID: Self.operationID
        )
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) != nil)
        let consumedData = try #require(try stateStore.loadState(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest
        ))
        #expect(try V3EnrollmentCeremonyState(
            canonicalBytes: consumedData
        ).phase == .consumed)

        let rendered = try workflow.approve(
            vaultID: Self.vaultID,
            invitationDigest: fixture.ceremony.invitationDigest,
            comparisonCode: transcript.comparisonCode,
            at: Self.approvalTime + 10_000,
            operationID: Self.operationID
        )

        #expect(rendered.contains("Enrollment approved."))
        #expect(fixture.anchorStore.anchor(vaultID: Self.vaultID) == nil)
        #expect(throws: V3EnrollmentCeremonyStateError.replayed) {
            _ = try workflow.approve(
                vaultID: Self.vaultID,
                invitationDigest: fixture.ceremony.invitationDigest,
                comparisonCode: transcript.comparisonCode,
                at: Self.approvalTime + 10_001,
                operationID: Self.operationID
            )
        }
    }

    @Test(arguments: [false, true], [false, true])
    func unconfiguredCLIJoinsAndSelectsOnlyAfterVerifiedAcceptance(explicitDirectory: Bool, interruptedSelection: Bool) throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = try VaultRootDirectoryHandle(opening: fixture.rootURL)
        let mailbox = V3FilesystemEnrollmentMailbox(rootHandle: root)
        let state = try fixture.joinerCeremony()
        let transcript = try #require(state.transcript)
        let invitationID = v3LowercaseHex(state.invitationDigest)
        try mailbox.publishInvitation(state.signedInvitation.canonicalBytes)
        let stateStore = ApprovalMemoryCeremonyStateStore()
        try stateStore.replaceState(state.canonicalBytes, expectedState: nil, vaultID: Self.vaultID, invitationDigest: state.invitationDigest)
        let checkpoints = MemoryCheckpointStore()
        let cache = MemoryCheckpointCache()
        let keys = MemoryVaultKeyStore()
        let selectionAttempt = AdoptionSelectionRecorder(failFirst: interruptedSelection)
        let service = V3UnconfiguredEnrollmentService(configStore: config, exchange: { handle in
            V3EnrollmentExchangeCoordinator(mailbox: V3FilesystemEnrollmentMailbox(rootHandle: handle), stateStore: stateStore)
        }, perform: { handle, request, select in
            let selector = TestEnrollmentSelector(select)
            let exchange = V3EnrollmentExchangeCoordinator(mailbox: V3FilesystemEnrollmentMailbox(rootHandle: handle), stateStore: stateStore)
            let session = V3DeviceWrappedVaultKeySessionStore()
            defer { session.invalidate() }
            let adoption = V3DeviceWrappedEnrollmentAdoptionService(
                source: fixture.store, checkpointStore: checkpoints, cache: cache,
                exchange: exchange, loadIdentity: { _, _ in fixture.joiner },
                session: session, selectVault: { vaultID in
                    try selectionAttempt.selectOrFail(vaultID)
                    try selector.select(vaultID)
                },
                verifyRuntime: { vaultID, installed in
                    let loaded = try installed.load(vaultID: vaultID, keyID: fixture.candidate.body.keyID)
                    #expect(loaded == Self.nextKey)
                    #expect(checkpoints.checkpoint != nil)
                    #expect(cache.storedManifest == fixture.candidate.manifestData)
                }
            )
            let workflow = V3EnrollmentWorkflowService(
                selectedVaultID: nil, source: fixture.store, objectStore: fixture.store,
                checkpointStore: checkpoints, exchange: exchange,
                identityManager: V3EnrollmentDeviceIdentityManager(recordStore: AdoptionIdentityRecordStore(), keyOperations: AdoptionDeviceKeyOperations()),
                vaultKeyStore: keys, keychainMode: .local,
                selectVault: { _ in Issue.record("Must use device-wrapped adoption") },
                verifyRuntime: { _ in Issue.record("Must not use legacy key runtime") },
                deviceWrappedAdoption: adoption
            )
            return KeyServiceHandler(
                keyStore: keys, entryStore: EntryStore(rootURL: handle.rootURL),
                now: { Date(timeIntervalSince1970: TimeInterval(Self.approvalTime)) },
                mutationOwner: VaultTransactionMutationOwner(), enrollmentService: workflow
            ).handle(.share(request))
        }, now: { Date(timeIntervalSince1970: TimeInterval(Self.approvalTime)) })
        func makeHost() -> KeyServiceHost {
            KeyServiceHost(hasConfiguration: { try config.hasConfiguration() }, makeHandler: {
                Issue.record("Joining must not compose a configured runtime"); return { _ in .failure("Unexpected") }
            }, initialize: { _ in Issue.record("Joining must not initialize"); return "" }, enroll: { try service.handle($0, path: $1) })
        }
        let firstHost = makeHost()
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(transport: MemoryTransport { firstHost.handle($0) }, io: io, clipboard: MemoryClipboard(), configStore: config, currentDirectory: { explicitDirectory ? home : fixture.rootURL })
        let option = explicitDirectory ? ["--vault-dir", fixture.rootURL.path] : []
        #expect(app.run(arguments: ["share", "invitations"] + option) == EXIT_SUCCESS)
        #expect(!FileManager.default.fileExists(atPath: config.initializationConfigFileURL.deletingLastPathComponent().path))
        #expect(app.run(arguments: ["share", "join", invitationID, "--name", "Joining Mac"] + option) == EXIT_SUCCESS)
        #expect(try !config.hasConfiguration())
        #expect(app.run(arguments: ["share", "accept", Self.vaultID, invitationID, transcript.comparisonCode] + option) != EXIT_SUCCESS)
        #expect(try !config.hasConfiguration())
        try fixture.publishCandidateDirectly()

        // A copied folder has the same public ceremony but cannot select it.
        let copied = home.appendingPathComponent("Copied Vault", isDirectory: true)
        try FileManager.default.copyItem(at: fixture.rootURL, to: copied)
        let restarted = makeHost()
        #expect(restarted.handle(.shareInDirectory(request: .accept(vaultID: Self.vaultID, invitationID: invitationID, comparisonCode: transcript.comparisonCode), path: copied.path)).exitCode != EXIT_SUCCESS)
        #expect(try !config.hasConfiguration())
        let resumed = KeyCLIApplication(transport: MemoryTransport { restarted.handle($0) }, io: io, clipboard: MemoryClipboard(), configStore: config, currentDirectory: { explicitDirectory ? home : fixture.rootURL })
        #expect(resumed.run(arguments: ["share", "accept", Self.vaultID, invitationID, "wrong-code"] + option) != EXIT_SUCCESS)
        #expect(try !config.hasConfiguration())
        #expect(resumed.run(arguments: ["share", "compare", Self.vaultID, invitationID] + option) == EXIT_SUCCESS)
        if interruptedSelection {
            #expect(resumed.run(arguments: ["share", "accept", Self.vaultID, invitationID, transcript.comparisonCode] + option) != EXIT_SUCCESS)
            #expect(try !config.hasConfiguration())
            let savedState = try #require(try stateStore.loadState(vaultID: Self.vaultID, invitationDigest: state.invitationDigest))
            #expect(try V3EnrollmentCeremonyState(canonicalBytes: savedState).phase == .consumed)
        }
        #expect(resumed.run(arguments: ["share", "accept", Self.vaultID, invitationID, transcript.comparisonCode] + option) == EXIT_SUCCESS)
        #expect(try config.load().vaultID == Self.vaultID)
        #expect(try config.load().vaultDirectoryURL.standardizedFileURL == fixture.rootURL.standardizedFileURL)
        #expect(keys.loadCount == 0)
        #expect(keys.storeCount == 0)
        #expect(restarted.handle(.list).errorMessage?.contains("restarting") == true)
        #expect(io.stdout.contains("Verified and selected the existing vault"))
    }

    @Test
    func joiningDeviceSelectsOnlyAfterPermanentFirstTrustIsUsable() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        try fixture.publishCandidateDirectly()
        let stateStore = ApprovalMemoryCeremonyStateStore()
        let joinerState = try fixture.joinerCeremony()
        try stateStore.replaceState(
            joinerState.canonicalBytes,
            expectedState: nil,
            vaultID: Self.vaultID,
            invitationDigest: joinerState.invitationDigest
        )
        let checkpointStore = MemoryCheckpointStore()
        let cache = MemoryCheckpointCache()
        let session = V3DeviceWrappedVaultKeySessionStore()
        let selection = AdoptionSelectionRecorder()
        let replacementCompletion = ReplacementCompletionRecorder()
        let service = V3DeviceWrappedEnrollmentAdoptionService(
            source: fixture.store,
            checkpointStore: checkpointStore,
            cache: cache,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: ApprovalNoopMailbox(),
                stateStore: stateStore
            ),
            loadIdentity: { _, _ in fixture.joiner },
            session: session,
            selectVault: { selection.select($0) },
            verifyRuntime: { vaultID, installedSession in
                #expect(vaultID == Self.vaultID)
                #expect(try installedSession.load(
                    vaultID: vaultID,
                    keyID: fixture.candidate.body.keyID
                ) == Self.nextKey)
                let checkpoint = try #require(checkpointStore.checkpoint)
                #expect(try V3ManifestCheckpoint(
                    canonicalBytes: checkpoint
                ).envelopeDigest == fixture.candidate.manifestDigest)
            },
            completeReplacement: { vaultID in
                #expect(selection.vaultID == vaultID)
                #expect(checkpointStore.checkpoint != nil)
                let installedKey = try session.load(
                    vaultID: vaultID,
                    keyID: fixture.candidate.body.keyID
                )
                #expect(installedKey == Self.nextKey)
                replacementCompletion.complete(vaultID)
            }
        )
        let transcript = try #require(joinerState.transcript)

        let report = try service.adopt(
            vaultID: Self.vaultID,
            invitationDigest: joinerState.invitationDigest,
            approvedTranscriptDigest: transcript.digest,
            at: Self.approvalTime,
            operationID: Self.operationID
        )

        #expect(report.deviceName == "Joining Mac")
        #expect(selection.vaultID == Self.vaultID)
        #expect(replacementCompletion.vaultIDs == [Self.vaultID])
        #expect(cache.storedManifest == fixture.candidate.manifestData)
        #expect(try V3EnrollmentCeremonyState(
            canonicalBytes: #require(try stateStore.loadState(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest
            ))
        ).phase == .consumed)
    }

    @Test
    func joiningDeviceCanRetryExactConsumedApprovalAfterSelectionFailure()
        throws
    {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        try fixture.publishCandidateDirectly()
        let stateStore = ApprovalMemoryCeremonyStateStore()
        let joinerState = try fixture.joinerCeremony()
        try stateStore.replaceState(
            joinerState.canonicalBytes,
            expectedState: nil,
            vaultID: Self.vaultID,
            invitationDigest: joinerState.invitationDigest
        )
        let checkpointStore = MemoryCheckpointStore()
        let cache = MemoryCheckpointCache()
        let session = V3DeviceWrappedVaultKeySessionStore()
        let selection = AdoptionSelectionRecorder(failFirst: true)
        let service = V3DeviceWrappedEnrollmentAdoptionService(
            source: fixture.store,
            checkpointStore: checkpointStore,
            cache: cache,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: ApprovalNoopMailbox(),
                stateStore: stateStore
            ),
            loadIdentity: { _, _ in fixture.joiner },
            session: session,
            selectVault: { try selection.selectOrFail($0) },
            verifyRuntime: { _, _ in }
        )
        let transcript = try #require(joinerState.transcript)

        #expect(throws:
            V3DeviceWrappedEnrollmentAdoptionError.selectionFailed
        ) {
            _ = try service.adopt(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest,
                approvedTranscriptDigest: transcript.digest,
                at: Self.approvalTime,
                operationID: Self.operationID
            )
        }
        #expect(try V3EnrollmentCeremonyState(
            canonicalBytes: #require(try stateStore.loadState(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest
            ))
        ).phase == .consumed)

        _ = try service.adopt(
            vaultID: Self.vaultID,
            invitationDigest: joinerState.invitationDigest,
            approvedTranscriptDigest: transcript.digest,
            at: Self.approvalTime + 10_000,
            operationID: Self.operationID
        )

        #expect(selection.vaultID == Self.vaultID)
    }

    @Test
    func unboundOrUnavailableApprovalChangesNoJoiningTrust() throws {
        let fixture = try Fixture()
        defer { fixture.removeRoot() }
        let stateStore = ApprovalMemoryCeremonyStateStore()
        let joinerState = try fixture.joinerCeremony()
        try stateStore.replaceState(
            joinerState.canonicalBytes,
            expectedState: nil,
            vaultID: Self.vaultID,
            invitationDigest: joinerState.invitationDigest
        )
        let checkpointStore = MemoryCheckpointStore()
        let session = V3DeviceWrappedVaultKeySessionStore()
        let selection = AdoptionSelectionRecorder()
        let service = V3DeviceWrappedEnrollmentAdoptionService(
            source: fixture.store,
            checkpointStore: checkpointStore,
            cache: MemoryCheckpointCache(),
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: ApprovalNoopMailbox(),
                stateStore: stateStore
            ),
            loadIdentity: { _, _ in fixture.joiner },
            session: session,
            selectVault: { selection.select($0) },
            verifyRuntime: { _, _ in }
        )
        let transcript = try #require(joinerState.transcript)

        #expect(throws:
            V3DeviceWrappedEnrollmentAdoptionError.approvalUnavailable
        ) {
            _ = try service.adopt(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest,
                approvedTranscriptDigest: transcript.digest,
                at: Self.approvalTime,
                operationID: Self.operationID
            )
        }
        #expect(checkpointStore.checkpoint == nil)
        #expect(selection.vaultID == nil)
        #expect(try V3EnrollmentCeremonyState(
            canonicalBytes: #require(try stateStore.loadState(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest
            ))
        ).phase == .awaitingComparison)

        try fixture.publishManifest(
            try fixture.futureProfileCandidateManifest()
        )
        #expect(throws:
            V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired
        ) {
            _ = try service.adopt(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest,
                approvedTranscriptDigest: transcript.digest,
                at: Self.approvalTime,
                operationID: Self.operationID
            )
        }
        #expect(checkpointStore.checkpoint == nil)
        #expect(selection.vaultID == nil)

        let unbound = try fixture.unboundCandidate()
        try fixture.publishCandidateDirectly(unbound)
        #expect(throws:
            V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
        ) {
            _ = try service.adopt(
                vaultID: Self.vaultID,
                invitationDigest: joinerState.invitationDigest,
                approvedTranscriptDigest: transcript.digest,
                at: Self.approvalTime,
                operationID: Self.operationID
            )
        }
        #expect(checkpointStore.checkpoint == nil)
        #expect(selection.vaultID == nil)
    }

    private final class Fixture: @unchecked Sendable {
        let rootURL: URL
        let store: V3FilesystemTransactionArtifactStore
        let checkpointStore: MemoryCheckpointStore
        let anchorStore = MemoryAnchorStore()
        let cache = MemoryCheckpointCache()
        let owner: SoftwareDevice
        let joiner: SoftwareDevice
        let base: V3DeviceWrappedTrustedCheckpoint
        let currentEntries: [V3EntryObjectKey: V3EncryptedEntry]
        let ceremony: V3EnrollmentCeremonyState
        let candidate: V3DeviceWrappedEnrollmentTransitionCandidate

        init() throws {
            rootURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(
                at: rootURL,
                withIntermediateDirectories: true
            )
            store = V3FilesystemTransactionArtifactStore(
                rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
            )
            owner = try SoftwareDevice(
                displayName: "Owner Mac",
                signingScalar: 0x11,
                wrappingScalar: 0x12
            )
            joiner = try SoftwareDevice(
                displayName: "Joining Mac",
                signingScalar: 0x21,
                wrappingScalar: 0x22
            )
            let publication = try V3DeviceWrappedGenesisBuilder()
                .buildPublicationCandidate(
                    vaultID: vaultID,
                    authorityTransitionID: genesisTransitionID,
                    entryIDs: [entryID],
                    sourceEntries: [V2MigrationSourceEntry(
                        name: "account/password",
                        type: .secret,
                        plaintext: "correct horse battery staple",
                        sourceData: Data("retained v2 source".utf8)
                    )],
                    vaultKey: currentKey,
                    ownerIdentity: owner.publicIdentity
                )
            for entry in publication.entries {
                try store.stageEntry(
                    entry.encryptedEntry.canonicalBytes,
                    entryID: entry.manifestEntry.entryID,
                    digest: entry.digest,
                    operationID: seedOperationID
                )
                try store.publishStagedEntry(
                    entry.encryptedEntry.canonicalBytes,
                    entryID: entry.manifestEntry.entryID,
                    digest: entry.digest,
                    operationID: seedOperationID
                )
            }
            try store.stageManifest(
                publication.genesis.manifestData,
                digest: publication.genesis.manifestDigest,
                operationID: seedOperationID
            )
            try store.publishStagedManifest(
                publication.genesis.manifestData,
                digest: publication.genesis.manifestDigest,
                operationID: seedOperationID
            )
            let checkpoint = try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: publication.genesis.manifestDigest
            )
            checkpointStore = MemoryCheckpointStore(checkpoint: checkpoint)
            try cache.store(publication.genesis.manifestData, for: checkpoint)
            base = V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                    publication.genesis.manifestData
                )
            )
            currentEntries = Dictionary(uniqueKeysWithValues:
                publication.entries.map {
                    (
                        V3EntryObjectKey(
                            entryID: $0.manifestEntry.entryID,
                            digest: $0.digest
                        ),
                        $0.encryptedEntry
                    )
                }
            )
            ceremony = try Self.makeCeremony(
                parentDigest: checkpoint.envelopeDigest,
                owner: owner,
                joiner: joiner
            )
            candidate = try V3DeviceWrappedEnrollmentTransitionBuilder()
                .build(
                    from: base,
                    currentEntries: currentEntries,
                    state: ceremony,
                    currentVaultKey: currentKey,
                    nextVaultKey: nextKey,
                    authorityTransitionID:
                        try v3EnrollmentAuthorityTransitionID(
                            transcriptDigest: #require(ceremony.transcript).digest
                        ),
                    owner: owner,
                    at: approvalTime,
                    authorizationReason: "Approve the compared Mac."
                )
        }

        var stagedManifestURL: URL {
            rootURL.appendingPathComponent(
                ".transactions/\(operationID)/manifests/"
                    + "\(v3LowercaseHex(candidate.manifestDigest)).json"
            )
        }

        func publisher(
            observer: any V3ImmutableTransactionPhaseObserving,
            objectStore: (any V3TransactionArtifactStore)? = nil,
            repositoryObserver:
                (any V3DeviceWrappedRepositoryObserving)? = nil,
            limits: V3ManifestRepositoryLimits = .standard
        ) -> V3DeviceWrappedEnrollmentTransitionPublisher {
            let repositoryObserver = repositoryObserver
                ?? ClosureRepositoryObserver { [self] _, _ in
                    try repositoryObservation()
                }
            return V3DeviceWrappedEnrollmentTransitionPublisher(
                mutationOwner: VaultTransactionMutationOwner(
                    makeOperationID: { operationID }
                ),
                repositoryObserver: repositoryObserver,
                objectStore: objectStore ?? store,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: anchorStore,
                cache: cache,
                limits: limits,
                phaseObserver: observer
            )
        }

        func publish(
            using publisher: V3DeviceWrappedEnrollmentTransitionPublisher
        ) throws -> V3DeviceWrappedTrustedCheckpoint {
            try publisher.publish(
                candidate,
                parent: base,
                currentEntries: currentEntries,
                currentVaultKey: currentKey,
                nextVaultKey: nextKey,
                state: ceremony,
                localIdentity: owner,
                at: approvalTime,
                unwrapReason: "Verify the owner's rotated-key wrapper."
            )
        }

        func recoveryIntent() throws -> Data? {
            guard case let .available(data) = try store.readRecoveryIntent(
                operationID: operationID,
                maximumBytes: V3ImmutableTransactionRecoveryIntent
                    .maximumBytes
            ) else {
                return nil
            }
            return data
        }

        func repositoryObservation()
            throws -> V3DeviceWrappedRepositoryObservation
        {
            let checkpointData = try #require(checkpointStore.checkpoint)
            let checkpoint = try V3ManifestCheckpoint(
                canonicalBytes: checkpointData
            )
            var manifestDigests: Set<Data> = [base.checkpoint.envelopeDigest]
            var referencedEntries = Set(currentEntries.keys)
            var totalManifestBytes = base.envelope.canonicalBytes.count
            var totalEntryBytes = currentEntries.values.reduce(0) {
                $0 + $1.canonicalBytes.count
            }
            var heads = [base.checkpoint.envelopeDigest]
            var historyDepth = 0
            if case .available = try store.readManifest(
                digest: candidate.manifestDigest,
                maximumBytes: 2 * 1_024 * 1_024
            ) {
                manifestDigests.insert(candidate.manifestDigest)
                totalManifestBytes += candidate.manifestData.count
                heads = [candidate.manifestDigest]
                historyDepth = 1
                for entry in candidate.stagedEntries {
                    let digest = try #require(Base64URL.decodeCanonical(
                        entry.ciphertextDigest
                    ))
                    let key = V3EntryObjectKey(
                        entryID: entry.context.entryID,
                        digest: digest
                    )
                    if referencedEntries.insert(key).inserted {
                        totalEntryBytes += entry.canonicalBytes.count
                    }
                }
            }
            return V3DeviceWrappedRepositoryObservation(
                checkpoint: checkpoint,
                heads: heads,
                manifestDigests: manifestDigests,
                parentsByManifestDigest: [
                    base.checkpoint.envelopeDigest: [],
                    candidate.manifestDigest: [
                        base.checkpoint.envelopeDigest,
                    ],
                ].filter { manifestDigests.contains($0.key) },
                referencedEntryObjects: referencedEntries,
                resourceUsage: V3ManifestRepositoryUsage(
                    manifestObjectCount: manifestDigests.count,
                    maximumHistoryDepth: historyDepth,
                    totalManifestBytes: totalManifestBytes,
                    referencedEntryObjectCount: referencedEntries.count,
                    totalEntryBytes: totalEntryBytes
                )
            )
        }

        func candidateManifestIsUnavailable() throws -> Bool {
            if case .unavailable = try store.readManifest(
                digest: candidate.manifestDigest,
                maximumBytes: 2 * 1_024 * 1_024
            ) {
                return true
            }
            return false
        }

        func requireCandidateObjectsPublished() throws {
            guard case let .available(manifest) = try store.readManifest(
                digest: candidate.manifestDigest,
                maximumBytes: 2 * 1_024 * 1_024
            ) else {
                Issue.record("The enrollment manifest was not published.")
                return
            }
            #expect(manifest == candidate.manifestData)
            for entry in candidate.stagedEntries {
                let digest = try #require(Base64URL.decodeCanonical(
                    entry.ciphertextDigest
                ))
                guard case let .available(data) = try store.readEntry(
                    entryID: entry.context.entryID,
                    digest: digest,
                    maximumBytes: 16 * 1_024 * 1_024
                ) else {
                    Issue.record("A re-encrypted entry was not published.")
                    continue
                }
                #expect(data == entry.canonicalBytes)
            }
        }

        func publishCandidateDirectly(
            _ publication: V3DeviceWrappedEnrollmentTransitionCandidate? = nil
        ) throws {
            let publication = publication ?? candidate
            for entry in publication.stagedEntries {
                let digest = try #require(Base64URL.decodeCanonical(
                    entry.ciphertextDigest
                ))
                try store.stageEntry(
                    entry.canonicalBytes,
                    entryID: entry.context.entryID,
                    digest: digest,
                    operationID: operationID
                )
                try store.publishStagedEntry(
                    entry.canonicalBytes,
                    entryID: entry.context.entryID,
                    digest: digest,
                    operationID: operationID
                )
            }
            try store.stageManifest(
                publication.manifestData,
                digest: publication.manifestDigest,
                operationID: operationID
            )
            try store.publishStagedManifest(
                publication.manifestData,
                digest: publication.manifestDigest,
                operationID: operationID
            )
        }

        func unboundCandidate()
            throws -> V3DeviceWrappedEnrollmentTransitionCandidate
        {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: base,
                currentEntries: currentEntries,
                state: ceremony,
                currentVaultKey: currentKey,
                nextVaultKey: nextKey,
                authorityTransitionID: enrollmentTransitionID,
                owner: owner,
                at: approvalTime,
                authorizationReason: "Approve the compared Mac."
            )
        }

        func futureProfileCandidateManifest() throws -> Data {
            var text = try #require(String(
                data: candidate.manifestData,
                encoding: .utf8
            ))
            let version = try #require(
                text.range(of: "\"profileVersion\":2")
            )
            text.replaceSubrange(
                version,
                with: "\"profileVersion\":3"
            )
            return Data(text.utf8)
        }

        func publishManifest(_ data: Data) throws {
            let digest = Data(SHA256.hash(data: data))
            try store.stageManifest(
                data,
                digest: digest,
                operationID: operationID
            )
            try store.publishStagedManifest(
                data,
                digest: digest,
                operationID: operationID
            )
        }

        func joinerCeremony() throws -> V3EnrollmentCeremonyState {
            try V3EnrollmentCeremonyState(
                vaultID: ceremony.vaultID,
                invitationDigest: ceremony.invitationDigest,
                role: .joiner,
                phase: .awaitingComparison,
                signedInvitation: ceremony.signedInvitation,
                signedJoinRequest: ceremony.signedJoinRequest
            )
        }

        func removeRoot() {
            try? FileManager.default.removeItem(at: rootURL)
        }

        private static func makeCeremony(
            parentDigest: Data,
            owner: SoftwareDevice,
            joiner: SoftwareDevice
        ) throws -> V3EnrollmentCeremonyState {
            let invitation = try V3EnrollmentInvitation(
                vaultID: vaultID,
                parentManifestDigest: parentDigest,
                invitingDevice: owner.publicIdentity,
                nonce: Data(repeating: 0x61, count: 32),
                expiresAt: approvalTime
            )
            let authenticator = V3EnrollmentMessageAuthenticator()
            let signedInvitation = try authenticator.sign(
                invitation,
                using: owner,
                reason: "Create invitation."
            )
            let verified = try authenticator.verify(signedInvitation)
            let request = try V3EnrollmentJoinRequest(
                invitationDigest: invitation.digest,
                joiningDevice: joiner.publicIdentity,
                nonce: Data(repeating: 0x62, count: 32)
            )
            let signedRequest = try authenticator.sign(
                request,
                answering: verified,
                using: joiner,
                reason: "Join vault."
            )
            return try V3EnrollmentCeremonyState(
                vaultID: vaultID,
                invitationDigest: invitation.digest,
                role: .inviter,
                phase: .awaitingComparison,
                signedInvitation: signedInvitation,
                signedJoinRequest: signedRequest
            )
        }
    }

    private static func limits(
        maximumReferencedEntryObjects: Int
    ) -> V3ManifestRepositoryLimits {
        V3ManifestRepositoryLimits(
            maximumManifestObjects: 8,
            maximumHistoryDepth: 8,
            maximumReferencedEntryObjects: maximumReferencedEntryObjects,
            maximumManifestBytes: 2 * 1_024 * 1_024,
            maximumEntryBytes: 16 * 1_024 * 1_024,
            maximumTotalManifestBytes: 64 * 1_024 * 1_024,
            maximumTotalEntryBytes: 256 * 1_024 * 1_024
        )
    }
}

private final class ClosureRepositoryObserver:
    V3DeviceWrappedRepositoryObserving,
    @unchecked Sendable
{
    typealias Observe = @Sendable (
        _ vaultID: String,
        _ vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation

    private let observe: Observe

    init(_ observe: @escaping Observe) {
        self.observe = observe
    }

    func observeRepository(
        vaultID: String,
        vaultKeys: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        try observe(vaultID, vaultKeys)
    }
}

private final class SequencedRepositoryObserver:
    V3DeviceWrappedRepositoryObserving,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let observations: [V3DeviceWrappedRepositoryObservation]
    private var index = 0

    init(_ observations: [V3DeviceWrappedRepositoryObservation]) {
        precondition(!observations.isEmpty)
        self.observations = observations
    }

    var observationCount: Int {
        lock.withLock { index }
    }

    func observeRepository(
        vaultID _: String,
        vaultKeys _: [Data]
    ) throws -> V3DeviceWrappedRepositoryObservation {
        lock.withLock {
            let observation = observations[min(index, observations.count - 1)]
            index += 1
            return observation
        }
    }
}

private final class FaultInjectingArtifactStore:
    V3TransactionArtifactStore,
    @unchecked Sendable
{
    enum Fault {
        case entryUnavailableOnSecondRead(entryID: String, digest: Data)
        case manifestInvalidOnSecondRead(digest: Data)
    }

    private let base: any V3TransactionArtifactStore
    private let fault: Fault
    private let lock = NSLock()
    private var matchingReadCount = 0

    init(base: any V3TransactionArtifactStore, fault: Fault) {
        self.base = base
        self.fault = fault
    }

    func manifestDigests(
        maximumCount: Int
    ) throws -> V3RepositoryDirectoryListing {
        try base.manifestDigests(maximumCount: maximumCount)
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        if case let .manifestInvalidOnSecondRead(target) = fault,
           digest == target,
           isSecondMatchingRead() {
            return .invalid
        }
        return try base.readManifest(
            digest: digest,
            maximumBytes: maximumBytes
        )
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        if case let .entryUnavailableOnSecondRead(targetID, targetDigest) =
            fault,
           entryID == targetID,
           digest == targetDigest,
           isSecondMatchingRead() {
            return .unavailable
        }
        return try base.readEntry(
            entryID: entryID,
            digest: digest,
            maximumBytes: maximumBytes
        )
    }

    func readStagedEntry(
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try base.readStagedEntry(
            entryID: entryID,
            digest: digest,
            operationID: operationID,
            maximumBytes: maximumBytes
        )
    }

    func readStagedManifest(
        digest: Data,
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try base.readStagedManifest(
            digest: digest,
            operationID: operationID,
            maximumBytes: maximumBytes
        )
    }

    func stageEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.stageEntry(
            data,
            entryID: entryID,
            digest: digest,
            operationID: operationID
        )
    }

    func stageManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.stageManifest(
            data,
            digest: digest,
            operationID: operationID
        )
    }

    func publishStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.publishStagedEntry(
            data,
            entryID: entryID,
            digest: digest,
            operationID: operationID
        )
    }

    func publishStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.publishStagedManifest(
            data,
            digest: digest,
            operationID: operationID
        )
    }

    func removeStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.removeStagedEntry(
            data,
            entryID: entryID,
            digest: digest,
            operationID: operationID
        )
    }

    func removeStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.removeStagedManifest(
            data,
            digest: digest,
            operationID: operationID
        )
    }

    func removeEmptyTransactionDirectories(
        operationID: VaultTransactionOperationID,
        entryIDs: [String]
    ) throws {
        try base.removeEmptyTransactionDirectories(
            operationID: operationID,
            entryIDs: entryIDs
        )
    }

    func persistRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.persistRecoveryIntent(data, operationID: operationID)
    }

    func readRecoveryIntent(
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try base.readRecoveryIntent(
            operationID: operationID,
            maximumBytes: maximumBytes
        )
    }

    func removeRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try base.removeRecoveryIntent(data, operationID: operationID)
    }

    private func isSecondMatchingRead() -> Bool {
        lock.withLock {
            matchingReadCount += 1
            return matchingReadCount == 2
        }
    }
}

private enum PublicationTestError: Error {
    case interrupted
    case commitFailed
}

private enum ApprovalTestError: Error {
    case consumptionFailed
    case cleanupFailed
    case selectionFailed
}

private struct ApprovalStateLoader:
    V3DeviceWrappedMutationStateLoading,
    Sendable
{
    let trusted: V3DeviceWrappedTrustedCheckpoint
    let vaultKey: Data

    func authenticatedCheckpoint(
        reason _: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        trusted
    }

    func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
        guard keyID == trusted.envelope.body.keyID else {
            throw V3DeviceWrappedVaultKeySessionError.unavailable
        }
        return vaultKey
    }
}

private struct ApprovalNoopMailbox: V3EnrollmentMailboxStoring {
    func invitationDigests(
        maximumCount _: Int
    ) throws -> V3EnrollmentMailboxListing {
        .available(digests: [], objectCount: 0)
    }

    func readInvitation(digest _: Data) throws -> V3RepositoryObjectRead {
        .unavailable
    }

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
    ) throws -> V3RepositoryObjectRead {
        .unavailable
    }

    func publishJoinRequest(
        _: Data,
        invitationDigest _: Data
    ) throws {}
}

private final class ApprovalMemoryCeremonyStateStore:
    V3EnrollmentCeremonyStateStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var state: Data?
    private var failConsumedReplacement = false

    func setFailConsumedReplacement(_ fail: Bool) {
        lock.withLock { failConsumedReplacement = fail }
    }

    func loadState(
        vaultID _: String,
        invitationDigest _: Data
    ) throws -> Data? {
        lock.withLock { state }
    }

    func replaceState(
        _ state: Data,
        expectedState: Data?,
        vaultID _: String,
        invitationDigest _: Data
    ) throws {
        let decoded = try V3EnrollmentCeremonyState(canonicalBytes: state)
        try lock.withLock {
            guard self.state == expectedState else {
                throw V3EnrollmentCeremonyStateError.conflict
            }
            if decoded.phase == .consumed, failConsumedReplacement {
                throw ApprovalTestError.consumptionFailed
            }
            self.state = state
        }
    }
}

private final class AdoptionSelectionRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var selectedVaultID: String?
    private var shouldFail: Bool

    init(failFirst: Bool = false) {
        shouldFail = failFirst
    }

    var vaultID: String? {
        lock.withLock { selectedVaultID }
    }

    func select(_ vaultID: String) {
        lock.withLock { selectedVaultID = vaultID }
    }

    func selectOrFail(_ vaultID: String) throws {
        try lock.withLock {
            if shouldFail {
                shouldFail = false
                throw ApprovalTestError.selectionFailed
            }
            selectedVaultID = vaultID
        }
    }
}

private final class ReplacementCompletionRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    var vaultIDs: [String] {
        lock.withLock { storage }
    }

    func complete(_ vaultID: String) {
        lock.withLock { storage.append(vaultID) }
    }
}

private final class EnrollmentCommitRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedCheckpoint: V3DeviceWrappedTrustedCheckpoint?
    private var recordedVaultKey: Data?
    private var invocationCount = 0

    var checkpoint: V3DeviceWrappedTrustedCheckpoint? {
        lock.withLock { recordedCheckpoint }
    }

    var vaultKey: Data? {
        lock.withLock { recordedVaultKey }
    }

    var count: Int {
        lock.withLock { invocationCount }
    }

    func record(
        trusted: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data
    ) {
        lock.withLock {
            recordedCheckpoint = trusted
            recordedVaultKey = vaultKey
            invocationCount += 1
        }
    }
}

private final class RecordingObserver:
    V3ImmutableTransactionPhaseObserving,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var recorded: [V3ImmutableTransactionPhase] = []

    var phases: [V3ImmutableTransactionPhase] {
        lock.withLock { recorded }
    }

    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        lock.withLock { recorded.append(phase) }
    }
}

private final class InterruptingObserver:
    V3ImmutableTransactionPhaseObserving,
    @unchecked Sendable
{
    private let target: V3ImmutableTransactionPhase
    private let lock = NSLock()
    private var interrupted = false

    init(target: V3ImmutableTransactionPhase) {
        self.target = target
    }

    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            guard !interrupted, phase == target else {
                return
            }
            interrupted = true
            throw PublicationTestError.interrupted
        }
    }
}

private final class CheckpointChangingObserver:
    V3ImmutableTransactionPhaseObserving,
    @unchecked Sendable
{
    private let target: V3ImmutableTransactionPhase
    private let store: MemoryCheckpointStore
    private let expected: V3ManifestCheckpoint
    private let replacement: V3ManifestCheckpoint
    private let lock = NSLock()
    private var changed = false

    init(
        target: V3ImmutableTransactionPhase,
        store: MemoryCheckpointStore,
        expected: V3ManifestCheckpoint,
        replacement: V3ManifestCheckpoint
    ) {
        self.target = target
        self.store = store
        self.expected = expected
        self.replacement = replacement
    }

    func didReach(
        _ phase: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            guard !changed, phase == target else {
                return
            }
            changed = true
            try store.replaceCheckpoint(
                replacement.canonicalBytes,
                expectedCheckpoint: expected.canonicalBytes,
                vaultID: expected.vaultID
            )
        }
    }
}

private final class MemoryCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Data?
    init(checkpoint: V3ManifestCheckpoint? = nil) {
        stored = checkpoint?.canonicalBytes
    }

    var checkpoint: Data? {
        lock.withLock { stored }
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        lock.withLock { stored }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID _: String
    ) throws {
        try lock.withLock {
            guard stored == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            stored = checkpoint
        }
    }
}

private final class MemoryAnchorStore:
    V3ImmutableTransactionRecoveryAnchorStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var anchors: [String: Data] = [:]
    private var shouldFailNextRemoval = false

    func failNextRemoval() {
        lock.withLock { shouldFailNextRemoval = true }
    }

    func anchor(vaultID: String) -> Data? {
        lock.withLock { anchors[vaultID] }
    }

    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
        anchor(vaultID: vaultID)
    }

    func replaceRecoveryAnchor(
        _ anchor: Data?,
        expectedAnchor: Data?,
        vaultID: String
    ) throws {
        try lock.withLock {
            guard anchors[vaultID] == expectedAnchor else {
                throw V3ImmutableTransactionRecoveryAnchorError.conflict
            }
            if anchor == nil, shouldFailNextRemoval {
                shouldFailNextRemoval = false
                throw ApprovalTestError.cleanupFailed
            }
            anchors[vaultID] = anchor
        }
    }
}

private final class MemoryCheckpointCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var checkpoint: V3ManifestCheckpoint?
    private var data: Data?

    var storedManifest: Data? {
        lock.withLock { data }
    }

    func load(
        for requested: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        lock.withLock {
            guard checkpoint == requested, let data else {
                return .missing
            }
            return .available(data)
        }
    }

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws {
        lock.withLock {
            self.checkpoint = checkpoint
            data = manifestData
        }
    }
}

private struct SoftwareDevice:
    V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
{
    let vaultID =
        V3DeviceWrappedEnrollmentTransitionPublisherTests.vaultID
    let publicIdentity: V3EnrollmentDeviceIdentity
    let signingPrivateKey: P256.Signing.PrivateKey
    let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    init(
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        signingPrivateKey = try P256.Signing.PrivateKey(
            rawRepresentation: privateKeyBytes(signingScalar)
        )
        wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: privateKeyBytes(wrappingScalar)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingPrivateKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingPrivateKey.signature(for: input).rawRepresentation
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: wrappingPrivateKey,
            context: context
        )
    }
}

private func privateKeyBytes(_ scalar: UInt8) -> Data {
    Data(SHA256.hash(data: Data([scalar])))
}
