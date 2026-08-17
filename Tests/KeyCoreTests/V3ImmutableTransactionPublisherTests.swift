import CryptoKit
import Darwin
import Foundation
import JSONCanonicalization
import Testing
@testable import KeyCore

struct V3ImmutableTransactionPublisherTests {
    fileprivate static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    fileprivate static let entryA = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    fileprivate static let entryB = "018f4d3a-a844-72ad-983e-b09a8fc0e924"
    fileprivate static let vaultKey = Data((0..<32).map(UInt8.init))
    fileprivate static let keyID = try! V3VaultKeyID.derive(
        vaultKey: vaultKey,
        vaultID: vaultID
    )
    fileprivate static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    )

    @Test
    func publishesEntriesBeforeManifestAndAdvancesCheckpointLast() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let sealed = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/new",
            revision: 1,
            plaintext: "secret"
        )
        let record = fixture.record(for: sealed)
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [record]
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let observer = ProofObserver([proof, proof])
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: observer,
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        let trusted = try publisher.publish(
            V3ImmutableTransactionRequest(
                kind: .addEntry,
                candidateManifestData: candidate.data,
                stagedEntries: [sealed],
                candidateVaultKey: Self.vaultKey
            )
        )

        #expect(observer.observationCount == 2)
        #expect(objectStore.events == [
            "persist-intent",
            "stage-entry:\(Self.entryA)",
            "stage-manifest",
            "publish-entry:\(Self.entryA)",
            "read-entry:\(Self.entryA)",
            "publish-manifest",
            "read-manifest"
        ])
        #expect(
            checkpointStore.checkpoint
                == trusted.checkpoint.canonicalBytes
        )
        #expect(
            trusted.verifiedManifest.envelopeDigest
                == candidate.verified.envelopeDigest
        )
    }

    @Test
    func recoveryIntentRoundTripsCanonicalState() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: Self.operationID,
            kind: .editEntry,
            vaultID: Self.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: candidate.verified.envelopeDigest,
            stagedEntries: []
        )

        let decoded = try V3ImmutableTransactionRecoveryIntent(
            canonicalBytes: intent.canonicalBytes
        )

        #expect(decoded == intent)
        #expect(decoded.canonicalBytes == intent.canonicalBytes)
    }

    @Test
    func revocationIntentUsesTheExistingCandidateBoundSchema() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: Self.operationID,
            kind: .revokeDevice,
            vaultID: Self.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: candidate.verified.envelopeDigest,
            stagedEntries: []
        )

        let decoded = try V3ImmutableTransactionRecoveryIntent(
            canonicalBytes: intent.canonicalBytes
        )

        #expect(decoded == intent)
        #expect(decoded.kind == .revokeDevice)
        #expect(decoded.enrollmentTranscriptDigest == nil)
        #expect(decoded.canonicalBytes == intent.canonicalBytes)
    }

    @Test
    func recoveryAnchorRoundTripsDeviceLocalOwnershipState() throws {
        for phase in [
            V3ImmutableTransactionRecoveryAnchorPhase.prepared,
            .recoverable
        ] {
            let anchor = try V3ImmutableTransactionRecoveryAnchor(
                operationID: Self.operationID,
                vaultID: Self.vaultID,
                intentDigest: Data(repeating: 3, count: 32),
                phase: phase
            )

            let decoded = try V3ImmutableTransactionRecoveryAnchor(
                canonicalBytes: anchor.canonicalBytes
            )

            #expect(decoded == anchor)
            #expect(decoded.canonicalBytes == anchor.canonicalBytes)
        }
    }

    @Test
    func everyPublicationInterruptionRecoversToOldOrNewCheckpoint() throws {
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
            (.cleanupCompleted, true)
        ]

        for testCase in cases {
            let fixture = Fixture()
            let base = try fixture.genesis()
            let sealed = try fixture.sealedEntry(
                id: Self.entryA,
                name: "recovery/entry",
                revision: 1,
                plaintext: "secret"
            )
            let candidate = try fixture.child(
                parents: [base.verified],
                entries: [fixture.record(for: sealed)]
            )
            let proof = try fixture.proof(
                checkpoint: base.verified,
                manifests: [base.verified],
                heads: [base.verified]
            )
            let objectStore = RecordingObjectStore()
            let checkpointStore = MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
            let recoveryAnchorStore = MemoryRecoveryAnchorStore()
            let publisher = fixture.publisher(
                observer: ProofObserver([proof, proof, proof]),
                objectStore: objectStore,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: recoveryAnchorStore,
                phaseObserver: InterruptingPhaseObserver(
                    target: testCase.phase
                )
            )

            #expect(throws: PublicationTestError.interrupted) {
                _ = try publisher.publish(
                    V3ImmutableTransactionRequest(
                        kind: .addEntry,
                        candidateManifestData: candidate.data,
                        stagedEntries: [sealed],
                        candidateVaultKey: Self.vaultKey
                    )
                )
            }

            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                availableVaultKeys: [Self.vaultKey]
            )

            let expectedCheckpoint = testCase.expectsNewCheckpoint
                ? try V3ManifestCheckpoint(
                    verifiedManifest: candidate.verified
                ).canonicalBytes
                : proof.checkpoint.canonicalBytes
            #expect(checkpointStore.checkpoint == expectedCheckpoint)
            #expect(objectStore.recoveryIntentCount == 0)
            #expect(objectStore.stagedObjectCount == 0)
            #expect(
                recoveryAnchorStore.anchor(vaultID: Self.vaultID) == nil
            )
            #expect(
                objectStore.publishedManifestCount
                    == (testCase.expectsNewCheckpoint ? 1 : 0)
            )
        }
    }

    @Test
    func sharedIntentsWithoutThisDevicesAnchorAreIgnored() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let first = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let secondOperationID = try VaultTransactionOperationID(
            validating: "018f4d3a-a844-72ad-983e-b09a8fc0e924"
        )
        let second = try V3ImmutableTransactionRecoveryIntent(
            operationID: secondOperationID,
            kind: .editEntry,
            vaultID: Self.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: Data(repeating: 7, count: 32),
            stagedEntries: []
        )
        let firstIntent = try V3ImmutableTransactionRecoveryIntent(
            operationID: Self.operationID,
            kind: .editEntry,
            vaultID: Self.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: first.verified.envelopeDigest,
            stagedEntries: []
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let objectStore = RecordingObjectStore()
        try objectStore.persistRecoveryIntent(
            firstIntent.canonicalBytes,
            operationID: firstIntent.operationID
        )
        try objectStore.persistRecoveryIntent(
            second.canonicalBytes,
            operationID: second.operationID
        )
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        let outcome = try publisher.recoverInterruptedTransaction(
            vaultID: Self.vaultID,
            availableVaultKeys: [Self.vaultKey]
        )
        #expect(outcome == .nothingToRecover)
        #expect(checkpointStore.checkpoint == proof.checkpoint.canonicalBytes)
        #expect(objectStore.recoveryIntentCount == 2)
    }

    @Test
    func changedCheckpointAbandonsStagingWithoutPublishingCandidate() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let concurrentEntry = try fixture.sealedEntry(
            id: Self.entryB,
            name: "concurrent/entry",
            revision: 1,
            plaintext: "other"
        )
        let concurrent = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: concurrentEntry)]
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let recoveryAnchorStore = MemoryRecoveryAnchorStore()
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            phaseObserver: InterruptingPhaseObserver(
                target: .manifestStaged
            )
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        let concurrentCheckpoint = try V3ManifestCheckpoint(
            verifiedManifest: concurrent.verified
        )
        try checkpointStore.replaceCheckpoint(
            concurrentCheckpoint.canonicalBytes,
            expectedCheckpoint: proof.checkpoint.canonicalBytes,
            vaultID: Self.vaultID
        )

        let outcome = try publisher.recoverInterruptedTransaction(
            vaultID: Self.vaultID,
            availableVaultKeys: [Self.vaultKey]
        )

        #expect(outcome == .abandoned(operationID: Self.operationID))
        #expect(checkpointStore.checkpoint == concurrentCheckpoint.canonicalBytes)
        #expect(objectStore.publishedManifestCount == 0)
        #expect(objectStore.recoveryIntentCount == 0)
        #expect(objectStore.stagedObjectCount == 0)
    }

    @Test
    func missingCandidateKeyRetainsRecoverableTransaction() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let recoveryAnchorStore = MemoryRecoveryAnchorStore()
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            phaseObserver: InterruptingPhaseObserver(
                target: .manifestStaged
            )
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }

        #expect(throws: V3ImmutableTransactionRecoveryError
            .vaultKeyUnavailable(keyID: Self.keyID.rawValue)) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                availableVaultKeys: []
            )
        }
        #expect(checkpointStore.checkpoint == proof.checkpoint.canonicalBytes)
        #expect(objectStore.recoveryIntentCount == 1)
        #expect(objectStore.stagedObjectCount == 1)
        #expect(
            recoveryAnchorStore.anchor(vaultID: Self.vaultID) != nil
        )
    }

    @Test
    func pendingIntentBlocksAnotherPublicationUntilRecovery() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let objectStore = RecordingObjectStore()
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof, proof]),
            objectStore: objectStore,
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            ),
            phaseObserver: InterruptingPhaseObserver(
                target: .manifestStaged
            )
        )
        let request = V3ImmutableTransactionRequest(
            kind: .editEntry,
            candidateManifestData: candidate.data,
            stagedEntries: [],
            candidateVaultKey: Self.vaultKey
        )
        #expect(throws: PublicationTestError.interrupted) {
            _ = try publisher.publish(request)
        }

        #expect(throws: V3ImmutableTransactionRecoveryError
            .interruptedTransactionPending(
                operationID: Self.operationID.rawValue
            )) {
            _ = try publisher.publish(request)
        }
        #expect(objectStore.publishedManifestCount == 0)
        #expect(objectStore.recoveryIntentCount == 1)
    }

    @Test
    func armedRecoveryRetainsAnchorWhileSharedIntentIsUnavailable() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let anchor = try V3ImmutableTransactionRecoveryAnchor(
            operationID: Self.operationID,
            vaultID: Self.vaultID,
            intentDigest: Data(repeating: 9, count: 32),
            phase: .recoverable
        )
        let recoveryAnchorStore = MemoryRecoveryAnchorStore()
        try recoveryAnchorStore.replaceRecoveryAnchor(
            anchor.canonicalBytes,
            expectedAnchor: nil,
            vaultID: Self.vaultID
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: RecordingObjectStore(),
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            ),
            recoveryAnchorStore: recoveryAnchorStore
        )

        #expect(throws: V3ImmutableTransactionRecoveryError
            .transactionDirectoryUnavailable) {
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: Self.vaultID,
                availableVaultKeys: [Self.vaultKey]
            )
        }
        #expect(
            recoveryAnchorStore.anchor(vaultID: Self.vaultID)
                == anchor.canonicalBytes
        )
    }

    @Test
    func publishesMergeAcrossCheckpointSiblingBranch() throws {
        let fixture = Fixture()
        let genesis = try fixture.genesis()
        let leftEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "branch/left",
            revision: 1,
            plaintext: "left"
        )
        let rightEntry = try fixture.sealedEntry(
            id: Self.entryB,
            name: "branch/right",
            revision: 1,
            plaintext: "right"
        )
        let left = try fixture.child(
            parents: [genesis.verified],
            entries: [fixture.record(for: leftEntry)]
        )
        let right = try fixture.child(
            parents: [genesis.verified],
            entries: [fixture.record(for: rightEntry)]
        )
        let proof = try fixture.proof(
            checkpoint: left.verified,
            manifests: [
                genesis.verified,
                left.verified,
                right.verified
            ],
            heads: [left.verified, right.verified]
        )
        let reconciliation = try V3ManifestReconciler().reconcile(proof)
        guard case let .automaticMerge(plan) = reconciliation else {
            Issue.record("Expected an automatic merge plan.")
            return
        }
        let candidate = try fixture.envelope(content: plan.content)
        let objectStore = RecordingObjectStore(entries: [
            fixture.objectKey(for: fixture.record(for: leftEntry)):
                leftEntry.canonicalBytes,
            fixture.objectKey(for: fixture.record(for: rightEntry)):
                rightEntry.canonicalBytes
        ])
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        let trusted = try publisher.publish(
            V3ImmutableTransactionRequest(
                kind: .mergeHeads,
                candidateManifestData: candidate.data,
                stagedEntries: [],
                candidateVaultKey: Self.vaultKey
            )
        )

        #expect(
            trusted.verifiedManifest.envelopeDigest
                == candidate.verified.envelopeDigest
        )
        #expect(objectStore.publishedManifestCount == 1)
    }

    @Test
    func repositoryWideEntryByteLimitStopsBeforeStaging() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let sealed = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/new",
            revision: 1,
            plaintext: "secret"
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: sealed)]
        )
        let observed = testResourceUsage(for: proof)
        let exhausted = V3ManifestRepositoryUsage(
            manifestObjectCount: observed.manifestObjectCount,
            maximumHistoryDepth: observed.maximumHistoryDepth,
            totalManifestBytes: observed.totalManifestBytes,
            referencedEntryObjectCount:
                observed.referencedEntryObjectCount,
            totalEntryBytes:
                V3ManifestRepositoryLimits.standard.maximumTotalEntryBytes
        )
        let observation = V3ManifestAncestryObservation(
            proof: proof,
            resourceUsage: exhausted
        )
        let objectStore = RecordingObjectStore()
        let publisher = fixture.publisher(
            observer: ProofObserver(observations: [
                observation,
                observation
            ]),
            objectStore: objectStore,
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
        )

        #expect(throws: V3ImmutableTransactionError.objectTooLarge) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .addEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [sealed],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events.isEmpty)
    }

    @Test
    func resourceUsageChangeAfterStagingStopsFinalPublication() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let initial = testResourceUsage(for: proof)
        let exhausted = V3ManifestRepositoryUsage(
            manifestObjectCount:
                V3ManifestRepositoryLimits.standard.maximumManifestObjects,
            maximumHistoryDepth: initial.maximumHistoryDepth,
            totalManifestBytes: initial.totalManifestBytes,
            referencedEntryObjectCount:
                initial.referencedEntryObjectCount,
            totalEntryBytes: initial.totalEntryBytes
        )
        let observer = ProofObserver(observations: [
            V3ManifestAncestryObservation(
                proof: proof,
                resourceUsage: initial
            ),
            V3ManifestAncestryObservation(
                proof: proof,
                resourceUsage: exhausted
            )
        ])
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: observer,
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        #expect(throws: V3ImmutableTransactionError.objectTooLarge) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events == [
            "persist-intent",
            "stage-manifest"
        ])
        #expect(objectStore.publishedManifestCount == 0)
        #expect(
            checkpointStore.checkpoint
                == proof.checkpoint.canonicalBytes
        )
    }

    @Test
    func changedHeadsAfterStagingPublishNoRepositoryObjects() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let firstProof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let changed = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let changedProof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified, changed.verified],
            heads: [changed.verified]
        )
        let sealed = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/new",
            revision: 1,
            plaintext: "secret"
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: sealed)]
        )
        let observer = ProofObserver([firstProof, changedProof])
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: firstProof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: observer,
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        #expect(throws: V3ImmutableTransactionError.expectedHeadsChanged) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .addEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [sealed],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }

        #expect(objectStore.events == [
            "persist-intent",
            "stage-entry:\(Self.entryA)",
            "stage-manifest"
        ])
        #expect(objectStore.publishedEntryCount == 0)
        #expect(objectStore.publishedManifestCount == 0)
        #expect(
            checkpointStore.checkpoint
                == firstProof.checkpoint.canonicalBytes
        )
    }

    @Test
    func failedEntryPublicationCannotExposeManifestOrCheckpoint() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let sealed = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/new",
            revision: 1,
            plaintext: "secret"
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: sealed)]
        )
        let objectStore = RecordingObjectStore(
            failure: .publishEntry
        )
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        #expect(throws: PublicationTestError.expected) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .addEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [sealed],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }

        #expect(objectStore.publishedManifestCount == 0)
        #expect(
            checkpointStore.checkpoint
                == proof.checkpoint.canonicalBytes
        )
    }

    @Test
    func failedManifestPublicationCannotAdvanceCheckpoint() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let objectStore = RecordingObjectStore(
            failure: .publishManifest
        )
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        #expect(throws: PublicationTestError.expected) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.publishedManifestCount == 0)
        #expect(
            checkpointStore.checkpoint
                == proof.checkpoint.canonicalBytes
        )
    }

    @Test
    func checkpointConflictLeavesPublishedManifestForRecovery() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint,
            failReplacement: true
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        #expect(throws: V3ManifestCheckpointStoreError.conflict) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.publishedManifestCount == 1)
        #expect(
            checkpointStore.checkpoint
                == proof.checkpoint.canonicalBytes
        )
    }

    @Test
    func missingExistingEntryStopsBeforeStaging() throws {
        let fixture = Fixture()
        let sealed = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/existing",
            revision: 1,
            plaintext: "secret"
        )
        let record = fixture.record(for: sealed)
        let base = try fixture.genesis(entries: [record])
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [record]
        )
        let objectStore = RecordingObjectStore()
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        #expect(throws: V3ImmutableTransactionError.referencedEntryUnavailable(
            entryID: Self.entryA,
            digest: record.ciphertextDigest
        )) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events == [
            "read-entry:\(Self.entryA)"
        ])
    }

    @Test
    func invalidExistingEntryIsNotReportedAsTransportDelay() throws {
        let fixture = Fixture()
        let sealed = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/existing",
            revision: 1,
            plaintext: "secret"
        )
        let record = fixture.record(for: sealed)
        let base = try fixture.genesis(entries: [record])
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [record]
        )
        let digest = try #require(Base64URL.decodeCanonical(
            record.ciphertextDigest
        ))
        let objectStore = RecordingObjectStore(entries: [
            TestEntryKey(entryID: Self.entryA, digest: digest):
                Data("substituted".utf8)
        ])
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: objectStore,
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
        )

        #expect(throws: V3ImmutableTransactionError.referencedEntryInvalid(
            entryID: Self.entryA,
            digest: record.ciphertextDigest
        )) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events == [
            "read-entry:\(Self.entryA)"
        ])
    }

    @Test
    func exactAutomaticMergeCanPublishWithoutResealingEntries() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let leftEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            plaintext: "left"
        )
        let rightEntry = try fixture.sealedEntry(
            id: Self.entryB,
            name: "account/b",
            revision: 1,
            plaintext: "right"
        )
        let leftRecord = fixture.record(for: leftEntry)
        let rightRecord = fixture.record(for: rightEntry)
        let left = try fixture.child(
            parents: [base.verified],
            entries: [leftRecord]
        )
        let right = try fixture.child(
            parents: [base.verified],
            entries: [rightRecord]
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified, left.verified, right.verified],
            heads: [right.verified, left.verified]
        )
        guard case let .automaticMerge(plan) =
            try V3ManifestReconciler().reconcile(proof)
        else {
            Issue.record("Expected an automatic merge plan.")
            return
        }
        let candidate = try fixture.envelope(content: plan.content)
        let objectStore = RecordingObjectStore(
            entries: [
                fixture.objectKey(for: leftRecord): leftEntry.canonicalBytes,
                fixture.objectKey(for: rightRecord): rightEntry.canonicalBytes
            ]
        )
        let checkpointStore = MemoryCheckpointStore(
            checkpoint: proof.checkpoint
        )
        let publisher = fixture.publisher(
            observer: ProofObserver([proof, proof]),
            objectStore: objectStore,
            checkpointStore: checkpointStore
        )

        _ = try publisher.publish(
            V3ImmutableTransactionRequest(
                kind: .mergeHeads,
                candidateManifestData: candidate.data,
                stagedEntries: [],
                candidateVaultKey: Self.vaultKey
            )
        )

        #expect(objectStore.events.first == "read-entry:\(Self.entryA)")
        #expect(!objectStore.events.contains(where: {
            $0.hasPrefix("stage-entry:")
        }))
        #expect(objectStore.events.suffix(2) == [
            "publish-manifest", "read-manifest"
        ])
    }

    @Test
    func automaticMergeCandidateMustMatchTheDeterministicPlan() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let leftEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            plaintext: "left"
        )
        let rightEntry = try fixture.sealedEntry(
            id: Self.entryB,
            name: "account/b",
            revision: 1,
            plaintext: "right"
        )
        let leftRecord = fixture.record(for: leftEntry)
        let rightRecord = fixture.record(for: rightEntry)
        let left = try fixture.child(
            parents: [base.verified],
            entries: [leftRecord]
        )
        let right = try fixture.child(
            parents: [base.verified],
            entries: [rightRecord]
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified, left.verified, right.verified],
            heads: [left.verified, right.verified]
        )
        let incompleteMerge = try fixture.child(
            parents: [left.verified, right.verified],
            entries: [leftRecord]
        )
        let objectStore = RecordingObjectStore()
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: objectStore,
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
        )

        #expect(
            throws: V3ImmutableTransactionError
                .candidateDoesNotMatchAutomaticMerge
        ) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .mergeHeads,
                    candidateManifestData: incompleteMerge.data,
                    stagedEntries: [],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events.isEmpty)
    }

    @Test
    func conflictedHistoryCannotEnterPublication() throws {
        let fixture = Fixture()
        let baseEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            plaintext: "base"
        )
        let base = try fixture.genesis(
            entries: [fixture.record(for: baseEntry)]
        )
        let leftEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            plaintext: "left"
        )
        let rightEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            plaintext: "right"
        )
        let left = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: leftEntry)]
        )
        let right = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: rightEntry)]
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified, left.verified, right.verified],
            heads: [left.verified, right.verified]
        )
        let objectStore = RecordingObjectStore()
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: objectStore,
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
        )

        #expect(throws: V3ImmutableTransactionError.unresolvedConflict) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .editEntry,
                    candidateManifestData: left.data,
                    stagedEntries: [leftEntry],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events.isEmpty)
    }

    @Test
    func stagedEntryMustMatchCandidateContextAndKey() throws {
        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidateEntry = try fixture.sealedEntry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            plaintext: "candidate"
        )
        let unrelatedEntry = try fixture.sealedEntry(
            id: Self.entryB,
            name: "account/b",
            revision: 1,
            plaintext: "unrelated"
        )
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: [fixture.record(for: candidateEntry)]
        )
        let proof = try fixture.proof(
            checkpoint: base.verified,
            manifests: [base.verified],
            heads: [base.verified]
        )
        let objectStore = RecordingObjectStore()
        let publisher = fixture.publisher(
            observer: ProofObserver([proof]),
            objectStore: objectStore,
            checkpointStore: MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
        )

        #expect(throws: V3ImmutableTransactionError.invalidStagedEntry) {
            _ = try publisher.publish(
                V3ImmutableTransactionRequest(
                    kind: .addEntry,
                    candidateManifestData: candidate.data,
                    stagedEntries: [unrelatedEntry],
                    candidateVaultKey: Self.vaultKey
                )
            )
        }
        #expect(objectStore.events.isEmpty)
    }
}

struct V3FilesystemImmutableObjectPublicationTests {
    @Test
    func filesystemRecoveryCoversEveryPublicationPhase() throws {
        let phases: [(
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
            (.cleanupCompleted, true)
        ]

        for testCase in phases {
            let rootURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(
                    UUID().uuidString,
                    isDirectory: true
                )
            try FileManager.default.createDirectory(
                at: rootURL,
                withIntermediateDirectories: true
            )
            defer { try? FileManager.default.removeItem(at: rootURL) }

            let fixture = Fixture()
            let base = try fixture.genesis()
            let sealed = try fixture.sealedEntry(
                id: V3ImmutableTransactionPublisherTests.entryA,
                name: "filesystem/recovery",
                revision: 1,
                plaintext: "secret"
            )
            let candidate = try fixture.child(
                parents: [base.verified],
                entries: [fixture.record(for: sealed)]
            )
            let proof = try fixture.proof(
                checkpoint: base.verified,
                manifests: [base.verified],
                heads: [base.verified]
            )
            let store = V3FilesystemTransactionArtifactStore(
                rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
            )
            let checkpointStore = MemoryCheckpointStore(
                checkpoint: proof.checkpoint
            )
            let recoveryAnchorStore = MemoryRecoveryAnchorStore()
            let publisher = fixture.publisher(
                observer: ProofObserver([proof, proof, proof]),
                objectStore: store,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: recoveryAnchorStore,
                phaseObserver: InterruptingPhaseObserver(
                    target: testCase.phase
                )
            )

            #expect(throws: PublicationTestError.interrupted) {
                _ = try publisher.publish(
                    V3ImmutableTransactionRequest(
                        kind: .addEntry,
                        candidateManifestData: candidate.data,
                        stagedEntries: [sealed],
                        candidateVaultKey:
                            V3ImmutableTransactionPublisherTests.vaultKey
                    )
                )
            }
            _ = try publisher.recoverInterruptedTransaction(
                vaultID: V3ImmutableTransactionPublisherTests.vaultID,
                availableVaultKeys: [
                    V3ImmutableTransactionPublisherTests.vaultKey
                ]
            )

            let expectedCheckpoint = testCase.expectsNewCheckpoint
                ? try V3ManifestCheckpoint(
                    verifiedManifest: candidate.verified
                ).canonicalBytes
                : proof.checkpoint.canonicalBytes
            #expect(checkpointStore.checkpoint == expectedCheckpoint)
            #expect(
                recoveryAnchorStore.anchor(
                    vaultID: V3ImmutableTransactionPublisherTests.vaultID
                ) == nil
            )
            guard case .unavailable = try store.readRecoveryIntent(
                operationID:
                    V3ImmutableTransactionPublisherTests.operationID,
                maximumBytes:
                    V3ImmutableTransactionRecoveryIntent.maximumBytes
            ) else {
                Issue.record("Recovery intent remained after recovery.")
                continue
            }

            let manifest = try store.readManifest(
                digest: candidate.verified.envelopeDigest,
                maximumBytes:
                    V3ManifestRepositoryLimits.standard.maximumManifestBytes
            )
            switch manifest {
            case .available:
                #expect(testCase.expectsNewCheckpoint)
            case .unavailable:
                #expect(!testCase.expectsNewCheckpoint)
            case .invalid, .tooLarge:
                Issue.record("Recovered manifest was invalid.")
            }
        }
    }

    @Test
    func persistsAndConservativelyRemovesRecoveryIntent() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: rootURL) }

        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let operationID = V3ImmutableTransactionPublisherTests.operationID
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: .editEntry,
            vaultID: V3ImmutableTransactionPublisherTests.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: candidate.verified.envelopeDigest,
            stagedEntries: []
        )
        let store = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )

        try store.persistRecoveryIntent(
            intent.canonicalBytes,
            operationID: operationID
        )
        guard case let .available(data) = try store.readRecoveryIntent(
                operationID: operationID,
                maximumBytes:
                    V3ImmutableTransactionRecoveryIntent.maximumBytes
            )
        else {
            Issue.record("Recovery intent was not durably discoverable.")
            return
        }
        #expect(data == intent.canonicalBytes)

        try store.removeRecoveryIntent(
            intent.canonicalBytes,
            operationID: operationID
        )
        try store.removeEmptyTransactionDirectories(
            operationID: operationID,
            entryIDs: []
        )

        guard case .unavailable = try store.readRecoveryIntent(
            operationID: operationID,
            maximumBytes:
                V3ImmutableTransactionRecoveryIntent.maximumBytes
        ) else {
            Issue.record("Cleaned recovery intent remained readable.")
            return
        }
    }

    @Test
    func recoveryCleanupNeverFollowsASubstitutedIntentPath() throws {
        let parentURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let rootURL = parentURL.appendingPathComponent(
            "vault",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: parentURL) }

        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let operationID = V3ImmutableTransactionPublisherTests.operationID
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: .editEntry,
            vaultID: V3ImmutableTransactionPublisherTests.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: candidate.verified.envelopeDigest,
            stagedEntries: []
        )
        let operationDirectory = rootURL
            .appendingPathComponent(".transactions", isDirectory: true)
            .appendingPathComponent(
                operationID.rawValue,
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: operationDirectory,
            withIntermediateDirectories: true
        )
        let outsideURL = parentURL.appendingPathComponent("outside-intent")
        let outsideData = intent.canonicalBytes
        try outsideData.write(to: outsideURL)
        let substitutedURL = operationDirectory.appendingPathComponent(
            "intent.json"
        )
        try FileManager.default.createSymbolicLink(
            at: substitutedURL,
            withDestinationURL: outsideURL
        )
        let store = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )

        #expect(throws: VaultPathResolutionError.symbolicLink(
            component: "intent.json"
        )) {
            try store.removeRecoveryIntent(
                intent.canonicalBytes,
                operationID: operationID
            )
        }
        #expect(try Data(contentsOf: outsideURL) == outsideData)
        #expect(FileManager.default.fileExists(atPath: substitutedURL.path))
    }

    @Test
    func processExitDuringAtomicWriteNeverExposesPartialRecoveryIntent()
        async throws
    {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: rootURL) }

        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let operationID = V3ImmutableTransactionPublisherTests.operationID
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: .editEntry,
            vaultID: V3ImmutableTransactionPublisherTests.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: candidate.verified.envelopeDigest,
            stagedEntries: []
        )
        let rootPath = rootURL.path
        let operationIDRawValue = operationID.rawValue
        let intentData = intent.canonicalBytes

        await #expect(processExitsWith: .exitCode(23)) {
            [
                rootPath = rootPath as String,
                operationIDRawValue = operationIDRawValue as String,
                intentData = intentData as Data
            ] in
            let operationID = try VaultTransactionOperationID(
                validating: operationIDRawValue
            )
            let interruptedStore = V3FilesystemTransactionArtifactStore(
                rootHandle: try VaultRootDirectoryHandle(
                    opening: URL(fileURLWithPath: rootPath)
                ),
                writeObserver: ExitingAtomicWriteObserver()
            )
            try interruptedStore.persistRecoveryIntent(
                intentData,
                operationID: operationID
            )
        }

        let resumedStore = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )
        guard case .unavailable = try resumedStore.readRecoveryIntent(
            operationID: operationID,
            maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes
        ) else {
            Issue.record("A partial recovery intent became visible.")
            return
        }

        let operationDirectory = rootURL
            .appendingPathComponent(".transactions", isDirectory: true)
            .appendingPathComponent(
                operationID.rawValue,
                isDirectory: true
            )
        let interruptedTemporaryNames = try FileManager.default
            .contentsOfDirectory(atPath: operationDirectory.path)
            .filter {
                $0.hasPrefix(".intent.json.")
                    && $0.hasSuffix(".partial")
            }
        try #require(interruptedTemporaryNames.count == 1)
        let interruptedTemporaryName = try #require(
            interruptedTemporaryNames.first
        )
        let interruptedTemporaryURL = operationDirectory
            .appendingPathComponent(interruptedTemporaryName)

        try resumedStore.persistRecoveryIntent(
            intent.canonicalBytes,
            operationID: operationID
        )
        guard case let .available(observed) =
            try resumedStore.readRecoveryIntent(
                operationID: operationID,
                maximumBytes:
                    V3ImmutableTransactionRecoveryIntent.maximumBytes
            )
        else {
            Issue.record("The atomic recovery-intent retry did not complete.")
            return
        }
        #expect(observed == intent.canonicalBytes)
        #expect(
            FileManager.default.fileExists(
                atPath: interruptedTemporaryURL.path
            )
        )
    }

    @Test
    func atomicWriteNeverOpensAPreexistingHardLinkedTemporaryPath() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: rootURL) }

        let fixture = Fixture()
        let base = try fixture.genesis()
        let candidate = try fixture.child(
            parents: [base.verified],
            entries: []
        )
        let operationID = V3ImmutableTransactionPublisherTests.operationID
        let intent = try V3ImmutableTransactionRecoveryIntent(
            operationID: operationID,
            kind: .editEntry,
            vaultID: V3ImmutableTransactionPublisherTests.vaultID,
            expectedCheckpoint: V3ManifestCheckpoint(
                verifiedManifest: base.verified
            ),
            expectedHeads: [base.verified.envelopeDigest],
            candidateManifestDigest: candidate.verified.envelopeDigest,
            stagedEntries: []
        )
        let operationDirectory = rootURL
            .appendingPathComponent(".transactions", isDirectory: true)
            .appendingPathComponent(
                operationID.rawValue,
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: operationDirectory,
            withIntermediateDirectories: true
        )
        let victimURL = rootURL.appendingPathComponent("victim")
        let victimData = Data("must remain unchanged".utf8)
        try victimData.write(to: victimURL)
        let hostileTemporaryURL = operationDirectory
            .appendingPathComponent(".intent.json.partial")
        try FileManager.default.linkItem(
            at: victimURL,
            to: hostileTemporaryURL
        )

        let store = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )
        try store.persistRecoveryIntent(
            intent.canonicalBytes,
            operationID: operationID
        )

        #expect(try Data(contentsOf: victimURL) == victimData)
        #expect(try Data(contentsOf: hostileTemporaryURL) == victimData)
        guard case let .available(observed) = try store.readRecoveryIntent(
            operationID: operationID,
            maximumBytes: V3ImmutableTransactionRecoveryIntent.maximumBytes
        ) else {
            Issue.record("The recovery intent was not published.")
            return
        }
        #expect(observed == intent.canonicalBytes)
    }

    @Test
    func stagesAndAtomicallyPublishesContentAddressedObjects() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: rootURL) }

        let store = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )
        let operationID = try VaultTransactionOperationID(
            validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        )
        let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
        let entryData = Data("entry".utf8)
        let entryDigest = Data(SHA256.hash(data: entryData))
        let manifestData = Data("manifest".utf8)
        let manifestDigest = Data(SHA256.hash(data: manifestData))

        try store.stageEntry(
            entryData,
            entryID: entryID,
            digest: entryDigest,
            operationID: operationID
        )
        try store.stageManifest(
            manifestData,
            digest: manifestDigest,
            operationID: operationID
        )
        try store.publishStagedEntry(
            entryData,
            entryID: entryID,
            digest: entryDigest,
            operationID: operationID
        )
        try store.publishStagedManifest(
            manifestData,
            digest: manifestDigest,
            operationID: operationID
        )

        guard case let .available(observedEntry) = try store.readEntry(
            entryID: entryID,
            digest: entryDigest,
            maximumBytes: 100
        ), case let .available(observedManifest) = try store.readManifest(
            digest: manifestDigest,
            maximumBytes: 100
        ) else {
            Issue.record("Published objects were not readable.")
            return
        }
        #expect(observedEntry == entryData)
        #expect(observedManifest == manifestData)
        #expect(throws: V3ImmutableObjectPublicationError.digestMismatch) {
            try store.stageManifest(
                Data("different".utf8),
                digest: manifestDigest,
                operationID: operationID
            )
        }
    }

    @Test
    func publicationNeverOverwritesDifferentDestinationBytes() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: rootURL) }

        let store = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )
        let operationID = try VaultTransactionOperationID(
            validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        )
        let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
        let data = Data("entry".utf8)
        let digest = Data(SHA256.hash(data: data))
        let destinationPath = entryPath(
            entryID: entryID,
            digest: Base64URL.encode(digest)
        )
        let destinationURL = rootURL.appendingPathComponent(destinationPath)
        try FileManager.default.createDirectory(
            at: destinationURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("different".utf8).write(to: destinationURL)
        try store.stageEntry(
            data,
            entryID: entryID,
            digest: digest,
            operationID: operationID
        )

        #expect(throws: V3ImmutableObjectPublicationError.conflictingObject(
            path: destinationPath
        )) {
            try store.publishStagedEntry(
                data,
                entryID: entryID,
                digest: digest,
                operationID: operationID
            )
        }
        #expect(try Data(contentsOf: destinationURL) == Data("different".utf8))
    }

    @Test
    func stagingCannotFollowAReplacedTransactionDirectory() throws {
        let rootURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let outsideURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: outsideURL,
            withIntermediateDirectories: true
        )
        defer {
            try? FileManager.default.removeItem(at: rootURL)
            try? FileManager.default.removeItem(at: outsideURL)
        }
        try FileManager.default.createSymbolicLink(
            at: rootURL.appendingPathComponent(".transactions"),
            withDestinationURL: outsideURL
        )

        let store = V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
        )
        let operationID = try VaultTransactionOperationID(
            validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        )
        let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
        let data = Data("entry".utf8)
        let digest = Data(SHA256.hash(data: data))

        #expect(throws: VaultPathResolutionError.self) {
            try store.stageEntry(
                data,
                entryID: entryID,
                digest: digest,
                operationID: operationID
            )
        }
        #expect(
            try FileManager.default.contentsOfDirectory(
                atPath: outsideURL.path
            ).isEmpty
        )
    }
}

private struct Fixture {
    typealias Manifest = (data: Data, verified: V3VerifiedManifest)

    func genesis(
        entries: [V3ManifestEntry] = []
    ) throws -> Manifest {
        let result = try envelope(
            parents: [],
            entries: entries
        )
        return (
            result.data,
            try V3ManifestAuthenticator().verify(
                result.data,
                vaultKey: V3ImmutableTransactionPublisherTests.vaultKey,
                trustAnchor: .localGenesis(
                    vaultID: V3ImmutableTransactionPublisherTests.vaultID
                )
            )
        )
    }

    func child(
        parents: [V3VerifiedManifest],
        entries: [V3ManifestEntry]
    ) throws -> Manifest {
        let result = try envelope(
            parents: parents,
            entries: entries
        )
        return (
            result.data,
            try V3ManifestAuthenticator().verify(
                result.data,
                vaultKey: V3ImmutableTransactionPublisherTests.vaultKey,
                trustAnchor: .verifiedParents(parents)
            )
        )
    }

    func envelope(
        content: V3ManifestContent
    ) throws -> Manifest {
        let data = try envelopeData(content: content)
        return (
            data,
            V3VerifiedManifest(
                envelope: try V3ManifestAuthenticator().parse(data),
                envelopeDigest: Data(SHA256.hash(data: data))
            )
        )
    }

    func proof(
        checkpoint: V3VerifiedManifest,
        manifests: [V3VerifiedManifest],
        heads: [V3VerifiedManifest]
    ) throws -> V3ManifestAncestryProof {
        V3ManifestAncestryProof(
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: checkpoint
            ),
            manifests: manifests,
            heads: heads
        )
    }

    func sealedEntry(
        id: String,
        name: String,
        revision: UInt64,
        plaintext: String
    ) throws -> V3EncryptedEntry {
        try V3EntryCipher().seal(
            plaintext,
            context: V3EntryAuthenticationContext(
                vaultID: V3ImmutableTransactionPublisherTests.vaultID,
                entryID: id,
                name: name,
                type: .secret,
                keyID: V3ImmutableTransactionPublisherTests.keyID,
                revision: revision
            ),
            vaultKey: V3ImmutableTransactionPublisherTests.vaultKey
        )
    }

    func record(for entry: V3EncryptedEntry) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: entry.context.entryID,
            name: entry.context.name,
            type: entry.context.type,
            revision: entry.context.revision,
            keyID: entry.context.keyID,
            ciphertextDigest: entry.ciphertextDigest
        )
    }

    func objectKey(for entry: V3ManifestEntry) -> TestEntryKey {
        TestEntryKey(
            entryID: entry.entryID,
            digest: Base64URL.decodeCanonical(entry.ciphertextDigest)!
        )
    }

    func publisher(
        observer: ProofObserver,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: MemoryCheckpointStore,
        recoveryAnchorStore: MemoryRecoveryAnchorStore =
            MemoryRecoveryAnchorStore(),
        phaseObserver: any V3ImmutableTransactionPhaseObserving =
            TestNoopPhaseObserver()
    ) -> V3ImmutableTransactionPublisher {
        V3ImmutableTransactionPublisher(
            mutationOwner: VaultTransactionMutationOwner(
                makeOperationID: {
                    V3ImmutableTransactionPublisherTests.operationID
                }
            ),
            ancestryObserver: observer,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            phaseObserver: phaseObserver
        )
    }

    private func envelope(
        parents: [V3VerifiedManifest],
        entries: [V3ManifestEntry]
    ) throws -> Manifest {
        let parentValues = parents
            .map(\.envelopeDigest)
            .sorted { $0.lexicographicallyPrecedes($1) }
            .map(Base64URL.encode)
        let content = V3ManifestContent(
            parents: parentValues,
            manifest: V3ManifestBody(
                vaultID: V3ImmutableTransactionPublisherTests.vaultID,
                mode: .local,
                keyID: V3ImmutableTransactionPublisherTests.keyID,
                devices: [],
                wrappedKeys: [],
                entries: entries.sorted(by: entryPrecedes)
            )
        )
        let data = try envelopeData(content: content)
        return (
            data,
            V3VerifiedManifest(
                envelope: try V3ManifestAuthenticator().parse(data),
                envelopeDigest: Data(SHA256.hash(data: data))
            )
        )
    }

    private func envelopeData(
        content: V3ManifestContent
    ) throws -> Data {
        let contentJSON = canonicalContent(content)
        let canonicalContent = CanonicalJSON.encode(contentJSON)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: content.manifest.vaultID,
            vaultKey: V3ImmutableTransactionPublisherTests.vaultKey
        )
        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", contentJSON),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array([]))
        ]))
    }

    private func canonicalContent(
        _ content: V3ManifestContent
    ) -> CanonicalJSONValue {
        .object([
            ("parents", .array(content.parents.map(
                CanonicalJSONValue.string
            ))),
            ("manifest", .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(content.manifest.vaultID)),
                ("mode", .string(content.manifest.mode.rawValue)),
                ("keyID", .string(content.manifest.keyID.rawValue)),
                ("devices", .array([])),
                ("wrappedKeys", .array([])),
                ("entries", .array(content.manifest.entries.map {
                    .object([
                        ("entryID", .string($0.entryID)),
                        ("name", .string($0.name)),
                        ("type", .string($0.type.rawValue)),
                        ("revision", .integer($0.revision)),
                        ("keyID", .string($0.keyID.rawValue)),
                        ("ciphertextDigest", .string(
                            $0.ciphertextDigest
                        ))
                    ])
                }))
            ]))
        ])
    }

    private func entryPrecedes(
        _ lhs: V3ManifestEntry,
        _ rhs: V3ManifestEntry
    ) -> Bool {
        Data(lhs.name.utf8).lexicographicallyPrecedes(Data(rhs.name.utf8))
            || (lhs.name == rhs.name
                && Data(lhs.entryID.utf8).lexicographicallyPrecedes(
                    Data(rhs.entryID.utf8)
                ))
    }
}

private struct ExitingAtomicWriteObserver:
    V3AtomicStagedObjectWriteObserving
{
    func didReach(_: V3AtomicStagedObjectWritePhase) throws {
        Darwin._exit(23)
    }
}

private final class ProofObserver:
    V3ManifestAncestryObserving,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let observations: [V3ManifestAncestryObservation]
    private var index = 0

    init(_ proofs: [V3ManifestAncestryProof]) {
        precondition(!proofs.isEmpty)
        observations = proofs.map {
            V3ManifestAncestryObservation(
                proof: $0,
                resourceUsage: testResourceUsage(for: $0)
            )
        }
    }

    init(observations: [V3ManifestAncestryObservation]) {
        precondition(!observations.isEmpty)
        self.observations = observations
    }

    var observationCount: Int {
        lock.withLock { index }
    }

    func observeAncestry() throws -> V3ManifestAncestryObservation {
        lock.withLock {
            let observation = observations[
                min(index, observations.count - 1)
            ]
            index += 1
            return observation
        }
    }
}

private func testResourceUsage(
    for proof: V3ManifestAncestryProof
) -> V3ManifestRepositoryUsage {
    var manifestsByDigest: [Data: V3VerifiedManifest] = [:]
    var entryObjects: Set<TestEntryKey> = []
    var totalManifestBytes = 0
    for manifest in proof.manifests {
        manifestsByDigest[manifest.envelopeDigest] = manifest
        totalManifestBytes += manifest.envelope.canonicalBytes.count
        for entry in manifest.envelope.content.manifest.entries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ) else {
                continue
            }
            entryObjects.insert(TestEntryKey(
                entryID: entry.entryID,
                digest: digest
            ))
        }
    }

    var depthCache: [Data: Int] = [:]
    func depth(of digest: Data) -> Int {
        if let cached = depthCache[digest] {
            return cached
        }
        guard let manifest = manifestsByDigest[digest] else {
            return 0
        }
        let parentDepth = manifest.envelope.content.parents.compactMap {
            Base64URL.decodeCanonical($0)
        }.map(depth(of:)).max() ?? -1
        let result = parentDepth + 1
        depthCache[digest] = result
        return result
    }

    return V3ManifestRepositoryUsage(
        manifestObjectCount: proof.manifests.count,
        maximumHistoryDepth: proof.manifests.map {
            depth(of: $0.envelopeDigest)
        }.max() ?? 0,
        totalManifestBytes: totalManifestBytes,
        referencedEntryObjectCount: entryObjects.count,
        // Tests that exercise existing entry reuse do not approach the
        // aggregate byte bound; production observations supply exact bytes.
        totalEntryBytes: 0
    )
}

private struct TestEntryKey: Hashable {
    let entryID: String
    let digest: Data
}

private enum PublicationTestError: Error {
    case expected
    case interrupted
}

private struct TestNoopPhaseObserver:
    V3ImmutableTransactionPhaseObserving
{
    func didReach(
        _: V3ImmutableTransactionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

private final class InterruptingPhaseObserver:
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
            if !interrupted, phase == target {
                interrupted = true
                throw PublicationTestError.interrupted
            }
        }
    }
}

private enum PublicationFailure: Equatable {
    case publishEntry
    case publishManifest
}

private final class RecordingObjectStore:
    V3TransactionArtifactStore,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let failure: PublicationFailure?
    private var entries: [TestEntryKey: Data]
    private var manifests: [Data: Data]
    private var stagedEntries: [TestEntryKey: Data] = [:]
    private var stagedManifests: [Data: Data] = [:]
    private var recoveryIntents: [VaultTransactionOperationID: Data] = [:]
    private var recordedEvents: [String] = []

    init(
        failure: PublicationFailure? = nil,
        entries: [TestEntryKey: Data] = [:],
        manifests: [Data: Data] = [:]
    ) {
        self.failure = failure
        self.entries = entries
        self.manifests = manifests
    }

    var events: [String] {
        lock.withLock { recordedEvents }
    }

    var publishedEntryCount: Int {
        lock.withLock { entries.count }
    }

    var publishedManifestCount: Int {
        lock.withLock { manifests.count }
    }

    var recoveryIntentCount: Int {
        lock.withLock { recoveryIntents.count }
    }

    var stagedObjectCount: Int {
        lock.withLock {
            stagedEntries.count + stagedManifests.count
        }
    }

    func manifestDigests(
        maximumCount: Int
    ) throws -> V3RepositoryDirectoryListing {
        lock.withLock {
            guard manifests.count <= maximumCount else {
                return .limitExceeded
            }
            return .available(
                digests: Array(manifests.keys),
                objectCount: manifests.count
            )
        }
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            recordedEvents.append("read-manifest")
            guard let data = manifests[digest] else {
                return .unavailable
            }
            return data.count <= maximumBytes
                ? .available(data)
                : .tooLarge
        }
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            recordedEvents.append("read-entry:\(entryID)")
            guard let data = entries[TestEntryKey(
                entryID: entryID,
                digest: digest
            )] else {
                return .unavailable
            }
            return data.count <= maximumBytes
                ? .available(data)
                : .tooLarge
        }
    }

    func persistRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            if let existing = recoveryIntents[operationID],
               existing != data {
                throw PublicationTestError.expected
            }
            recordedEvents.append("persist-intent")
            recoveryIntents[operationID] = data
        }
    }

    func readRecoveryIntent(
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            guard let data = recoveryIntents[operationID] else {
                return .unavailable
            }
            return data.count <= maximumBytes
                ? .available(data)
                : .tooLarge
        }
    }

    func readStagedEntry(
        entryID: String,
        digest: Data,
        operationID _: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            guard let data = stagedEntries[TestEntryKey(
                entryID: entryID,
                digest: digest
            )] else {
                return .unavailable
            }
            return data.count <= maximumBytes
                ? .available(data)
                : .tooLarge
        }
    }

    func readStagedManifest(
        digest: Data,
        operationID _: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            guard let data = stagedManifests[digest] else {
                return .unavailable
            }
            return data.count <= maximumBytes
                ? .available(data)
                : .tooLarge
        }
    }

    func stageEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        lock.withLock {
            recordedEvents.append("stage-entry:\(entryID)")
            stagedEntries[TestEntryKey(
                entryID: entryID,
                digest: digest
            )] = data
        }
    }

    func stageManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        lock.withLock {
            recordedEvents.append("stage-manifest")
            stagedManifests[digest] = data
        }
    }

    func publishStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            if failure == .publishEntry {
                throw PublicationTestError.expected
            }
            recordedEvents.append("publish-entry:\(entryID)")
            let key = TestEntryKey(entryID: entryID, digest: digest)
            entries[key] = stagedEntries[key]
        }
    }

    func publishStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            if failure == .publishManifest {
                throw PublicationTestError.expected
            }
            recordedEvents.append("publish-manifest")
            manifests[digest] = stagedManifests[digest]
        }
    }

    func removeStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID _: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            let key = TestEntryKey(entryID: entryID, digest: digest)
            if let existing = stagedEntries[key], existing != data {
                throw PublicationTestError.expected
            }
            stagedEntries.removeValue(forKey: key)
        }
    }

    func removeStagedManifest(
        _ data: Data,
        digest: Data,
        operationID _: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            if let existing = stagedManifests[digest], existing != data {
                throw PublicationTestError.expected
            }
            stagedManifests.removeValue(forKey: digest)
        }
    }

    func removeRecoveryIntent(
        _ data: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try lock.withLock {
            if let existing = recoveryIntents[operationID],
               existing != data {
                throw PublicationTestError.expected
            }
            recoveryIntents.removeValue(forKey: operationID)
        }
    }

    func removeEmptyTransactionDirectories(
        operationID _: VaultTransactionOperationID,
        entryIDs _: [String]
    ) throws {}
}

private final class MemoryCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Data?
    private let failReplacement: Bool

    init(
        checkpoint: V3ManifestCheckpoint,
        failReplacement: Bool = false
    ) {
        stored = checkpoint.canonicalBytes
        self.failReplacement = failReplacement
    }

    var checkpoint: Data? {
        lock.withLock { stored }
    }

    func loadCheckpoint(vaultID: String) throws -> Data? {
        lock.withLock { stored }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {
        try lock.withLock {
            if failReplacement {
                throw V3ManifestCheckpointStoreError.conflict
            }
            guard stored == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            stored = checkpoint
        }
    }
}

private final class MemoryRecoveryAnchorStore:
    V3ImmutableTransactionRecoveryAnchorStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var anchors: [String: Data] = [:]

    func loadRecoveryAnchor(vaultID: String) throws -> Data? {
        lock.withLock { anchors[vaultID] }
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
            anchors[vaultID] = anchor
        }
    }

    func anchor(vaultID: String) -> Data? {
        lock.withLock { anchors[vaultID] }
    }
}
