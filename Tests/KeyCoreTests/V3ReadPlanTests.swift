import Foundation
import Testing
@testable import KeyCore

struct V3ReadPlanTests {
    @Test
    func readyReadBindsTheExactEffectiveEntryCheckpointAndHeads() throws {
        let baseEntry = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 1
        )
        let currentEntry = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 2
        )
        let base = ReadPlanFixture.manifest(
            digestByte: 10,
            entries: [baseEntry]
        )
        let head = ReadPlanFixture.manifest(
            digestByte: 11,
            parents: [base],
            entries: [currentEntry]
        )
        let trusted = try ReadPlanFixture.trusted(base)
        let classification = try ReadPlanFixture.classification(
            checkpoint: base,
            manifests: [base, head],
            heads: [head],
            status: .ready
        )

        let plan = try V3AuthenticatedReadPlanner().planRead(
            named: currentEntry.name,
            allowStale: false,
            classification: classification,
            trustedCurrent: trusted
        )

        #expect(plan.entry == currentEntry)
        #expect(
            plan.ciphertextDigest
                == Data(repeating: 2, count: 32)
        )
        guard case let .current(expected) = plan.authority else {
            Issue.record("Expected a current-state read plan.")
            return
        }
        #expect(expected.checkpoint == trusted.checkpoint)
        #expect(expected.heads == classification.heads)

        let inconsistent = V3VaultRepositoryClassification(
            status: .ready,
            heads: [try V3VaultHead(verifiedManifest: base)],
            issues: [],
            ancestryProof: classification.ancestryProof
        )
        #expect(throws: V3ManifestReconciliationError.invalidAncestryProof) {
            try V3AuthenticatedReadPlanner().planRead(
                named: currentEntry.name,
                allowStale: false,
                classification: inconsistent,
                trustedCurrent: trusted
            )
        }
    }

    @Test
    func incompleteStateRequiresExplicitStaleReadAndUsesTheCheckpoint()
        throws
    {
        let trustedEntry = ReadPlanFixture.entry(
            revision: 3,
            digestByte: 3
        )
        let checkpoint = ReadPlanFixture.manifest(
            digestByte: 20,
            entries: [trustedEntry]
        )
        let trusted = try ReadPlanFixture.trusted(checkpoint)
        let classification = V3VaultRepositoryClassification(
            status: .incomplete,
            heads: [try V3VaultHead(verifiedManifest: checkpoint)],
            issues: [.manifestDirectoryUnavailable],
            ancestryProof: nil
        )
        let planner = V3AuthenticatedReadPlanner()

        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try planner.planRead(
                named: trustedEntry.name,
                allowStale: false,
                classification: classification,
                trustedCurrent: trusted
            )
        }

        let plan = try planner.planRead(
            named: trustedEntry.name,
            allowStale: true,
            classification: classification,
            trustedCurrent: trusted
        )
        #expect(plan.entry == trustedEntry)
        #expect(
            plan.authority == .lastTrusted(trusted.checkpoint)
        )

        let list = try planner.planList(
            allowStale: true,
            classification: classification,
            trustedCurrent: trusted
        )
        #expect(list.entries == [trustedEntry])
        #expect(
            list.authority == .lastTrusted(trusted.checkpoint)
        )
    }

    @Test
    func normalizesCLIInputAndRejectsInvalidLogicalNames() throws {
        let canonicalName = "mail/caf\u{00E9}"
        let decomposedName = "mail/cafe\u{0301}"
        let entry = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 7,
            name: canonicalName
        )
        let manifest = ReadPlanFixture.manifest(
            digestByte: 21,
            entries: [entry]
        )
        let classification = try ReadPlanFixture.classification(
            checkpoint: manifest,
            manifests: [manifest],
            heads: [manifest],
            status: .ready
        )
        let trusted = try ReadPlanFixture.trusted(manifest)
        let planner = V3AuthenticatedReadPlanner()

        #expect(
            try planner.planRead(
                named: decomposedName,
                allowStale: false,
                classification: classification,
                trustedCurrent: trusted
            ).entry == entry
        )
        #expect(throws: AppError.self) {
            try planner.planRead(
                named: "../mail",
                allowStale: false,
                classification: classification,
                trustedCurrent: trusted
            )
        }
    }

    @Test
    func deterministicMergePlansTheExactUnambiguousResult() throws {
        let firstBase = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 1
        )
        let secondBase = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 2,
            entryID: ReadPlanFixture.secondEntryID,
            name: "mail/work"
        )
        let firstChanged = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 3
        )
        let secondChanged = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 4,
            entryID: ReadPlanFixture.secondEntryID,
            name: "mail/work"
        )
        let base = ReadPlanFixture.manifest(
            digestByte: 30,
            entries: [firstBase, secondBase]
        )
        let left = ReadPlanFixture.manifest(
            digestByte: 31,
            parents: [base],
            entries: [firstChanged, secondBase]
        )
        let right = ReadPlanFixture.manifest(
            digestByte: 32,
            parents: [base],
            entries: [firstBase, secondChanged]
        )
        let classification = try ReadPlanFixture.classification(
            checkpoint: base,
            manifests: [base, left, right],
            heads: [left, right],
            status: .contentConflicted
        )

        let plan = try V3AuthenticatedReadPlanner().planRead(
            named: secondChanged.name,
            allowStale: false,
            classification: classification,
            trustedCurrent: try ReadPlanFixture.trusted(base)
        )

        #expect(plan.entry == secondChanged)
    }

    @Test
    func contentConflictBlocksOnlyAmbiguousNames() throws {
        let baseConflicted = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 1
        )
        let baseSafe = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 2,
            entryID: ReadPlanFixture.secondEntryID,
            name: "mail/work"
        )
        let leftConflicted = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 3
        )
        let rightConflicted = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 4
        )
        let currentSafe = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 5,
            entryID: ReadPlanFixture.secondEntryID,
            name: "mail/work"
        )
        let base = ReadPlanFixture.manifest(
            digestByte: 40,
            entries: [baseConflicted, baseSafe]
        )
        let left = ReadPlanFixture.manifest(
            digestByte: 41,
            parents: [base],
            entries: [leftConflicted, baseSafe]
        )
        let right = ReadPlanFixture.manifest(
            digestByte: 42,
            parents: [base],
            entries: [rightConflicted, currentSafe]
        )
        let classification = try ReadPlanFixture.classification(
            checkpoint: base,
            manifests: [base, left, right],
            heads: [left, right],
            status: .contentConflicted
        )
        let planner = V3AuthenticatedReadPlanner()
        let trusted = try ReadPlanFixture.trusted(base)

        #expect(throws: VaultUXServiceError.contentConflict) {
            try planner.planRead(
                named: baseConflicted.name,
                allowStale: false,
                classification: classification,
                trustedCurrent: trusted
            )
        }

        let safe = try planner.planRead(
            named: currentSafe.name,
            allowStale: false,
            classification: classification,
            trustedCurrent: trusted
        )
        #expect(safe.entry == currentSafe)

        let list = try planner.planList(
            allowStale: false,
            classification: classification,
            trustedCurrent: trusted
        )
        #expect(list.entries == [currentSafe])
    }

    @Test
    func destinationCollisionAndRollbackFailClosed() throws {
        let collisionLeft = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 1,
            name: "shared/name"
        )
        let collisionRight = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 2,
            entryID: ReadPlanFixture.secondEntryID,
            name: "shared/name"
        )
        let emptyBase = ReadPlanFixture.manifest(
            digestByte: 50,
            entries: []
        )
        let collisionA = ReadPlanFixture.manifest(
            digestByte: 51,
            parents: [emptyBase],
            entries: [collisionLeft]
        )
        let collisionB = ReadPlanFixture.manifest(
            digestByte: 52,
            parents: [emptyBase],
            entries: [collisionRight]
        )
        let collisionClassification = try ReadPlanFixture.classification(
            checkpoint: emptyBase,
            manifests: [emptyBase, collisionA, collisionB],
            heads: [collisionA, collisionB],
            status: .contentConflicted
        )
        let planner = V3AuthenticatedReadPlanner()

        #expect(throws: VaultUXServiceError.contentConflict) {
            try planner.planRead(
                named: "shared/name",
                allowStale: false,
                classification: collisionClassification,
                trustedCurrent: try ReadPlanFixture.trusted(emptyBase)
            )
        }

        let baseEntry = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 3
        )
        let safeEntry = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 4,
            entryID: ReadPlanFixture.secondEntryID,
            name: "mail/work"
        )
        let rollbackBase = ReadPlanFixture.manifest(
            digestByte: 53,
            entries: [baseEntry, safeEntry]
        )
        let rollback = ReadPlanFixture.manifest(
            digestByte: 54,
            parents: [rollbackBase],
            entries: [
                ReadPlanFixture.entry(revision: 1, digestByte: 5),
                safeEntry
            ]
        )
        let forward = ReadPlanFixture.manifest(
            digestByte: 55,
            parents: [rollbackBase],
            entries: [
                ReadPlanFixture.entry(revision: 3, digestByte: 6),
                safeEntry
            ]
        )
        let rollbackClassification = try ReadPlanFixture.classification(
            checkpoint: rollbackBase,
            manifests: [rollbackBase, rollback, forward],
            heads: [rollback, forward],
            status: .contentConflicted
        )

        #expect(throws: VaultUXServiceError.rollbackDetected) {
            try planner.planRead(
                named: safeEntry.name,
                allowStale: false,
                classification: rollbackClassification,
                trustedCurrent: try ReadPlanFixture.trusted(rollbackBase)
            )
        }
    }

    @Test
    func selectedConflictVersionMustStillBelongToTheExactHeadSet() throws {
        let baseEntry = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 1
        )
        let leftEntry = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 2
        )
        let rightEntry = ReadPlanFixture.entry(
            revision: 2,
            digestByte: 3
        )
        let base = ReadPlanFixture.manifest(
            digestByte: 60,
            entries: [baseEntry]
        )
        let left = ReadPlanFixture.manifest(
            digestByte: 61,
            parents: [base],
            entries: [leftEntry]
        )
        let right = ReadPlanFixture.manifest(
            digestByte: 62,
            parents: [base],
            entries: [rightEntry]
        )
        let classification = try ReadPlanFixture.classification(
            checkpoint: base,
            manifests: [base, left, right],
            heads: [left, right],
            status: .contentConflicted
        )
        let trusted = try ReadPlanFixture.trusted(base)
        let planner = V3AuthenticatedReadPlanner()

        let selected = try planner.planConflictRead(
            entry: leftEntry,
            expectedHeads: classification.heads,
            classification: classification,
            trustedCurrent: trusted
        )
        #expect(selected.entry == leftEntry)

        #expect(throws: VaultUXServiceError.expectedHeadsChanged) {
            try planner.planConflictRead(
                entry: leftEntry,
                expectedHeads: [try V3VaultHead(verifiedManifest: left)],
                classification: classification,
                trustedCurrent: trusted
            )
        }

        #expect(throws: VaultUXServiceError.conflictVersionNotFound) {
            try planner.planConflictRead(
                entry: ReadPlanFixture.entry(
                    revision: 4,
                    digestByte: 9
                ),
                expectedHeads: classification.heads,
                classification: classification,
                trustedCurrent: trusted
            )
        }
    }

    @Test
    func securityAndRecoveryStatesNeverProduceOrdinaryReadPlans() throws {
        let entry = ReadPlanFixture.entry(
            revision: 1,
            digestByte: 1
        )
        let manifest = ReadPlanFixture.manifest(
            digestByte: 70,
            entries: [entry]
        )
        let trusted = try ReadPlanFixture.trusted(manifest)
        let head = try V3VaultHead(verifiedManifest: manifest)
        let planner = V3AuthenticatedReadPlanner()

        #expect(throws: VaultUXServiceError.securityConflict) {
            try planner.planRead(
                named: entry.name,
                allowStale: true,
                classification: V3VaultRepositoryClassification(
                    status: .securityConflicted,
                    heads: [head],
                    issues: [],
                    ancestryProof: nil
                ),
                trustedCurrent: trusted
            )
        }
        #expect(throws: VaultUXServiceError.recoveryRequired) {
            try planner.planRead(
                named: entry.name,
                allowStale: true,
                classification: V3VaultRepositoryClassification(
                    status: .recoveryRequired,
                    heads: [head],
                    issues: [.resourceLimitExceeded],
                    ancestryProof: nil
                ),
                trustedCurrent: trusted
            )
        }
    }
}

private enum ReadPlanFixture {
    static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    static let firstEntryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    static let secondEntryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
    static let keyID = try! V3VaultKeyID(
        rawValue: Base64URL.encode(Data(repeating: 9, count: 32))
    )

    static func entry(
        revision: UInt64,
        digestByte: UInt8,
        entryID: String = firstEntryID,
        name: String = "mail/personal"
    ) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: entryID,
            name: name,
            type: .secret,
            revision: revision,
            keyID: keyID,
            ciphertextDigest: Base64URL.encode(
                Data(repeating: digestByte, count: 32)
            )
        )
    }

    static func manifest(
        digestByte: UInt8,
        parents: [V3VerifiedManifest] = [],
        entries: [V3ManifestEntry]
    ) -> V3VerifiedManifest {
        let body = V3ManifestBody(
            vaultID: vaultID,
            mode: .local,
            keyID: keyID,
            devices: [],
            wrappedKeys: [],
            entries: entries
        )
        let content = V3ManifestContent(
            parents: parents
                .map(\.envelopeDigest)
                .sorted { $0.lexicographicallyPrecedes($1) }
                .map(Base64URL.encode),
            manifest: body
        )
        return V3VerifiedManifest(
            envelope: V3ManifestEnvelope(
                content: content,
                authentication: V3ManifestAuthentication(
                    tag: String(repeating: "A", count: 43)
                ),
                authorizations: [],
                canonicalBytes: Data([digestByte]),
                canonicalContentBytes: Data([digestByte])
            ),
            envelopeDigest: Data(repeating: digestByte, count: 32)
        )
    }

    static func trusted(
        _ manifest: V3VerifiedManifest
    ) throws -> V3TrustedManifest {
        V3TrustedManifest(
            verifiedManifest: manifest,
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: manifest
            )
        )
    }

    static func classification(
        checkpoint: V3VerifiedManifest,
        manifests: [V3VerifiedManifest],
        heads: [V3VerifiedManifest],
        status: V3VaultRepositoryStatus
    ) throws -> V3VaultRepositoryClassification {
        V3VaultRepositoryClassification(
            status: status,
            heads: try heads.map(V3VaultHead.init(verifiedManifest:)),
            issues: [],
            ancestryProof: V3ManifestAncestryProof(
                checkpoint: try V3ManifestCheckpoint(
                    verifiedManifest: checkpoint
                ),
                manifests: manifests,
                heads: heads
            )
        )
    }
}
