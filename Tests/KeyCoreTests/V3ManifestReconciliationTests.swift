import Foundation
import Testing
@testable import KeyCore

struct V3ManifestReconciliationTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let entryA = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let entryB = "018f4d3a-a844-72ad-983e-b09a8fc0e924"
    private static let entryC = "018f4d3b-033d-770e-a63c-ddb280e24d1f"
    private static let keyID = try! V3VaultKeyID(
        rawValue: Base64URL.encode(Data(repeating: 0, count: 32))
    )

    @Test
    func oneHeadNeedsNoMerge() throws {
        let head = manifest(digestByte: 0x10)
        let proof = try ancestryProof(manifests: [head], heads: [head])

        let result = try V3ManifestReconciler().reconcile(proof)

        #expect(result == .noMergeRequired(
            head: try V3VaultHead(verifiedManifest: head)
        ))
    }

    @Test
    func independentEntryChangesProduceOneDeterministicMergePlan() throws {
        let baseA = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "A"
        )
        let baseB = entry(
            id: Self.entryB,
            name: "account/b",
            revision: 1,
            digestCharacter: "B"
        )
        let base = manifest(
            digestByte: 0x10,
            entries: [baseA, baseB]
        )
        let changedA = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "C"
        )
        let changedB = entry(
            id: Self.entryB,
            name: "account/b",
            revision: 2,
            digestCharacter: "D"
        )
        let left = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: [changedA, baseB]
        )
        let right = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [baseA, changedB]
        )
        let forward = try ancestryProof(
            manifests: [base, left, right],
            heads: [left, right]
        )
        let reversed = try ancestryProof(
            manifests: [right, left, base],
            heads: [right, left]
        )

        let first = try V3ManifestReconciler().reconcile(forward)
        let second = try V3ManifestReconciler().reconcile(reversed)

        #expect(first == second)
        guard case let .automaticMerge(plan) = first else {
            Issue.record("Independent changes did not produce an automatic merge.")
            return
        }
        #expect(plan.commonAncestor == (try V3VaultHead(
            verifiedManifest: base
        )))
        #expect(plan.parentHeads == [
            try V3VaultHead(verifiedManifest: left),
            try V3VaultHead(verifiedManifest: right)
        ])
        #expect(plan.content.manifest.entries == [changedA, changedB])
        #expect(plan.content.parents == [
            Base64URL.encode(left.envelopeDigest),
            Base64URL.encode(right.envelopeDigest)
        ])
    }

    @Test
    func threeHeadsMergeIndependentEditDeleteAndCreation() throws {
        let baseA = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "A"
        )
        let baseB = entry(
            id: Self.entryB,
            name: "account/b",
            revision: 1,
            digestCharacter: "B"
        )
        let base = manifest(
            digestByte: 0x10,
            entries: [baseA, baseB]
        )
        let changedA = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "C"
        )
        let createdC = entry(
            id: Self.entryC,
            name: "account/c",
            revision: 1,
            digestCharacter: "D"
        )
        let editHead = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: [changedA, baseB]
        )
        let deleteHead = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [baseA]
        )
        let createHead = manifest(
            digestByte: 0x40,
            parents: [base],
            entries: [baseA, baseB, createdC]
        )
        let proof = try ancestryProof(
            manifests: [base, editHead, deleteHead, createHead],
            heads: [createHead, deleteHead, editHead]
        )

        let result = try V3ManifestReconciler().reconcile(proof)

        guard case let .automaticMerge(plan) = result else {
            Issue.record("Independent three-head changes did not merge.")
            return
        }
        #expect(plan.parentHeads == [
            try V3VaultHead(verifiedManifest: editHead),
            try V3VaultHead(verifiedManifest: deleteHead),
            try V3VaultHead(verifiedManifest: createHead)
        ])
        #expect(plan.content.manifest.entries == [changedA, createdC])
    }

    @Test
    func editEditConflictPreservesEveryExactVersion() throws {
        let baseEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "A"
        )
        let base = manifest(digestByte: 0x10, entries: [baseEntry])
        let leftEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "B"
        )
        let rightEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "C"
        )
        let left = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: [leftEntry]
        )
        let right = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [rightEntry]
        )

        let report = try contentConflict(base: base, heads: [left, right])

        #expect(report.entryConflicts.count == 1)
        #expect(report.entryConflicts[0].kind == .editEdit)
        #expect(report.entryConflicts[0].commonAncestorEntry == baseEntry)
        #expect(report.entryConflicts[0].versions.map(\.entry) == [
            leftEntry, rightEntry
        ])
    }

    @Test
    func rollbackAndSameRevisionSubstitutionRemainExplicitConflicts() throws {
        let baseEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "A"
        )
        let base = manifest(digestByte: 0x10, entries: [baseEntry])
        let unchanged = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: [baseEntry]
        )
        let rollbackEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "B"
        )
        let rollback = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [rollbackEntry]
        )

        let rollbackReport = try contentConflict(
            base: base,
            heads: [unchanged, rollback]
        )
        #expect(rollbackReport.entryConflicts[0].kind == .revisionRollback)
        #expect(rollbackReport.entryConflicts[0].versions.map(\.entry) == [
            rollbackEntry
        ])

        let substitutedEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "C"
        )
        let substituted = manifest(
            digestByte: 0x40,
            parents: [base],
            entries: [substitutedEntry]
        )

        let substitutionReport = try contentConflict(
            base: base,
            heads: [unchanged, substituted]
        )
        #expect(
            substitutionReport.entryConflicts[0].kind
                == .conflictingRevision
        )
        #expect(substitutionReport.entryConflicts[0].versions.map(\.entry) == [
            substitutedEntry
        ])
    }

    @Test
    func concurrentCreationOfOneStableIDPreservesBothValues() throws {
        let base = manifest(digestByte: 0x10)
        let leftEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "A"
        )
        let rightEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "B"
        )
        let left = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: [leftEntry]
        )
        let right = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [rightEntry]
        )

        let report = try contentConflict(base: base, heads: [left, right])

        #expect(report.entryConflicts == [
            V3EntryConflict(
                entryID: Self.entryA,
                kind: .concurrentCreation,
                commonAncestorEntry: nil,
                versions: [
                    V3EntryConflictVersion(
                        head: try V3VaultHead(verifiedManifest: left),
                        entry: leftEntry
                    ),
                    V3EntryConflictVersion(
                        head: try V3VaultHead(verifiedManifest: right),
                        entry: rightEntry
                    )
                ]
            )
        ])
    }

    @Test
    func deleteEditAndRenameEditRemainExplicitConflicts() throws {
        let baseEntry = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "A"
        )
        let base = manifest(digestByte: 0x10, entries: [baseEntry])
        let edited = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 2,
            digestCharacter: "B"
        )
        let deleted = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: []
        )
        let editHead = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [edited]
        )

        let deleteEdit = try contentConflict(
            base: base,
            heads: [deleted, editHead]
        )
        #expect(deleteEdit.entryConflicts[0].kind == .deleteEdit)
        #expect(deleteEdit.entryConflicts[0].versions.map(\.entry) == [
            nil, edited
        ])

        let renamed = entry(
            id: Self.entryA,
            name: "account/renamed",
            revision: 2,
            digestCharacter: "C"
        )
        let renameHead = manifest(
            digestByte: 0x40,
            parents: [base],
            entries: [renamed]
        )
        let renameEdit = try contentConflict(
            base: base,
            heads: [editHead, renameHead]
        )
        #expect(renameEdit.entryConflicts[0].kind == .renameEdit)
        #expect(Set(renameEdit.entryConflicts[0].versions.compactMap {
            $0.entry?.ciphertextDigest
        }) == Set([edited.ciphertextDigest, renamed.ciphertextDigest]))
    }

    @Test
    func conflictingRenamesAndDestinationCollisionsStayDistinct() throws {
        let baseA = entry(
            id: Self.entryA,
            name: "account/a",
            revision: 1,
            digestCharacter: "A"
        )
        let baseB = entry(
            id: Self.entryB,
            name: "account/b",
            revision: 1,
            digestCharacter: "B"
        )
        let base = manifest(
            digestByte: 0x10,
            entries: [baseA, baseB]
        )
        let leftRename = entry(
            id: Self.entryA,
            name: "account/left",
            revision: 2,
            digestCharacter: "C"
        )
        let rightRename = entry(
            id: Self.entryA,
            name: "account/right",
            revision: 2,
            digestCharacter: "D"
        )
        let left = manifest(
            digestByte: 0x20,
            parents: [base],
            entries: [leftRename, baseB]
        )
        let right = manifest(
            digestByte: 0x30,
            parents: [base],
            entries: [rightRename, baseB]
        )

        let renameReport = try contentConflict(
            base: base,
            heads: [left, right]
        )
        #expect(renameReport.entryConflicts[0].kind == .conflictingRename)

        let renamedA = entry(
            id: Self.entryA,
            name: "account/collision",
            revision: 2,
            digestCharacter: "E"
        )
        let renamedB = entry(
            id: Self.entryB,
            name: "account/collision",
            revision: 2,
            digestCharacter: "F"
        )
        let collisionLeft = manifest(
            digestByte: 0x40,
            parents: [base],
            entries: [renamedA, baseB]
        )
        let collisionRight = manifest(
            digestByte: 0x50,
            parents: [base],
            entries: [baseA, renamedB]
        )

        let collisionReport = try contentConflict(
            base: base,
            heads: [collisionLeft, collisionRight]
        )
        #expect(collisionReport.entryConflicts.isEmpty)
        #expect(collisionReport.destinationConflicts == [
            V3DestinationConflict(
                name: "account/collision",
                entries: [renamedA, renamedB]
            )
        ])
    }

    @Test
    func authorityDivergenceCannotEnterContentReconciliation() throws {
        let base = manifest(digestByte: 0x10)
        let left = manifest(digestByte: 0x20, parents: [base])
        let otherKeyID = try V3VaultKeyID(
            rawValue: Base64URL.encode(Data(repeating: 1, count: 32))
        )
        let right = manifest(
            digestByte: 0x30,
            parents: [base],
            keyID: otherKeyID
        )
        let proof = try ancestryProof(
            manifests: [base, left, right],
            heads: [left, right]
        )

        let result = try V3ManifestReconciler().reconcile(proof)

        #expect(result == .securityConflict(heads: [
            try V3VaultHead(verifiedManifest: left),
            try V3VaultHead(verifiedManifest: right)
        ]))
    }

    @Test
    func crissCrossHistoryReturnsEveryNearestCommonAncestor() throws {
        let root = manifest(digestByte: 0x10)
        let leftBase = manifest(
            digestByte: 0x20,
            parents: [root]
        )
        let rightBase = manifest(
            digestByte: 0x30,
            parents: [root]
        )
        let firstMerge = manifest(
            digestByte: 0x40,
            parents: [leftBase, rightBase]
        )
        let secondMerge = manifest(
            digestByte: 0x50,
            parents: [leftBase, rightBase]
        )
        let proof = try ancestryProof(
            manifests: [root, leftBase, rightBase, firstMerge, secondMerge],
            heads: [firstMerge, secondMerge]
        )

        let result = try V3ManifestReconciler().reconcile(proof)

        #expect(result == .historyConflict(V3HistoryConflict(
            heads: [
                try V3VaultHead(verifiedManifest: firstMerge),
                try V3VaultHead(verifiedManifest: secondMerge)
            ],
            commonAncestors: [
                try V3VaultHead(verifiedManifest: leftBase),
                try V3VaultHead(verifiedManifest: rightBase)
            ]
        )))
    }

    @Test
    func disconnectedHeadsAreNotAValidAncestryProof() throws {
        let firstRoot = manifest(digestByte: 0x10)
        let secondRoot = manifest(digestByte: 0x20)
        let proof = try ancestryProof(
            manifests: [firstRoot, secondRoot],
            heads: [firstRoot, secondRoot]
        )

        #expect(throws: V3ManifestReconciliationError.invalidAncestryProof) {
            _ = try V3ManifestReconciler().reconcile(proof)
        }
    }

    private func contentConflict(
        base: V3VerifiedManifest,
        heads: [V3VerifiedManifest]
    ) throws -> V3ContentConflictReport {
        let proof = try ancestryProof(
            manifests: [base] + heads,
            heads: heads
        )
        let result = try V3ManifestReconciler().reconcile(proof)
        guard case let .contentConflict(report) = result else {
            Issue.record("Expected an explicit content conflict.")
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        return report
    }

    private func ancestryProof(
        manifests: [V3VerifiedManifest],
        heads: [V3VerifiedManifest]
    ) throws -> V3ManifestAncestryProof {
        guard let checkpointManifest = manifests.first else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        return V3ManifestAncestryProof(
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: checkpointManifest
            ),
            manifests: manifests,
            heads: heads
        )
    }

    private func manifest(
        digestByte: UInt8,
        parents: [V3VerifiedManifest] = [],
        entries: [V3ManifestEntry] = [],
        keyID: V3VaultKeyID = Self.keyID
    ) -> V3VerifiedManifest {
        let parentDigests = parents
            .map(\.envelopeDigest)
            .sorted { $0.lexicographicallyPrecedes($1) }
            .map(Base64URL.encode)
        let body = V3ManifestBody(
            vaultID: Self.vaultID,
            mode: .local,
            keyID: keyID,
            devices: [],
            wrappedKeys: [],
            entries: entries.sorted(by: entryPrecedes)
        )
        let content = V3ManifestContent(
            parents: parentDigests,
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

    private func entry(
        id: String,
        name: String,
        revision: UInt64,
        digestCharacter: Character
    ) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: id,
            name: name,
            type: .secret,
            revision: revision,
            keyID: Self.keyID,
            ciphertextDigest: String(repeating: digestCharacter, count: 43)
        )
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
