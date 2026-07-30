import Foundation
import Testing
@testable import KeyCore

struct V3VaultUXTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let keyID = try! V3VaultKeyID(
        rawValue: Base64URL.encode(Data(repeating: 9, count: 32))
    )
    private static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"

    @Test
    func projectsContentConflictsIntoStableCLISafeDetails() throws {
        let baseEntry = entry(revision: 1, digestByte: 1)
        let leftEntry = entry(revision: 2, digestByte: 2)
        let rightEntry = entry(revision: 2, digestByte: 3)
        let base = manifest(
            digestByte: 10,
            entries: [baseEntry]
        )
        let left = manifest(
            digestByte: 11,
            parents: [base],
            entries: [leftEntry]
        )
        let right = manifest(
            digestByte: 12,
            parents: [base],
            entries: [rightEntry]
        )
        let snapshot = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: base,
                manifests: [base, left, right],
                heads: [left, right],
                status: .contentConflicted
            ),
            trustedCurrent: trusted(base)
        )

        #expect(snapshot.status.format == .version3)
        #expect(snapshot.status.health == .contentConflicted)
        #expect(snapshot.status.entryCount == 1)
        #expect(snapshot.status.entries.basis == .lastTrusted)
        #expect(snapshot.status.conflictCount == 1)
        let conflict = try #require(snapshot.conflicts.first)
        #expect(conflict.summary.kind == .editEdit)
        #expect(conflict.summary.entryName == "mail/personal")
        #expect(conflict.summary.id.hasPrefix("c-"))
        #expect(conflict.summary.id.count == 66)
        #expect(conflict.versions.count == 2)
        #expect(conflict.versions.allSatisfy {
            !$0.previouslyTrustedOnThisMac
        })
        #expect(snapshot.selections[conflict.summary.id] != nil)
    }

    @Test
    func readyStateReportsTheEffectiveHeadEntryCount() throws {
        let base = manifest(
            digestByte: 16,
            entries: [entry(revision: 1, digestByte: 1)]
        )
        let head = manifest(
            digestByte: 17,
            parents: [base],
            entries: [
                entry(revision: 2, digestByte: 2),
                entry(
                    revision: 1,
                    digestByte: 3,
                    entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5",
                    name: "mail/work"
                )
            ]
        )

        let snapshot = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: base,
                manifests: [base, head],
                heads: [head],
                status: .ready
            ),
            trustedCurrent: trusted(base)
        )

        #expect(snapshot.status.entries == .effective(2))
        #expect(
            snapshot.status.trustedVersionID
                == String(v3LowercaseHex(base.envelopeDigest).prefix(16))
        )
    }

    @Test
    func automaticMergeReportsTheMergedEntryCount() throws {
        let baseEntry = entry(revision: 1, digestByte: 1)
        let base = manifest(digestByte: 18, entries: [baseEntry])
        let left = manifest(
            digestByte: 19,
            parents: [base],
            entries: [entry(revision: 2, digestByte: 2)]
        )
        let right = manifest(
            digestByte: 20,
            parents: [base],
            entries: [
                baseEntry,
                entry(
                    revision: 1,
                    digestByte: 3,
                    entryID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5",
                    name: "mail/work"
                )
            ]
        )

        let snapshot = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: base,
                manifests: [base, left, right],
                heads: [left, right],
                status: .contentConflicted
            ),
            trustedCurrent: trusted(base)
        )

        #expect(snapshot.status.health == .ready)
        #expect(snapshot.status.entries == .effective(2))
    }

    @Test
    func marksOnlyAnExactLocallyTrustedConflictVersion() throws {
        let base = manifest(
            digestByte: 13,
            entries: [entry(revision: 1, digestByte: 1)]
        )
        let trusted = manifest(
            digestByte: 14,
            parents: [base],
            entries: [entry(revision: 2, digestByte: 2)]
        )
        let synchronized = manifest(
            digestByte: 15,
            parents: [base],
            entries: [entry(revision: 2, digestByte: 3)]
        )
        let snapshot = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: trusted,
                manifests: [base, trusted, synchronized],
                heads: [trusted, synchronized],
                status: .contentConflicted
            ),
            trustedCurrent: self.trusted(trusted)
        )

        let conflict = try #require(snapshot.conflicts.first)
        #expect(
            conflict.versions.filter(\.previouslyTrustedOnThisMac).count == 1
        )
        #expect(
            conflict.versions.first(where: \.previouslyTrustedOnThisMac)?
                .revision == 2
        )
    }

    @Test
    func conflictActionsReobserveAndBindResolutionToTheExactSnapshot() throws {
        let base = manifest(
            digestByte: 20,
            entries: [entry(revision: 1, digestByte: 1)]
        )
        let left = manifest(
            digestByte: 21,
            parents: [base],
            entries: [entry(revision: 2, digestByte: 2)]
        )
        let right = manifest(
            digestByte: 22,
            parents: [base],
            entries: [entry(revision: 2, digestByte: 3)]
        )
        let conflicted = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: base,
                manifests: [base, left, right],
                heads: [left, right],
                status: .contentConflicted
            ),
            trustedCurrent: trusted(base)
        )
        let box = SnapshotBox(conflicted)
        let recorder = ResolutionRecorder()
        let service = V3VaultUXService(
            snapshotProvider: { box.snapshot },
            valueReader: { entry, expectedHeads in
                #expect(entry.entryID == Self.entryID)
                #expect(expectedHeads.count == 2)
                return "decrypted-\(entry.revision)"
            },
            resolutionPublisher: { selections, expectedHeads in
                recorder.record(
                    selections: selections,
                    heads: expectedHeads
                )
            }
        )
        let conflict = try #require(conflicted.conflicts.first)
        let version = try #require(conflict.versions.first)
        let resolution = VaultConflictResolution(
            conflictID: conflict.summary.id,
            versionID: version.id
        )

        #expect(
            try service.conflictValue(
                id: conflict.summary.id,
                versionID: version.id
            ).hasPrefix("decrypted-")
        )
        try service.resolve([resolution])
        #expect(recorder.selections.count == 1)
        #expect(recorder.heads.count == 2)

        box.snapshot = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: left,
                manifests: [base, left],
                heads: [left],
                status: .ready
            ),
            trustedCurrent: trusted(left)
        )
        #expect(throws: VaultUXServiceError.expectedHeadsChanged) {
            try service.resolve([resolution])
        }
    }

    @Test
    func rollbackIsNotPresentedAsAnOrdinaryContentChoice() throws {
        let base = manifest(
            digestByte: 30,
            entries: [entry(revision: 2, digestByte: 1)]
        )
        let rollback = manifest(
            digestByte: 31,
            parents: [base],
            entries: [entry(revision: 1, digestByte: 2)]
        )
        let forward = manifest(
            digestByte: 32,
            parents: [base],
            entries: [entry(revision: 3, digestByte: 3)]
        )
        let snapshot = try V3VaultObservationBuilder().build(
            classification(
                checkpoint: base,
                manifests: [base, rollback, forward],
                heads: [rollback, forward],
                status: .contentConflicted
            ),
            trustedCurrent: trusted(base)
        )

        #expect(snapshot.status.health == .rollbackDetected)
        #expect(
            snapshot.status.issues.map(\.code).contains(.revisionRollback)
        )
        #expect(
            snapshot.conflicts.map(\.summary.kind)
                .contains(.revisionRollback)
        )
        let conflict = try #require(snapshot.conflicts.first)
        let version = try #require(conflict.versions.first)
        let service = V3VaultUXService(
            snapshotProvider: { snapshot },
            valueReader: { _, _ in "" },
            resolutionPublisher: { _, _ in
                Issue.record("Rollback resolution reached publication.")
            }
        )
        #expect(throws: AppError.self) {
            try service.resolve([
                VaultConflictResolution(
                    conflictID: conflict.summary.id,
                    versionID: version.id
                )
            ])
        }
    }

    @Test
    func repositoryFailureClassesRemainDistinctInStatus() throws {
        let head = manifest(
            digestByte: 40,
            entries: [entry(revision: 1, digestByte: 4)]
        )
        let builder = V3VaultObservationBuilder()
        let incomplete = try builder.build(
            V3VaultRepositoryClassification(
                status: .incomplete,
                heads: [try V3VaultHead(verifiedManifest: head)],
                issues: [.manifestDirectoryUnavailable],
                ancestryProof: nil
            ),
            trustedCurrent: trusted(head)
        )
        let recovery = try builder.build(
            V3VaultRepositoryClassification(
                status: .recoveryRequired,
                heads: [try V3VaultHead(verifiedManifest: head)],
                issues: [
                    .invalidReferencedObject(path: "manifests/object.json")
                ],
                ancestryProof: nil
            ),
            trustedCurrent: trusted(head)
        )

        #expect(incomplete.status.health == .incomplete)
        #expect(incomplete.status.entries == .lastTrusted(1))
        #expect(incomplete.status.trustedVersionID != nil)
        #expect(
            incomplete.status.issues.map(\.code)
                == [.transportUnavailable]
        )
        #expect(recovery.status.health == .recoveryRequired)
        #expect(recovery.status.entries == .lastTrusted(1))
        #expect(
            recovery.status.issues.map(\.code)
                == [.invalidReferencedObject]
        )
    }

    @Test
    func staleReadsAreExplicitAndContentConflictsBlockOnlyAffectedReads()
        throws
    {
        let incomplete = V3VaultUXSnapshot(
            status: VaultStatus(
                format: .version3,
                health: .incomplete,
                entries: .lastTrusted(1)
            ),
            conflicts: [],
            expectedHeads: [],
            selections: [:]
        )
        let box = SnapshotBox(incomplete)
        let service = V3VaultUXService(
            snapshotProvider: { box.snapshot },
            valueReader: { _, _ in "" },
            resolutionPublisher: { _, _ in }
        )

        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try service.authorizeRead(
                name: "mail/personal",
                allowStale: false
            )
        }
        try service.authorizeRead(
            name: "mail/personal",
            allowStale: true
        )
        #expect(throws: VaultUXServiceError.vaultIncomplete) {
            try service.authorizeMutation()
        }

        let summary = VaultConflictSummary(
            id: "c-123",
            entryName: "mail/personal",
            kind: .editEdit,
            versionCount: 2
        )
        box.snapshot = V3VaultUXSnapshot(
            status: VaultStatus(
                format: .version3,
                health: .contentConflicted,
                entries: .lastTrusted(2),
                conflictCount: 1
            ),
            conflicts: [
                VaultConflictDetail(
                    summary: summary,
                    versions: [
                        VaultConflictVersion(
                            id: "aaaaaaaaaaaaaaaa",
                            entryName: "mail/personal",
                            entryType: .secret,
                            revision: 2,
                            previouslyTrustedOnThisMac: false
                        )
                    ]
                )
            ],
            expectedHeads: [],
            selections: [:]
        )
        #expect(throws: VaultUXServiceError.contentConflict) {
            try service.authorizeRead(
                name: "mail/personal",
                allowStale: false
            )
        }
        try service.authorizeRead(
            name: "unaffected/entry",
            allowStale: false
        )
        #expect(throws: VaultUXServiceError.contentConflict) {
            try service.authorizeMutation()
        }
    }

    private func classification(
        checkpoint: V3VerifiedManifest,
        manifests: [V3VerifiedManifest],
        heads: [V3VerifiedManifest],
        status: V3VaultRepositoryStatus
    ) throws -> V3VaultRepositoryClassification {
        V3VaultRepositoryClassification(
            status: status,
            heads: try heads.map(V3VaultHead.init),
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

    private func trusted(
        _ manifest: V3VerifiedManifest
    ) throws -> V3TrustedManifest {
        V3TrustedManifest(
            verifiedManifest: manifest,
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: manifest
            )
        )
    }

    private func manifest(
        digestByte: UInt8,
        parents: [V3VerifiedManifest] = [],
        entries: [V3ManifestEntry] = []
    ) -> V3VerifiedManifest {
        let body = V3ManifestBody(
            vaultID: Self.vaultID,
            mode: .local,
            keyID: Self.keyID,
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

    private func entry(
        revision: UInt64,
        digestByte: UInt8,
        entryID: String = Self.entryID,
        name: String = "mail/personal"
    ) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: entryID,
            name: name,
            type: .secret,
            revision: revision,
            keyID: Self.keyID,
            ciphertextDigest: Base64URL.encode(
                Data(repeating: digestByte, count: 32)
            )
        )
    }
}

private final class SnapshotBox {
    var snapshot: V3VaultUXSnapshot

    init(_ snapshot: V3VaultUXSnapshot) {
        self.snapshot = snapshot
    }
}

private final class ResolutionRecorder {
    private(set) var selections: [V3ResolvedConflictSelection] = []
    private(set) var heads: [V3VaultHead] = []

    func record(
        selections: [V3ResolvedConflictSelection],
        heads: [V3VaultHead]
    ) {
        self.selections = selections
        self.heads = heads
    }
}
