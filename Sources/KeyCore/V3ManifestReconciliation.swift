import Foundation

public enum V3ManifestReconciliationError: Error, Equatable, LocalizedError {
    case invalidAncestryProof

    public var errorDescription: String? {
        switch self {
        case .invalidAncestryProof:
            "Version 3 reconciliation requires a complete, internally consistent ancestry proof."
        }
    }
}

public enum V3EntryConflictKind: String, Equatable, Sendable {
    case concurrentCreation
    case editEdit
    case deleteEdit
    case renameEdit
    case conflictingRename
    case revisionRollback
    case conflictingRevision
}

/// One exact head's value for a conflicted stable entry identity.
///
/// A nil entry records that this head deleted the entry. Non-nil entries retain
/// the exact immutable ciphertext digest needed for later inspection.
public struct V3EntryConflictVersion: Equatable, Sendable {
    public let head: V3VaultHead
    public let entry: V3ManifestEntry?
}

public struct V3EntryConflict: Equatable, Sendable {
    public let entryID: String
    public let kind: V3EntryConflictKind
    public let commonAncestorEntry: V3ManifestEntry?
    public let versions: [V3EntryConflictVersion]
}

public struct V3DestinationConflict: Equatable, Sendable {
    public let name: String
    public let entries: [V3ManifestEntry]
}

public struct V3ContentConflictReport: Equatable, Sendable {
    public let commonAncestor: V3VaultHead
    public let heads: [V3VaultHead]
    public let entryConflicts: [V3EntryConflict]
    public let destinationConflicts: [V3DestinationConflict]
}

/// A valid history shape whose nearest common ancestor is not unique.
///
/// This can arise from criss-cross merges. Enclave preserves the heads and
/// requires a later explicit or recursive-base policy instead of selecting one
/// ancestor arbitrarily.
public struct V3HistoryConflict: Equatable, Sendable {
    public let heads: [V3VaultHead]
    public let commonAncestors: [V3VaultHead]
}

/// Deterministic logical content for a future authenticated merge manifest.
///
/// Reconciliation does not authenticate, publish, or checkpoint this content.
/// A later transaction must use the exact parent heads and preserve the
/// expected-head and immutable-publication rules.
public struct V3AutomaticMergePlan: Equatable, Sendable {
    public let commonAncestor: V3VaultHead
    public let parentHeads: [V3VaultHead]
    public let content: V3ManifestContent
}

public enum V3ManifestReconciliationResult: Equatable, Sendable {
    case noMergeRequired(head: V3VaultHead)
    case automaticMerge(V3AutomaticMergePlan)
    case contentConflict(V3ContentConflictReport)
    case securityConflict(heads: [V3VaultHead])
    case historyConflict(V3HistoryConflict)
}

/// Pure three-way reconciliation over authenticated manifest history.
///
/// The reconciler performs no file access, decryption, random generation,
/// publication, or checkpoint mutation. Concurrent changes to different
/// stable entry IDs merge automatically. Concurrent changes to the same entry
/// remain explicit conflicts, including rename-plus-edit, because opaque
/// resealed ciphertext cannot prove that the rename branch preserved the
/// ancestor plaintext.
public struct V3ManifestReconciler: Sendable {
    public init() {}

    public func reconcile(
        _ proof: V3ManifestAncestryProof
    ) throws -> V3ManifestReconciliationResult {
        var graph = try ReconciliationGraph(proof: proof)
        let heads = graph.heads
        guard heads.count > 1 else {
            return .noMergeRequired(
                head: try V3VaultHead(verifiedManifest: heads[0])
            )
        }

        let headReferences = try heads.map(V3VaultHead.init(verifiedManifest:))
        let firstBody = heads[0].envelope.content.manifest
        guard heads.dropFirst().allSatisfy({
            hasSameV3ManifestAuthority(firstBody, $0.envelope.content.manifest)
        }) else {
            return .securityConflict(heads: headReferences)
        }

        let commonAncestors = try graph.nearestCommonAncestors()
        guard !commonAncestors.isEmpty else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        guard commonAncestors.count == 1, let commonAncestor = commonAncestors.first else {
            return .historyConflict(V3HistoryConflict(
                heads: headReferences,
                commonAncestors: try commonAncestors.map(
                    V3VaultHead.init(verifiedManifest:)
                )
            ))
        }

        return try reconcileContent(
            commonAncestor: commonAncestor,
            heads: heads,
            headReferences: headReferences
        )
    }

    private func reconcileContent(
        commonAncestor: V3VerifiedManifest,
        heads: [V3VerifiedManifest],
        headReferences: [V3VaultHead]
    ) throws -> V3ManifestReconciliationResult {
        let ancestorEntries = try entriesByID(
            commonAncestor.envelope.content.manifest.entries
        )
        let headEntries = try heads.map {
            try entriesByID($0.envelope.content.manifest.entries)
        }
        var entryIDs = Set(ancestorEntries.keys)
        for entries in headEntries {
            entryIDs.formUnion(entries.keys)
        }

        var mergedEntries: [V3ManifestEntry] = []
        var entryConflicts: [V3EntryConflict] = []
        for entryID in entryIDs.sorted(by: utf8PrecedesForReconciliation) {
            let ancestorEntry = ancestorEntries[entryID]
            let versions = headEntries.enumerated().map { index, entries in
                V3EntryConflictVersion(
                    head: headReferences[index],
                    entry: entries[entryID]
                )
            }
            let changedVersions = versions.filter {
                $0.entry != ancestorEntry
            }
            let distinctChanges = distinctEntryValues(
                changedVersions.map(\.entry)
            )

            if let revisionConflict = revisionConflictKind(
                ancestor: ancestorEntry,
                changes: distinctChanges
            ) {
                entryConflicts.append(V3EntryConflict(
                    entryID: entryID,
                    kind: revisionConflict,
                    commonAncestorEntry: ancestorEntry,
                    versions: changedVersions
                ))
            } else if distinctChanges.isEmpty {
                if let ancestorEntry {
                    mergedEntries.append(ancestorEntry)
                }
            } else if distinctChanges.count == 1 {
                if let selected = distinctChanges[0] {
                    mergedEntries.append(selected)
                }
            } else {
                entryConflicts.append(V3EntryConflict(
                    entryID: entryID,
                    kind: conflictKind(
                        ancestor: ancestorEntry,
                        changes: distinctChanges
                    ),
                    commonAncestorEntry: ancestorEntry,
                    versions: changedVersions
                ))
            }
        }

        let destinationConflicts = destinationConflicts(in: mergedEntries)
        let ancestorHead = try V3VaultHead(
            verifiedManifest: commonAncestor
        )
        if !entryConflicts.isEmpty || !destinationConflicts.isEmpty {
            return .contentConflict(V3ContentConflictReport(
                commonAncestor: ancestorHead,
                heads: headReferences,
                entryConflicts: entryConflicts,
                destinationConflicts: destinationConflicts
            ))
        }

        mergedEntries.sort(by: manifestEntryPrecedesForReconciliation)
        let authority = heads[0].envelope.content.manifest
        let mergedBody = V3ManifestBody(
            vaultID: authority.vaultID,
            mode: authority.mode,
            keyID: authority.keyID,
            devices: authority.devices,
            wrappedKeys: authority.wrappedKeys,
            entries: mergedEntries
        )
        let content = V3ManifestContent(
            parents: headReferences.map {
                Base64URL.encode($0.envelopeDigest)
            },
            manifest: mergedBody
        )
        return .automaticMerge(V3AutomaticMergePlan(
            commonAncestor: ancestorHead,
            parentHeads: headReferences,
            content: content
        ))
    }
}

private struct ReconciliationGraph {
    let manifestsByDigest: [Data: V3VerifiedManifest]
    let heads: [V3VerifiedManifest]
    private var ancestorCache: [Data: Set<Data>] = [:]
    private var visiting: Set<Data> = []

    init(proof: V3ManifestAncestryProof) throws {
        guard !proof.manifests.isEmpty, !proof.heads.isEmpty else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }

        var manifestsByDigest: [Data: V3VerifiedManifest] = [:]
        for manifest in proof.manifests {
            guard manifest.envelopeDigest.count == 32,
                  manifestsByDigest[manifest.envelopeDigest] == nil
            else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
            manifestsByDigest[manifest.envelopeDigest] = manifest
        }

        var seenHeads: Set<Data> = []
        for head in proof.heads {
            guard manifestsByDigest[head.envelopeDigest] == head,
                  seenHeads.insert(head.envelopeDigest).inserted
            else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
        }

        self.manifestsByDigest = manifestsByDigest
        heads = proof.heads.sorted {
            $0.envelopeDigest.lexicographicallyPrecedes($1.envelopeDigest)
        }

        var validationGraph = self
        let headAncestorSets = try heads.map {
            try validationGraph.ancestors(of: $0.envelopeDigest)
        }
        for firstIndex in heads.indices {
            for secondIndex in heads.indices where firstIndex != secondIndex {
                guard !headAncestorSets[secondIndex].contains(
                    heads[firstIndex].envelopeDigest
                ) else {
                    throw V3ManifestReconciliationError.invalidAncestryProof
                }
            }
        }
    }

    mutating func nearestCommonAncestors() throws -> [V3VerifiedManifest] {
        let ancestorSets = try heads.map {
            try ancestors(of: $0.envelopeDigest)
        }
        guard var common = ancestorSets.first else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        for ancestors in ancestorSets.dropFirst() {
            common.formIntersection(ancestors)
        }

        let nearestDigests = try common.filter { candidate in
            for other in common where other != candidate {
                if try ancestors(of: other).contains(candidate) {
                    return false
                }
            }
            return true
        }.sorted { $0.lexicographicallyPrecedes($1) }

        return try nearestDigests.map { digest in
            guard let manifest = manifestsByDigest[digest] else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
            return manifest
        }
    }

    private mutating func ancestors(of digest: Data) throws -> Set<Data> {
        if let cached = ancestorCache[digest] {
            return cached
        }
        guard let manifest = manifestsByDigest[digest],
              visiting.insert(digest).inserted
        else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        defer { visiting.remove(digest) }

        var result: Set<Data> = [digest]
        for encodedParent in manifest.envelope.content.parents {
            guard let parentDigest = reconciliationDigest(encodedParent),
                  manifestsByDigest[parentDigest] != nil
            else {
                throw V3ManifestReconciliationError.invalidAncestryProof
            }
            result.formUnion(try ancestors(of: parentDigest))
        }
        ancestorCache[digest] = result
        return result
    }
}

private func entriesByID(
    _ entries: [V3ManifestEntry]
) throws -> [String: V3ManifestEntry] {
    var result: [String: V3ManifestEntry] = [:]
    for entry in entries {
        guard result[entry.entryID] == nil else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        result[entry.entryID] = entry
    }
    return result
}

private func distinctEntryValues(
    _ values: [V3ManifestEntry?]
) -> [V3ManifestEntry?] {
    var result: [V3ManifestEntry?] = []
    for value in values where !result.contains(where: { $0 == value }) {
        result.append(value)
    }
    return result
}

private func conflictKind(
    ancestor: V3ManifestEntry?,
    changes: [V3ManifestEntry?]
) -> V3EntryConflictKind {
    guard let ancestor else {
        return .concurrentCreation
    }
    guard changes.allSatisfy({ $0 != nil }) else {
        return .deleteEdit
    }

    let names = Set(changes.compactMap { $0?.name })
    guard names.count > 1 else {
        return .editEdit
    }
    return names.contains(ancestor.name) ? .renameEdit : .conflictingRename
}

private func revisionConflictKind(
    ancestor: V3ManifestEntry?,
    changes: [V3ManifestEntry?]
) -> V3EntryConflictKind? {
    guard let ancestor else {
        return nil
    }
    let changedEntries = changes.compactMap { $0 }
    if changedEntries.contains(where: {
        $0.revision < ancestor.revision
    }) {
        return .revisionRollback
    }
    if changedEntries.contains(where: {
        $0.revision == ancestor.revision && $0 != ancestor
    }) {
        return .conflictingRevision
    }
    return nil
}

private func destinationConflicts(
    in entries: [V3ManifestEntry]
) -> [V3DestinationConflict] {
    let entriesByName = Dictionary(grouping: entries, by: \.name)
    return entriesByName.compactMap { name, entries in
        guard entries.count > 1 else {
            return nil
        }
        return V3DestinationConflict(
            name: name,
            entries: entries.sorted {
                utf8PrecedesForReconciliation($0.entryID, $1.entryID)
            }
        )
    }.sorted {
        utf8PrecedesForReconciliation($0.name, $1.name)
    }
}

private func manifestEntryPrecedesForReconciliation(
    _ lhs: V3ManifestEntry,
    _ rhs: V3ManifestEntry
) -> Bool {
    utf8PrecedesForReconciliation(lhs.name, rhs.name)
        || (lhs.name == rhs.name
            && utf8PrecedesForReconciliation(lhs.entryID, rhs.entryID))
}

private func utf8PrecedesForReconciliation(
    _ lhs: String,
    _ rhs: String
) -> Bool {
    Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
}

private func reconciliationDigest(_ encoded: String) -> Data? {
    guard let digest = Base64URL.decodeCanonical(encoded),
          digest.count == 32
    else {
        return nil
    }
    return digest
}
