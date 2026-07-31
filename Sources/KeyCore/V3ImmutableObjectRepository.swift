import CryptoKit
import Foundation

public enum V3VaultRepositoryStatus: String, Equatable, Sendable {
    case ready
    case incomplete
    case contentConflicted
    case securityConflicted
    case recoveryRequired
}

public enum V3VaultRepositoryIssue: Equatable, Sendable {
    case manifestDirectoryUnavailable
    case manifestUnavailable(digest: String)
    case entryUnavailable(entryID: String, digest: String)
    case invalidReferencedObject(path: String)
    case resourceLimitExceeded
}

/// Authenticated reachability from one device-local checkpoint.
///
/// This proof is produced only after every required immutable object is
/// available and valid. It does not itself advance the checkpoint.
public struct V3ManifestAncestryProof: Equatable, Sendable {
    public let checkpoint: V3ManifestCheckpoint
    public let manifests: [V3VerifiedManifest]
    public let heads: [V3VerifiedManifest]
}

/// Resource usage observed while producing a complete ancestry proof.
///
/// Manifest totals include unrelated objects that consume the bounded
/// directory budget. Entry totals cover the distinct immutable objects
/// referenced by the authenticated manifest graph.
struct V3ManifestRepositoryUsage: Equatable, Sendable {
    let manifestObjectCount: Int
    let maximumHistoryDepth: Int
    let totalManifestBytes: Int
    let referencedEntryObjectCount: Int
    let totalEntryBytes: Int
}

public struct V3VaultRepositoryClassification: Equatable, Sendable {
    public let status: V3VaultRepositoryStatus
    public let heads: [V3VaultHead]
    public let issues: [V3VaultRepositoryIssue]
    public let ancestryProof: V3ManifestAncestryProof?
}

/// Internal state captured with one repository classification for a guarded
/// publication attempt.
struct V3VaultRepositoryObservation: Equatable, Sendable {
    let classification: V3VaultRepositoryClassification
    let resourceUsage: V3ManifestRepositoryUsage?
}

/// One exact device-local checkpoint and authenticated repository head set.
///
/// Reads revalidate this state before releasing plaintext; transactions
/// revalidate it before publishing immutable objects.
struct V3ExpectedRepositoryState: Equatable, Sendable {
    let checkpoint: V3ManifestCheckpoint
    let heads: [V3VaultHead]

    init(
        checkpoint: V3ManifestCheckpoint,
        heads: [V3VaultHead]
    ) {
        self.checkpoint = checkpoint
        self.heads = heads
    }

    init(proof: V3ManifestAncestryProof) throws {
        let heads = try proof.heads.map(V3VaultHead.init(verifiedManifest:))
            .sorted {
                $0.envelopeDigest.lexicographicallyPrecedes(
                    $1.envelopeDigest
                )
            }
        guard !heads.isEmpty,
              Set(heads).count == heads.count,
              heads.allSatisfy({
                  $0.vaultID == proof.checkpoint.vaultID
              })
        else {
            throw V3ManifestReconciliationError.invalidAncestryProof
        }
        checkpoint = proof.checkpoint
        self.heads = heads
    }
}

struct V3ManifestRepositoryLimits: Equatable, Sendable {
    static let standard = V3ManifestRepositoryLimits(
        maximumManifestObjects: 4_096,
        maximumHistoryDepth: 1_024,
        maximumReferencedEntryObjects: 16_384,
        maximumManifestBytes: 2 * 1_024 * 1_024,
        maximumEntryBytes: 16 * 1_024 * 1_024,
        maximumTotalManifestBytes: 64 * 1_024 * 1_024,
        maximumTotalEntryBytes: 256 * 1_024 * 1_024
    )

    let maximumManifestObjects: Int
    let maximumHistoryDepth: Int
    let maximumReferencedEntryObjects: Int
    let maximumManifestBytes: Int
    let maximumEntryBytes: Int
    let maximumTotalManifestBytes: Int
    let maximumTotalEntryBytes: Int

    init(
        maximumManifestObjects: Int,
        maximumHistoryDepth: Int,
        maximumReferencedEntryObjects: Int = 16_384,
        maximumManifestBytes: Int = 2 * 1_024 * 1_024,
        maximumEntryBytes: Int = 16 * 1_024 * 1_024,
        maximumTotalManifestBytes: Int = 64 * 1_024 * 1_024,
        maximumTotalEntryBytes: Int = 256 * 1_024 * 1_024
    ) {
        precondition(maximumManifestObjects > 0)
        precondition(maximumHistoryDepth >= 0)
        precondition(maximumReferencedEntryObjects > 0)
        precondition(maximumManifestBytes > 0)
        precondition(maximumEntryBytes > 0)
        precondition(maximumTotalManifestBytes >= maximumManifestBytes)
        precondition(maximumTotalEntryBytes >= maximumEntryBytes)
        self.maximumManifestObjects = maximumManifestObjects
        self.maximumHistoryDepth = maximumHistoryDepth
        self.maximumReferencedEntryObjects = maximumReferencedEntryObjects
        self.maximumManifestBytes = maximumManifestBytes
        self.maximumEntryBytes = maximumEntryBytes
        self.maximumTotalManifestBytes = maximumTotalManifestBytes
        self.maximumTotalEntryBytes = maximumTotalEntryBytes
    }
}

/// Read-only access to version 3 immutable manifest and encrypted-entry
/// objects beneath a previously opened vault root.
public struct V3ImmutableObjectRepository: Sendable {
    private let source: any V3ImmutableObjectReading
    private let limits: V3ManifestRepositoryLimits
    private let authenticator: V3ManifestAuthenticator

    public init(rootHandle: VaultRootDirectoryHandle) {
        source = V3FilesystemImmutableObjectSource(rootHandle: rootHandle)
        limits = .standard
        authenticator = V3ManifestAuthenticator()
    }

    init(
        source: any V3ImmutableObjectReading,
        limits: V3ManifestRepositoryLimits = .standard,
        authenticator: V3ManifestAuthenticator = V3ManifestAuthenticator()
    ) {
        self.source = source
        self.limits = limits
        self.authenticator = authenticator
    }

    /// Classifies immutable synchronized state without changing files or the
    /// device-local checkpoint.
    ///
    /// Supply every locally available vault key that may authenticate a
    /// reachable branch. Unrecognized keys and unrelated repository objects
    /// do not gain authority from their presence on disk.
    public func classify(
        trustedCurrent: V3TrustedManifest,
        vaultKeys: [Data]
    ) throws -> V3VaultRepositoryClassification {
        try observeForPublication(
            trustedCurrent: trustedCurrent,
            vaultKeys: vaultKeys
        ).classification
    }

    func observeForPublication(
        trustedCurrent: V3TrustedManifest,
        vaultKeys: [Data]
    ) throws -> V3VaultRepositoryObservation {
        var keysByID: [V3VaultKeyID: Data] = [:]
        let vaultID = trustedCurrent.envelope.content.manifest.vaultID
        for key in vaultKeys {
            let keyID = try V3VaultKeyID.derive(
                vaultKey: key,
                vaultID: vaultID
            )
            keysByID[keyID] = key
        }
        return try observeForPublication(
            trustedCurrent: trustedCurrent,
            keysByID: keysByID
        )
    }

    private func observeForPublication(
        trustedCurrent: V3TrustedManifest,
        keysByID: [V3VaultKeyID: Data]
    ) throws -> V3VaultRepositoryObservation {
        let listing = try source.manifestDigests(
            maximumCount: limits.maximumManifestObjects
        )
        var incompleteIssues: [V3VaultRepositoryIssue] = []
        var recoveryIssues: [V3VaultRepositoryIssue] = []
        let enumeratedDigests: [Data]
        let listedManifestObjectCount: Int

        switch listing {
        case let .available(digests, objectCount):
            enumeratedDigests = digests
            listedManifestObjectCount = objectCount
        case .unavailable:
            enumeratedDigests = []
            listedManifestObjectCount = 0
            incompleteIssues.append(.manifestDirectoryUnavailable)
        case .invalid:
            enumeratedDigests = []
            listedManifestObjectCount = 0
            recoveryIssues.append(.invalidReferencedObject(path: "manifests"))
        case .limitExceeded:
            enumeratedDigests = []
            listedManifestObjectCount = 0
            recoveryIssues.append(.resourceLimitExceeded)
        }

        var observations: [Data: ManifestObservation] = [:]
        var totalManifestBytes = 0

        func observe(_ digest: Data) throws -> ManifestObservation {
            if let observation = observations[digest] {
                return observation
            }
            guard observations.count < limits.maximumManifestObjects else {
                if !recoveryIssues.contains(.resourceLimitExceeded) {
                    recoveryIssues.append(.resourceLimitExceeded)
                }
                return .invalid
            }
            let result = try source.readManifest(
                digest: digest,
                maximumBytes: limits.maximumManifestBytes
            )
            let observation: ManifestObservation
            switch result {
            case let .available(data):
                guard data.count <= limits.maximumTotalManifestBytes - totalManifestBytes else {
                    if !recoveryIssues.contains(.resourceLimitExceeded) {
                        recoveryIssues.append(.resourceLimitExceeded)
                    }
                    return .invalid
                }
                totalManifestBytes += data.count
                guard Data(SHA256.hash(data: data)) == digest,
                      let envelope = try? authenticator.parse(data)
                else {
                    observation = .invalid
                    observations[digest] = observation
                    return observation
                }
                observation = .available(data: data, envelope: envelope)
            case .unavailable:
                observation = .unavailable
            case .invalid, .tooLarge:
                observation = .invalid
            }
            observations[digest] = observation
            return observation
        }

        for digest in enumeratedDigests {
            _ = try observe(digest)
            if recoveryIssues.contains(.resourceLimitExceeded) {
                break
            }
        }

        let vaultID = trustedCurrent.envelope.content.manifest.vaultID
        let checkpointDigest = trustedCurrent.checkpoint.envelopeDigest
        switch try observe(checkpointDigest) {
        case let .available(data, _):
            if data != trustedCurrent.envelope.canonicalBytes {
                recoveryIssues.append(.invalidReferencedObject(
                    path: manifestPath(for: checkpointDigest)
                ))
            }
        case .unavailable:
            incompleteIssues.append(.manifestUnavailable(
                digest: Base64URL.encode(checkpointDigest)
            ))
        case .invalid:
            recoveryIssues.append(.invalidReferencedObject(
                path: manifestPath(for: checkpointDigest)
            ))
        }

        var verified: [Data: V3VerifiedManifest] = [:]
        var historyDepth: [Data: Int] = [:]
        var visiting: Set<Data> = []

        func anchorCheckpointHistory(
            digest: Data,
            trustedOverride: V3VerifiedManifest?,
            distanceFromCheckpoint: Int
        ) throws -> Int? {
            if let depth = historyDepth[digest] {
                return depth
            }
            guard distanceFromCheckpoint <= limits.maximumHistoryDepth else {
                recoveryIssues.append(.resourceLimitExceeded)
                return nil
            }
            guard visiting.insert(digest).inserted else {
                recoveryIssues.append(.invalidReferencedObject(
                    path: manifestPath(for: digest)
                ))
                return nil
            }
            defer { visiting.remove(digest) }

            let manifest: V3VerifiedManifest
            if let trustedOverride {
                manifest = trustedOverride
            } else {
                switch try observe(digest) {
                case let .available(data, _):
                    do {
                        manifest = try authenticator.reopenCheckpointAncestor(
                            data,
                            expectedVaultID: vaultID,
                            expectedDigest: digest
                        )
                    } catch {
                        recoveryIssues.append(.invalidReferencedObject(
                            path: manifestPath(for: digest)
                        ))
                        return nil
                    }
                case .unavailable:
                    incompleteIssues.append(.manifestUnavailable(
                        digest: Base64URL.encode(digest)
                    ))
                    return nil
                case .invalid:
                    recoveryIssues.append(.invalidReferencedObject(
                        path: manifestPath(for: digest)
                    ))
                    return nil
                }
            }

            var parentDepth = -1
            var allParentsValid = true
            for encodedParent in manifest.envelope.content.parents {
                guard let parentDigest = canonicalDigest(encodedParent) else {
                    recoveryIssues.append(.invalidReferencedObject(
                        path: manifestPath(for: digest)
                    ))
                    allParentsValid = false
                    continue
                }
                if let depth = try anchorCheckpointHistory(
                    digest: parentDigest,
                    trustedOverride: nil,
                    distanceFromCheckpoint: distanceFromCheckpoint + 1
                ) {
                    parentDepth = max(parentDepth, depth)
                } else {
                    allParentsValid = false
                }
            }
            guard allParentsValid else {
                return nil
            }

            let depth = parentDepth + 1
            guard depth <= limits.maximumHistoryDepth else {
                recoveryIssues.append(.resourceLimitExceeded)
                return nil
            }
            verified[digest] = manifest
            historyDepth[digest] = depth
            return depth
        }

        _ = try anchorCheckpointHistory(
            digest: checkpointDigest,
            trustedOverride: trustedCurrent.verifiedManifest,
            distanceFromCheckpoint: 0
        )

        var madeProgress = true
        while madeProgress, recoveryIssues.isEmpty, incompleteIssues.isEmpty {
            madeProgress = false
            for digest in enumeratedDigests.sorted(by: dataPrecedes) where verified[digest] == nil {
                guard case let .available(data, envelope) = try observe(digest),
                      envelope.content.manifest.vaultID == vaultID,
                      !envelope.content.parents.isEmpty
                else {
                    continue
                }
                let parentDigests = envelope.content.parents.compactMap(canonicalDigest)
                guard parentDigests.count == envelope.content.parents.count else {
                    continue
                }
                let parents = parentDigests.compactMap { verified[$0] }
                guard parents.count == parentDigests.count,
                      let vaultKey = keysByID[envelope.content.manifest.keyID],
                      let candidate = try? authenticator.verify(
                          data,
                          vaultKey: vaultKey,
                          trustAnchor: .verifiedParents(parents)
                      )
                else {
                    continue
                }

                let depth = 1 + (parentDigests.compactMap { historyDepth[$0] }.max() ?? -1)
                guard depth <= limits.maximumHistoryDepth else {
                    recoveryIssues.append(.resourceLimitExceeded)
                    break
                }
                verified[digest] = candidate
                historyDepth[digest] = depth
                madeProgress = true
            }
        }

        var discoveryObservations: [Data: DiscoveryManifestObservation] = [:]

        func discoveryObservation(
            _ digest: Data
        ) throws -> DiscoveryManifestObservation {
            if let observation = discoveryObservations[digest] {
                return observation
            }

            let observation: DiscoveryManifestObservation
            switch try observe(digest) {
            case let .available(data, envelope):
                guard envelope.content.manifest.vaultID == vaultID,
                      let vaultKey = keysByID[envelope.content.manifest.keyID],
                      let authenticated = try? authenticator
                          .authenticateForRepositoryDiscovery(
                              data,
                              vaultKey: vaultKey
                          )
                else {
                    observation = .unauthenticated
                    discoveryObservations[digest] = observation
                    return observation
                }
                observation = .authenticated(
                    DiscoveryManifestCandidate(
                        data: data,
                        authenticated: authenticated,
                        vaultKey: vaultKey
                    )
                )
            case .unavailable:
                observation = .unavailable
            case .invalid:
                observation = .invalid
            }
            discoveryObservations[digest] = observation
            return observation
        }

        func inspectPendingManifest(
            digest: Data,
            requiredMergeAuthority: V3ManifestBody?,
            distance: Int,
            visiting: inout Set<Data>
        ) throws -> PendingManifestInspection {
            if let manifest = verified[digest] {
                if let requiredMergeAuthority,
                   !hasSameV3ManifestAuthority(
                       requiredMergeAuthority,
                       manifest.envelope.content.manifest
                   ) {
                    return .impossible
                }
                return .plausible(PendingManifestIssues())
            }
            guard distance <= limits.maximumHistoryDepth else {
                return .plausible(PendingManifestIssues(
                    recovery: [.resourceLimitExceeded]
                ))
            }
            guard visiting.insert(digest).inserted else {
                return .impossible
            }
            defer { visiting.remove(digest) }

            let candidate: DiscoveryManifestCandidate
            switch try discoveryObservation(digest) {
            case let .authenticated(value):
                candidate = value
            case .unavailable:
                return .plausible(PendingManifestIssues(incomplete: [
                    .manifestUnavailable(digest: Base64URL.encode(digest))
                ]))
            case .invalid:
                return .plausible(PendingManifestIssues(recovery: [
                    .invalidReferencedObject(path: manifestPath(for: digest))
                ]))
            case .unauthenticated:
                return .impossible
            }

            let body = candidate.authenticated.envelope.content.manifest
            if let requiredMergeAuthority,
               !hasSameV3ManifestAuthority(requiredMergeAuthority, body) {
                return .impossible
            }

            let encodedParents = candidate.authenticated.envelope.content.parents
            let parentDigests = encodedParents.compactMap(canonicalDigest)
            guard !parentDigests.isEmpty,
                  parentDigests.count == encodedParents.count
            else {
                return .impossible
            }
            let unresolvedParents = parentDigests.filter { verified[$0] == nil }
            guard !unresolvedParents.isEmpty else {
                // A fully available candidate that did not pass ordinary
                // verification cannot become valid merely through more sync.
                return .impossible
            }

            if parentDigests.count > 1 {
                guard candidate.authenticated.envelope.authorizations.isEmpty else {
                    return .impossible
                }
                for parentDigest in parentDigests {
                    if let parent = verified[parentDigest] {
                        guard hasSameV3ManifestAuthority(
                            body,
                            parent.envelope.content.manifest
                        ) else {
                            return .impossible
                        }
                    } else if case let .authenticated(parent) =
                                try discoveryObservation(parentDigest) {
                        guard hasSameV3ManifestAuthority(
                            body,
                            parent.authenticated.envelope.content.manifest
                        ) else {
                            return .impossible
                        }
                    } else if case .unauthenticated =
                                try discoveryObservation(parentDigest) {
                        return .impossible
                    }
                }
            } else if let parentDigest = parentDigests.first,
                      case let .authenticated(parent) =
                        try discoveryObservation(parentDigest) {
                let provisionalParent = V3VerifiedManifest(
                    envelope: parent.authenticated.envelope,
                    envelopeDigest: parent.authenticated.envelopeDigest
                )
                guard (try? authenticator.verify(
                    candidate.data,
                    vaultKey: candidate.vaultKey,
                    trustAnchor: .verifiedParents([provisionalParent])
                )) != nil else {
                    return .impossible
                }
            } else if case .unauthenticated =
                        try discoveryObservation(parentDigests[0]) {
                return .impossible
            }

            var issues = PendingManifestIssues()
            for parentDigest in unresolvedParents {
                let requiredAuthority = parentDigests.count > 1 ? body : nil
                switch try inspectPendingManifest(
                    digest: parentDigest,
                    requiredMergeAuthority: requiredAuthority,
                    distance: distance + 1,
                    visiting: &visiting
                ) {
                case let .plausible(parentIssues):
                    issues.formUnion(parentIssues)
                case .impossible:
                    return .impossible
                }
            }
            guard !issues.isEmpty else {
                return .impossible
            }
            return .plausible(issues)
        }

        if recoveryIssues.isEmpty, incompleteIssues.isEmpty {
            for digest in enumeratedDigests.sorted(by: dataPrecedes)
            where verified[digest] == nil {
                guard case let .authenticated(candidate) =
                        try discoveryObservation(digest)
                else {
                    continue
                }
                let parentDigests = candidate.authenticated.envelope.content
                    .parents.compactMap(canonicalDigest)
                guard parentDigests.contains(where: { verified[$0] != nil }) else {
                    continue
                }

                var pendingVisiting: Set<Data> = []
                if case let .plausible(issues) = try inspectPendingManifest(
                    digest: digest,
                    requiredMergeAuthority: nil,
                    distance: 0,
                    visiting: &pendingVisiting
                ) {
                    for issue in issues.incomplete
                    where !incompleteIssues.contains(issue) {
                        incompleteIssues.append(issue)
                    }
                    for issue in issues.recovery
                    where !recoveryIssues.contains(issue) {
                        recoveryIssues.append(issue)
                    }
                }
            }
        }

        var entryContexts: [EntryObjectKey: [V3EntryAuthenticationContext]] = [:]
        if recoveryIssues.isEmpty, incompleteIssues.isEmpty {
            collectEntryContexts: for manifest in verified.values {
                for entry in manifest.envelope.content.manifest.entries {
                    guard let digest = canonicalDigest(entry.ciphertextDigest) else {
                        recoveryIssues.append(.invalidReferencedObject(
                            path: entryPath(
                                entryID: entry.entryID,
                                digest: entry.ciphertextDigest
                            )
                        ))
                        continue
                    }
                    let objectKey = EntryObjectKey(
                        entryID: entry.entryID,
                        digest: digest
                    )
                    if entryContexts[objectKey] == nil,
                       entryContexts.count >= limits.maximumReferencedEntryObjects {
                        recoveryIssues.append(.resourceLimitExceeded)
                        break collectEntryContexts
                    }
                    guard let context = try? V3EntryAuthenticationContext(
                        vaultID: manifest.envelope.content.manifest.vaultID,
                        entry: entry
                    )
                    else {
                        recoveryIssues.append(.invalidReferencedObject(
                            path: entryPath(
                                entryID: entry.entryID,
                                digest: entry.ciphertextDigest
                            )
                        ))
                        continue
                    }
                    entryContexts[objectKey, default: []].append(context)
                }
            }
        }

        var totalEntryBytes = 0
        if recoveryIssues.isEmpty, incompleteIssues.isEmpty {
            let entryCipher = V3EntryCipher()
            for reference in entryContexts.keys.sorted(by: entryReferencePrecedes) {
                let encodedDigest = Base64URL.encode(reference.digest)
                let path = entryPath(
                    entryID: reference.entryID,
                    digest: encodedDigest
                )

                switch try source.readEntry(
                    entryID: reference.entryID,
                    digest: reference.digest,
                    maximumBytes: limits.maximumEntryBytes
                ) {
                case let .available(data):
                    guard data.count <= limits.maximumTotalEntryBytes - totalEntryBytes else {
                        recoveryIssues.append(.resourceLimitExceeded)
                        break
                    }
                    totalEntryBytes += data.count
                    guard Data(SHA256.hash(data: data)) == reference.digest,
                          let parsed = try? entryCipher.parse(data),
                          entryContexts[reference]?.allSatisfy({
                              parsed.context == $0
                          }) == true
                    else {
                        recoveryIssues.append(.invalidReferencedObject(path: path))
                        continue
                    }
                case .unavailable:
                    incompleteIssues.append(.entryUnavailable(
                        entryID: reference.entryID,
                        digest: encodedDigest
                    ))
                case .invalid, .tooLarge:
                    recoveryIssues.append(.invalidReferencedObject(path: path))
                }
            }
        }

        let manifests = verified.values.sorted {
            dataPrecedes($0.envelopeDigest, $1.envelopeDigest)
        }
        let parentDigests = Set(manifests.flatMap { manifest in
            manifest.envelope.content.parents.compactMap(canonicalDigest)
        })
        let headManifests = manifests.filter {
            !parentDigests.contains($0.envelopeDigest)
        }
        let heads = try headManifests.map(V3VaultHead.init(verifiedManifest:))

        if !recoveryIssues.isEmpty {
            return V3VaultRepositoryObservation(
                classification: V3VaultRepositoryClassification(
                    status: .recoveryRequired,
                    heads: heads,
                    issues: recoveryIssues + incompleteIssues,
                    ancestryProof: nil
                ),
                resourceUsage: nil
            )
        }
        if !incompleteIssues.isEmpty {
            return V3VaultRepositoryObservation(
                classification: V3VaultRepositoryClassification(
                    status: .incomplete,
                    heads: heads,
                    issues: incompleteIssues,
                    ancestryProof: nil
                ),
                resourceUsage: nil
            )
        }

        let proof = V3ManifestAncestryProof(
            checkpoint: trustedCurrent.checkpoint,
            manifests: manifests,
            heads: headManifests
        )
        let status: V3VaultRepositoryStatus
        if headManifests.count <= 1 {
            status = .ready
        } else if let first = headManifests.first,
                  headManifests.dropFirst().allSatisfy({
                      hasSameV3ManifestAuthority(
                          first.envelope.content.manifest,
                          $0.envelope.content.manifest
                      )
                  }) {
            status = .contentConflicted
        } else {
            status = .securityConflicted
        }
        return V3VaultRepositoryObservation(
            classification: V3VaultRepositoryClassification(
                status: status,
                heads: heads,
                issues: [],
                ancestryProof: proof
            ),
            resourceUsage: V3ManifestRepositoryUsage(
                manifestObjectCount: max(
                    listedManifestObjectCount,
                    observations.count
                ),
                maximumHistoryDepth: historyDepth.values.max() ?? 0,
                totalManifestBytes: totalManifestBytes,
                referencedEntryObjectCount: entryContexts.count,
                totalEntryBytes: totalEntryBytes
            )
        )
    }
}

private enum ManifestObservation {
    case available(data: Data, envelope: V3ManifestEnvelope)
    case unavailable
    case invalid
}

private struct DiscoveryManifestCandidate {
    let data: Data
    let authenticated: V3AuthenticatedManifestObject
    let vaultKey: Data
}

private enum DiscoveryManifestObservation {
    case authenticated(DiscoveryManifestCandidate)
    case unavailable
    case invalid
    case unauthenticated
}

private struct PendingManifestIssues {
    var incomplete: [V3VaultRepositoryIssue] = []
    var recovery: [V3VaultRepositoryIssue] = []

    var isEmpty: Bool {
        incomplete.isEmpty && recovery.isEmpty
    }

    mutating func formUnion(_ other: PendingManifestIssues) {
        for issue in other.incomplete where !incomplete.contains(issue) {
            incomplete.append(issue)
        }
        for issue in other.recovery where !recovery.contains(issue) {
            recovery.append(issue)
        }
    }
}

private enum PendingManifestInspection {
    case plausible(PendingManifestIssues)
    case impossible
}

private struct EntryObjectKey: Hashable {
    let entryID: String
    let digest: Data
}

private func entryReferencePrecedes(
    _ lhs: EntryObjectKey,
    _ rhs: EntryObjectKey
) -> Bool {
    if lhs.entryID != rhs.entryID {
        return lhs.entryID < rhs.entryID
    }
    return dataPrecedes(lhs.digest, rhs.digest)
}

private func canonicalDigest(_ encoded: String) -> Data? {
    guard let digest = Base64URL.decodeCanonical(encoded),
          digest.count == 32
    else {
        return nil
    }
    return digest
}

func manifestPath(for digest: Data) -> String {
    "manifests/\(v3LowercaseHex(digest)).json"
}

func entryPath(entryID: String, digest: String) -> String {
    guard let digestBytes = canonicalDigest(digest) else {
        return "entries/\(entryID)/invalid-digest.json"
    }
    return "entries/\(entryID)/\(v3LowercaseHex(digestBytes)).json"
}

func v3LowercaseHex(_ data: Data) -> String {
    let digits = Array("0123456789abcdef".utf8)
    var encoded: [UInt8] = []
    encoded.reserveCapacity(data.count * 2)
    for byte in data {
        encoded.append(digits[Int(byte >> 4)])
        encoded.append(digits[Int(byte & 0x0f)])
    }
    return String(decoding: encoded, as: UTF8.self)
}

private func dataPrecedes(_ lhs: Data, _ rhs: Data) -> Bool {
    lhs.lexicographicallyPrecedes(rhs)
}
