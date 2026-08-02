import CryptoKit
import Foundation
import JSONCanonicalization
import Testing
@testable import KeyCore

struct V3ImmutableObjectRepositoryTests {
    fileprivate static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    fileprivate static let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    fileprivate static let vaultKey = Data(0..<32)

    @Test
    func discoversDescendantsAndSiblingBranchesFromCheckpointAncestry() throws {
        let genesis = try localManifest()
        let left = try localManifest(parents: [genesis])
        let trustedLeft = try trustedManifest(
            left,
            parents: [try verifiedLocalGenesis(genesis)]
        )
        let rightEntry = try sealedEntry(name: "branch/right")
        let right = try localManifest(
            parents: [genesis],
            entry: rightEntry.record
        )
        let source = MemoryV3ObjectSource(
            manifests: [
                digest(genesis): genesis,
                digest(left): left,
                digest(right): right
            ],
            entries: [
                EntryKey(
                    entryID: rightEntry.record.entryID,
                    digest: digest(rightEntry.data)
                ): rightEntry.data
            ]
        )

        let observation = try V3ImmutableObjectRepository(
            source: source
        ).observeForPublication(
            trustedCurrent: trustedLeft,
            vaultKeys: [Self.vaultKey]
        )
        let classification = observation.classification

        #expect(classification.status == .contentConflicted)
        #expect(classification.issues.isEmpty)
        #expect(classification.ancestryProof?.manifests.count == 3)
        #expect(Set(classification.heads.map(\.envelopeDigest)) == Set([
            digest(left), digest(right)
        ]))
        let usage = try #require(observation.resourceUsage)
        #expect(usage.manifestObjectCount == 3)
        #expect(usage.maximumHistoryDepth == 1)
        #expect(usage.referencedEntryObjectCount == 1)
        #expect(usage.totalEntryBytes == rightEntry.data.count)
    }

    @Test
    func oneAuthenticatedDescendantIsReadyWithoutChangingTheCheckpoint() throws {
        let genesis = try localManifest()
        let trustedGenesis = try trustedManifest(genesis)
        let child = try localManifest(parents: [genesis])
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(child): child
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .ready)
        #expect(classification.heads.map(\.envelopeDigest) == [digest(child)])
        #expect(classification.ancestryProof?.checkpoint == trustedGenesis.checkpoint)
        #expect(trustedGenesis.checkpoint.envelopeDigest == digest(genesis))
    }

    @Test
    func distinguishesSecurityStateDivergenceFromContentBranches() throws {
        let fixture = SharedManifestFixture()
        let parent = try fixture.manifest()
        let trustedParent = try fixture.trusted(parent)
        let contentChild = try fixture.manifest(parents: [parent])
        let securityChild = try fixture.manifest(
            parents: [parent],
            wrapperCiphertext: v3TestWrappedKeyCiphertext(
                scalar: 2,
                fill: 0x6b
            ),
            authorizeWithOwner: true
        )
        let source = MemoryV3ObjectSource(manifests: [
            digest(parent): parent,
            digest(contentChild): contentChild,
            digest(securityChild): securityChild
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedParent,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .securityConflicted)
        #expect(classification.issues.isEmpty)
        #expect(Set(classification.heads.map(\.envelopeDigest)) == Set([
            digest(contentChild), digest(securityChild)
        ]))
    }

    @Test
    func authenticatedMergeWithMissingParentIsIncompleteTransport() throws {
        let genesis = try localManifest()
        let trustedGenesis = try trustedManifest(genesis)
        let left = try localManifest(
            parents: [genesis],
            markerEntryName: "branch/left"
        )
        let missingRight = try localManifest(
            parents: [genesis],
            markerEntryName: "branch/right"
        )
        let merge = try localManifest(parents: [left, missingRight])
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(left): left,
            digest(merge): merge
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .incomplete)
        #expect(classification.ancestryProof == nil)
        #expect(classification.issues.contains(.manifestUnavailable(
            digest: Base64URL.encode(digest(missingRight))
        )))
    }

    @Test
    func availableMergeParentWithMissingAncestryIsIncompleteTransport() throws {
        let genesis = try localManifest()
        let trustedGenesis = try trustedManifest(genesis)
        let left = try localManifest(parents: [genesis])
        let missingAncestor = try localManifest(
            parents: [genesis],
            markerEntryName: "branch/missing-ancestor"
        )
        let availableRight = try localManifest(parents: [missingAncestor])
        let merge = try localManifest(parents: [left, availableRight])
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(left): left,
            digest(availableRight): availableRight,
            digest(merge): merge
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .incomplete)
        #expect(classification.ancestryProof == nil)
        #expect(classification.issues.contains(.manifestUnavailable(
            digest: Base64URL.encode(digest(missingAncestor))
        )))
    }

    @Test
    func impossibleMergeDoesNotCreateAFalseTransportGap() throws {
        let genesis = try localManifest()
        let trustedGenesis = try trustedManifest(genesis)
        let left = try localManifest(parents: [genesis])
        let missingRight = try localManifest(parents: [genesis])
        let impossibleMerge = try localManifest(
            parents: [left, missingRight],
            hasAuthorization: true
        )
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(left): left,
            digest(impossibleMerge): impossibleMerge
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .ready)
        #expect(classification.heads.map(\.envelopeDigest) == [digest(left)])
        #expect(classification.issues.isEmpty)
        #expect(classification.ancestryProof?.manifests.count == 2)
    }

    @Test
    func checkpointMergeReportsCorruptionAlongsideAMissingParent() throws {
        let genesis = try localManifest()
        let verifiedGenesis = try verifiedLocalGenesis(genesis)
        let branchA = try localManifest(
            parents: [genesis],
            markerEntryName: "branch/a"
        )
        let branchB = try localManifest(
            parents: [genesis],
            markerEntryName: "branch/b"
        )
        let orderedParents = [branchA, branchB].sorted {
            digest($0).lexicographicallyPrecedes(digest($1))
        }
        let missingParent = orderedParents[0]
        let corruptParent = orderedParents[1]
        let verifiedParents = try orderedParents.map {
            try V3ManifestAuthenticator().verify(
                $0,
                vaultKey: Self.vaultKey,
                trustAnchor: .verifiedParents([verifiedGenesis])
            )
        }
        let merge = try localManifest(parents: orderedParents)
        let trustedMerge = try trustedManifest(
            merge,
            parents: verifiedParents
        )
        var corruptBytes = corruptParent
        corruptBytes[corruptBytes.startIndex] ^= 0x01
        let source = MemoryV3ObjectSource(manifests: [
            digest(merge): merge,
            digest(corruptParent): corruptBytes
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedMerge,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .recoveryRequired)
        #expect(classification.ancestryProof == nil)
        #expect(classification.issues.contains(.manifestUnavailable(
            digest: Base64URL.encode(digest(missingParent))
        )))
        #expect(classification.issues.contains(.invalidReferencedObject(
            path: manifestPath(for: digest(corruptParent))
        )))
    }

    @Test
    func invalidUnreferencedObjectsCannotReplaceTrustedHistory() throws {
        let genesis = try localManifest()
        let trustedGenesis = try trustedManifest(genesis)
        let unrelatedGarbage = Data("not a manifest".utf8)
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(unrelatedGarbage): unrelatedGarbage
        ])

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .ready)
        #expect(classification.heads.map(\.envelopeDigest) == [digest(genesis)])
        #expect(classification.issues.isEmpty)
    }

    @Test
    func missingAndMalformedReferencedEntriesHaveDifferentOutcomes() throws {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        let context = try V3EntryAuthenticationContext(
            vaultID: Self.vaultID,
            entryID: Self.entryID,
            name: "email/personal",
            type: .secret,
            keyID: keyID,
            revision: 1
        )
        let entry = try V3EntryCipher().seal(
            "secret",
            context: context,
            vaultKey: Self.vaultKey
        )
        let manifest = try localManifest(entry: V3ManifestEntry(
            entryID: Self.entryID,
            name: "email/personal",
            type: .secret,
            revision: 1,
            keyID: keyID,
            ciphertextDigest: entry.ciphertextDigest
        ))
        let trusted = try trustedManifest(manifest)
        let missingSource = MemoryV3ObjectSource(manifests: [
            digest(manifest): manifest
        ])

        let missing = try V3ImmutableObjectRepository(source: missingSource).classify(
            trustedCurrent: trusted,
            vaultKeys: [Self.vaultKey]
        )
        #expect(missing.status == .incomplete)
        #expect(missing.issues == [.entryUnavailable(
            entryID: Self.entryID,
            digest: entry.ciphertextDigest
        )])

        var corruptedEntry = entry.canonicalBytes
        corruptedEntry[corruptedEntry.startIndex] ^= 0x01
        let corruptSource = MemoryV3ObjectSource(
            manifests: [digest(manifest): manifest],
            entries: [
                EntryKey(entryID: Self.entryID, digest: digest(entry.canonicalBytes)):
                    corruptedEntry
            ]
        )
        let corrupt = try V3ImmutableObjectRepository(source: corruptSource).classify(
            trustedCurrent: trusted,
            vaultKeys: [Self.vaultKey]
        )
        #expect(corrupt.status == .recoveryRequired)
        #expect(corrupt.ancestryProof == nil)
    }

    @Test
    func validatesEveryManifestContextForOneEntryObject() throws {
        let sealed = try sealedEntry(name: "email/personal")
        let genesis = try localManifest(entry: sealed.record)
        let trustedGenesis = try trustedManifest(genesis)
        let changedContext = V3ManifestEntry(
            entryID: sealed.record.entryID,
            name: "email/renamed",
            type: sealed.record.type,
            revision: sealed.record.revision + 1,
            keyID: sealed.record.keyID,
            ciphertextDigest: sealed.record.ciphertextDigest
        )
        let child = try localManifest(
            parents: [genesis],
            entry: changedContext
        )
        let source = MemoryV3ObjectSource(
            manifests: [
                digest(genesis): genesis,
                digest(child): child
            ],
            entries: [
                EntryKey(
                    entryID: sealed.record.entryID,
                    digest: digest(sealed.data)
                ): sealed.data
            ]
        )

        let classification = try V3ImmutableObjectRepository(source: source).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .recoveryRequired)
        #expect(classification.ancestryProof == nil)
        #expect(classification.issues.contains(.invalidReferencedObject(
            path: entryPath(
                entryID: sealed.record.entryID,
                digest: sealed.record.ciphertextDigest
            )
        )))
    }

    @Test
    func entryObjectLimitStopsCollectionAtConfiguredCap() throws {
        let firstEntry = try sealedEntry(name: "entry/first").record
        let genesis = try localManifest(entry: firstEntry)
        let secondEntry = V3ManifestEntry(
            entryID: "018f4d39-930c-735d-8d6f-588e9b0a3a49",
            name: "entry/second",
            type: firstEntry.type,
            revision: firstEntry.revision,
            keyID: firstEntry.keyID,
            ciphertextDigest: firstEntry.ciphertextDigest
        )
        let child = try localManifest(
            parents: [genesis],
            entry: secondEntry
        )
        let trustedGenesis = try trustedManifest(genesis)
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(child): child
        ])

        let classification = try V3ImmutableObjectRepository(
            source: source,
            limits: V3ManifestRepositoryLimits(
                maximumManifestObjects: 2,
                maximumHistoryDepth: 1,
                maximumReferencedEntryObjects: 1
            )
        ).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .recoveryRequired)
        #expect(classification.issues == [.resourceLimitExceeded])
        #expect(classification.ancestryProof == nil)
    }

    @Test
    func graphTraversalStopsAtConfiguredObjectAndDepthBounds() throws {
        let genesis = try localManifest()
        let child = try localManifest(parents: [genesis])
        let grandchild = try localManifest(parents: [child])
        let trustedGenesis = try trustedManifest(genesis)
        let source = MemoryV3ObjectSource(manifests: [
            digest(genesis): genesis,
            digest(child): child,
            digest(grandchild): grandchild
        ])

        let depthLimited = try V3ImmutableObjectRepository(
            source: source,
            limits: V3ManifestRepositoryLimits(
                maximumManifestObjects: 3,
                maximumHistoryDepth: 1
            )
        ).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )
        #expect(depthLimited.status == .recoveryRequired)
        #expect(depthLimited.issues.contains(.resourceLimitExceeded))

        let countLimited = try V3ImmutableObjectRepository(
            source: source,
            limits: V3ManifestRepositoryLimits(
                maximumManifestObjects: 2,
                maximumHistoryDepth: 10
            )
        ).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )
        #expect(countLimited.status == .recoveryRequired)
        #expect(countLimited.issues.contains(.resourceLimitExceeded))

        let largestManifest = [genesis, child, grandchild].map(\.count).max()!
        let byteLimited = try V3ImmutableObjectRepository(
            source: source,
            limits: V3ManifestRepositoryLimits(
                maximumManifestObjects: 3,
                maximumHistoryDepth: 10,
                maximumManifestBytes: largestManifest,
                maximumTotalManifestBytes: largestManifest
            )
        ).classify(
            trustedCurrent: trustedGenesis,
            vaultKeys: [Self.vaultKey]
        )
        #expect(byteLimited.status == .recoveryRequired)
        #expect(byteLimited.issues.contains(.resourceLimitExceeded))
    }

    @Test
    func filesystemRepositoryUsesLowercaseDigestPathsAndIgnoresMutablePointers() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let manifestsDirectory = root.appendingPathComponent(
            "manifests",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: manifestsDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let genesis = try localManifest()
        let filename = lowercaseHex(digest(genesis)) + ".json"
        try genesis.write(to: manifestsDirectory.appendingPathComponent(filename))
        try Data("not authoritative".utf8).write(
            to: manifestsDirectory.appendingPathComponent("current.json")
        )

        let trusted = try trustedManifest(genesis)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)
        let classification = try V3ImmutableObjectRepository(
            rootHandle: rootHandle
        ).classify(
            trustedCurrent: trusted,
            vaultKeys: [Self.vaultKey]
        )

        #expect(classification.status == .ready)
        #expect(classification.heads.map(\.envelopeDigest) == [digest(genesis)])
    }

    private func localManifest(
        parents: [Data] = [],
        markerEntryName: String? = nil,
        entry: V3ManifestEntry? = nil,
        hasAuthorization: Bool = false
    ) throws -> Data {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        var entries: [CanonicalJSONValue] = []
        if let markerEntryName {
            entries.append(.object([
                ("entryID", .string(Self.entryID)),
                ("name", .string(markerEntryName)),
                ("type", .string("secret")),
                ("revision", .integer(1)),
                ("keyID", .string(keyID.rawValue)),
                ("ciphertextDigest", .string(String(repeating: "A", count: 43)))
            ]))
        } else if let entry {
            entries.append(.object([
                ("entryID", .string(entry.entryID)),
                ("name", .string(entry.name)),
                ("type", .string(entry.type.rawValue)),
                ("revision", .integer(entry.revision)),
                ("keyID", .string(entry.keyID.rawValue)),
                ("ciphertextDigest", .string(entry.ciphertextDigest))
            ]))
        }

        return try envelope(
            parents: parents,
            manifest: .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(Self.vaultID)),
                ("mode", .string("local")),
                ("keyID", .string(keyID.rawValue)),
                ("devices", .array([])),
                ("wrappedKeys", .array([])),
                ("entries", .array(entries))
            ]),
            vaultKey: Self.vaultKey,
            authorizations: hasAuthorization ? [
                .object([
                    ("algorithm", .string("P-256-ECDSA-SHA256")),
                    ("signerDeviceID", .string(String(repeating: "A", count: 43))),
                    ("signature", .string(String(repeating: "A", count: 86)))
                ])
            ] : []
        )
    }

    private func trustedManifest(
        _ data: Data,
        parents: [V3VerifiedManifest] = []
    ) throws -> V3TrustedManifest {
        let authenticator = V3ManifestAuthenticator()
        let verified: V3VerifiedManifest
        if parents.isEmpty {
            verified = try authenticator.verify(
                data,
                vaultKey: Self.vaultKey,
                trustAnchor: .localGenesis(vaultID: Self.vaultID)
            )
        } else {
            verified = try authenticator.verify(
                data,
                vaultKey: Self.vaultKey,
                trustAnchor: .verifiedParents(parents)
            )
        }
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: try V3ManifestCheckpoint(verifiedManifest: verified)
        )
    }

    private func verifiedLocalGenesis(_ data: Data) throws -> V3VerifiedManifest {
        try V3ManifestAuthenticator().verify(
            data,
            vaultKey: Self.vaultKey,
            trustAnchor: .localGenesis(vaultID: Self.vaultID)
        )
    }

    private func sealedEntry(
        name: String
    ) throws -> (record: V3ManifestEntry, data: Data) {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        let context = try V3EntryAuthenticationContext(
            vaultID: Self.vaultID,
            entryID: Self.entryID,
            name: name,
            type: .secret,
            keyID: keyID,
            revision: 1
        )
        let sealed = try V3EntryCipher().seal(
            "branch value",
            context: context,
            vaultKey: Self.vaultKey
        )
        return (
            V3ManifestEntry(
                entryID: Self.entryID,
                name: name,
                type: .secret,
                revision: 1,
                keyID: keyID,
                ciphertextDigest: sealed.ciphertextDigest
            ),
            sealed.canonicalBytes
        )
    }
}

private struct SharedManifestFixture {
    private let signingKey = P256.Signing.PrivateKey()
    private let wrappingKey = P256.KeyAgreement.PrivateKey()

    private var deviceID: String {
        V3ManifestAuthenticator.deviceID(
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func manifest(
        parents: [Data] = [],
        wrapperCiphertext: String = v3TestWrappedKeyCiphertext(),
        authorizeWithOwner: Bool = false
    ) throws -> Data {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: V3ImmutableObjectRepositoryTests.vaultKey,
            vaultID: V3ImmutableObjectRepositoryTests.vaultID
        )
        let body = CanonicalJSONValue.object([
            ("format", .string("key-vault-manifest")),
            ("version", .integer(3)),
            ("vaultID", .string(V3ImmutableObjectRepositoryTests.vaultID)),
            ("mode", .string("shared")),
            ("keyID", .string(keyID.rawValue)),
            ("devices", .array([
                .object([
                    ("deviceID", .string(deviceID)),
                    ("displayName", .string("Laptop")),
                    ("role", .string("owner")),
                    ("status", .string("active")),
                    ("signingPublicKey", .object([
                        ("algorithm", .string("P-256-ECDSA")),
                        ("encoding", .string("x963")),
                        ("value", .string(Base64URL.encode(
                            signingKey.publicKey.x963Representation
                        )))
                    ])),
                    ("wrappingPublicKey", .object([
                        ("algorithm", .string("P-256-ECDH")),
                        ("encoding", .string("x963")),
                        ("value", .string(Base64URL.encode(
                            wrappingKey.publicKey.x963Representation
                        )))
                    ]))
                ])
            ])),
            ("wrappedKeys", .array([
                .object([
                    ("deviceID", .string(deviceID)),
                    ("algorithm", .string("p256-ecies-x963-sha256-aes-gcm")),
                    ("ciphertext", .string(wrapperCiphertext))
                ])
            ])),
            ("entries", .array([]))
        ])
        let parentValues = parentDigestStrings(parents)
            .map(CanonicalJSONValue.string)
        let content = CanonicalJSONValue.object([
            ("parents", .array(parentValues)),
            ("manifest", body)
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: V3ImmutableObjectRepositoryTests.vaultID,
            vaultKey: V3ImmutableObjectRepositoryTests.vaultKey
        )
        let authorizations: [CanonicalJSONValue]
        if authorizeWithOwner {
            let input = V3ManifestAuthenticator.authenticationInput(
                for: canonicalContent
            )
            let signature = try signingKey.signature(
                for: SHA256.hash(data: input)
            )
            let canonicalSignature = try V3ManifestAuthenticator
                .canonicalizeP256Signature(signature.rawRepresentation)
            authorizations = [.object([
                ("algorithm", .string("P-256-ECDSA-SHA256")),
                ("signerDeviceID", .string(deviceID)),
                ("signature", .string(Base64URL.encode(canonicalSignature)))
            ])]
        } else {
            authorizations = []
        }

        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array(authorizations))
        ]))
    }

    func trusted(_ data: Data) throws -> V3TrustedManifest {
        let authenticated = try V3ManifestAuthenticator()
            .authenticateForRepositoryDiscovery(
                data,
                vaultKey: V3ImmutableObjectRepositoryTests.vaultKey
            )
        let verified = V3VerifiedManifest(
            envelope: authenticated.envelope,
            envelopeDigest: authenticated.envelopeDigest
        )
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: try V3ManifestCheckpoint(verifiedManifest: verified)
        )
    }
}

private struct EntryKey: Hashable, Sendable {
    let entryID: String
    let digest: Data
}

private struct MemoryV3ObjectSource: V3ImmutableObjectReading {
    let manifests: [Data: Data]
    let entries: [EntryKey: Data]

    init(
        manifests: [Data: Data],
        entries: [EntryKey: Data] = [:]
    ) {
        self.manifests = manifests
        self.entries = entries
    }

    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
        guard manifests.count <= maximumCount else {
            return .limitExceeded
        }
        return .available(
            digests: Array(manifests.keys),
            objectCount: manifests.count
        )
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        guard let data = manifests[digest] else {
            return .unavailable
        }
        return data.count <= maximumBytes ? .available(data) : .tooLarge
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        guard let data = entries[EntryKey(entryID: entryID, digest: digest)] else {
            return .unavailable
        }
        return data.count <= maximumBytes ? .available(data) : .tooLarge
    }
}

private func envelope(
    parents: [Data],
    manifest: CanonicalJSONValue,
    vaultKey: Data,
    authorizations: [CanonicalJSONValue] = []
) throws -> Data {
    let content = CanonicalJSONValue.object([
        ("parents", .array(parentDigestStrings(parents).map(
            CanonicalJSONValue.string
        ))),
        ("manifest", manifest)
    ])
    let canonicalContent = CanonicalJSON.encode(content)
    let tag = try V3ManifestAuthenticator.authenticationTag(
        canonicalContent: canonicalContent,
        vaultID: V3ImmutableObjectRepositoryTests.vaultID,
        vaultKey: vaultKey
    )
    return CanonicalJSON.encode(.object([
        ("format", .string("key-vault-manifest-envelope")),
        ("version", .integer(3)),
        ("content", content),
        ("authentication", .object([
            ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
            ("tag", .string(Base64URL.encode(tag)))
        ])),
        ("authorizations", .array(authorizations))
    ]))
}

private func parentDigestStrings(_ parents: [Data]) -> [String] {
    parents
        .map(digest)
        .sorted(by: { $0.lexicographicallyPrecedes($1) })
        .map(Base64URL.encode)
}

private func digest(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

private func lowercaseHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}
