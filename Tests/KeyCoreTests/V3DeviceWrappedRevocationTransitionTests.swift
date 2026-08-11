import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3DeviceWrappedRevocationTransitionTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b3"
    fileprivate static let parentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b4"
    fileprivate static let revocationTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b5"
    fileprivate static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b6"
    fileprivate static let currentKey = Data(0..<32)
    fileprivate static let nextKey = Data(repeating: 0x51, count: 32)

    @Test
    func revocationRotatesTheKeyAndExcludesTheSelectedDevice() throws {
        let fixture = try Fixture()

        let candidate = try V3DeviceWrappedRevocationTransitionBuilder()
            .build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                plan: fixture.plan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )

        #expect(candidate.plan == fixture.plan)
        #expect(candidate.body.keyID != fixture.base.envelope.body.keyID)
        #expect(candidate.body.authorityTransitionID
            == Self.revocationTransitionID)
        #expect(candidate.manifestDigest == Data(SHA256.hash(
            data: candidate.manifestData
        )))
        #expect(candidate.body.devices.first(where: {
            $0.identity.deviceID == fixture.member.identity.deviceID
        })?.status == .revoked)
        #expect(candidate.body.wrappedKeys.map(\.recipientDeviceID) == [
            fixture.owner.identity.deviceID,
        ])

        let ownerWrapper = try #require(candidate.body.wrappedKeys.first)
        let context = try V3VaultKeyHPKEContext(
            vaultID: Self.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: Self.revocationTransitionID,
            recipientDeviceID: fixture.owner.identity.deviceID
        )
        #expect(try V3VaultKeyHPKE().unwrap(
            ownerWrapper.wrappedKey,
            recipientPrivateKey: fixture.owner.wrappingPrivateKey,
            context: context
        ) == Self.nextKey)

        let oldEntry = try #require(fixture.base.envelope.body.entries.first)
        let newEntry = try #require(candidate.body.entries.first)
        let staged = try #require(candidate.stagedEntries.first)
        #expect(newEntry.entryID == oldEntry.entryID)
        #expect(newEntry.name == oldEntry.name)
        #expect(newEntry.type == oldEntry.type)
        #expect(newEntry.revision == oldEntry.revision)
        #expect(newEntry.keyID == candidate.body.keyID)
        #expect(newEntry.ciphertextDigest != oldEntry.ciphertextDigest)
        #expect(try V3EntryCipher().openTrusted(
            staged.canonicalBytes,
            vaultID: Self.vaultID,
            manifestEntry: newEntry,
            vaultKey: Self.nextKey
        ) == "correct horse battery staple")
        #expect(throws: V3EncryptedEntryError.self) {
            try V3EntryCipher().openTrusted(
                staged.canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: newEntry,
                vaultKey: Self.currentKey
            )
        }

        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            candidate.manifestData
        )
        let authorization = try #require(envelope.authorizations.first)
        let signatureBytes = try #require(Base64URL.decodeCanonical(
            authorization.signature
        ))
        let signature = try P256.Signing.ECDSASignature(
            rawRepresentation: signatureBytes
        )
        #expect(fixture.owner.signingPrivateKey.publicKey.isValidSignature(
            signature,
            for: SHA256.hash(data:
                V3ManifestAuthenticator.authenticationInput(
                    for: envelope.canonicalContentBytes
                )
            )
        ))
    }

    @Test
    func refusesAPlanThatNoLongerMatchesTheCheckpoint() throws {
        let fixture = try Fixture()
        let alteredPlan = V3DeviceWrappedRevocationPlan(
            expectedCheckpoint: fixture.plan.expectedCheckpoint,
            authorizingOwner: fixture.plan.authorizingOwner,
            revokedDevice: fixture.plan.authorizingOwner,
            resultingDevices: fixture.plan.resultingDevices
        )

        #expect(
            throws: V3DeviceWrappedRevocationTransitionError.invalidPlan
        ) {
            _ = try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                plan: alteredPlan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )
        }
    }

    @Test
    func requiresTheCompleteCurrentSnapshot() throws {
        let fixture = try Fixture()

        #expect(
            throws: V3DeviceWrappedRevocationTransitionError
                .incompleteEntrySnapshot
        ) {
            _ = try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: fixture.base,
                currentEntries: [:],
                plan: fixture.plan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )
        }
    }

    @Test
    func refusesToReuseTheCurrentVaultKey() throws {
        let fixture = try Fixture()

        #expect(
            throws: V3DeviceWrappedRevocationTransitionError
                .invalidNextVaultKey
        ) {
            _ = try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                plan: fixture.plan,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.currentKey,
                authorityTransitionID: Self.revocationTransitionID,
                owner: fixture.owner,
                authorizationReason: "Revoke the selected Mac."
            )
        }
    }

    @Test
    func independentlyValidatesTheReviewedRevocation() throws {
        let fixture = try Fixture()
        let candidate = try fixture.makeCandidate()

        let validated = try V3DeviceWrappedRevocationTransitionValidator()
            .validate(
                candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                localIdentity: fixture.owner,
                unwrapReason: "Confirm the new vault key."
            )

        #expect(validated.plan == fixture.plan)
        #expect(validated.candidate.body == candidate.body)
        #expect(validated.manifestDigest == candidate.manifestDigest)
        #expect(validated.stagedEntries.count == 1)
    }

    @Test
    func validatorRejectsAChangedReviewedPlan() throws {
        let fixture = try Fixture()
        let candidate = try fixture.makeCandidate()
        let alteredPlan = V3DeviceWrappedRevocationPlan(
            expectedCheckpoint: candidate.plan.expectedCheckpoint,
            authorizingOwner: candidate.plan.authorizingOwner,
            revokedDevice: candidate.plan.authorizingOwner,
            resultingDevices: candidate.plan.resultingDevices
        )
        let altered = V3DeviceWrappedRevocationTransitionCandidate(
            plan: alteredPlan,
            body: candidate.body,
            manifestData: candidate.manifestData,
            manifestDigest: candidate.manifestDigest,
            stagedEntries: candidate.stagedEntries
        )

        #expect(
            throws: V3DeviceWrappedRevocationValidationError.invalidPlan
        ) {
            _ = try V3DeviceWrappedRevocationTransitionValidator().validate(
                altered,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                localIdentity: fixture.owner,
                unwrapReason: "Confirm the new vault key."
            )
        }
    }

    @Test
    func validatorRejectsSubstitutedStagedEntryBytes() throws {
        let fixture = try Fixture()
        let candidate = try fixture.makeCandidate()
        let current = try #require(fixture.currentEntries.values.first)
        let altered = V3DeviceWrappedRevocationTransitionCandidate(
            plan: candidate.plan,
            body: candidate.body,
            manifestData: candidate.manifestData,
            manifestDigest: candidate.manifestDigest,
            stagedEntries: [current]
        )

        #expect(
            throws:
                V3DeviceWrappedRevocationValidationError.invalidStagedEntry
        ) {
            _ = try V3DeviceWrappedRevocationTransitionValidator().validate(
                altered,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                localIdentity: fixture.owner,
                unwrapReason: "Confirm the new vault key."
            )
        }
    }

    @Test
    func validatorEnforcesEntryResourceLimitsBeforeOpening() throws {
        let fixture = try Fixture()
        let candidate = try fixture.makeCandidate()
        let staged = try #require(candidate.stagedEntries.first)
        let limits = V3ManifestRepositoryLimits(
            maximumManifestObjects: 4_096,
            maximumHistoryDepth: 1_024,
            maximumEntryBytes: staged.canonicalBytes.count - 1,
            maximumTotalEntryBytes: staged.canonicalBytes.count - 1
        )

        #expect(
            throws: V3DeviceWrappedRevocationValidationError.objectTooLarge
        ) {
            _ = try V3DeviceWrappedRevocationTransitionValidator(
                limits: limits
            ).validate(
                candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                localIdentity: fixture.owner,
                unwrapReason: "Confirm the new vault key."
            )
        }
    }
}

@Suite(.serialized)
struct V3DeviceWrappedRevocationTransitionPublisherTests {
    private static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c94b7"
    )
    private static let seedOperationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c94b8"
    )

    @Test
    func publishesTheCompleteRevokedEpochBeforeAdvancingCheckpoint() throws {
        let fixture = try RevocationPublicationFixture()
        defer { fixture.removeRoot() }
        let observer = RevocationPublicationObserver()
        let completion = RevocationPublicationCompletion()

        let trusted = try fixture.publisher(observer: observer).publish(
            fixture.candidate,
            parent: fixture.transition.base,
            currentEntries: fixture.transition.currentEntries,
            currentVaultKey:
                V3DeviceWrappedRevocationTransitionTests.currentKey,
            nextVaultKey: V3DeviceWrappedRevocationTransitionTests.nextKey,
            localIdentity: fixture.transition.owner,
            unwrapReason: "Verify the owner's rotated-key wrapper.",
            afterCheckpointAdvance: { checkpoint, vaultKey in
                completion.record(checkpoint: checkpoint, vaultKey: vaultKey)
            }
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
        #expect(fixture.checkpointStore.checkpoint
            == trusted.checkpoint.canonicalBytes)
        #expect(fixture.anchorStore.anchor == nil)
        #expect(fixture.cache.manifest == fixture.candidate.manifestData)
        #expect(completion.checkpoint == trusted)
        #expect(completion.vaultKey
            == V3DeviceWrappedRevocationTransitionTests.nextKey)
        try fixture.requireCandidateObjectsPublished()
    }

    private final class RevocationPublicationFixture:
        V3DeviceWrappedRepositoryObserving,
        @unchecked Sendable
    {
        let rootURL: URL
        let store: V3FilesystemTransactionArtifactStore
        let checkpointStore: RevocationPublicationCheckpointStore
        let anchorStore = RevocationPublicationAnchorStore()
        let cache = RevocationPublicationCache()
        let transition: RevocationTransitionFixture
        let candidate: V3DeviceWrappedRevocationTransitionCandidate

        init() throws {
            transition = try RevocationTransitionFixture()
            candidate = try transition.makeCandidate()
            rootURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(
                at: rootURL,
                withIntermediateDirectories: true
            )
            store = V3FilesystemTransactionArtifactStore(
                rootHandle: try VaultRootDirectoryHandle(opening: rootURL)
            )
            checkpointStore = RevocationPublicationCheckpointStore(
                transition.base.checkpoint
            )

            for (key, entry) in transition.currentEntries {
                try store.stageEntry(
                    entry.canonicalBytes,
                    entryID: key.entryID,
                    digest: key.digest,
                    operationID: seedOperationID
                )
                try store.publishStagedEntry(
                    entry.canonicalBytes,
                    entryID: key.entryID,
                    digest: key.digest,
                    operationID: seedOperationID
                )
            }
            try store.stageManifest(
                transition.base.envelope.canonicalBytes,
                digest: transition.base.checkpoint.envelopeDigest,
                operationID: seedOperationID
            )
            try store.publishStagedManifest(
                transition.base.envelope.canonicalBytes,
                digest: transition.base.checkpoint.envelopeDigest,
                operationID: seedOperationID
            )
        }

        func publisher(
            observer: any V3ImmutableTransactionPhaseObserving
        ) -> V3DeviceWrappedRevocationTransitionPublisher {
            V3DeviceWrappedRevocationTransitionPublisher(
                mutationOwner: VaultTransactionMutationOwner(
                    makeOperationID: { operationID }
                ),
                repositoryObserver: self,
                objectStore: store,
                checkpointStore: checkpointStore,
                recoveryAnchorStore: anchorStore,
                cache: cache,
                phaseObserver: observer
            )
        }

        func observeRepository(
            vaultID _: String,
            vaultKeys _: [Data]
        ) throws -> V3DeviceWrappedRepositoryObservation {
            let checkpoint = try V3ManifestCheckpoint(
                canonicalBytes: #require(checkpointStore.checkpoint)
            )
            var manifestDigests = Set([
                transition.base.checkpoint.envelopeDigest,
            ])
            var referencedEntries = Set(transition.currentEntries.keys)
            var totalManifestBytes =
                transition.base.envelope.canonicalBytes.count
            var totalEntryBytes = transition.currentEntries.values.reduce(0) {
                $0 + $1.canonicalBytes.count
            }
            var heads = [transition.base.checkpoint.envelopeDigest]
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
                    transition.base.checkpoint.envelopeDigest: [],
                    candidate.manifestDigest: [
                        transition.base.checkpoint.envelopeDigest,
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

        func requireCandidateObjectsPublished() throws {
            guard case let .available(manifest) = try store.readManifest(
                digest: candidate.manifestDigest,
                maximumBytes: 2 * 1_024 * 1_024
            ) else {
                Issue.record("The revocation manifest was not published.")
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

        func removeRoot() {
            try? FileManager.default.removeItem(at: rootURL)
        }
    }
}

private struct RevocationTestDevice:
    V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
{
    let vaultID = V3DeviceWrappedRevocationTransitionTests.vaultID
    let identity: V3EnrollmentDeviceIdentity
    let signingPrivateKey: P256.Signing.PrivateKey
    let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    var publicIdentity: V3EnrollmentDeviceIdentity { identity }

    init(name: String, signing: UInt8, wrapping: UInt8) throws {
        signingPrivateKey = try P256.Signing.PrivateKey(
            rawRepresentation: Self.scalar(signing)
        )
        wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Self.scalar(wrapping)
        )
        identity = try V3EnrollmentDeviceIdentity(
            displayName: name,
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

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}

private struct RevocationTransitionFixture {
    let owner: RevocationTestDevice
    let member: RevocationTestDevice
    let base: V3DeviceWrappedTrustedCheckpoint
    let currentEntries: [V3EntryObjectKey: V3EncryptedEntry]
    let plan: V3DeviceWrappedRevocationPlan

    init() throws {
        owner = try RevocationTestDevice(
            name: "Owner Mac",
            signing: 0x11,
            wrapping: 0x12
        )
        member = try RevocationTestDevice(
            name: "Member Mac",
            signing: 0x21,
            wrapping: 0x22
        )
        let keyID = try V3VaultKeyID.derive(
            vaultKey: V3DeviceWrappedRevocationTransitionTests.currentKey,
            vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID
        )
        let encrypted = try V3EntryCipher().seal(
            "correct horse battery staple",
            context: V3EntryAuthenticationContext(
                vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID,
                entryID: V3DeviceWrappedRevocationTransitionTests.entryID,
                name: "account/password",
                type: .secret,
                keyID: keyID,
                revision: 1
            ),
            vaultKey: V3DeviceWrappedRevocationTransitionTests.currentKey
        )
        let devices = [
            V3DeviceWrappedManifestDevice(
                identity: owner.identity,
                role: .owner,
                status: .active
            ),
            V3DeviceWrappedManifestDevice(
                identity: member.identity,
                role: .member,
                status: .active
            ),
        ].sorted {
            Data($0.identity.deviceID.utf8).lexicographicallyPrecedes(
                Data($1.identity.deviceID.utf8)
            )
        }
        let wrappedKeys = try devices.map { device in
            let context = try V3VaultKeyHPKEContext(
                vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID,
                keyID: keyID,
                authorityTransitionID:
                    V3DeviceWrappedRevocationTransitionTests
                        .parentTransitionID,
                recipientDeviceID: device.identity.deviceID
            )
            return try V3DeviceWrappedManifestKey(
                recipientDeviceID: device.identity.deviceID,
                wrappedKey: V3VaultKeyHPKE().wrap(
                    vaultKey:
                        V3DeviceWrappedRevocationTransitionTests.currentKey,
                    recipientPublicKey: device.identity.wrappingPublicKey,
                    context: context
                )
            )
        }
        let body = try V3DeviceWrappedManifestBody(
            vaultID: V3DeviceWrappedRevocationTransitionTests.vaultID,
            keyID: keyID,
            authorityTransitionID:
                V3DeviceWrappedRevocationTransitionTests.parentTransitionID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: [V3ManifestEntry(
                entryID: encrypted.context.entryID,
                name: encrypted.context.name,
                type: encrypted.context.type,
                revision: encrypted.context.revision,
                keyID: encrypted.context.keyID,
                ciphertextDigest: encrypted.ciphertextDigest
            )]
        )
        let content: CanonicalJSONValue = .object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: body.vaultID,
            vaultKey: V3DeviceWrappedRevocationTransitionTests.currentKey
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([])),
        ]))
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            manifestData
        )
        base = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: body.vaultID,
                envelopeDigest: Data(SHA256.hash(data: manifestData))
            ),
            envelope: envelope
        )
        guard let digest = Base64URL.decodeCanonical(
            encrypted.ciphertextDigest
        ) else {
            throw V3DeviceWrappedRevocationTransitionError.invalidEntry
        }
        currentEntries = [V3EntryObjectKey(
            entryID: encrypted.context.entryID,
            digest: digest
        ): encrypted]
        plan = try V3DeviceWrappedRevocationPlanner().plan(
            from: base,
            authorizingDeviceID: owner.identity.deviceID,
            revoking: member.identity.deviceID
        )
    }

    func makeCandidate() throws
        -> V3DeviceWrappedRevocationTransitionCandidate
    {
        try V3DeviceWrappedRevocationTransitionBuilder().build(
            from: base,
            currentEntries: currentEntries,
            plan: plan,
            currentVaultKey:
                V3DeviceWrappedRevocationTransitionTests.currentKey,
            nextVaultKey: V3DeviceWrappedRevocationTransitionTests.nextKey,
            authorityTransitionID:
                V3DeviceWrappedRevocationTransitionTests
                    .revocationTransitionID,
            owner: owner,
            authorizationReason: "Revoke the selected Mac."
        )
    }
}

private typealias Fixture = RevocationTransitionFixture

private final class RevocationPublicationObserver:
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

private final class RevocationPublicationCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var recordedCheckpoint: V3DeviceWrappedTrustedCheckpoint?
    private var recordedVaultKey: Data?

    var checkpoint: V3DeviceWrappedTrustedCheckpoint? {
        lock.withLock { recordedCheckpoint }
    }

    var vaultKey: Data? {
        lock.withLock { recordedVaultKey }
    }

    func record(
        checkpoint: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data
    ) {
        lock.withLock {
            recordedCheckpoint = checkpoint
            recordedVaultKey = vaultKey
        }
    }
}

private final class RevocationPublicationCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Data?

    init(_ checkpoint: V3ManifestCheckpoint) {
        stored = checkpoint.canonicalBytes
    }

    var checkpoint: Data? {
        lock.withLock { stored }
    }

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        checkpoint
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

private final class RevocationPublicationAnchorStore:
    V3ImmutableTransactionRecoveryAnchorStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var stored: Data?

    var anchor: Data? {
        lock.withLock { stored }
    }

    func loadRecoveryAnchor(vaultID _: String) throws -> Data? {
        anchor
    }

    func replaceRecoveryAnchor(
        _ anchor: Data?,
        expectedAnchor: Data?,
        vaultID _: String
    ) throws {
        try lock.withLock {
            guard stored == expectedAnchor else {
                throw V3ImmutableTransactionRecoveryAnchorError.conflict
            }
            stored = anchor
        }
    }
}

private final class RevocationPublicationCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var storedCheckpoint: V3ManifestCheckpoint?
    private var storedManifest: Data?

    var manifest: Data? {
        lock.withLock { storedManifest }
    }

    func load(
        for checkpoint: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        lock.withLock {
            guard storedCheckpoint == checkpoint, let storedManifest else {
                return .missing
            }
            return .available(storedManifest)
        }
    }

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws {
        lock.withLock {
            storedCheckpoint = checkpoint
            storedManifest = manifestData
        }
    }
}
