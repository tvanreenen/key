import CryptoKit
import Foundation
import Testing
@testable import KeyCore

struct V3ReadExecutorTests {
    @Test
    func opensOnlyThePlannedObjectWithTheExactKeyAndRevalidatesAuthority()
        throws
    {
        let fixture = try ExecutorFixture()
        let recorder = ReadAuthorityRecorder()
        let executor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: fixture.plan.entry.entryID,
                expectedDigest: fixture.plan.ciphertextDigest,
                result: .available(fixture.entryData)
            ),
            vaultKeyProvider: { keyID in
                #expect(keyID == fixture.plan.entry.keyID)
                return fixture.vaultKey
            },
            authorityValidator: authorityValidator(
                for: fixture.plan.authority,
                recorder: recorder
            )
        )

        #expect(try executor.execute(fixture.plan) == fixture.plaintext)
        #expect(recorder.authorities == [fixture.plan.authority])
    }

    @Test
    func changedAuthorityIsRejectedAfterSuccessfulDecryption() throws {
        let fixture = try ExecutorFixture()
        guard case let .current(expected) = fixture.plan.authority else {
            Issue.record("Expected current read authority.")
            return
        }
        let executor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: fixture.plan.entry.entryID,
                expectedDigest: fixture.plan.ciphertextDigest,
                result: .available(fixture.entryData)
            ),
            vaultKeyProvider: { _ in fixture.vaultKey },
            authorityValidator: authorityValidator(
                for: fixture.plan.authority,
                currentOverride: V3ExpectedRepositoryState(
                    checkpoint: expected.checkpoint,
                    heads: []
                )
            )
        )

        #expect(throws: V3AuthenticatedReadError.authorityChanged) {
            try executor.execute(fixture.plan)
        }
    }

    @Test
    func staleReadRetainsAndRevalidatesTheExactLocalCheckpoint() throws {
        let fixture = try ExecutorFixture(stale: true)
        let recorder = ReadAuthorityRecorder()
        let executor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: fixture.plan.entry.entryID,
                expectedDigest: fixture.plan.ciphertextDigest,
                result: .available(fixture.entryData)
            ),
            vaultKeyProvider: { _ in fixture.vaultKey },
            authorityValidator: authorityValidator(
                for: fixture.plan.authority,
                recorder: recorder
            )
        )

        #expect(try executor.execute(fixture.plan) == fixture.plaintext)
        guard case let .lastTrusted(checkpoint) =
                try #require(recorder.authorities.first)
        else {
            Issue.record("Expected last-trusted read authority.")
            return
        }
        #expect(checkpoint == fixture.trusted.checkpoint)

        let advancedCheckpoint = try V3ManifestCheckpoint(
            vaultID: fixture.trusted.checkpoint.vaultID,
            envelopeDigest: Data(repeating: 0x99, count: 32)
        )
        let changedExecutor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: fixture.plan.entry.entryID,
                expectedDigest: fixture.plan.ciphertextDigest,
                result: .available(fixture.entryData)
            ),
            vaultKeyProvider: { _ in fixture.vaultKey },
            authorityValidator: authorityValidator(
                for: fixture.plan.authority,
                checkpointOverride: advancedCheckpoint
            )
        )
        #expect(throws: V3AuthenticatedReadError.authorityChanged) {
            try changedExecutor.execute(fixture.plan)
        }
    }

    @Test
    func missingInvalidAndOversizedObjectsFailBeforeKeyAccess() throws {
        let fixture = try ExecutorFixture()
        let keyAccess = Counter()

        func executor(
            result: V3RepositoryObjectRead,
            maximumBytes: Int = 1_024
        ) -> V3AuthenticatedReadExecutor {
            V3AuthenticatedReadExecutor(
                source: SingleEntryReadSource(
                    expectedEntryID: fixture.plan.entry.entryID,
                    expectedDigest: fixture.plan.ciphertextDigest,
                    result: result
                ),
                maximumEntryBytes: maximumBytes,
                vaultKeyProvider: { _ in
                    keyAccess.increment()
                    return fixture.vaultKey
                },
                authorityValidator: authorityValidator(
                    for: fixture.plan.authority
                )
            )
        }

        #expect(throws: V3AuthenticatedReadError.entryUnavailable) {
            try executor(result: .unavailable).execute(fixture.plan)
        }
        #expect(throws: V3AuthenticatedReadError.invalidEntryObject) {
            try executor(result: .invalid).execute(fixture.plan)
        }
        #expect(throws: V3AuthenticatedReadError.entryObjectTooLarge) {
            try executor(result: .tooLarge).execute(fixture.plan)
        }
        #expect(throws: V3AuthenticatedReadError.entryObjectTooLarge) {
            try executor(
                result: .available(fixture.entryData),
                maximumBytes: fixture.entryData.count - 1
            ).execute(fixture.plan)
        }
        #expect(keyAccess.value == 0)
    }

    @Test
    func substitutedDigestAndWrongVaultKeyFailBeforeAuthorityApproval()
        throws
    {
        let fixture = try ExecutorFixture()
        let other = try ExecutorFixture(
            plaintext: "substituted",
            nonceByte: 0xC0
        )
        let recorder = ReadAuthorityRecorder()
        let substitutedExecutor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: fixture.plan.entry.entryID,
                expectedDigest: fixture.plan.ciphertextDigest,
                result: .available(other.entryData)
            ),
            vaultKeyProvider: { _ in fixture.vaultKey },
            authorityValidator: authorityValidator(
                for: fixture.plan.authority,
                recorder: recorder
            )
        )

        #expect(throws: V3EncryptedEntryError.conflictingRevision(
            trustedRevision: 1,
            observedRevision: 1
        )) {
            try substitutedExecutor.execute(fixture.plan)
        }
        #expect(recorder.authorities.isEmpty)

        let wrongKeyExecutor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: fixture.plan.entry.entryID,
                expectedDigest: fixture.plan.ciphertextDigest,
                result: .available(fixture.entryData)
            ),
            vaultKeyProvider: { _ in
                Data(repeating: 0xFF, count: 32)
            },
            authorityValidator: authorityValidator(
                for: fixture.plan.authority,
                recorder: recorder
            )
        )
        #expect(throws: V3EncryptedEntryError.keyIdentityMismatch) {
            try wrongKeyExecutor.execute(fixture.plan)
        }
        #expect(recorder.authorities.isEmpty)
    }

    @Test
    func matchingDigestWithMalformedOrMismatchedContextStillFails()
        throws
    {
        let malformed = Data("not canonical entry JSON".utf8)
        let malformedFixture = try ExecutorFixture(
            objectData: malformed
        )
        let malformedRecorder = ReadAuthorityRecorder()
        let malformedExecutor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: malformedFixture.plan.entry.entryID,
                expectedDigest: malformedFixture.plan.ciphertextDigest,
                result: .available(malformed)
            ),
            vaultKeyProvider: { _ in malformedFixture.vaultKey },
            authorityValidator: authorityValidator(
                for: malformedFixture.plan.authority,
                recorder: malformedRecorder
            )
        )

        #expect(throws: V3EncryptedEntryError.self) {
            try malformedExecutor.execute(malformedFixture.plan)
        }
        #expect(malformedRecorder.authorities.isEmpty)

        let contextMismatch = try ExecutorFixture(
            sealedName: "mail/personal",
            manifestName: "mail/work"
        )
        let mismatchRecorder = ReadAuthorityRecorder()
        let mismatchExecutor = V3AuthenticatedReadExecutor(
            source: SingleEntryReadSource(
                expectedEntryID: contextMismatch.plan.entry.entryID,
                expectedDigest: contextMismatch.plan.ciphertextDigest,
                result: .available(contextMismatch.entryData)
            ),
            vaultKeyProvider: { _ in contextMismatch.vaultKey },
            authorityValidator: authorityValidator(
                for: contextMismatch.plan.authority,
                recorder: mismatchRecorder
            )
        )
        #expect(throws: V3EncryptedEntryError.contextMismatch) {
            try mismatchExecutor.execute(contextMismatch.plan)
        }
        #expect(mismatchRecorder.authorities.isEmpty)
    }
}

private struct ExecutorFixture {
    static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"

    let plaintext: String
    let vaultKey: Data
    let entryData: Data
    let trusted: V3TrustedManifest
    let plan: V3AuthenticatedReadPlan

    init(
        plaintext: String = "correct horse battery staple",
        nonceByte: UInt8 = 0xA0,
        sealedName: String = "mail/personal",
        manifestName: String? = nil,
        objectData: Data? = nil,
        stale: Bool = false
    ) throws {
        let vaultKey = Data(0..<32)
        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: Self.vaultID
        )
        let context = try V3EntryAuthenticationContext(
            vaultID: Self.vaultID,
            entryID: Self.entryID,
            name: sealedName,
            type: .secret,
            keyID: keyID,
            revision: 1
        )
        let sealed = try V3EntryCipher().seal(
            Data(plaintext.utf8),
            context: context,
            vaultKey: vaultKey,
            nonce: AES.GCM.Nonce(
                data: Data(repeating: nonceByte, count: 12)
            )
        )
        let storedData = objectData ?? sealed.canonicalBytes
        let digest = Base64URL.encode(
            Data(SHA256.hash(data: storedData))
        )
        let manifestEntry = V3ManifestEntry(
            entryID: Self.entryID,
            name: manifestName ?? sealedName,
            type: .secret,
            revision: 1,
            keyID: keyID,
            ciphertextDigest: digest
        )
        let manifest = Self.manifest(entry: manifestEntry)
        let trusted = V3TrustedManifest(
            verifiedManifest: manifest,
            checkpoint: try V3ManifestCheckpoint(
                verifiedManifest: manifest
            )
        )
        let classification = V3VaultRepositoryClassification(
            status: stale ? .incomplete : .ready,
            heads: [try V3VaultHead(verifiedManifest: manifest)],
            issues: stale ? [.manifestDirectoryUnavailable] : [],
            ancestryProof: stale
                ? nil
                : V3ManifestAncestryProof(
                    checkpoint: trusted.checkpoint,
                    manifests: [manifest],
                    heads: [manifest]
                )
        )

        self.plaintext = plaintext
        self.vaultKey = vaultKey
        entryData = storedData
        self.trusted = trusted
        plan = try V3AuthenticatedReadPlanner().planRead(
            named: manifestEntry.name,
            allowStale: stale,
            classification: classification,
            trustedCurrent: trusted
        )
    }

    private static func manifest(
        entry: V3ManifestEntry
    ) -> V3VerifiedManifest {
        let content = V3ManifestContent(
            parents: [],
            manifest: V3ManifestBody(
                vaultID: vaultID,
                mode: .local,
                keyID: entry.keyID,
                devices: [],
                wrappedKeys: [],
                entries: [entry]
            )
        )
        return V3VerifiedManifest(
            envelope: V3ManifestEnvelope(
                content: content,
                authentication: V3ManifestAuthentication(
                    tag: String(repeating: "A", count: 43)
                ),
                authorizations: [],
                canonicalBytes: Data(repeating: 0x44, count: 32),
                canonicalContentBytes: Data(repeating: 0x45, count: 32)
            ),
            envelopeDigest: Data(repeating: 0x46, count: 32)
        )
    }
}

private struct SingleEntryReadSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    let expectedEntryID: String
    let expectedDigest: Data
    let result: V3RepositoryObjectRead

    func manifestDigests(
        maximumCount _: Int
    ) throws -> V3RepositoryDirectoryListing {
        .available(digests: [], objectCount: 0)
    }

    func readManifest(
        digest _: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        .unavailable
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        #expect(entryID == expectedEntryID)
        #expect(digest == expectedDigest)
        return result
    }
}

private func authorityValidator(
    for authority: V3ReadAuthority,
    recorder: ReadAuthorityRecorder? = nil,
    currentOverride: V3ExpectedRepositoryState? = nil,
    checkpointOverride: V3ManifestCheckpoint? = nil
) -> V3ReadAuthorityValidator {
    let expectedCurrent: V3ExpectedRepositoryState?
    let expectedCheckpoint: V3ManifestCheckpoint?
    switch authority {
    case let .current(state):
        expectedCurrent = state
        expectedCheckpoint = nil
    case let .lastTrusted(checkpoint):
        expectedCurrent = nil
        expectedCheckpoint = checkpoint
    }

    return V3ReadAuthorityValidator(
        currentStateProvider: { checkpoint in
            guard let expectedCurrent,
                  checkpoint == expectedCurrent.checkpoint
            else {
                throw V3AuthenticatedReadError.authorityChanged
            }
            recorder?.record(.current(expectedCurrent))
            return currentOverride ?? expectedCurrent
        },
        checkpointProvider: { vaultID in
            guard let expectedCheckpoint,
                  vaultID == expectedCheckpoint.vaultID
            else {
                throw V3AuthenticatedReadError.authorityChanged
            }
            recorder?.record(.lastTrusted(expectedCheckpoint))
            return checkpointOverride ?? expectedCheckpoint
        }
    )
}

private final class ReadAuthorityRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storedAuthorities: [V3ReadAuthority] = []

    var authorities: [V3ReadAuthority] {
        lock.withLock { storedAuthorities }
    }

    func record(_ authority: V3ReadAuthority) {
        lock.withLock {
            storedAuthorities.append(authority)
        }
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue = 0

    var value: Int {
        lock.withLock { storedValue }
    }

    func increment() {
        lock.withLock {
            storedValue += 1
        }
    }
}
