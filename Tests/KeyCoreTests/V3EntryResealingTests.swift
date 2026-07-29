import CryptoKit
import Foundation
import Testing
@testable import KeyCore

struct V3EntryResealingTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let sourceEntryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let destinationEntryID = "018f4d3a-a844-72ad-983e-b09a8fc0e924"
    private static let otherEntryID = "018f4d3b-033d-770e-a63c-ddb280e24d1f"
    private static let key = Data(0..<32)
    private static let sourceNonce = Data(0xA0...0xAB)
    private static let destinationNonce = Data(0xB0...0xBB)

    @Test
    func copyCreatesNewIdentityAtRevisionOneAndReseals() throws {
        let fixture = try makeFixture(type: .totp)
        let result = try V3EntryCipher().copy(
            fixture.entry.canonicalBytes,
            trustedManifest: fixture.manifest,
            sourceEntryID: Self.sourceEntryID,
            destinationEntryID: Self.destinationEntryID,
            destinationName: "email/copied",
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Self.destinationNonce)
        )

        #expect(result.encryptedEntry.context.vaultID == Self.vaultID)
        #expect(result.encryptedEntry.context.entryID == Self.destinationEntryID)
        #expect(result.encryptedEntry.context.name == "email/copied")
        #expect(result.encryptedEntry.context.type == .totp)
        #expect(result.encryptedEntry.context.keyEpoch == 3)
        #expect(result.encryptedEntry.context.revision == 1)
        #expect(result.encryptedEntry.nonce == Self.destinationNonce)
        #expect(result.encryptedEntry.canonicalBytes != fixture.entry.canonicalBytes)
        #expect(result.encryptedEntry.ciphertext != fixture.entry.ciphertext)
        #expect(result.manifestEntry == manifestEntry(for: result.encryptedEntry))

        let targetManifest = trustedManifest(entries: [result.manifestEntry])
        #expect(
            try V3EntryCipher().open(
                result.encryptedEntry.canonicalBytes,
                trustedManifest: targetManifest,
                entryID: Self.destinationEntryID,
                vaultKey: Self.key
            ) == "JBSWY3DPEHPK3PXP"
        )
    }

    @Test
    func renamePreservesIdentityAndAdvancesRevision() throws {
        let fixture = try makeFixture()
        let result = try V3EntryCipher().rename(
            fixture.entry.canonicalBytes,
            trustedManifest: fixture.manifest,
            sourceEntryID: Self.sourceEntryID,
            destinationName: "email/renamed",
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Self.destinationNonce)
        )

        #expect(result.encryptedEntry.context.entryID == Self.sourceEntryID)
        #expect(result.encryptedEntry.context.name == "email/renamed")
        #expect(result.encryptedEntry.context.type == .secret)
        #expect(result.encryptedEntry.context.keyEpoch == 3)
        #expect(result.encryptedEntry.context.revision == 5)
        #expect(result.encryptedEntry.nonce == Self.destinationNonce)
        #expect(result.encryptedEntry.canonicalBytes != fixture.entry.canonicalBytes)
        #expect(result.manifestEntry == manifestEntry(for: result.encryptedEntry))

        let targetManifest = trustedManifest(entries: [result.manifestEntry])
        #expect(
            try V3EntryCipher().open(
                result.encryptedEntry.canonicalBytes,
                trustedManifest: targetManifest,
                entryID: Self.sourceEntryID,
                vaultKey: Self.key
            ) == "correct horse battery staple"
        )
        #expect(throws: V3EncryptedEntryError.replayedRevision(
            trustedRevision: 5,
            observedRevision: 4
        )) {
            _ = try V3EntryCipher().open(
                fixture.entry.canonicalBytes,
                trustedManifest: targetManifest,
                entryID: Self.sourceEntryID,
                vaultKey: Self.key
            )
        }
    }

    @Test
    func publicCopyAllocatesANewCanonicalEntryID() throws {
        let fixture = try makeFixture()
        let result = try V3EntryCipher().copy(
            fixture.entry.canonicalBytes,
            trustedManifest: fixture.manifest,
            sourceEntryID: Self.sourceEntryID,
            destinationName: "email/generated-copy",
            vaultKey: Self.key
        )

        #expect(result.encryptedEntry.context.entryID != Self.sourceEntryID)
        #expect(
            UUID(uuidString: result.encryptedEntry.context.entryID)?.uuidString.lowercased()
                == result.encryptedEntry.context.entryID
        )
        #expect(result.encryptedEntry.context.revision == 1)
    }

    @Test
    func copyRejectsInvalidOrCollidingDestinationIdentity() throws {
        let fixture = try makeFixture(
            additionalEntries: [
                V3ManifestEntry(
                    entryID: Self.otherEntryID,
                    name: "email/existing",
                    type: .secret,
                    revision: 2,
                    keyEpoch: 3,
                    ciphertextDigest: String(repeating: "A", count: 43)
                )
            ]
        )
        let cipher = V3EntryCipher()
        let nonce = try AES.GCM.Nonce(data: Self.destinationNonce)

        #expect(throws: V3EntryResealingError.invalidDestinationEntryID) {
            _ = try cipher.copy(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationEntryID: "not-an-entry-id",
                destinationName: "email/copied",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
        #expect(throws: V3EntryResealingError.invalidDestinationName) {
            _ = try cipher.copy(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationEntryID: Self.destinationEntryID,
                destinationName: "../escape",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
        #expect(throws: V3EntryResealingError.destinationEntryIDExists) {
            _ = try cipher.copy(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationEntryID: Self.otherEntryID,
                destinationName: "email/copied",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
        #expect(throws: V3EntryResealingError.destinationNameExists) {
            _ = try cipher.copy(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationEntryID: Self.destinationEntryID,
                destinationName: "email/existing",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
    }

    @Test
    func renameRejectsNoOpCollisionInvalidNameAndRevisionOverflow() throws {
        let fixture = try makeFixture(
            additionalEntries: [
                V3ManifestEntry(
                    entryID: Self.otherEntryID,
                    name: "email/existing",
                    type: .secret,
                    revision: 2,
                    keyEpoch: 3,
                    ciphertextDigest: String(repeating: "A", count: 43)
                )
            ]
        )
        let cipher = V3EntryCipher()
        let nonce = try AES.GCM.Nonce(data: Self.destinationNonce)

        #expect(throws: V3EntryResealingError.unchangedName) {
            _ = try cipher.rename(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationName: "email/personal",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
        #expect(throws: V3EntryResealingError.destinationNameExists) {
            _ = try cipher.rename(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationName: "email/existing",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
        #expect(throws: V3EntryResealingError.invalidDestinationName) {
            _ = try cipher.rename(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationName: "cafe\u{301}",
                vaultKey: Self.key,
                nonce: nonce
            )
        }

        let overflowEntry = V3ManifestEntry(
            entryID: Self.sourceEntryID,
            name: "email/personal",
            type: .secret,
            revision: 9_007_199_254_740_991,
            keyEpoch: 3,
            ciphertextDigest: fixture.entry.ciphertextDigest
        )
        #expect(throws: V3EntryResealingError.revisionOverflow) {
            _ = try cipher.rename(
                fixture.entry.canonicalBytes,
                trustedManifest: trustedManifest(entries: [overflowEntry]),
                sourceEntryID: Self.sourceEntryID,
                destinationName: "email/renamed",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
    }

    @Test
    func resealingAuthenticatesSourceBeforeProducingDestination() throws {
        let fixture = try makeFixture()
        var tampered = fixture.entry.canonicalBytes
        tampered[tampered.index(before: tampered.endIndex)] ^= 1
        let cipher = V3EntryCipher()
        let nonce = try AES.GCM.Nonce(data: Self.destinationNonce)

        #expect(throws: V3EncryptedEntryError.digestMismatch) {
            _ = try cipher.copy(
                tampered,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationEntryID: Self.destinationEntryID,
                destinationName: "email/copied",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
        #expect(throws: V3EncryptedEntryError.authenticationFailed) {
            _ = try cipher.rename(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.sourceEntryID,
                destinationName: "email/renamed",
                vaultKey: Data(repeating: 0xFF, count: 32),
                nonce: nonce
            )
        }
        #expect(throws: V3EncryptedEntryError.manifestEntryNotFound) {
            _ = try cipher.copy(
                fixture.entry.canonicalBytes,
                trustedManifest: fixture.manifest,
                sourceEntryID: Self.otherEntryID,
                destinationEntryID: Self.destinationEntryID,
                destinationName: "email/copied",
                vaultKey: Self.key,
                nonce: nonce
            )
        }
    }

    @Test
    func resealingPreservesExactValidUTF8Bytes() throws {
        let context = try V3EntryAuthenticationContext(
            vaultID: Self.vaultID,
            entryID: Self.sourceEntryID,
            name: "unicode/value",
            type: .secret,
            keyEpoch: 3,
            revision: 1
        )
        let plaintext = Data("cafe\u{301}".utf8)
        let source = try V3EntryCipher().seal(
            plaintext,
            context: context,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Self.sourceNonce)
        )
        let sourceRecord = manifestEntry(for: source)
        let result = try V3EntryCipher().copy(
            source.canonicalBytes,
            trustedManifest: trustedManifest(entries: [sourceRecord]),
            sourceEntryID: Self.sourceEntryID,
            destinationEntryID: Self.destinationEntryID,
            destinationName: "unicode/copied",
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Self.destinationNonce)
        )

        let openedBytes = try V3EntryCipher().openPlaintextDataTrusted(
            result.encryptedEntry.canonicalBytes,
            vaultID: Self.vaultID,
            manifestEntry: result.manifestEntry,
            vaultKey: Self.key
        )
        #expect(openedBytes == plaintext)
    }

    private func makeFixture(
        type: SecretEntryType = .secret,
        additionalEntries: [V3ManifestEntry] = []
    ) throws -> (
        entry: V3EncryptedEntry,
        manifest: V3TrustedManifest
    ) {
        let context = try V3EntryAuthenticationContext(
            vaultID: Self.vaultID,
            entryID: Self.sourceEntryID,
            name: "email/personal",
            type: type,
            keyEpoch: 3,
            revision: 4
        )
        let plaintext = type == .totp
            ? "JBSWY3DPEHPK3PXP"
            : "correct horse battery staple"
        let entry = try V3EntryCipher().seal(
            Data(plaintext.utf8),
            context: context,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Self.sourceNonce)
        )
        let entries = [manifestEntry(for: entry)] + additionalEntries
        return (entry, trustedManifest(entries: entries))
    }

    private func manifestEntry(for entry: V3EncryptedEntry) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: entry.context.entryID,
            name: entry.context.name,
            type: entry.context.type,
            revision: entry.context.revision,
            keyEpoch: entry.context.keyEpoch,
            ciphertextDigest: entry.ciphertextDigest
        )
    }

    private func trustedManifest(entries: [V3ManifestEntry]) -> V3TrustedManifest {
        let body = V3ManifestBody(
            vaultID: Self.vaultID,
            mode: .local,
            keyEpoch: 3,
            devices: [],
            wrappedKeys: [],
            entries: entries
        )
        let envelope = V3ManifestEnvelope(
            content: V3ManifestContent(parent: .genesis, manifest: body),
            authentication: V3ManifestAuthentication(
                keyEpoch: 3,
                tag: String(repeating: "A", count: 43)
            ),
            authorizations: [],
            canonicalBytes: Data(),
            canonicalContentBytes: Data()
        )
        let envelopeDigest = Data(repeating: 0xA5, count: 32)
        let verified = V3VerifiedManifest(
            envelope: envelope,
            envelopeDigest: envelopeDigest
        )
        let checkpoint = try! V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: envelopeDigest
        )
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: checkpoint
        )
    }
}
