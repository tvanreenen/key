import CryptoKit
import Foundation
import JSONCanonicalization
import Testing
@testable import KeyCore

struct V3EntryCipherTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let key = Data(0..<32)
    private static let nonce = Data(0xA0...0xAB)
    private static let keyID = try! V3VaultKeyID.derive(
        vaultKey: key,
        vaultID: vaultID
    )
    private static let alternateKeyID = try! V3VaultKeyID.derive(
        vaultKey: Data(repeating: 0xFF, count: 32),
        vaultID: vaultID
    )

    @Test
    func deterministicSealMatchesExactVectorAndOpens() throws {
        let context = try makeContext()
        let entry = try V3EntryCipher().seal(
            Data("correct horse battery staple".utf8),
            context: context,
            vaultKey: Self.key,
            nonce: try AES.GCM.Nonce(data: Self.nonce)
        )
        let expected = Data(#"{"encryption":{"algorithm":"AES-256-GCM","ciphertext":"hXcOXyCodp8KCvWgYlqivwTYPGLrlzEY_X5K4w","nonce":"oKGio6Slpqeoqaqr","tag":"ZPuWt7iIjJEoK-GOTrPxPQ"},"entryID":"018f4d39-930c-735d-8d6f-588e9b0a3a48","format":"key-vault-entry","keyID":"YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA","name":"email/personal","revision":4,"type":"secret","vaultID":"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3","version":3}"#.utf8)

        #expect(entry.canonicalBytes == expected)
        #expect(entry.ciphertextDigest == "J4YmO39caeVQKdVeSrURsou9fYnj7DY0QEz-lGTJPUE")
        #expect(try open(entry, context: context) == "correct horse battery staple")
    }

    @Test
    func randomSealRoundTripsSecretTOTPAndEmptyPlaintext() throws {
        let cipher = V3EntryCipher()
        let cases: [(String, V3EntryAuthenticationContext)] = try [
            ("sëcret\nvalue", makeContext()),
            ("JBSWY3DPEHPK3PXP", makeContext(type: .totp)),
            ("", makeContext(name: "empty"))
        ]

        for (plaintext, context) in cases {
            let entry = try cipher.seal(plaintext, context: context, vaultKey: Self.key)

            #expect(entry.nonce.count == 12)
            #expect(entry.tag.count == 16)
            #expect(try open(entry, context: context) == plaintext)
        }
    }

    @Test
    func everyBoundFieldIsCryptographicallyAuthenticated() throws {
        let originalContext = try makeContext()
        let original = try deterministicEntry(context: originalContext)
        let alternateVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
        let alternateVaultKeyID = try V3VaultKeyID.derive(
            vaultKey: Self.key,
            vaultID: alternateVaultID
        )
        let substitutions = try [
            makeContext(vaultID: alternateVaultID, keyID: alternateVaultKeyID),
            makeContext(entryID: "018f4d39-930c-735d-8d6f-588e9b0a3a49"),
            makeContext(name: "email/work"),
            makeContext(type: .totp),
            makeContext(revision: 5)
        ]

        for substitutedContext in substitutions {
            let substitutedData = entryData(
                context: substitutedContext,
                nonce: original.nonce,
                ciphertext: original.ciphertext,
                tag: original.tag
            )
            let manifestEntry = manifestEntry(
                context: substitutedContext,
                digest: digest(of: substitutedData)
            )

            #expect(throws: V3EncryptedEntryError.authenticationFailed) {
                _ = try V3EntryCipher().openTrusted(
                    substitutedData,
                    vaultID: substitutedContext.vaultID,
                    manifestEntry: manifestEntry,
                    vaultKey: Self.key
                )
            }
        }

        let substitutedKeyContext = try makeContext(keyID: Self.alternateKeyID)
        let substitutedKeyData = entryData(
            context: substitutedKeyContext,
            nonce: original.nonce,
            ciphertext: original.ciphertext,
            tag: original.tag
        )
        #expect(throws: V3EncryptedEntryError.keyIdentityMismatch) {
            _ = try V3EntryCipher().openTrusted(
                substitutedKeyData,
                vaultID: substitutedKeyContext.vaultID,
                manifestEntry: manifestEntry(
                    context: substitutedKeyContext,
                    digest: digest(of: substitutedKeyData)
                ),
                vaultKey: Self.key
            )
        }
    }

    @Test
    func manifestIdentityMismatchFailsBeforeDecryption() throws {
        let context = try makeContext()
        let entry = try deterministicEntry(context: context)
        let differentContext = try makeContext(name: "email/work")
        let manifestEntry = manifestEntry(
            context: differentContext,
            digest: entry.ciphertextDigest
        )

        #expect(throws: V3EncryptedEntryError.contextMismatch) {
            _ = try V3EntryCipher().openTrusted(
                entry.canonicalBytes,
                vaultID: differentContext.vaultID,
                manifestEntry: manifestEntry,
                vaultKey: Self.key
            )
        }
    }

    @Test
    func authenticatedHistoricalAndForkedEntriesReturnExplicitReplayErrors() throws {
        let cipher = V3EntryCipher()
        let currentContext = try makeContext(revision: 5)
        let current = try cipher.seal(
            Data("current".utf8),
            context: currentContext,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Data(0xB0...0xBB))
        )
        let manifest = trustedManifest(
            context: currentContext,
            digest: current.ciphertextDigest
        )

        let historicalContext = try makeContext(revision: 4)
        let historical = try cipher.seal(
            Data("historical".utf8),
            context: historicalContext,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Data(0xC0...0xCB))
        )
        #expect(throws: V3EncryptedEntryError.replayedRevision(
            trustedRevision: 5,
            observedRevision: 4
        )) {
            _ = try cipher.open(
                historical.canonicalBytes,
                trustedManifest: manifest,
                entryID: Self.entryID,
                vaultKey: Self.key
            )
        }

        let fork = try cipher.seal(
            Data("fork".utf8),
            context: currentContext,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Data(0xD0...0xDB))
        )
        #expect(throws: V3EncryptedEntryError.conflictingRevision(
            trustedRevision: 5,
            observedRevision: 5
        )) {
            _ = try cipher.open(
                fork.canonicalBytes,
                trustedManifest: manifest,
                entryID: Self.entryID,
                vaultKey: Self.key
            )
        }
    }

    @Test
    func digestMismatchClassificationRequiresAnHonestObservedKeyID() throws {
        let currentContext = try makeContext(revision: 5)
        let current = try V3EntryCipher().seal(
            Data("current".utf8),
            context: currentContext,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Data(0xB0...0xBB))
        )
        let dishonestContext = try makeContext(
            keyID: Self.alternateKeyID,
            revision: 4
        )
        let sealed = try AES.GCM.seal(
            Data("historical".utf8),
            using: SymmetricKey(data: Self.key),
            nonce: AES.GCM.Nonce(data: Data(0xC0...0xCB)),
            authenticating: dishonestContext.associatedData
        )
        let dishonestData = entryData(
            context: dishonestContext,
            nonce: Data(0xC0...0xCB),
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )

        #expect(throws: V3EncryptedEntryError.digestMismatch) {
            _ = try V3EntryCipher().openTrusted(
                dishonestData,
                vaultID: Self.vaultID,
                manifestEntry: manifestEntry(
                    context: currentContext,
                    digest: current.ciphertextDigest
                ),
                vaultKey: Self.key
            )
        }
    }

    @Test
    func nonceCiphertextAndTagTamperingFailAuthentication() throws {
        let context = try makeContext()
        let original = try deterministicEntry(context: context)
        let tamperedComponents: [(Data, Data, Data)] = [
            (flippingFirstBit(of: original.nonce), original.ciphertext, original.tag),
            (original.nonce, flippingFirstBit(of: original.ciphertext), original.tag),
            (original.nonce, original.ciphertext, flippingFirstBit(of: original.tag))
        ]

        for (nonce, ciphertext, tag) in tamperedComponents {
            let data = entryData(
                context: context,
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag
            )
            let manifestEntry = manifestEntry(context: context, digest: digest(of: data))

            #expect(throws: V3EncryptedEntryError.authenticationFailed) {
                _ = try V3EntryCipher().openTrusted(
                    data,
                    vaultID: context.vaultID,
                    manifestEntry: manifestEntry,
                    vaultKey: Self.key
                )
            }
        }
    }

    @Test
    func wrongKeyDigestAndTrustedContextFailClosed() throws {
        let context = try makeContext()
        let entry = try deterministicEntry(context: context)

        #expect(throws: V3EncryptedEntryError.invalidVaultKey) {
            _ = try V3EntryCipher().openTrusted(
                entry.canonicalBytes,
                vaultID: context.vaultID,
                manifestEntry: manifestEntry(context: context, digest: "not-base64url"),
                vaultKey: Data(repeating: 0, count: 31)
            )
        }
        #expect(throws: V3EncryptedEntryError.conflictingRevision(
            trustedRevision: 4,
            observedRevision: 4
        )) {
            _ = try V3EntryCipher().openTrusted(
                entry.canonicalBytes,
                vaultID: context.vaultID,
                manifestEntry: manifestEntry(
                    context: context,
                    digest: encodeTestBase64URL(Data(repeating: 0, count: 32))
                ),
                vaultKey: Self.key
            )
        }
        #expect(throws: V3EncryptedEntryError.invalidTrustedContext) {
            _ = try V3EntryCipher().openTrusted(
                entry.canonicalBytes,
                vaultID: context.vaultID,
                manifestEntry: manifestEntry(context: context, digest: "not-base64url"),
                vaultKey: Self.key
            )
        }
        #expect(throws: V3EncryptedEntryError.invalidTrustedContext) {
            _ = try V3EntryCipher().openTrusted(
                entry.canonicalBytes,
                vaultID: context.vaultID.uppercased(),
                manifestEntry: manifestEntry(context: context, digest: entry.ciphertextDigest),
                vaultKey: Self.key
            )
        }
        #expect(throws: V3EncryptedEntryError.keyIdentityMismatch) {
            _ = try V3EntryCipher().openTrusted(
                entry.canonicalBytes,
                vaultID: context.vaultID,
                manifestEntry: manifestEntry(context: context, digest: entry.ciphertextDigest),
                vaultKey: Data(repeating: 0xFF, count: 32)
            )
        }
    }

    @Test
    func parserRejectsNoncanonicalDuplicateUnknownAndUnsupportedJSON() throws {
        let entry = try deterministicEntry(context: makeContext())
        let canonical = String(decoding: entry.canonicalBytes, as: UTF8.self)
        let duplicate = canonical.replacingOccurrences(
            of: #"{"encryption":"#,
            with: #"{"format":"key-vault-entry","encryption":"#
        )
        let unknown = canonical.replacingOccurrences(
            of: #"{"encryption":"#,
            with: #"{"extra":null,"encryption":"#
        )

        #expect(throws: V3EncryptedEntryError.nonCanonicalJSON) {
            _ = try V3EntryCipher().parse(Data((" " + canonical).utf8))
        }
        #expect(throws: V3EncryptedEntryError.duplicateProperty) {
            _ = try V3EntryCipher().parse(Data(duplicate.utf8))
        }
        #expect(throws: V3EncryptedEntryError.invalidStructure("$")) {
            _ = try V3EntryCipher().parse(Data(unknown.utf8))
        }
        #expect(throws: V3EncryptedEntryError.invalidStructure("$.version")) {
            _ = try V3EntryCipher().parse(
                Data(canonical.replacingOccurrences(of: #""version":3"#, with: #""version":4"#).utf8)
            )
        }
        #expect(throws: V3EncryptedEntryError.invalidStructure("$.encryption.algorithm")) {
            _ = try V3EntryCipher().parse(
                Data(canonical.replacingOccurrences(of: "AES-256-GCM", with: "AES.GCM").utf8)
            )
        }
        #expect(throws: V3EncryptedEntryError.invalidStructure("$")) {
            _ = try V3EntryCipher().parse(Data(
                canonical.replacingOccurrences(
                    of: #""keyID":"\#(Self.keyID.rawValue)""#,
                    with: #""keyEpoch":3"#
                ).utf8
            ))
        }
    }

    @Test
    func parserRejectsMalformedBase64URLAndInvalidComponentLengths() throws {
        let entry = try deterministicEntry(context: makeContext())
        let canonical = String(decoding: entry.canonicalBytes, as: UTF8.self)
        let nonce = encodeTestBase64URL(entry.nonce)
        let ciphertext = encodeTestBase64URL(entry.ciphertext)
        let tag = encodeTestBase64URL(entry.tag)
        let malformedDocuments: [(String, String)] = [
            (
                canonical.replacingOccurrences(of: #""nonce":"\#(nonce)""#, with: #""nonce":"AA""#),
                "$.encryption.nonce"
            ),
            (
                canonical.replacingOccurrences(
                    of: #""ciphertext":"\#(ciphertext)""#,
                    with: #""ciphertext":"\#(ciphertext)=""#
                ),
                "$.encryption.ciphertext"
            ),
            (
                canonical.replacingOccurrences(of: #""tag":"\#(tag)""#, with: #""tag":"AA""#),
                "$.encryption.tag"
            )
        ]

        for (document, path) in malformedDocuments {
            #expect(throws: V3EncryptedEntryError.invalidStructure(path)) {
                _ = try V3EntryCipher().parse(Data(document.utf8))
            }
        }
    }

    @Test
    func invalidUTF8PlaintextIsNotReleased() throws {
        let context = try makeContext()
        let entry = try V3EntryCipher().seal(
            Data([0xFF]),
            context: context,
            vaultKey: Self.key,
            nonce: try AES.GCM.Nonce(data: Self.nonce)
        )

        #expect(throws: V3EncryptedEntryError.invalidPlaintext) {
            _ = try open(entry, context: context)
        }
    }

    @Test
    func publicOpenRequiresAndSelectsFromTrustedManifest() throws {
        let context = try makeContext()
        let entry = try deterministicEntry(context: context)
        let manifest = trustedManifest(
            context: context,
            digest: entry.ciphertextDigest
        )

        #expect(
            try V3EntryCipher().open(
                entry.canonicalBytes,
                trustedManifest: manifest,
                entryID: context.entryID,
                vaultKey: Self.key
            ) == "correct horse battery staple"
        )
        #expect(throws: V3EncryptedEntryError.manifestEntryNotFound) {
            _ = try V3EntryCipher().open(
                entry.canonicalBytes,
                trustedManifest: manifest,
                entryID: "018f4d39-930c-735d-8d6f-588e9b0a3a49",
                vaultKey: Self.key
            )
        }
    }

    private func deterministicEntry(
        context: V3EntryAuthenticationContext
    ) throws -> V3EncryptedEntry {
        try V3EntryCipher().seal(
            Data("correct horse battery staple".utf8),
            context: context,
            vaultKey: Self.key,
            nonce: AES.GCM.Nonce(data: Self.nonce)
        )
    }

    private func open(
        _ entry: V3EncryptedEntry,
        context: V3EntryAuthenticationContext
    ) throws -> String {
        try V3EntryCipher().openTrusted(
            entry.canonicalBytes,
            vaultID: context.vaultID,
            manifestEntry: manifestEntry(context: context, digest: entry.ciphertextDigest),
            vaultKey: Self.key
        )
    }

    private func makeContext(
        vaultID: String = V3EntryCipherTests.vaultID,
        entryID: String = V3EntryCipherTests.entryID,
        name: String = "email/personal",
        type: SecretEntryType = .secret,
        keyID: V3VaultKeyID = V3EntryCipherTests.keyID,
        revision: UInt64 = 4
    ) throws -> V3EntryAuthenticationContext {
        try V3EntryAuthenticationContext(
            vaultID: vaultID,
            entryID: entryID,
            name: name,
            type: type,
            keyID: keyID,
            revision: revision
        )
    }

    private func manifestEntry(
        context: V3EntryAuthenticationContext,
        digest: String
    ) -> V3ManifestEntry {
        V3ManifestEntry(
            entryID: context.entryID,
            name: context.name,
            type: context.type,
            revision: context.revision,
            keyID: context.keyID,
            ciphertextDigest: digest
        )
    }

    private func trustedManifest(
        context: V3EntryAuthenticationContext,
        digest: String
    ) -> V3TrustedManifest {
        let body = V3ManifestBody(
            vaultID: context.vaultID,
            mode: .local,
            keyID: context.keyID,
            devices: [],
            wrappedKeys: [],
            entries: [manifestEntry(context: context, digest: digest)]
        )
        let envelope = V3ManifestEnvelope(
            content: V3ManifestContent(parent: .genesis, manifest: body),
            authentication: V3ManifestAuthentication(
                keyID: context.keyID,
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
            vaultID: context.vaultID,
            envelopeDigest: envelopeDigest
        )
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: checkpoint
        )
    }

    private func entryData(
        context: V3EntryAuthenticationContext,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) -> Data {
        CanonicalJSON.encode(.object([
            ("format", .string("key-vault-entry")),
            ("version", .integer(3)),
            ("vaultID", .string(context.vaultID)),
            ("entryID", .string(context.entryID)),
            ("name", .string(context.name)),
            ("type", .string(context.type.rawValue)),
            ("keyID", .string(context.keyID.rawValue)),
            ("revision", .integer(context.revision)),
            ("encryption", .object([
                ("algorithm", .string("AES-256-GCM")),
                ("nonce", .string(encodeTestBase64URL(nonce))),
                ("ciphertext", .string(encodeTestBase64URL(ciphertext))),
                ("tag", .string(encodeTestBase64URL(tag)))
            ]))
        ]))
    }

    private func digest(of data: Data) -> String {
        encodeTestBase64URL(Data(SHA256.hash(data: data)))
    }

    private func flippingFirstBit(of data: Data) -> Data {
        var result = data
        result[result.startIndex] ^= 1
        return result
    }
}

private func encodeTestBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
