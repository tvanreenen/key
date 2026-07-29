import Foundation
import Testing
@testable import KeyCore

struct V3EntryAuthenticationContextTests {
    private static let fixtureVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let fixtureEntryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    private static let fixtureKeyID = try! V3VaultKeyID(
        rawValue: String(repeating: "A", count: 43)
    )
    private static let alternateKeyID = try! V3VaultKeyID(
        rawValue: Base64URL.encode(Data(repeating: 1, count: 32))
    )

    @Test
    func canonicalContextAndAssociatedDataMatchExactVector() throws {
        let context = try makeContext()
        let canonical = Data(#"{"entryID":"018f4d39-930c-735d-8d6f-588e9b0a3a48","format":"key-vault-entry","keyID":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","name":"email/personal","revision":4,"type":"secret","vaultID":"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3","version":3}"#.utf8)
        var associatedData = Data("work.tvr.key/v3/entry-aad".utf8)
        associatedData.append(0)
        associatedData.append(canonical)

        #expect(context.canonicalBytes == canonical)
        #expect(context.associatedData == associatedData)
    }

    @Test
    func everyMutableIdentityFieldChangesAssociatedData() throws {
        let contexts = try [
            makeContext(),
            makeContext(vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"),
            makeContext(entryID: "018f4d39-930c-735d-8d6f-588e9b0a3a49"),
            makeContext(name: "email/work"),
            makeContext(type: .totp),
            makeContext(keyID: Self.alternateKeyID),
            makeContext(revision: 5)
        ]

        #expect(Set(contexts.map(\.associatedData)).count == contexts.count)
    }

    @Test
    func manifestEntryBuildsTheSameContext() throws {
        let entry = V3ManifestEntry(
            entryID: Self.fixtureEntryID,
            name: "email/personal",
            type: .secret,
            revision: 4,
            keyID: Self.fixtureKeyID,
            ciphertextDigest: String(repeating: "A", count: 43)
        )

        let fromEntry = try V3EntryAuthenticationContext(vaultID: Self.fixtureVaultID, entry: entry)
        let expected = try makeContext()

        #expect(fromEntry == expected)
    }

    @Test
    func contextRejectsInvalidIdentityValues() {
        #expect(throws: V3EntryAuthenticationContextError.invalidVaultID) {
            _ = try makeContext(vaultID: Self.fixtureVaultID.uppercased())
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidEntryID) {
            _ = try makeContext(entryID: "not-an-entry-id")
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidName) {
            _ = try makeContext(name: "../escape")
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidName) {
            _ = try makeContext(name: "cafe\u{301}")
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidRevision) {
            _ = try makeContext(revision: 0)
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidRevision) {
            _ = try makeContext(revision: 9_007_199_254_740_992)
        }
    }

    @Test
    func vaultKeyIDRejectsInvalidInputsAndIsVaultScoped() throws {
        #expect(throws: V3VaultKeyIDError.invalidEncoding) {
            _ = try V3VaultKeyID(rawValue: "not-a-key-id")
        }
        #expect(throws: V3VaultKeyIDError.invalidVaultKey) {
            _ = try V3VaultKeyID.derive(
                vaultKey: Data(repeating: 0, count: 31),
                vaultID: Self.fixtureVaultID
            )
        }
        #expect(throws: V3VaultKeyIDError.invalidVaultID) {
            _ = try V3VaultKeyID.derive(
                vaultKey: Data(0..<32),
                vaultID: "not-a-vault-id"
            )
        }

        let keyID = try V3VaultKeyID.derive(
            vaultKey: Data(0..<32),
            vaultID: Self.fixtureVaultID
        )
        let otherVaultID = try V3VaultKeyID.derive(
            vaultKey: Data(0..<32),
            vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
        )
        let otherKeyID = try V3VaultKeyID.derive(
            vaultKey: Data(repeating: 0xFF, count: 32),
            vaultID: Self.fixtureVaultID
        )

        #expect(keyID.rawValue == "YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA")
        #expect(keyID != otherVaultID)
        #expect(keyID != otherKeyID)
    }

    private func makeContext(
        vaultID: String = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        entryID: String = "018f4d39-930c-735d-8d6f-588e9b0a3a48",
        name: String = "email/personal",
        type: SecretEntryType = .secret,
        keyID: V3VaultKeyID = V3EntryAuthenticationContextTests.fixtureKeyID,
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
}
