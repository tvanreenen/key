import Foundation
import Testing
@testable import KeyCore

struct V3EntryAuthenticationContextTests {
    private static let fixtureVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let fixtureEntryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"

    @Test
    func canonicalContextAndAssociatedDataMatchExactVector() throws {
        let context = try makeContext()
        let canonical = Data(#"{"entryID":"018f4d39-930c-735d-8d6f-588e9b0a3a48","format":"key-vault-entry","keyEpoch":3,"name":"email/personal","revision":4,"type":"secret","vaultID":"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3","version":3}"#.utf8)
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
            makeContext(keyEpoch: 4),
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
            keyEpoch: 3,
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
        #expect(throws: V3EntryAuthenticationContextError.invalidKeyEpoch) {
            _ = try makeContext(keyEpoch: 9_007_199_254_740_992)
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidRevision) {
            _ = try makeContext(revision: 0)
        }
        #expect(throws: V3EntryAuthenticationContextError.invalidRevision) {
            _ = try makeContext(revision: 9_007_199_254_740_992)
        }
    }

    private func makeContext(
        vaultID: String = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        entryID: String = "018f4d39-930c-735d-8d6f-588e9b0a3a48",
        name: String = "email/personal",
        type: SecretEntryType = .secret,
        keyEpoch: UInt64 = 3,
        revision: UInt64 = 4
    ) throws -> V3EntryAuthenticationContext {
        try V3EntryAuthenticationContext(
            vaultID: vaultID,
            entryID: entryID,
            name: name,
            type: type,
            keyEpoch: keyEpoch,
            revision: revision
        )
    }
}
