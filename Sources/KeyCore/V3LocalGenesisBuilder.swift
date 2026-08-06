import Foundation
internal import JSONCanonicalization

struct V3LocalMigrationCandidate: Sendable {
    struct Entry: Sendable {
        let source: V2MigrationSourceEntry
        let manifestEntry: V3ManifestEntry
        let encryptedEntry: V3EncryptedEntry
        let digest: Data
    }

    let vaultID: String
    let manifestData: Data
    let verifiedManifest: V3VerifiedManifest
    let entries: [Entry]
}

/// Pure construction of an authenticated local-mode v3 genesis candidate.
/// Publication, checkpointing, and device selection remain the migration
/// service's responsibility.
struct V3LocalGenesisBuilder: Sendable {
    private let authenticator = V3ManifestAuthenticator()
    private let entryCipher = V3EntryCipher()

    func build(
        vaultID: String,
        entryIDs: [String],
        sourceEntries: [V2MigrationSourceEntry],
        vaultKey: Data
    ) throws -> V3LocalMigrationCandidate {
        guard isValidV3UUID(vaultID),
              entryIDs.count == sourceEntries.count,
              entryIDs.allSatisfy(isValidV3UUID)
        else {
            throw V3LocalMigrationError.invalidGeneratedIdentity
        }
        guard Set(entryIDs).count == entryIDs.count else {
            throw V3LocalMigrationError.duplicateGeneratedIdentity
        }

        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        var entries: [V3LocalMigrationCandidate.Entry] = []
        entries.reserveCapacity(sourceEntries.count)

        for (source, entryID) in zip(sourceEntries, entryIDs) {
            let context = try V3EntryAuthenticationContext(
                vaultID: vaultID,
                entryID: entryID,
                name: source.name,
                type: source.type,
                keyID: keyID,
                revision: 1
            )
            let encrypted = try entryCipher.seal(
                source.plaintext,
                context: context,
                vaultKey: vaultKey
            )
            let manifestEntry = V3ManifestEntry(
                entryID: entryID,
                name: source.name,
                type: source.type,
                revision: 1,
                keyID: keyID,
                ciphertextDigest: encrypted.ciphertextDigest
            )
            guard let digest = Base64URL.decodeCanonical(
                encrypted.ciphertextDigest
            ) else {
                throw V3EncryptedEntryError.digestMismatch
            }
            entries.append(V3LocalMigrationCandidate.Entry(
                source: source,
                manifestEntry: manifestEntry,
                encryptedEntry: encrypted,
                digest: digest
            ))
        }

        entries.sort {
            v3ManifestEntryPrecedes(
                $0.manifestEntry,
                $1.manifestEntry
            )
        }

        let entryValues = entries.map { entry in
            let value = entry.manifestEntry
            return CanonicalJSONValue.object([
                ("entryID", .string(value.entryID)),
                ("name", .string(value.name)),
                ("type", .string(value.type.rawValue)),
                ("revision", .integer(value.revision)),
                ("keyID", .string(value.keyID.rawValue)),
                (
                    "ciphertextDigest",
                    .string(value.ciphertextDigest)
                )
            ])
        }
        let content = CanonicalJSONValue.object([
            ("parents", .array([])),
            ("manifest", .object([
                ("format", .string("key-vault-manifest")),
                ("version", .integer(3)),
                ("vaultID", .string(vaultID)),
                ("mode", .string(V3VaultMode.local.rawValue)),
                ("keyID", .string(keyID.rawValue)),
                ("devices", .array([])),
                ("wrappedKeys", .array([])),
                ("entries", .array(entryValues))
            ]))
        ])
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: CanonicalJSON.encode(content),
            vaultID: vaultID,
            vaultKey: vaultKey
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                (
                    "algorithm",
                    .string("HKDF-SHA256+HMAC-SHA256")
                ),
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array([]))
        ]))
        let verified = try authenticator.verify(
            manifestData,
            vaultKey: vaultKey,
            trustAnchor: .localGenesis(vaultID: vaultID)
        )
        return V3LocalMigrationCandidate(
            vaultID: vaultID,
            manifestData: manifestData,
            verifiedManifest: verified,
            entries: entries
        )
    }
}
