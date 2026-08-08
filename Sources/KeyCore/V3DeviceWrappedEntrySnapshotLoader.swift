import CryptoKit
import Foundation

/// Reopens the complete encrypted entry snapshot named by one authenticated
/// permanent-profile manifest. Plaintext remains sealed here; the enrollment
/// builder opens and reseals it only while rotating between key epochs.
struct V3DeviceWrappedEntrySnapshotLoader: Sendable {
    private let source: any V3ImmutableObjectReading
    private let limits: V3ManifestRepositoryLimits
    private let entryCipher = V3EntryCipher()

    init(
        source: any V3ImmutableObjectReading,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.source = source
        self.limits = limits
    }

    func load(
        _ checkpoint: V3DeviceWrappedTrustedCheckpoint
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        let entries = checkpoint.envelope.body.entries
        guard entries.count <= limits.maximumReferencedEntryObjects else {
            throw V3ImmutableTransactionError.objectTooLarge
        }

        var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var totalBytes = 0
        for entry in entries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32 else {
                throw invalidEntry(entry, digest: Data())
            }
            let data: Data
            switch try source.readEntry(
                entryID: entry.entryID,
                digest: digest,
                maximumBytes: limits.maximumEntryBytes
            ) {
            case let .available(available):
                data = available
            case .unavailable:
                throw V3ImmutableTransactionError
                    .referencedEntryUnavailable(
                        entryID: entry.entryID,
                        digest: entry.ciphertextDigest
                    )
            case .invalid, .tooLarge:
                throw invalidEntry(entry, digest: digest)
            }
            guard data.count <= limits.maximumEntryBytes,
                  data.count <= limits.maximumTotalEntryBytes - totalBytes,
                  Data(SHA256.hash(data: data)) == digest,
                  let encrypted = try? entryCipher.parse(data),
                  encrypted.context == (try? V3EntryAuthenticationContext(
                      vaultID: checkpoint.checkpoint.vaultID,
                      entry: entry
                  ))
            else {
                throw invalidEntry(entry, digest: digest)
            }
            totalBytes += data.count
            let key = V3EntryObjectKey(
                entryID: entry.entryID,
                digest: digest
            )
            guard result.updateValue(encrypted, forKey: key) == nil else {
                throw invalidEntry(entry, digest: digest)
            }
        }
        return result
    }

    private func invalidEntry(
        _ entry: V3ManifestEntry,
        digest: Data
    ) -> V3ImmutableTransactionError {
        .referencedEntryInvalid(
            entryID: entry.entryID,
            digest: digest.count == 32
                ? Base64URL.encode(digest)
                : entry.ciphertextDigest
        )
    }
}
