import CryptoKit
import Foundation

public enum V3EntryResealingError: Error, Equatable, LocalizedError {
    case invalidDestinationEntryID
    case invalidDestinationName
    case destinationEntryIDExists
    case destinationNameExists
    case unchangedName
    case revisionOverflow

    public var errorDescription: String? {
        switch self {
        case .invalidDestinationEntryID:
            "The version 3 destination entry ID is invalid."
        case .invalidDestinationName:
            "The version 3 destination entry name is invalid."
        case .destinationEntryIDExists:
            "The version 3 destination entry ID already exists."
        case .destinationNameExists:
            "The version 3 destination entry name already exists."
        case .unchangedName:
            "The version 3 rename destination is unchanged."
        case .revisionOverflow:
            "The version 3 entry revision cannot be incremented."
        }
    }
}

public struct V3ResealedEntry: Equatable, Sendable {
    public let encryptedEntry: V3EncryptedEntry
    public let manifestEntry: V3ManifestEntry

    init(encryptedEntry: V3EncryptedEntry) {
        self.encryptedEntry = encryptedEntry
        manifestEntry = V3ManifestEntry(
            entryID: encryptedEntry.context.entryID,
            name: encryptedEntry.context.name,
            type: encryptedEntry.context.type,
            revision: encryptedEntry.context.revision,
            keyEpoch: encryptedEntry.context.keyEpoch,
            ciphertextDigest: encryptedEntry.ciphertextDigest
        )
    }
}

extension V3EntryCipher {
    /// Copies an authenticated entry into a new logical entry at revision 1.
    ///
    /// The destination must not already exist in the verified manifest.
    /// Transaction-level overwrite policy is deliberately outside this
    /// cryptographic operation.
    public func copy(
        _ sourceData: Data,
        verifiedManifest: V3VerifiedManifest,
        sourceEntryID: String,
        destinationName: String,
        vaultKey: Data
    ) throws -> V3ResealedEntry {
        var destinationEntryID: String
        repeat {
            destinationEntryID = UUID().uuidString.lowercased()
        } while verifiedManifest.envelope.content.manifest.entries.contains {
            $0.entryID == destinationEntryID
        }

        return try copy(
            sourceData,
            verifiedManifest: verifiedManifest,
            sourceEntryID: sourceEntryID,
            destinationEntryID: destinationEntryID,
            destinationName: destinationName,
            vaultKey: vaultKey,
            nonce: AES.GCM.Nonce()
        )
    }

    /// Renames an authenticated logical entry and advances its revision.
    ///
    /// A transaction must commit the returned entry and manifest record
    /// together; moving the original ciphertext is never a valid v3 rename.
    public func rename(
        _ sourceData: Data,
        verifiedManifest: V3VerifiedManifest,
        sourceEntryID: String,
        destinationName: String,
        vaultKey: Data
    ) throws -> V3ResealedEntry {
        try rename(
            sourceData,
            verifiedManifest: verifiedManifest,
            sourceEntryID: sourceEntryID,
            destinationName: destinationName,
            vaultKey: vaultKey,
            nonce: AES.GCM.Nonce()
        )
    }

    func copy(
        _ sourceData: Data,
        verifiedManifest: V3VerifiedManifest,
        sourceEntryID: String,
        destinationEntryID: String,
        destinationName: String,
        vaultKey: Data,
        nonce: AES.GCM.Nonce
    ) throws -> V3ResealedEntry {
        let body = verifiedManifest.envelope.content.manifest
        let source = try authenticatedManifestEntry(
            in: verifiedManifest,
            entryID: sourceEntryID
        )
        guard isValidV3UUID(destinationEntryID) else {
            throw V3EntryResealingError.invalidDestinationEntryID
        }
        guard isValidV3EntryName(destinationName) else {
            throw V3EntryResealingError.invalidDestinationName
        }
        guard !body.entries.contains(where: { $0.entryID == destinationEntryID }) else {
            throw V3EntryResealingError.destinationEntryIDExists
        }
        guard !body.entries.contains(where: { $0.name == destinationName }) else {
            throw V3EntryResealingError.destinationNameExists
        }

        let destination = try V3EntryAuthenticationContext(
            vaultID: body.vaultID,
            entryID: destinationEntryID,
            name: destinationName,
            type: source.type,
            keyEpoch: source.keyEpoch,
            revision: 1
        )
        return try reseal(
            sourceData,
            verifiedManifest: verifiedManifest,
            source: source,
            destination: destination,
            vaultKey: vaultKey,
            nonce: nonce
        )
    }

    func rename(
        _ sourceData: Data,
        verifiedManifest: V3VerifiedManifest,
        sourceEntryID: String,
        destinationName: String,
        vaultKey: Data,
        nonce: AES.GCM.Nonce
    ) throws -> V3ResealedEntry {
        let body = verifiedManifest.envelope.content.manifest
        let source = try authenticatedManifestEntry(
            in: verifiedManifest,
            entryID: sourceEntryID
        )
        guard isValidV3EntryName(destinationName) else {
            throw V3EntryResealingError.invalidDestinationName
        }
        guard destinationName != source.name else {
            throw V3EntryResealingError.unchangedName
        }
        guard !body.entries.contains(where: { $0.name == destinationName }) else {
            throw V3EntryResealingError.destinationNameExists
        }
        guard source.revision < v3MaximumSafeInteger else {
            throw V3EntryResealingError.revisionOverflow
        }

        let destination = try V3EntryAuthenticationContext(
            vaultID: body.vaultID,
            entryID: source.entryID,
            name: destinationName,
            type: source.type,
            keyEpoch: source.keyEpoch,
            revision: source.revision + 1
        )
        return try reseal(
            sourceData,
            verifiedManifest: verifiedManifest,
            source: source,
            destination: destination,
            vaultKey: vaultKey,
            nonce: nonce
        )
    }

    private func reseal(
        _ sourceData: Data,
        verifiedManifest: V3VerifiedManifest,
        source: V3ManifestEntry,
        destination: V3EntryAuthenticationContext,
        vaultKey: Data,
        nonce: AES.GCM.Nonce
    ) throws -> V3ResealedEntry {
        let vaultID = verifiedManifest.envelope.content.manifest.vaultID
        let plaintext = try openPlaintextDataTrusted(
            sourceData,
            vaultID: vaultID,
            manifestEntry: source,
            vaultKey: vaultKey
        )
        let encryptedEntry = try seal(
            plaintext,
            context: destination,
            vaultKey: vaultKey,
            nonce: nonce
        )
        return V3ResealedEntry(encryptedEntry: encryptedEntry)
    }
}
