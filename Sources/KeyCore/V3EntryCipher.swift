import CryptoKit
import Foundation
import JSONCanonicalization

public enum V3EncryptedEntryError: Error, Equatable, LocalizedError {
    case invalidEncoding
    case invalidJSON
    case duplicateProperty
    case nonCanonicalJSON
    case invalidStructure(String)
    case invalidVaultKey
    case keyIdentityMismatch
    case invalidTrustedContext
    case manifestEntryNotFound
    case digestMismatch
    case replayedRevision(trustedRevision: UInt64, observedRevision: UInt64)
    case conflictingRevision(trustedRevision: UInt64, observedRevision: UInt64)
    case contextMismatch
    case encryptionFailed
    case authenticationFailed
    case invalidPlaintext

    public var errorDescription: String? {
        switch self {
        case .invalidEncoding:
            "Encrypted entry is not valid BOM-free UTF-8."
        case .invalidJSON:
            "Encrypted entry is not valid I-JSON."
        case .duplicateProperty:
            "Encrypted entry contains a duplicate property."
        case .nonCanonicalJSON:
            "Encrypted entry is not encoded as canonical JSON."
        case let .invalidStructure(path):
            "Encrypted entry has an invalid structure at \(path)."
        case .invalidVaultKey:
            "The version 3 vault key must contain exactly 32 bytes."
        case .keyIdentityMismatch:
            "The supplied vault key does not match the authenticated version 3 key ID."
        case .invalidTrustedContext:
            "The authenticated manifest supplied an invalid entry context."
        case .manifestEntryNotFound:
            "The authenticated manifest does not contain the requested entry."
        case .digestMismatch:
            "Encrypted entry does not match its authenticated manifest digest."
        case let .replayedRevision(trustedRevision, observedRevision):
            "Encrypted entry rollback detected: trusted revision \(trustedRevision), observed revision \(observedRevision)."
        case let .conflictingRevision(trustedRevision, observedRevision):
            "Encrypted entry conflicts with trusted revision \(trustedRevision) at observed revision \(observedRevision)."
        case .contextMismatch:
            "Encrypted entry identity does not match its authenticated manifest entry."
        case .encryptionFailed:
            "Version 3 entry encryption failed."
        case .authenticationFailed:
            "Encrypted entry authentication failed."
        case .invalidPlaintext:
            "Decrypted entry is not valid UTF-8."
        }
    }
}

/// A parsed version 3 encrypted entry.
///
/// Parsing establishes canonical encoding and structural validity only. Treat
/// these values as untrusted until `V3EntryCipher.open` verifies the file
/// against a freshness-approved manifest entry and successfully opens AES-GCM.
public struct V3EncryptedEntry: Equatable, Sendable {
    public let context: V3EntryAuthenticationContext
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data
    public let canonicalBytes: Data
    public let ciphertextDigest: String

    init(
        context: V3EntryAuthenticationContext,
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        canonicalBytes: Data
    ) {
        self.context = context
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.canonicalBytes = canonicalBytes
        ciphertextDigest = Base64URL.encode(Data(SHA256.hash(data: canonicalBytes)))
    }
}

public struct V3EntryCipher: Sendable {
    public init() {}

    /// Seals UTF-8 plaintext with a fresh nonce and the complete entry identity
    /// as AES-GCM associated data.
    public func seal(
        _ plaintext: String,
        context: V3EntryAuthenticationContext,
        vaultKey: Data
    ) throws -> V3EncryptedEntry {
        try seal(
            Data(plaintext.utf8),
            context: context,
            vaultKey: vaultKey,
            nonce: AES.GCM.Nonce()
        )
    }

    /// Parses a version 3 entry without trusting or decrypting it.
    public func parse(_ data: Data) throws -> V3EncryptedEntry {
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(data)
        } catch let error as CanonicalJSONError {
            throw entryError(for: error)
        }

        guard let root = json.objectValue else {
            throw V3EncryptedEntryError.invalidStructure("$")
        }
        try requireEntryFields(
            root,
            required: [
                "format", "version", "vaultID", "entryID", "name",
                "type", "keyID", "revision", "encryption"
            ],
            path: "$"
        )
        guard entryStringMember("format", in: root) == "key-vault-entry" else {
            throw V3EncryptedEntryError.invalidStructure("$.format")
        }
        guard entryIntegerMember("version", in: root) == 3 else {
            throw V3EncryptedEntryError.invalidStructure("$.version")
        }

        let keyID: V3VaultKeyID
        do {
            keyID = try V3VaultKeyID(
                rawValue: requiredEntryString("keyID", in: root, path: "$")
            )
        } catch {
            throw V3EncryptedEntryError.invalidStructure("$.keyID")
        }

        let context: V3EntryAuthenticationContext
        do {
            context = try V3EntryAuthenticationContext(
                vaultID: try requiredEntryString("vaultID", in: root, path: "$"),
                entryID: try requiredEntryString("entryID", in: root, path: "$"),
                name: try requiredEntryString("name", in: root, path: "$"),
                type: try requiredEntryType("type", in: root, path: "$"),
                keyID: keyID,
                revision: try requiredEntryInteger("revision", in: root, path: "$")
            )
        } catch let error as V3EntryAuthenticationContextError {
            switch error {
            case .invalidVaultID:
                throw V3EncryptedEntryError.invalidStructure("$.vaultID")
            case .invalidEntryID:
                throw V3EncryptedEntryError.invalidStructure("$.entryID")
            case .invalidName:
                throw V3EncryptedEntryError.invalidStructure("$.name")
            case .invalidRevision:
                throw V3EncryptedEntryError.invalidStructure("$.revision")
            }
        } catch {
            throw V3EncryptedEntryError.invalidStructure("$")
        }

        let encryptionValue = try requiredEntryMember("encryption", in: root, path: "$")
        guard let encryption = encryptionValue.objectValue else {
            throw V3EncryptedEntryError.invalidStructure("$.encryption")
        }
        try requireEntryFields(
            encryption,
            required: ["algorithm", "nonce", "ciphertext", "tag"],
            path: "$.encryption"
        )
        guard entryStringMember("algorithm", in: encryption) == "AES-256-GCM" else {
            throw V3EncryptedEntryError.invalidStructure("$.encryption.algorithm")
        }

        let nonce = try requiredBase64URL(
            "nonce",
            in: encryption,
            path: "$.encryption",
            expectedByteCount: 12
        )
        let ciphertext = try requiredBase64URL(
            "ciphertext",
            in: encryption,
            path: "$.encryption",
            allowingEmpty: true
        )
        let tag = try requiredBase64URL(
            "tag",
            in: encryption,
            path: "$.encryption",
            expectedByteCount: 16
        )

        guard CanonicalJSON.encode(json) == data else {
            throw V3EncryptedEntryError.nonCanonicalJSON
        }

        return V3EncryptedEntry(
            context: context,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
            canonicalBytes: data
        )
    }

    /// Opens an encrypted entry only after binding it to authenticated,
    /// freshness-approved manifest state.
    public func open(
        _ data: Data,
        trustedManifest: V3TrustedManifest,
        entryID: String,
        vaultKey: Data
    ) throws -> String {
        guard vaultKey.count == 32 else {
            throw V3EncryptedEntryError.invalidVaultKey
        }
        let body = trustedManifest.envelope.content.manifest
        let manifestEntry = try authenticatedManifestEntry(
            in: trustedManifest,
            entryID: entryID
        )
        return try openTrusted(
            data,
            vaultID: body.vaultID,
            manifestEntry: manifestEntry,
            vaultKey: vaultKey
        )
    }

    func openTrusted(
        _ data: Data,
        vaultID: String,
        manifestEntry: V3ManifestEntry,
        vaultKey: Data
    ) throws -> String {
        let plaintext = try openPlaintextDataTrusted(
            data,
            vaultID: vaultID,
            manifestEntry: manifestEntry,
            vaultKey: vaultKey
        )
        guard let decoded = String(data: plaintext, encoding: .utf8) else {
            throw V3EncryptedEntryError.invalidPlaintext
        }
        return decoded
    }

    func openPlaintextDataTrusted(
        _ data: Data,
        vaultID: String,
        manifestEntry: V3ManifestEntry,
        vaultKey: Data
    ) throws -> Data {
        guard vaultKey.count == 32 else {
            throw V3EncryptedEntryError.invalidVaultKey
        }
        try requireMatchingKeyID(
            manifestEntry.keyID,
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        guard let expectedDigest = Base64URL.decodeCanonical(
            manifestEntry.ciphertextDigest
        ), expectedDigest.count == 32 else {
            throw V3EncryptedEntryError.invalidTrustedContext
        }
        guard Data(SHA256.hash(data: data)) == expectedDigest else {
            if let replayError = authenticatedDigestMismatchError(
                data,
                vaultID: vaultID,
                manifestEntry: manifestEntry,
                vaultKey: vaultKey
            ) {
                throw replayError
            }
            throw V3EncryptedEntryError.digestMismatch
        }

        let expectedContext: V3EntryAuthenticationContext
        do {
            expectedContext = try V3EntryAuthenticationContext(
                vaultID: vaultID,
                entry: manifestEntry
            )
        } catch {
            throw V3EncryptedEntryError.invalidTrustedContext
        }

        let entry = try parse(data)
        guard entry.context == expectedContext else {
            throw V3EncryptedEntryError.contextMismatch
        }

        let plaintext: Data
        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: entry.nonce),
                ciphertext: entry.ciphertext,
                tag: entry.tag
            )
            plaintext = try AES.GCM.open(
                sealedBox,
                using: SymmetricKey(data: vaultKey),
                authenticating: expectedContext.associatedData
            )
        } catch {
            throw V3EncryptedEntryError.authenticationFailed
        }

        guard String(data: plaintext, encoding: .utf8) != nil else {
            throw V3EncryptedEntryError.invalidPlaintext
        }
        return plaintext
    }

    func authenticatedManifestEntry(
        in trustedManifest: V3TrustedManifest,
        entryID: String
    ) throws -> V3ManifestEntry {
        let matches = trustedManifest.envelope.content.manifest.entries.filter {
            $0.entryID == entryID
        }
        guard let manifestEntry = matches.first else {
            throw V3EncryptedEntryError.manifestEntryNotFound
        }
        guard matches.count == 1 else {
            throw V3EncryptedEntryError.invalidTrustedContext
        }
        return manifestEntry
    }

    private func authenticatedDigestMismatchError(
        _ data: Data,
        vaultID: String,
        manifestEntry: V3ManifestEntry,
        vaultKey: Data
    ) -> V3EncryptedEntryError? {
        guard let entry = try? parse(data),
              entry.context.vaultID == vaultID,
              entry.context.entryID == manifestEntry.entryID,
              let derivedKeyID = try? V3VaultKeyID.derive(
                  vaultKey: vaultKey,
                  vaultID: vaultID
              ),
              entry.context.keyID == derivedKeyID
        else {
            return nil
        }

        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: entry.nonce),
                ciphertext: entry.ciphertext,
                tag: entry.tag
            )
            _ = try AES.GCM.open(
                sealedBox,
                using: SymmetricKey(data: vaultKey),
                authenticating: entry.context.associatedData
            )
        } catch {
            return nil
        }

        if entry.context.revision < manifestEntry.revision {
            return .replayedRevision(
                trustedRevision: manifestEntry.revision,
                observedRevision: entry.context.revision
            )
        }
        return .conflictingRevision(
            trustedRevision: manifestEntry.revision,
            observedRevision: entry.context.revision
        )
    }

    func seal(
        _ plaintext: Data,
        context: V3EntryAuthenticationContext,
        vaultKey: Data,
        nonce: AES.GCM.Nonce
    ) throws -> V3EncryptedEntry {
        guard vaultKey.count == 32 else {
            throw V3EncryptedEntryError.invalidVaultKey
        }
        try requireMatchingKeyID(
            context.keyID,
            vaultKey: vaultKey,
            vaultID: context.vaultID
        )

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: vaultKey),
                nonce: nonce,
                authenticating: context.associatedData
            )
        } catch {
            throw V3EncryptedEntryError.encryptionFailed
        }

        let nonceData = Data(nonce)
        let canonicalBytes = encodeEntry(
            context: context,
            nonce: nonceData,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag
        )
        return V3EncryptedEntry(
            context: context,
            nonce: nonceData,
            ciphertext: sealedBox.ciphertext,
            tag: sealedBox.tag,
            canonicalBytes: canonicalBytes
        )
    }
}

private func encodeEntry(
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
            ("nonce", .string(Base64URL.encode(nonce))),
            ("ciphertext", .string(Base64URL.encode(ciphertext))),
            ("tag", .string(Base64URL.encode(tag)))
        ]))
    ]))
}

private func requireMatchingKeyID(
    _ expectedKeyID: V3VaultKeyID,
    vaultKey: Data,
    vaultID: String
) throws {
    let derivedKeyID: V3VaultKeyID
    do {
        derivedKeyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
    } catch V3VaultKeyIDError.invalidVaultKey {
        throw V3EncryptedEntryError.invalidVaultKey
    } catch {
        throw V3EncryptedEntryError.invalidTrustedContext
    }
    guard derivedKeyID == expectedKeyID else {
        throw V3EncryptedEntryError.keyIdentityMismatch
    }
}

private func entryError(for error: CanonicalJSONError) -> V3EncryptedEntryError {
    switch error {
    case .invalidEncoding:
        .invalidEncoding
    case .invalidJSON:
        .invalidJSON
    case .duplicateProperty:
        .duplicateProperty
    }
}

private func requireEntryFields(
    _ object: [(String, CanonicalJSONValue)],
    required: Set<String>,
    path: String
) throws {
    guard object.count == required.count,
          Set(object.map(\.0)) == required
    else {
        throw V3EncryptedEntryError.invalidStructure(path)
    }
}

private func requiredEntryMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> CanonicalJSONValue {
    guard let value = object.first(where: { $0.0 == name })?.1 else {
        throw V3EncryptedEntryError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func entryStringMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    object.first(where: { $0.0 == name })?.1.stringValue
}

private func entryIntegerMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    object.first(where: { $0.0 == name })?.1.integerValue
}

private func requiredEntryString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> String {
    guard let value = entryStringMember(name, in: object) else {
        throw V3EncryptedEntryError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func requiredEntryInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> UInt64 {
    guard let value = entryIntegerMember(name, in: object) else {
        throw V3EncryptedEntryError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func requiredEntryType(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> SecretEntryType {
    let value = try requiredEntryString(name, in: object, path: path)
    guard let type = SecretEntryType(rawValue: value) else {
        throw V3EncryptedEntryError.invalidStructure("\(path).\(name)")
    }
    return type
}

private func requiredBase64URL(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String,
    allowingEmpty: Bool = false,
    expectedByteCount: Int? = nil
) throws -> Data {
    let value = try requiredEntryString(name, in: object, path: path)
    guard allowingEmpty || !value.isEmpty,
          let decoded = Base64URL.decodeCanonical(value),
          expectedByteCount.map({ decoded.count == $0 }) ?? true
    else {
        throw V3EncryptedEntryError.invalidStructure("\(path).\(name)")
    }
    return decoded
}
