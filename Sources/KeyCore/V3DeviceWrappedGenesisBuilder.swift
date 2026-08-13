import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3DeviceWrappedGenesisError: Error, Equatable, LocalizedError {
    case invalidVaultKey
    case invalidManifest

    var errorDescription: String? {
        switch self {
        case .invalidVaultKey:
            "Permanent version 3 genesis requires a 32-byte in-memory vault key."
        case .invalidManifest:
            "The permanent version 3 genesis manifest could not be constructed."
        }
    }
}

/// Publishable output of permanent-profile genesis construction.
///
/// The raw vault key is intentionally absent. Its caller owns the in-memory
/// session lifetime; this value contains only authenticated public metadata
/// and the device-addressed HPKE ciphertext.
struct V3DeviceWrappedGenesisCandidate: Equatable, Sendable {
    let body: V3DeviceWrappedManifestBody
    let manifestData: Data
    let manifestDigest: Data
}

/// Complete, still-unpublished permanent genesis snapshot.
///
/// Source plaintext remains here only while the helper-owned migration call
/// validates its exact staged and published output. It is never written to
/// transaction or recovery state.
struct V3DeviceWrappedGenesisPublicationCandidate: Sendable {
    struct Entry: Sendable {
        let source: V2MigrationSourceEntry
        let manifestEntry: V3ManifestEntry
        let encryptedEntry: V3EncryptedEntry
        let digest: Data
    }

    let genesis: V3DeviceWrappedGenesisCandidate
    let entries: [Entry]
}

/// Pure construction of a one-owner permanent-profile genesis manifest.
///
/// Device-identity creation, immutable publication, checkpoint installation,
/// and session ownership remain separate transactional responsibilities.
struct V3DeviceWrappedGenesisBuilder: Sendable {
    private static let envelopeFormat = "key-vault-manifest-envelope"
    private static let envelopeVersion: UInt64 = 3
    private static let authenticationAlgorithm =
        "HKDF-SHA256+HMAC-SHA256"

    private let hpke = V3VaultKeyHPKE()
    private let bodyCodec = V3DeviceWrappedManifestCodec()
    private let entryCipher = V3EntryCipher()

    func buildPublicationCandidate(
        vaultID: String,
        authorityTransitionID: String,
        entryIDs: [String],
        sourceEntries: [V2MigrationSourceEntry],
        vaultKey: Data,
        ownerIdentity: V3EnrollmentDeviceIdentity
    ) throws -> V3DeviceWrappedGenesisPublicationCandidate {
        guard isValidV3UUID(vaultID),
              isValidV3UUID(authorityTransitionID),
              entryIDs.count == sourceEntries.count,
              entryIDs.allSatisfy(isValidV3UUID)
        else {
            throw V3DeviceWrappedGenesisError.invalidManifest
        }
        guard Set(entryIDs).count == entryIDs.count else {
            throw V3DeviceWrappedGenesisError.invalidManifest
        }

        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        var entries: [V3DeviceWrappedGenesisPublicationCandidate.Entry] = []
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
            let encryptedEntry = try entryCipher.seal(
                source.plaintext,
                context: context,
                vaultKey: vaultKey
            )
            guard let digest = Base64URL.decodeCanonical(
                encryptedEntry.ciphertextDigest
            ), digest.count == 32 else {
                throw V3DeviceWrappedGenesisError.invalidManifest
            }
            entries.append(.init(
                source: source,
                manifestEntry: V3ManifestEntry(
                    entryID: entryID,
                    name: source.name,
                    type: source.type,
                    revision: 1,
                    keyID: keyID,
                    ciphertextDigest: encryptedEntry.ciphertextDigest
                ),
                encryptedEntry: encryptedEntry,
                digest: digest
            ))
        }
        entries.sort {
            v3ManifestEntryPrecedes($0.manifestEntry, $1.manifestEntry)
        }
        let genesis = try build(
            vaultID: vaultID,
            authorityTransitionID: authorityTransitionID,
            vaultKey: vaultKey,
            ownerIdentity: ownerIdentity,
            entries: entries.map(\.manifestEntry)
        )
        return V3DeviceWrappedGenesisPublicationCandidate(
            genesis: genesis,
            entries: entries
        )
    }

    func build(
        vaultID: String,
        authorityTransitionID: String,
        vaultKey: Data,
        ownerIdentity: V3EnrollmentDeviceIdentity,
        entries: [V3ManifestEntry] = []
    ) throws -> V3DeviceWrappedGenesisCandidate {
        guard vaultKey.count == 32 else {
            throw V3DeviceWrappedGenesisError.invalidVaultKey
        }

        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        let context = try V3VaultKeyHPKEContext(
            vaultID: vaultID,
            keyID: keyID,
            authorityTransitionID: authorityTransitionID,
            recipientDeviceID: ownerIdentity.deviceID
        )
        let wrappedKey = try hpke.wrap(
            vaultKey: vaultKey,
            recipientPublicKey: ownerIdentity.wrappingPublicKey,
            context: context
        )
        let body = try V3DeviceWrappedManifestBody(
            vaultID: vaultID,
            keyID: keyID,
            authorityTransitionID: authorityTransitionID,
            devices: [V3DeviceWrappedManifestDevice(
                identity: ownerIdentity,
                status: .active
            )],
            wrappedKeys: [try V3DeviceWrappedManifestKey(
                recipientDeviceID: ownerIdentity.deviceID,
                wrappedKey: wrappedKey
            )],
            entries: entries
        )

        // Re-enter through the strict schema before authenticating or
        // returning bytes. This keeps construction and parsing in lockstep.
        guard try bodyCodec.parseCanonicalBody(body.canonicalBytes) == body else {
            throw V3DeviceWrappedGenesisError.invalidManifest
        }

        let content = CanonicalJSONValue.object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: vaultID,
            vaultKey: vaultKey
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string(Self.envelopeFormat)),
            ("version", .integer(Self.envelopeVersion)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string(Self.authenticationAlgorithm)),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            // Genesis is trusted by its exact device-local checkpoint. There
            // is no parent owner capable of authorizing the first roster.
            ("authorizations", .array([])),
        ]))

        return V3DeviceWrappedGenesisCandidate(
            body: body,
            manifestData: manifestData,
            manifestDigest: Data(SHA256.hash(data: manifestData))
        )
    }
}
