import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3DeviceWrappedContentMutationError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidTrustedCheckpoint
    case invalidVaultKey
    case invalidEntryID
    case invalidEntryName
    case entryNotFound
    case entryExists
    case unchangedName
    case revisionOverflow
    case invalidCandidate

    var errorDescription: String? {
        switch self {
        case .invalidTrustedCheckpoint:
            "The vault state for this change does not match this Mac's last verified record. Key has stopped the change."
        case .invalidVaultKey:
            "The unlocked encryption key does not match this Mac's verified vault record. Key has stopped the change."
        case .invalidEntryID:
            "The ID for the destination entry is invalid."
        case .invalidEntryName:
            "The entry name is invalid. Use a name like github/personal with no leading or trailing spaces or slashes. Path parts cannot be empty, '.' or '..'."
        case .entryNotFound:
            "The requested entry was not found. Run `key list` to see saved names."
        case .entryExists:
            "An entry already uses the destination name. Use `key edit` to replace its secret, or see `key help duplicate` and `key help rename` for overwrite options."
        case .unchangedName:
            "The new name is the same as the existing name."
        case .revisionOverflow:
            "This entry has reached the maximum supported revision number. Key cannot save another change to it."
        case .invalidCandidate:
            "Key could not prepare a valid vault update for this change."
        }
    }
}

/// One complete, still-unpublished ordinary content mutation.
///
/// The expected checkpoint makes the candidate's authority dependency
/// explicit. A publisher must compare-and-replace that exact checkpoint only
/// after every staged entry and `manifestData` are durable.
struct V3DeviceWrappedContentMutationCandidate: Equatable, Sendable {
    let kind: VaultTransactionMutationKind
    let expectedCheckpoint: V3ManifestCheckpoint
    let body: V3DeviceWrappedManifestBody
    let manifestData: Data
    let manifestDigest: Data
    let stagedEntries: [V3EncryptedEntry]
}

/// Pure planning and cryptographic construction for ordinary permanent-profile
/// entry mutations.
///
/// Repository reads, conflict policy, durable publication, checkpoint CAS, and
/// recovery remain outside this type. Copy and move receive the exact source
/// object selected by their caller and authenticate it before resealing.
struct V3DeviceWrappedManifestCandidateBuilder: Sendable {
    private static let envelopeFormat = "key-vault-manifest-envelope"
    private static let envelopeVersion: UInt64 = 3
    private static let authenticationAlgorithm =
        "HKDF-SHA256+HMAC-SHA256"

    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()

    private let planner = V3EntryMutationPlanner()

    func add(
        to base: V3DeviceWrappedTrustedCheckpoint, entryID: String,
        name: String, type: SecretEntryType, plaintext: String, vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        try plan(
            .add(entryID: entryID, name: name, type: type, plaintext: plaintext),
            base: base, vaultKey: vaultKey)
    }

    func edit(
        in base: V3DeviceWrappedTrustedCheckpoint, name: String,
        type: SecretEntryType, plaintext: String, vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        try plan(
            .edit(name: name, type: type, plaintext: plaintext),
            base: base, vaultKey: vaultKey)
    }

    func copy(
        in base: V3DeviceWrappedTrustedCheckpoint, sourceName: String,
        sourceData: Data, destinationEntryID: String, destinationName: String,
        overwrite: Bool, vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        try plan(
            .copy(
                sourceName: sourceName, sourceData: sourceData,
                destinationEntryID: destinationEntryID,
                destinationName: destinationName, overwrite: overwrite),
            base: base, vaultKey: vaultKey)
    }

    func move(
        in base: V3DeviceWrappedTrustedCheckpoint, sourceName: String,
        sourceData: Data, destinationName: String, overwrite: Bool, vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        try plan(
            .move(
                sourceName: sourceName, sourceData: sourceData,
                destinationName: destinationName, overwrite: overwrite),
            base: base, vaultKey: vaultKey)
    }

    func remove(
        from base: V3DeviceWrappedTrustedCheckpoint, name: String, vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        try plan(.remove(name: name), base: base, vaultKey: vaultKey)
    }

    private func plan(
        _ request: V3EntryMutationRequest,
        base: V3DeviceWrappedTrustedCheckpoint, vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        try validate(base: base, vaultKey: vaultKey)
        let plan = try planner.plan(request, fields: base.envelope.body.fields, vaultKey: vaultKey)
        return try build(
            kind: plan.kind, entries: plan.entries,
            stagedEntries: plan.stagedEntries, base: base, vaultKey: vaultKey)
    }

    private func validate(
        base: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data
    ) throws {
        guard vaultKey.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: vaultKey,
                  vaultID: base.envelope.body.vaultID
              )) == base.envelope.body.keyID
        else {
            throw V3DeviceWrappedContentMutationError.invalidVaultKey
        }
        guard let reparsed = try? envelopeCodec.parse(
                  base.envelope.canonicalBytes
              ),
              reparsed == base.envelope,
              base.checkpoint.vaultID == base.envelope.body.vaultID,
              base.checkpoint.envelopeDigest
                == Data(SHA256.hash(data: base.envelope.canonicalBytes)),
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  base.envelope.authenticationTag,
                  canonicalContent: base.envelope.canonicalContentBytes,
                  vaultID: base.envelope.body.vaultID,
                  vaultKey: vaultKey
              )) == true
        else {
            throw V3DeviceWrappedContentMutationError
                .invalidTrustedCheckpoint
        }
    }

    private func build(
        kind: VaultTransactionMutationKind,
        entries: [V3ManifestEntry],
        stagedEntries: [V3EncryptedEntry],
        base: V3DeviceWrappedTrustedCheckpoint,
        vaultKey: Data
    ) throws -> V3DeviceWrappedContentMutationCandidate {
        let baseBody = base.envelope.body
        let body: V3DeviceWrappedManifestBody
        do {
            body = try V3DeviceWrappedManifestBody(
                vaultID: baseBody.vaultID,
                keyID: baseBody.keyID,
                authorityTransitionID: baseBody.authorityTransitionID,
                devices: baseBody.devices,
                wrappedKeys: baseBody.wrappedKeys,
                entries: entries.sorted(by: v3ManifestEntryPrecedes)
            )
        } catch {
            throw V3DeviceWrappedContentMutationError.invalidCandidate
        }

        let content = CanonicalJSONValue.object([
            (
                "parents",
                .array([.string(Base64URL.encode(
                    base.checkpoint.envelopeDigest
                ))])
            ),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: body.vaultID,
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
            // Content-only mutations do not alter device authority and need no
            // Secure Enclave owner authorization.
            ("authorizations", .array([])),
        ]))

        let parsed: V3DeviceWrappedManifestEnvelope
        do {
            parsed = try envelopeCodec.parse(manifestData)
        } catch {
            throw V3DeviceWrappedContentMutationError.invalidCandidate
        }
        guard parsed.parents == [base.checkpoint.envelopeDigest],
              parsed.body == body,
              parsed.authorizations.isEmpty,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  parsed.authenticationTag,
                  canonicalContent: parsed.canonicalContentBytes,
                  vaultID: body.vaultID,
                  vaultKey: vaultKey
              )) == true
        else {
            throw V3DeviceWrappedContentMutationError.invalidCandidate
        }

        return V3DeviceWrappedContentMutationCandidate(
            kind: kind,
            expectedCheckpoint: base.checkpoint,
            body: body,
            manifestData: manifestData,
            manifestDigest: Data(SHA256.hash(data: manifestData)),
            stagedEntries: stagedEntries
        )
    }
}
