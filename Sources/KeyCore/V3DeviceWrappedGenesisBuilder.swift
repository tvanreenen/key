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
                role: .owner,
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
