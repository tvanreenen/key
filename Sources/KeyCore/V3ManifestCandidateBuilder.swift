import Foundation
internal import JSONCanonicalization

struct V3ManifestCandidate: Sendable {
    let data: Data
    let verified: V3VerifiedManifest
}

/// Canonically encodes and authenticates an already-planned v3 manifest.
///
/// Callers remain responsible for choosing parents, authority, entries, and
/// any owner authorizations. The builder performs no repository access or
/// publication and verifies its own output before returning it.
struct V3ManifestCandidateBuilder: Sendable {
    private let authenticator = V3ManifestAuthenticator()

    func build(
        content: V3ManifestContent,
        vaultKey: Data,
        trustAnchor: V3ManifestTrustAnchor,
        authorizations: [V3ManifestAuthorization] = []
    ) throws -> V3ManifestCandidate {
        let contentValue = canonicalContent(content)
        let canonicalContent = CanonicalJSON.encode(contentValue)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: content.manifest.vaultID,
            vaultKey: vaultKey
        )
        let data = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", contentValue),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag)))
            ])),
            ("authorizations", .array(authorizations.map {
                .object([
                    ("algorithm", .string("P-256-ECDSA-SHA256")),
                    ("signerDeviceID", .string($0.signerDeviceID)),
                    ("signature", .string($0.signature))
                ])
            }))
        ]))
        return V3ManifestCandidate(
            data: data,
            verified: try authenticator.verify(
                data,
                vaultKey: vaultKey,
                trustAnchor: trustAnchor
            )
        )
    }

    private func canonicalContent(
        _ content: V3ManifestContent
    ) -> CanonicalJSONValue {
        .object([
            ("parents", .array(content.parents.map(CanonicalJSONValue.string))),
            ("manifest", canonicalManifest(content.manifest))
        ])
    }

    private func canonicalManifest(
        _ manifest: V3ManifestBody
    ) -> CanonicalJSONValue {
        .object([
            ("format", .string("key-vault-manifest")),
            ("version", .integer(3)),
            ("vaultID", .string(manifest.vaultID)),
            ("mode", .string(manifest.mode.rawValue)),
            ("keyID", .string(manifest.keyID.rawValue)),
            ("devices", .array(manifest.devices.map(canonicalDevice))),
            ("wrappedKeys", .array(manifest.wrappedKeys.map {
                .object([
                    ("deviceID", .string($0.deviceID)),
                    (
                        "algorithm",
                        .string("p256-ecies-x963-sha256-aes-gcm")
                    ),
                    ("ciphertext", .string($0.ciphertext))
                ])
            })),
            ("entries", .array(manifest.entries.map(canonicalEntry)))
        ])
    }

    private func canonicalDevice(
        _ device: V3ManifestDevice
    ) -> CanonicalJSONValue {
        .object([
            ("deviceID", .string(device.deviceID)),
            ("displayName", .string(device.displayName)),
            ("role", .string(device.role.rawValue)),
            ("status", .string(device.status.rawValue)),
            ("signingPublicKey", .object([
                ("algorithm", .string("P-256-ECDSA")),
                ("encoding", .string("x963")),
                ("value", .string(device.signingPublicKey.value))
            ])),
            ("wrappingPublicKey", .object([
                ("algorithm", .string("P-256-ECDH")),
                ("encoding", .string("x963")),
                ("value", .string(device.wrappingPublicKey.value))
            ]))
        ])
    }

    private func canonicalEntry(
        _ entry: V3ManifestEntry
    ) -> CanonicalJSONValue {
        .object([
            ("entryID", .string(entry.entryID)),
            ("name", .string(entry.name)),
            ("type", .string(entry.type.rawValue)),
            ("revision", .integer(entry.revision)),
            ("keyID", .string(entry.keyID.rawValue)),
            ("ciphertextDigest", .string(entry.ciphertextDigest))
        ])
    }
}
