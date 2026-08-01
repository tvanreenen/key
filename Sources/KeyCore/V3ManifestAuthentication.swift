import CryptoKit
import Foundation
internal import JSONCanonicalization

public enum V3ManifestError: Error, Equatable, LocalizedError {
    case invalidEncoding
    case invalidJSON
    case duplicateProperty
    case nonCanonicalJSON
    case invalidStructure(String)
    case unsupportedVersion(UInt64)
    case notVersion3(UInt64)
    case invalidVaultKey
    case parentMismatch
    case parentAuthorityConflict
    case authenticationFailed
    case authorizationRequired
    case unexpectedAuthorization
    case authorizationFailed
    case semanticViolation(String)

    public var errorDescription: String? {
        switch self {
        case .invalidEncoding:
            "Manifest envelope is not valid BOM-free UTF-8."
        case .invalidJSON:
            "Manifest envelope is not valid I-JSON."
        case .duplicateProperty:
            "Manifest envelope contains a duplicate property."
        case .nonCanonicalJSON:
            "Manifest envelope is not encoded as canonical JSON."
        case let .invalidStructure(path):
            "Manifest envelope has an invalid structure at \(path)."
        case let .unsupportedVersion(version):
            "Manifest envelope version \(version) is newer than this reader supports."
        case let .notVersion3(version):
            "Manifest envelope version \(version) is not a version 3 artifact."
        case .invalidVaultKey:
            "The version 3 vault key must contain exactly 32 bytes."
        case .parentMismatch:
            "Manifest envelope does not extend the exact verified parent set."
        case .parentAuthorityConflict:
            "Manifest parents disagree on vault authority and cannot be merged automatically."
        case .authenticationFailed:
            "Manifest envelope authentication failed."
        case .authorizationRequired:
            "Manifest authority changed without an active parent-owner authorization."
        case .unexpectedAuthorization:
            "Manifest envelope contains an authorization for a transition that does not permit one."
        case .authorizationFailed:
            "Manifest owner authorization failed."
        case let .semanticViolation(field):
            "Manifest envelope violates a semantic invariant at \(field)."
        }
    }
}

public enum V3VaultMode: String, Equatable, Sendable {
    case local
    case shared
}

public enum V3DeviceRole: String, Equatable, Sendable {
    case owner
    case member
}

public enum V3DeviceStatus: String, Equatable, Sendable {
    case active
    case revoked
}

public struct V3DevicePublicKey: Equatable, Sendable {
    public let value: String

    public init(value: String) {
        self.value = value
    }
}

public struct V3ManifestDevice: Equatable, Sendable {
    public let deviceID: String
    public let displayName: String
    public let role: V3DeviceRole
    public let status: V3DeviceStatus
    public let signingPublicKey: V3DevicePublicKey
    public let wrappingPublicKey: V3DevicePublicKey
}

public struct V3WrappedKey: Equatable, Sendable {
    public let deviceID: String
    public let ciphertext: String
}

public struct V3ManifestEntry: Equatable, Hashable, Sendable {
    public let entryID: String
    public let name: String
    public let type: SecretEntryType
    public let revision: UInt64
    public let keyID: V3VaultKeyID
    public let ciphertextDigest: String
}

public struct V3ManifestBody: Equatable, Sendable {
    public let vaultID: String
    public let mode: V3VaultMode
    public let keyID: V3VaultKeyID
    public let devices: [V3ManifestDevice]
    public let wrappedKeys: [V3WrappedKey]
    public let entries: [V3ManifestEntry]
}

public struct V3ManifestContent: Equatable, Sendable {
    /// Canonical SHA-256 digests of every direct parent envelope.
    ///
    /// Empty identifies genesis, one digest identifies an ordinary commit,
    /// and two or more identify a merge commit.
    public let parents: [String]
    public let manifest: V3ManifestBody
}

public struct V3ManifestAuthentication: Equatable, Sendable {
    public let tag: String
}

public struct V3ManifestAuthorization: Equatable, Sendable {
    public let signerDeviceID: String
    public let signature: String
}

public struct V3ManifestEnvelope: Equatable, Sendable {
    public let content: V3ManifestContent
    public let authentication: V3ManifestAuthentication
    public let authorizations: [V3ManifestAuthorization]
    public let canonicalBytes: Data
    public let canonicalContentBytes: Data
}

public struct V3VerifiedManifest: Equatable, Sendable {
    public let envelope: V3ManifestEnvelope
    public let envelopeDigest: Data
}

/// A structurally and cryptographically authenticated manifest object whose
/// history relationship has not yet been established.
///
/// Repository discovery uses this intermediate state only to distinguish a
/// genuinely incomplete synchronized branch from unrelated invalid files.
struct V3AuthenticatedManifestObject: Equatable, Sendable {
    let envelope: V3ManifestEnvelope
    let envelopeDigest: Data
}

public enum V3VaultHeadError: Error, Equatable, LocalizedError {
    case invalidVaultID
    case invalidDigest

    public var errorDescription: String? {
        switch self {
        case .invalidVaultID:
            "A version 3 vault head requires a canonical vault UUID."
        case .invalidDigest:
            "A version 3 vault head requires a complete SHA-256 manifest-envelope digest."
        }
    }
}

/// Exact identity of one authenticated manifest-envelope state.
///
/// The digest is SHA-256 over the canonical envelope bytes. It establishes
/// identity; it does not imply that the manifest is current on this device.
public struct V3VaultHead: Equatable, Hashable, Sendable {
    public let vaultID: String
    public let envelopeDigest: Data

    public init(vaultID: String, envelopeDigest: Data) throws {
        guard isValidV3UUID(vaultID) else {
            throw V3VaultHeadError.invalidVaultID
        }
        guard envelopeDigest.count == 32 else {
            throw V3VaultHeadError.invalidDigest
        }
        self.vaultID = vaultID
        self.envelopeDigest = envelopeDigest
    }

    init(verifiedManifest: V3VerifiedManifest) throws {
        try self.init(
            vaultID: verifiedManifest.envelope.content.manifest.vaultID,
            envelopeDigest: verifiedManifest.envelopeDigest
        )
    }
}

public enum V3ManifestTrustAnchor: Equatable, Sendable {
    /// The caller independently trusts local creation of this vault identity.
    case localGenesis(vaultID: String)
    /// Every exact direct parent, already authenticated by the caller.
    case verifiedParents([V3VerifiedManifest])
}

public struct V3ManifestAuthenticator: Sendable {
    public init() {}

    public func parse(_ data: Data) throws -> V3ManifestEnvelope {
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(data)
        } catch let error as CanonicalJSONError {
            throw manifestError(for: error)
        }
        guard let root = json.objectValue else {
            throw V3ManifestError.invalidStructure("$")
        }

        guard stringMember("format", in: root) == "key-vault-manifest-envelope" else {
            throw V3ManifestError.invalidStructure("$.format")
        }
        guard let version = integerMember("version", in: root) else {
            throw V3ManifestError.invalidStructure("$.version")
        }
        if version > 3 {
            throw V3ManifestError.unsupportedVersion(version)
        }
        if version < 3 {
            throw V3ManifestError.notVersion3(version)
        }

        let canonical = CanonicalJSON.encode(json)
        guard canonical == data else {
            throw V3ManifestError.nonCanonicalJSON
        }
        return try ManifestDecoder.decode(root: root, canonicalBytes: data)
    }

    public func verify(
        _ candidateData: Data,
        vaultKey: Data,
        trustAnchor: V3ManifestTrustAnchor
    ) throws -> V3VerifiedManifest {
        guard vaultKey.count == 32 else {
            throw V3ManifestError.invalidVaultKey
        }

        let candidate = try parse(candidateData)
        let parents = try validateParentSet(
            of: candidate,
            against: trustAnchor
        )
        let input = try authenticate(candidate, vaultKey: vaultKey)
        try validateTransition(to: candidate, from: parents, input: input)
        try validateSemantics(candidate.content.manifest)
        try validateAuthorizationOrdering(candidate.authorizations)

        return V3VerifiedManifest(
            envelope: candidate,
            envelopeDigest: Data(SHA256.hash(data: candidateData))
        )
    }

    private func validateParentSet(
        of candidate: V3ManifestEnvelope,
        against trustAnchor: V3ManifestTrustAnchor
    ) throws -> [V3VerifiedManifest] {
        switch trustAnchor {
        case let .localGenesis(expectedVaultID):
            guard candidate.content.parents.isEmpty,
                  candidate.content.manifest.mode == .local,
                  candidate.content.manifest.vaultID == expectedVaultID
            else {
                throw V3ManifestError.parentMismatch
            }
            guard candidate.authorizations.isEmpty else {
                throw V3ManifestError.unexpectedAuthorization
            }
            return []

        case let .verifiedParents(verifiedParents):
            let expectedParentDigests = verifiedParents
                .map(\.envelopeDigest)
                .sorted(by: { $0.lexicographicallyPrecedes($1) })
            let candidateParentDigests = try candidate.content.parents.map {
                try decodeBase64URL($0, expectedByteCount: 32)
            }
            guard !verifiedParents.isEmpty,
                  Set(expectedParentDigests).count == verifiedParents.count,
                  candidateParentDigests == expectedParentDigests,
                  verifiedParents.allSatisfy({
                      $0.envelope.content.manifest.vaultID
                          == candidate.content.manifest.vaultID
                  })
            else {
                throw V3ManifestError.parentMismatch
            }
            return verifiedParents
        }
    }

    private func validateTransition(
        to candidate: V3ManifestEnvelope,
        from parents: [V3VerifiedManifest],
        input: Data
    ) throws {
        if parents.count == 1, let parent = parents.first {
            if authorityChanged(
                from: parent.envelope.content.manifest,
                to: candidate.content.manifest
            ) {
                try verifyAuthorizations(
                    candidate.authorizations,
                    input: input,
                    parent: parent.envelope
                )
            } else if !candidate.authorizations.isEmpty {
                throw V3ManifestError.unexpectedAuthorization
            }
            try validateEntryRevisionTransition(
                to: candidate.content.manifest,
                from: parents
            )
            return
        }

        guard parents.count > 1 else {
            return
        }
        guard let firstParent = parents.first,
              parents.dropFirst().allSatisfy({
                  hasSameV3ManifestAuthority(
                      firstParent.envelope.content.manifest,
                      $0.envelope.content.manifest
                  )
              }),
              hasSameV3ManifestAuthority(
                  firstParent.envelope.content.manifest,
                  candidate.content.manifest
              )
        else {
            throw V3ManifestError.parentAuthorityConflict
        }
        guard candidate.authorizations.isEmpty else {
            throw V3ManifestError.unexpectedAuthorization
        }
        try validateEntryRevisionTransition(
            to: candidate.content.manifest,
            from: parents
        )
    }

    private func validateEntryRevisionTransition(
        to candidate: V3ManifestBody,
        from parents: [V3VerifiedManifest]
    ) throws {
        let parentEntriesByID = try parents.map { parent in
            var entriesByID: [String: V3ManifestEntry] = [:]
            for entry in parent.envelope.content.manifest.entries {
                guard entriesByID.updateValue(
                    entry,
                    forKey: entry.entryID
                ) == nil else {
                    throw V3ManifestError.semanticViolation("entries.duplicate")
                }
            }
            return entriesByID
        }

        for candidateEntry in candidate.entries {
            let parentEntries = parentEntriesByID.compactMap {
                $0[candidateEntry.entryID]
            }

            guard !parentEntries.isEmpty else {
                guard candidateEntry.revision == 1 else {
                    throw V3ManifestError.semanticViolation("entries.revision")
                }
                continue
            }

            guard let highestRevision = parentEntries.map(\.revision).max()
            else {
                throw V3ManifestError.semanticViolation("entries.revision")
            }
            let highestRevisionEntries = parentEntries.filter {
                $0.revision == highestRevision
            }

            if parentEntries.contains(candidateEntry) {
                guard candidateEntry.revision == highestRevision,
                      highestRevisionEntries.allSatisfy({
                          $0 == candidateEntry
                      })
                else {
                    throw V3ManifestError.semanticViolation("entries.revision")
                }
            } else {
                guard candidateEntry.revision > highestRevision else {
                    throw V3ManifestError.semanticViolation("entries.revision")
                }
            }
        }
    }

    func verifyCheckpointedCurrent(
        _ candidateData: Data,
        vaultKey: Data,
        checkpoint: V3ManifestCheckpoint
    ) throws -> V3VerifiedManifest {
        guard vaultKey.count == 32 else {
            throw V3ManifestError.invalidVaultKey
        }
        let candidate = try parse(candidateData)
        guard candidate.content.manifest.vaultID == checkpoint.vaultID,
              Data(SHA256.hash(data: candidateData)) == checkpoint.envelopeDigest
        else {
            throw V3ManifestError.parentMismatch
        }

        _ = try authenticate(candidate, vaultKey: vaultKey)
        try validateSemantics(candidate.content.manifest)
        try validateAuthorizationOrdering(candidate.authorizations)
        return V3VerifiedManifest(
            envelope: candidate,
            envelopeDigest: checkpoint.envelopeDigest
        )
    }

    /// Reopens an exact historical object named by authenticated checkpoint
    /// ancestry.
    ///
    /// The expected digest must come from a manifest that is already anchored
    /// by the device-local checkpoint. The digest link authenticates the exact
    /// bytes without requiring retention of every historical vault key.
    func reopenCheckpointAncestor(
        _ data: Data,
        expectedVaultID: String,
        expectedDigest: Data
    ) throws -> V3VerifiedManifest {
        guard expectedDigest.count == 32,
              Data(SHA256.hash(data: data)) == expectedDigest
        else {
            throw V3ManifestError.parentMismatch
        }
        let manifest = try parse(data)
        guard manifest.content.manifest.vaultID == expectedVaultID else {
            throw V3ManifestError.parentMismatch
        }
        try validateSemantics(manifest.content.manifest)
        try validateAuthorizationOrdering(manifest.authorizations)
        return V3VerifiedManifest(
            envelope: manifest,
            envelopeDigest: expectedDigest
        )
    }

    /// Authenticates synchronized bytes without granting them ancestry.
    ///
    /// A repository candidate returned here still cannot become a parent
    /// authority or trusted head until graph traversal verifies its complete
    /// direct-parent set.
    func authenticateForRepositoryDiscovery(
        _ data: Data,
        vaultKey: Data
    ) throws -> V3AuthenticatedManifestObject {
        guard vaultKey.count == 32 else {
            throw V3ManifestError.invalidVaultKey
        }
        let manifest = try parse(data)
        _ = try authenticate(manifest, vaultKey: vaultKey)
        try validateSemantics(manifest.content.manifest)
        try validateAuthorizationOrdering(manifest.authorizations)
        return V3AuthenticatedManifestObject(
            envelope: manifest,
            envelopeDigest: Data(SHA256.hash(data: data))
        )
    }

    static func authenticationInput(for canonicalContent: Data) -> Data {
        var input = Data("work.tvr.key/v3/manifest-content".utf8)
        input.append(0)
        input.append(canonicalContent)
        return input
    }

    static func authenticationTag(
        canonicalContent: Data,
        vaultID: String,
        vaultKey: Data
    ) throws -> Data {
        guard vaultKey.count == 32 else {
            throw V3ManifestError.invalidVaultKey
        }
        let key = try manifestAuthenticationKey(vaultKey: vaultKey, vaultID: vaultID)
        return Data(HMAC<SHA256>.authenticationCode(
            for: authenticationInput(for: canonicalContent),
            using: key
        ))
    }

    static func deviceID(
        signingPublicKey: Data,
        wrappingPublicKey: Data
    ) -> String {
        let identity = CanonicalJSONValue.object([
            ("format", .string("key-vault-device-identity")),
            ("version", .integer(3)),
            ("signingPublicKey", .object([
                ("algorithm", .string("P-256-ECDSA")),
                ("encoding", .string("x963")),
                ("value", .string(Base64URL.encode(signingPublicKey)))
            ])),
            ("wrappingPublicKey", .object([
                ("algorithm", .string("P-256-ECDH")),
                ("encoding", .string("x963")),
                ("value", .string(Base64URL.encode(wrappingPublicKey)))
            ]))
        ])
        return Base64URL.encode(Data(SHA256.hash(data: CanonicalJSON.encode(identity))))
    }

    static func canonicalizeP256Signature(_ rawSignature: Data) throws -> Data {
        do {
            return try V3P256Signature.canonicalize(rawSignature)
        } catch {
            throw V3ManifestError.authorizationFailed
        }
    }

    private func authenticate(
        _ candidate: V3ManifestEnvelope,
        vaultKey: Data
    ) throws -> Data {
        let expectedKeyID: V3VaultKeyID
        do {
            expectedKeyID = try V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: candidate.content.manifest.vaultID
            )
        } catch {
            throw V3ManifestError.authenticationFailed
        }
        guard candidate.content.manifest.keyID == expectedKeyID else {
            throw V3ManifestError.authenticationFailed
        }
        let suppliedTag = try decodeBase64URL(
            candidate.authentication.tag,
            expectedByteCount: 32,
            error: .authenticationFailed
        )
        let authenticationKey = try manifestAuthenticationKey(
            vaultKey: vaultKey,
            vaultID: candidate.content.manifest.vaultID
        )
        let input = Self.authenticationInput(for: candidate.canonicalContentBytes)
        guard HMAC<SHA256>.isValidAuthenticationCode(
            suppliedTag,
            authenticating: input,
            using: authenticationKey
        ) else {
            throw V3ManifestError.authenticationFailed
        }
        return input
    }

    private func verifyAuthorizations(
        _ authorizations: [V3ManifestAuthorization],
        input: Data,
        parent: V3ManifestEnvelope
    ) throws {
        guard !authorizations.isEmpty else {
            throw V3ManifestError.authorizationRequired
        }
        try validateAuthorizationOrdering(authorizations)

        let digest = SHA256.hash(data: input)
        for authorization in authorizations {
            guard let signer = parent.content.manifest.devices.first(where: {
                $0.deviceID == authorization.signerDeviceID
            }), signer.role == .owner, signer.status == .active else {
                throw V3ManifestError.authorizationFailed
            }

            let signatureBytes = try decodeBase64URL(
                authorization.signature,
                expectedByteCount: 64,
                error: .authorizationFailed
            )
            guard V3P256Signature.isCanonical(signatureBytes) else {
                throw V3ManifestError.authorizationFailed
            }

            do {
                let publicKeyBytes = try decodeBase64URL(
                    signer.signingPublicKey.value,
                    expectedByteCount: 65,
                    error: .authorizationFailed
                )
                let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyBytes)
                let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                guard publicKey.isValidSignature(signature, for: digest) else {
                    throw V3ManifestError.authorizationFailed
                }
            } catch let error as V3ManifestError {
                throw error
            } catch {
                throw V3ManifestError.authorizationFailed
            }
        }
    }
}

private func manifestError(for error: CanonicalJSONError) -> V3ManifestError {
    switch error {
    case .invalidEncoding:
        .invalidEncoding
    case .invalidJSON:
        .invalidJSON
    case .duplicateProperty:
        .duplicateProperty
    }
}

private enum ManifestDecoder {
    static func decode(
        root: [(String, CanonicalJSONValue)],
        canonicalBytes: Data
    ) throws -> V3ManifestEnvelope {
        try requireFields(
            root,
            required: ["format", "version", "content", "authentication", "authorizations"],
            path: "$"
        )
        let contentValue = try requiredMember("content", in: root, path: "$")
        let contentObject = try object(contentValue, path: "$.content")
        try requireFields(contentObject, required: ["parents", "manifest"], path: "$.content")

        let parents = try decodeParents(
            try requiredMember("parents", in: contentObject, path: "$.content")
        )
        let manifest = try decodeManifest(try requiredMember("manifest", in: contentObject, path: "$.content"))
        let authentication = try decodeAuthentication(
            try requiredMember("authentication", in: root, path: "$")
        )
        let authorizationValues = try array(
            try requiredMember("authorizations", in: root, path: "$"),
            path: "$.authorizations"
        )
        let authorizations = try authorizationValues.enumerated().map {
            try decodeAuthorization($0.element, index: $0.offset)
        }

        return V3ManifestEnvelope(
            content: V3ManifestContent(parents: parents, manifest: manifest),
            authentication: authentication,
            authorizations: authorizations,
            canonicalBytes: canonicalBytes,
            canonicalContentBytes: CanonicalJSON.encode(contentValue)
        )
    }

    private static func decodeParents(_ value: CanonicalJSONValue) throws -> [String] {
        let values = try array(value, path: "$.content.parents")
        var parents: [String] = []
        var previousDigest: Data?

        for (index, value) in values.enumerated() {
            let path = "$.content.parents[\(index)]"
            let parent = try base64URLString(value, length: 43, path: path)
            let digest = try decodeBase64URL(
                parent,
                expectedByteCount: 32,
                error: .invalidStructure(path)
            )
            if let previousDigest,
               !previousDigest.lexicographicallyPrecedes(digest) {
                throw V3ManifestError.invalidStructure("$.content.parents")
            }
            parents.append(parent)
            previousDigest = digest
        }
        return parents
    }

    private static func decodeManifest(_ value: CanonicalJSONValue) throws -> V3ManifestBody {
        let manifest = try object(value, path: "$.content.manifest")
        try requireFields(
            manifest,
            required: [
                "format", "version", "vaultID", "mode", "keyID",
                "devices", "wrappedKeys", "entries"
            ],
            path: "$.content.manifest"
        )
        try requireConstant(
            "key-vault-manifest",
            value: requiredMember("format", in: manifest, path: "$.content.manifest"),
            path: "$.content.manifest.format"
        )
        try requireConstant(
            3,
            value: requiredMember("version", in: manifest, path: "$.content.manifest"),
            path: "$.content.manifest.version"
        )

        let modeValue = try string(
            requiredMember("mode", in: manifest, path: "$.content.manifest"),
            path: "$.content.manifest.mode"
        )
        guard let mode = V3VaultMode(rawValue: modeValue) else {
            throw V3ManifestError.invalidStructure("$.content.manifest.mode")
        }

        let devices = try array(
            requiredMember("devices", in: manifest, path: "$.content.manifest"),
            path: "$.content.manifest.devices"
        ).enumerated().map {
            try decodeDevice($0.element, index: $0.offset)
        }
        let wrappedKeys = try array(
            requiredMember("wrappedKeys", in: manifest, path: "$.content.manifest"),
            path: "$.content.manifest.wrappedKeys"
        ).enumerated().map {
            try decodeWrappedKey($0.element, index: $0.offset)
        }
        let entries = try array(
            requiredMember("entries", in: manifest, path: "$.content.manifest"),
            path: "$.content.manifest.entries"
        ).enumerated().map {
            try decodeEntry($0.element, index: $0.offset)
        }

        return V3ManifestBody(
            vaultID: try uuidString(
                requiredMember("vaultID", in: manifest, path: "$.content.manifest"),
                path: "$.content.manifest.vaultID"
            ),
            mode: mode,
            keyID: try vaultKeyID(
                requiredMember("keyID", in: manifest, path: "$.content.manifest"),
                path: "$.content.manifest.keyID"
            ),
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: entries
        )
    }

    private static func decodeDevice(_ value: CanonicalJSONValue, index: Int) throws -> V3ManifestDevice {
        let path = "$.content.manifest.devices[\(index)]"
        let device = try object(value, path: path)
        try requireFields(
            device,
            required: [
                "deviceID", "displayName", "role", "status", "signingPublicKey",
                "wrappingPublicKey"
            ],
            path: path
        )

        let roleValue = try string(requiredMember("role", in: device, path: path), path: "\(path).role")
        let statusValue = try string(requiredMember("status", in: device, path: path), path: "\(path).status")
        guard let role = V3DeviceRole(rawValue: roleValue) else {
            throw V3ManifestError.invalidStructure("\(path).role")
        }
        guard let status = V3DeviceStatus(rawValue: statusValue) else {
            throw V3ManifestError.invalidStructure("\(path).status")
        }

        return V3ManifestDevice(
            deviceID: try base64URLString(
                requiredMember("deviceID", in: device, path: path),
                length: 43,
                path: "\(path).deviceID"
            ),
            displayName: try string(
                requiredMember("displayName", in: device, path: path),
                path: "\(path).displayName"
            ),
            role: role,
            status: status,
            signingPublicKey: try decodePublicKey(
                requiredMember("signingPublicKey", in: device, path: path),
                algorithm: "P-256-ECDSA",
                path: "\(path).signingPublicKey"
            ),
            wrappingPublicKey: try decodePublicKey(
                requiredMember("wrappingPublicKey", in: device, path: path),
                algorithm: "P-256-ECDH",
                path: "\(path).wrappingPublicKey"
            )
        )
    }

    private static func decodePublicKey(
        _ value: CanonicalJSONValue,
        algorithm: String,
        path: String
    ) throws -> V3DevicePublicKey {
        let key = try object(value, path: path)
        try requireFields(key, required: ["algorithm", "encoding", "value"], path: path)
        try requireConstant(
            algorithm,
            value: requiredMember("algorithm", in: key, path: path),
            path: "\(path).algorithm"
        )
        try requireConstant(
            "x963",
            value: requiredMember("encoding", in: key, path: path),
            path: "\(path).encoding"
        )
        return V3DevicePublicKey(value: try base64URLString(
            requiredMember("value", in: key, path: path),
            length: 87,
            path: "\(path).value"
        ))
    }

    private static func decodeWrappedKey(_ value: CanonicalJSONValue, index: Int) throws -> V3WrappedKey {
        let path = "$.content.manifest.wrappedKeys[\(index)]"
        let wrappedKey = try object(value, path: path)
        try requireFields(
            wrappedKey,
            required: ["deviceID", "algorithm", "ciphertext"],
            path: path
        )
        try requireConstant(
            "p256-ecies-x963-sha256-aes-gcm",
            value: requiredMember("algorithm", in: wrappedKey, path: path),
            path: "\(path).algorithm"
        )
        return V3WrappedKey(
            deviceID: try base64URLString(
                requiredMember("deviceID", in: wrappedKey, path: path),
                length: 43,
                path: "\(path).deviceID"
            ),
            ciphertext: try base64URLString(
                requiredMember("ciphertext", in: wrappedKey, path: path),
                path: "\(path).ciphertext"
            )
        )
    }

    private static func decodeEntry(_ value: CanonicalJSONValue, index: Int) throws -> V3ManifestEntry {
        let path = "$.content.manifest.entries[\(index)]"
        let entry = try object(value, path: path)
        try requireFields(
            entry,
            required: ["entryID", "name", "type", "revision", "keyID", "ciphertextDigest"],
            path: path
        )
        let typeValue = try string(requiredMember("type", in: entry, path: path), path: "\(path).type")
        guard let type = SecretEntryType(rawValue: typeValue) else {
            throw V3ManifestError.invalidStructure("\(path).type")
        }
        let revision = try integer(
            requiredMember("revision", in: entry, path: path),
            path: "\(path).revision"
        )
        guard revision > 0 else {
            throw V3ManifestError.invalidStructure("\(path).revision")
        }
        return V3ManifestEntry(
            entryID: try uuidString(
                requiredMember("entryID", in: entry, path: path),
                path: "\(path).entryID"
            ),
            name: try string(requiredMember("name", in: entry, path: path), path: "\(path).name"),
            type: type,
            revision: revision,
            keyID: try vaultKeyID(
                requiredMember("keyID", in: entry, path: path),
                path: "\(path).keyID"
            ),
            ciphertextDigest: try base64URLString(
                requiredMember("ciphertextDigest", in: entry, path: path),
                length: 43,
                path: "\(path).ciphertextDigest"
            )
        )
    }

    private static func decodeAuthentication(_ value: CanonicalJSONValue) throws -> V3ManifestAuthentication {
        let path = "$.authentication"
        let authentication = try object(value, path: path)
        try requireFields(authentication, required: ["algorithm", "tag"], path: path)
        try requireConstant(
            "HKDF-SHA256+HMAC-SHA256",
            value: requiredMember("algorithm", in: authentication, path: path),
            path: "\(path).algorithm"
        )
        return V3ManifestAuthentication(
            tag: try base64URLString(
                requiredMember("tag", in: authentication, path: path),
                length: 43,
                path: "\(path).tag"
            )
        )
    }

    private static func decodeAuthorization(
        _ value: CanonicalJSONValue,
        index: Int
    ) throws -> V3ManifestAuthorization {
        let path = "$.authorizations[\(index)]"
        let authorization = try object(value, path: path)
        try requireFields(
            authorization,
            required: ["algorithm", "signerDeviceID", "signature"],
            path: path
        )
        try requireConstant(
            "P-256-ECDSA-SHA256",
            value: requiredMember("algorithm", in: authorization, path: path),
            path: "\(path).algorithm"
        )
        return V3ManifestAuthorization(
            signerDeviceID: try base64URLString(
                requiredMember("signerDeviceID", in: authorization, path: path),
                length: 43,
                path: "\(path).signerDeviceID"
            ),
            signature: try base64URLString(
                requiredMember("signature", in: authorization, path: path),
                length: 86,
                path: "\(path).signature"
            )
        )
    }
}

private func validateSemantics(_ manifest: V3ManifestBody) throws {
    try validateDisplayNames(manifest.devices)
    try validateDeviceOrderingAndIdentity(manifest.devices)
    try validateWrappedKeyOrdering(manifest.wrappedKeys)
    try validateEntryOrdering(manifest.entries)
    try validateModeSpecificMembership(manifest)
}

private func validateDisplayNames(_ devices: [V3ManifestDevice]) throws {
    for device in devices {
        guard isValidV3DeviceDisplayName(device.displayName) else {
            throw V3ManifestError.semanticViolation("devices.displayName")
        }
    }
}

private func validateDeviceOrderingAndIdentity(_ devices: [V3ManifestDevice]) throws {
    var previousID: String?
    for device in devices {
        if let previousID, !utf8Precedes(previousID, device.deviceID) {
            throw V3ManifestError.semanticViolation("devices.order")
        }
        previousID = device.deviceID

        let signingBytes = try decodeBase64URL(
            device.signingPublicKey.value,
            expectedByteCount: 65,
            error: .semanticViolation("devices.signingPublicKey")
        )
        let wrappingBytes = try decodeBase64URL(
            device.wrappingPublicKey.value,
            expectedByteCount: 65,
            error: .semanticViolation("devices.wrappingPublicKey")
        )
        guard signingBytes != wrappingBytes,
              signingBytes.first == 0x04,
              wrappingBytes.first == 0x04
        else {
            throw V3ManifestError.semanticViolation("devices.publicKeys")
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: signingBytes)
            _ = try P256.KeyAgreement.PublicKey(x963Representation: wrappingBytes)
        } catch {
            throw V3ManifestError.semanticViolation("devices.publicKeys")
        }

        let expectedID = V3ManifestAuthenticator.deviceID(
            signingPublicKey: signingBytes,
            wrappingPublicKey: wrappingBytes
        )
        guard device.deviceID == expectedID else {
            throw V3ManifestError.semanticViolation("devices.deviceID")
        }
    }
}

private func validateWrappedKeyOrdering(_ wrappedKeys: [V3WrappedKey]) throws {
    var previousDeviceID: String?
    for wrappedKey in wrappedKeys {
        _ = try decodeBase64URL(
            wrappedKey.ciphertext,
            error: .semanticViolation("wrappedKeys.ciphertext")
        )
        if let previousDeviceID,
           !utf8Precedes(previousDeviceID, wrappedKey.deviceID) {
            throw V3ManifestError.semanticViolation("wrappedKeys.order")
        }
        previousDeviceID = wrappedKey.deviceID
    }
}

private func validateModeSpecificMembership(_ manifest: V3ManifestBody) throws {
    switch manifest.mode {
    case .local:
        guard manifest.devices.isEmpty else {
            throw V3ManifestError.semanticViolation("devices.localMode")
        }
        guard manifest.wrappedKeys.isEmpty else {
            throw V3ManifestError.semanticViolation("wrappedKeys.localMode")
        }
    case .shared:
        let activeDevices = manifest.devices.filter { $0.status == .active }
        guard activeDevices.contains(where: { $0.role == .owner }) else {
            throw V3ManifestError.semanticViolation("devices.activeOwner")
        }

        let activeDeviceIDs = Set(activeDevices.map(\.deviceID))
        for wrappedKey in manifest.wrappedKeys {
            guard activeDeviceIDs.contains(wrappedKey.deviceID) else {
                throw V3ManifestError.semanticViolation("wrappedKeys.deviceID")
            }
        }

        let wrappedDeviceIDs = Set(manifest.wrappedKeys.map(\.deviceID))
        guard wrappedDeviceIDs == activeDeviceIDs,
              manifest.wrappedKeys.count == activeDeviceIDs.count
        else {
            throw V3ManifestError.semanticViolation("wrappedKeys.coverage")
        }
    }
}

private func validateEntryOrdering(_ entries: [V3ManifestEntry]) throws {
    var previous: V3ManifestEntry?
    var entryIDs = Set<String>()
    var names = Set<Data>()
    for entry in entries {
        try validateEntryName(entry.name)
        _ = try decodeBase64URL(
            entry.ciphertextDigest,
            expectedByteCount: 32,
            error: .semanticViolation("entries.ciphertextDigest")
        )
        guard entryIDs.insert(entry.entryID).inserted,
              names.insert(Data(entry.name.utf8)).inserted
        else {
            throw V3ManifestError.semanticViolation("entries.duplicate")
        }
        if let previous {
            let correctlyOrdered = utf8Precedes(previous.name, entry.name)
                || (previous.name == entry.name && utf8Precedes(previous.entryID, entry.entryID))
            guard correctlyOrdered else {
                throw V3ManifestError.semanticViolation("entries.order")
            }
        }
        previous = entry
    }
}

private func validateEntryName(_ name: String) throws {
    guard isValidV3EntryName(name) else {
        throw V3ManifestError.semanticViolation("entries.name")
    }
}

private func authorityChanged(from parent: V3ManifestBody, to candidate: V3ManifestBody) -> Bool {
    parent.mode != candidate.mode
        || parent.keyID != candidate.keyID
        || parent.devices != candidate.devices
        || parent.wrappedKeys != candidate.wrappedKeys
}

func hasSameV3ManifestAuthority(_ lhs: V3ManifestBody, _ rhs: V3ManifestBody) -> Bool {
    lhs.vaultID == rhs.vaultID
        && !authorityChanged(from: lhs, to: rhs)
}

private func validateAuthorizationOrdering(
    _ authorizations: [V3ManifestAuthorization]
) throws {
    var previousID: String?
    for authorization in authorizations {
        if let previousID, !utf8Precedes(previousID, authorization.signerDeviceID) {
            throw V3ManifestError.authorizationFailed
        }
        previousID = authorization.signerDeviceID
    }
}

private func manifestAuthenticationKey(
    vaultKey: Data,
    vaultID: String
) throws -> SymmetricKey {
    guard let salt = v3UUIDBytes(vaultID) else {
        throw V3ManifestError.invalidStructure("$.content.manifest.vaultID")
    }
    return HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: vaultKey),
        salt: salt,
        info: Data("work.tvr.key/v3/manifest-auth-key".utf8),
        outputByteCount: 32
    )
}

private func decodeBase64URL(
    _ value: String,
    expectedByteCount: Int? = nil,
    error: V3ManifestError = .invalidStructure("base64url")
) throws -> Data {
    guard !value.isEmpty,
          let decoded = Base64URL.decodeCanonical(value),
          expectedByteCount.map({ decoded.count == $0 }) ?? true
    else {
        throw error
    }
    return decoded
}

private func utf8Precedes(_ lhs: String, _ rhs: String) -> Bool {
    Array(lhs.utf8).lexicographicallyPrecedes(Array(rhs.utf8))
}

private func stringMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    optionalMember(name, in: object)?.stringValue
}

private func integerMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    optionalMember(name, in: object)?.integerValue
}

private func optionalMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func requiredMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> CanonicalJSONValue {
    guard let value = optionalMember(name, in: object) else {
        throw V3ManifestError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func object(
    _ value: CanonicalJSONValue,
    path: String
) throws -> [(String, CanonicalJSONValue)] {
    guard let object = value.objectValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return object
}

private func array(
    _ value: CanonicalJSONValue,
    path: String
) throws -> [CanonicalJSONValue] {
    guard let array = value.arrayValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return array
}

private func string(
    _ value: CanonicalJSONValue,
    path: String
) throws -> String {
    guard let string = value.stringValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return string
}

private func integer(
    _ value: CanonicalJSONValue,
    path: String
) throws -> UInt64 {
    guard let integer = value.integerValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return integer
}

private func requireFields(
    _ object: [(String, CanonicalJSONValue)],
    required: Set<String>,
    optional: Set<String> = [],
    path: String
) throws {
    let names = Set(object.map(\.0))
    guard required.isSubset(of: names),
          names.isSubset(of: required.union(optional))
    else {
        throw V3ManifestError.invalidStructure(path)
    }
}

private func requireConstant(
    _ expected: String,
    value: CanonicalJSONValue,
    path: String
) throws {
    guard value.stringValue == expected else {
        throw V3ManifestError.invalidStructure(path)
    }
}

private func requireConstant(
    _ expected: UInt64,
    value: CanonicalJSONValue,
    path: String
) throws {
    guard value.integerValue == expected else {
        throw V3ManifestError.invalidStructure(path)
    }
}

private func uuidString(
    _ value: CanonicalJSONValue,
    path: String
) throws -> String {
    let string = try string(value, path: path)
    guard isValidV3UUID(string) else {
        throw V3ManifestError.invalidStructure(path)
    }
    return string
}

private func vaultKeyID(
    _ value: CanonicalJSONValue,
    path: String
) throws -> V3VaultKeyID {
    let rawValue = try base64URLString(value, length: 43, path: path)
    do {
        return try V3VaultKeyID(rawValue: rawValue)
    } catch {
        throw V3ManifestError.invalidStructure(path)
    }
}

private func base64URLString(
    _ value: CanonicalJSONValue,
    length: Int? = nil,
    path: String
) throws -> String {
    let string = try string(value, path: path)
    guard !string.isEmpty,
          length.map({ string.utf8.count == $0 }) ?? true,
          Base64URL.decodeCanonical(string) != nil
    else {
        throw V3ManifestError.invalidStructure(path)
    }
    return string
}
