import CryptoKit
import Foundation

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
            "Manifest envelope does not extend the trusted parent."
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
    public let enrolledAtGeneration: UInt64
    public let revokedAtGeneration: UInt64?
}

public struct V3WrappedKey: Equatable, Sendable {
    public let deviceID: String
    public let keyEpoch: UInt64
    public let ciphertext: String
}

public struct V3ManifestEntry: Equatable, Sendable {
    public let entryID: String
    public let name: String
    public let type: SecretEntryType
    public let revision: UInt64
    public let keyEpoch: UInt64
    public let ciphertextDigest: String
}

public struct V3ManifestBody: Equatable, Sendable {
    public let vaultID: String
    public let mode: V3VaultMode
    public let generation: UInt64
    public let keyEpoch: UInt64
    public let devices: [V3ManifestDevice]
    public let wrappedKeys: [V3WrappedKey]
    public let entries: [V3ManifestEntry]
}

public enum V3ManifestParent: Equatable, Sendable {
    case genesis
    case manifest(generation: UInt64, digest: String)
}

public struct V3ManifestContent: Equatable, Sendable {
    public let parent: V3ManifestParent
    public let manifest: V3ManifestBody
}

public struct V3ManifestAuthentication: Equatable, Sendable {
    public let keyEpoch: UInt64
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

public enum V3ManifestTrustAnchor: Equatable, Sendable {
    /// The caller independently trusts local creation of this vault identity.
    case localGenesis(vaultID: String)
    /// The exact, already-trusted current envelope bytes.
    case parent(Data)
}

public struct V3ManifestAuthenticator: Sendable {
    public init() {}

    public func parse(_ data: Data) throws -> V3ManifestEnvelope {
        let json = try V3CanonicalJSON.parse(data)
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

        let canonical = V3CanonicalJSON.encode(json)
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
        let parent: V3ManifestEnvelope?

        switch trustAnchor {
        case let .localGenesis(expectedVaultID):
            guard candidate.content.parent == .genesis,
                  candidate.content.manifest.mode == .local,
                  candidate.content.manifest.vaultID == expectedVaultID
            else {
                throw V3ManifestError.parentMismatch
            }
            guard candidate.authorizations.isEmpty else {
                throw V3ManifestError.unexpectedAuthorization
            }
            parent = nil
        case let .parent(parentData):
            let parsedParent = try parse(parentData)
            try validateSemantics(parsedParent.content.manifest)
            guard case let .manifest(generation, digest) = candidate.content.parent,
                  generation == parsedParent.content.manifest.generation,
                  candidate.content.manifest.generation == generation + 1,
                  candidate.content.manifest.vaultID == parsedParent.content.manifest.vaultID,
                  try decodeBase64URL(digest, expectedByteCount: 32)
                    == Data(SHA256.hash(data: parentData))
            else {
                throw V3ManifestError.parentMismatch
            }
            parent = parsedParent
        }

        guard candidate.authentication.keyEpoch == candidate.content.manifest.keyEpoch else {
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

        if let parent {
            if authorityChanged(from: parent.content.manifest, to: candidate.content.manifest) {
                try verifyAuthorizations(candidate.authorizations, input: input, parent: parent)
            } else if !candidate.authorizations.isEmpty {
                throw V3ManifestError.unexpectedAuthorization
            }
        }

        try validateSemantics(candidate.content.manifest)
        try validateAuthorizationOrdering(candidate.authorizations)

        return V3VerifiedManifest(
            envelope: candidate,
            envelopeDigest: Data(SHA256.hash(data: candidateData))
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
        let identity = V3JSONValue.object([
            ("format", .string("key-vault-device-identity")),
            ("version", .integer(3)),
            ("signingPublicKey", .object([
                ("algorithm", .string("P-256-ECDSA")),
                ("encoding", .string("x963")),
                ("value", .string(encodeBase64URL(signingPublicKey)))
            ])),
            ("wrappingPublicKey", .object([
                ("algorithm", .string("P-256-ECDH")),
                ("encoding", .string("x963")),
                ("value", .string(encodeBase64URL(wrappingPublicKey)))
            ]))
        ])
        return encodeBase64URL(Data(SHA256.hash(data: V3CanonicalJSON.encode(identity))))
    }

    static func canonicalizeP256Signature(_ rawSignature: Data) throws -> Data {
        guard rawSignature.count == 64 else {
            throw V3ManifestError.authorizationFailed
        }
        let order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
            0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
        ]
        var result = Array(rawSignature)
        let s = Array(result[32..<64])
        if !isLowP256Scalar(s) {
            var normalized = [UInt8](repeating: 0, count: 32)
            var borrow = 0
            for index in stride(from: 31, through: 0, by: -1) {
                let difference = Int(order[index]) - Int(s[index]) - borrow
                if difference < 0 {
                    normalized[index] = UInt8(difference + 256)
                    borrow = 1
                } else {
                    normalized[index] = UInt8(difference)
                    borrow = 0
                }
            }
            result.replaceSubrange(32..<64, with: normalized)
        }
        return Data(result)
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
            guard isLowP256Scalar(Array(signatureBytes.suffix(32))) else {
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

private enum ManifestDecoder {
    static func decode(
        root: [(String, V3JSONValue)],
        canonicalBytes: Data
    ) throws -> V3ManifestEnvelope {
        try requireFields(
            root,
            required: ["format", "version", "content", "authentication", "authorizations"],
            path: "$"
        )
        let contentValue = try requiredMember("content", in: root, path: "$")
        let contentObject = try object(contentValue, path: "$.content")
        try requireFields(contentObject, required: ["parent", "manifest"], path: "$.content")

        let parent = try decodeParent(try requiredMember("parent", in: contentObject, path: "$.content"))
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
            content: V3ManifestContent(parent: parent, manifest: manifest),
            authentication: authentication,
            authorizations: authorizations,
            canonicalBytes: canonicalBytes,
            canonicalContentBytes: V3CanonicalJSON.encode(contentValue)
        )
    }

    private static func decodeParent(_ value: V3JSONValue) throws -> V3ManifestParent {
        let parent = try object(value, path: "$.content.parent")
        let kind = try string(
            try requiredMember("kind", in: parent, path: "$.content.parent"),
            path: "$.content.parent.kind"
        )
        switch kind {
        case "genesis":
            try requireFields(parent, required: ["kind"], path: "$.content.parent")
            return .genesis
        case "manifest":
            try requireFields(
                parent,
                required: ["kind", "generation", "digest"],
                path: "$.content.parent"
            )
            return .manifest(
                generation: try integer(
                    try requiredMember("generation", in: parent, path: "$.content.parent"),
                    path: "$.content.parent.generation"
                ),
                digest: try base64URLString(
                    try requiredMember("digest", in: parent, path: "$.content.parent"),
                    length: 43,
                    path: "$.content.parent.digest"
                )
            )
        default:
            throw V3ManifestError.invalidStructure("$.content.parent.kind")
        }
    }

    private static func decodeManifest(_ value: V3JSONValue) throws -> V3ManifestBody {
        let manifest = try object(value, path: "$.content.manifest")
        try requireFields(
            manifest,
            required: [
                "format", "version", "vaultID", "mode", "generation", "keyEpoch",
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
            generation: try integer(
                requiredMember("generation", in: manifest, path: "$.content.manifest"),
                path: "$.content.manifest.generation"
            ),
            keyEpoch: try integer(
                requiredMember("keyEpoch", in: manifest, path: "$.content.manifest"),
                path: "$.content.manifest.keyEpoch"
            ),
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: entries
        )
    }

    private static func decodeDevice(_ value: V3JSONValue, index: Int) throws -> V3ManifestDevice {
        let path = "$.content.manifest.devices[\(index)]"
        let device = try object(value, path: path)
        try requireFields(
            device,
            required: [
                "deviceID", "displayName", "role", "status", "signingPublicKey",
                "wrappingPublicKey", "enrolledAtGeneration"
            ],
            optional: ["revokedAtGeneration"],
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
            ),
            enrolledAtGeneration: try integer(
                requiredMember("enrolledAtGeneration", in: device, path: path),
                path: "\(path).enrolledAtGeneration"
            ),
            revokedAtGeneration: try optionalMember("revokedAtGeneration", in: device).map {
                try integer($0, path: "\(path).revokedAtGeneration")
            }
        )
    }

    private static func decodePublicKey(
        _ value: V3JSONValue,
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

    private static func decodeWrappedKey(_ value: V3JSONValue, index: Int) throws -> V3WrappedKey {
        let path = "$.content.manifest.wrappedKeys[\(index)]"
        let wrappedKey = try object(value, path: path)
        try requireFields(
            wrappedKey,
            required: ["deviceID", "keyEpoch", "algorithm", "ciphertext"],
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
            keyEpoch: try integer(
                requiredMember("keyEpoch", in: wrappedKey, path: path),
                path: "\(path).keyEpoch"
            ),
            ciphertext: try base64URLString(
                requiredMember("ciphertext", in: wrappedKey, path: path),
                path: "\(path).ciphertext"
            )
        )
    }

    private static func decodeEntry(_ value: V3JSONValue, index: Int) throws -> V3ManifestEntry {
        let path = "$.content.manifest.entries[\(index)]"
        let entry = try object(value, path: path)
        try requireFields(
            entry,
            required: ["entryID", "name", "type", "revision", "keyEpoch", "ciphertextDigest"],
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
            keyEpoch: try integer(
                requiredMember("keyEpoch", in: entry, path: path),
                path: "\(path).keyEpoch"
            ),
            ciphertextDigest: try base64URLString(
                requiredMember("ciphertextDigest", in: entry, path: path),
                length: 43,
                path: "\(path).ciphertextDigest"
            )
        )
    }

    private static func decodeAuthentication(_ value: V3JSONValue) throws -> V3ManifestAuthentication {
        let path = "$.authentication"
        let authentication = try object(value, path: path)
        try requireFields(authentication, required: ["algorithm", "keyEpoch", "tag"], path: path)
        try requireConstant(
            "HKDF-SHA256+HMAC-SHA256",
            value: requiredMember("algorithm", in: authentication, path: path),
            path: "\(path).algorithm"
        )
        return V3ManifestAuthentication(
            keyEpoch: try integer(
                requiredMember("keyEpoch", in: authentication, path: path),
                path: "\(path).keyEpoch"
            ),
            tag: try base64URLString(
                requiredMember("tag", in: authentication, path: path),
                length: 43,
                path: "\(path).tag"
            )
        )
    }

    private static func decodeAuthorization(
        _ value: V3JSONValue,
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
    try validateWrappedKeyOrdering(manifest.wrappedKeys, manifestKeyEpoch: manifest.keyEpoch)
    try validateEntryOrdering(manifest.entries, manifestKeyEpoch: manifest.keyEpoch)

    for device in manifest.devices {
        guard device.enrolledAtGeneration <= manifest.generation else {
            throw V3ManifestError.semanticViolation("devices.enrolledAtGeneration")
        }
        switch (device.status, device.revokedAtGeneration) {
        case (.active, nil):
            break
        case let (.revoked, .some(generation))
            where generation >= device.enrolledAtGeneration && generation <= manifest.generation:
            break
        default:
            throw V3ManifestError.semanticViolation("devices.revokedAtGeneration")
        }
    }
}

private func validateDisplayNames(_ devices: [V3ManifestDevice]) throws {
    for device in devices {
        let name = device.displayName
        guard !name.isEmpty,
              name.unicodeScalars.count <= 128,
              Data(name.utf8) == Data(name.precomposedStringWithCanonicalMapping.utf8),
              !name.unicodeScalars.contains(where: isControlCharacter)
        else {
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

private func validateWrappedKeyOrdering(
    _ wrappedKeys: [V3WrappedKey],
    manifestKeyEpoch: UInt64
) throws {
    var previous: V3WrappedKey?
    var seen = Set<String>()
    for wrappedKey in wrappedKeys {
        guard wrappedKey.keyEpoch <= manifestKeyEpoch else {
            throw V3ManifestError.semanticViolation("wrappedKeys.keyEpoch")
        }
        _ = try decodeBase64URL(
            wrappedKey.ciphertext,
            error: .semanticViolation("wrappedKeys.ciphertext")
        )
        let identity = "\(wrappedKey.keyEpoch):\(wrappedKey.deviceID)"
        guard seen.insert(identity).inserted else {
            throw V3ManifestError.semanticViolation("wrappedKeys.duplicate")
        }
        if let previous {
            let correctlyOrdered = previous.keyEpoch < wrappedKey.keyEpoch
                || (previous.keyEpoch == wrappedKey.keyEpoch
                    && utf8Precedes(previous.deviceID, wrappedKey.deviceID))
            guard correctlyOrdered else {
                throw V3ManifestError.semanticViolation("wrappedKeys.order")
            }
        }
        previous = wrappedKey
    }
}

private func validateEntryOrdering(
    _ entries: [V3ManifestEntry],
    manifestKeyEpoch: UInt64
) throws {
    var previous: V3ManifestEntry?
    var entryIDs = Set<String>()
    var names = Set<Data>()
    for entry in entries {
        try validateEntryName(entry.name)
        guard entry.keyEpoch <= manifestKeyEpoch else {
            throw V3ManifestError.semanticViolation("entries.keyEpoch")
        }
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
    let utf8 = Data(name.utf8)
    let segments = name.split(separator: "/", omittingEmptySubsequences: false)
    guard !name.isEmpty,
          name.unicodeScalars.count <= 1_024,
          utf8.count <= 1_024,
          utf8 == Data(name.precomposedStringWithCanonicalMapping.utf8),
          name.first != "/", name.last != "/",
          !name.contains("\\"),
          !name.unicodeScalars.contains(where: isControlCharacter),
          let first = name.unicodeScalars.first,
          let last = name.unicodeScalars.last,
          !CharacterSet.whitespacesAndNewlines.contains(first),
          !CharacterSet.whitespacesAndNewlines.contains(last),
          segments.allSatisfy({
              !$0.isEmpty && $0 != "." && $0 != ".." && $0.utf8.count <= 255
          })
    else {
        throw V3ManifestError.semanticViolation("entries.name")
    }
}

private func authorityChanged(from parent: V3ManifestBody, to candidate: V3ManifestBody) -> Bool {
    parent.mode != candidate.mode
        || parent.keyEpoch != candidate.keyEpoch
        || parent.devices != candidate.devices
        || parent.wrappedKeys != candidate.wrappedKeys
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
    guard let salt = uuidBytes(vaultID) else {
        throw V3ManifestError.invalidStructure("$.content.manifest.vaultID")
    }
    return HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: vaultKey),
        salt: salt,
        info: Data("work.tvr.key/v3/manifest-auth-key".utf8),
        outputByteCount: 32
    )
}

private func uuidBytes(_ value: String) -> Data? {
    let compact = value.replacingOccurrences(of: "-", with: "")
    guard compact.count == 32 else {
        return nil
    }
    var bytes = Data()
    bytes.reserveCapacity(16)
    var index = compact.startIndex
    for _ in 0..<16 {
        let next = compact.index(index, offsetBy: 2)
        guard let byte = UInt8(compact[index..<next], radix: 16) else {
            return nil
        }
        bytes.append(byte)
        index = next
    }
    return bytes
}

private func encodeBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func decodeBase64URL(
    _ value: String,
    expectedByteCount: Int? = nil,
    error: V3ManifestError = .invalidStructure("base64url")
) throws -> Data {
    guard !value.isEmpty,
          value.utf8.allSatisfy({
              ($0 >= CharacterByteForBase64.upperA && $0 <= CharacterByteForBase64.upperZ)
                  || ($0 >= CharacterByteForBase64.lowerA && $0 <= CharacterByteForBase64.lowerZ)
                  || ($0 >= CharacterByteForBase64.zero && $0 <= CharacterByteForBase64.nine)
                  || $0 == CharacterByteForBase64.hyphen
                  || $0 == CharacterByteForBase64.underscore
          })
    else {
        throw error
    }
    var standard = value
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
    guard let decoded = Data(base64Encoded: standard),
          encodeBase64URL(decoded) == value,
          expectedByteCount.map({ decoded.count == $0 }) ?? true
    else {
        throw error
    }
    return decoded
}

private func isLowP256Scalar(_ scalar: [UInt8]) -> Bool {
    let halfOrder: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
        0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
    ]
    guard scalar.count == 32 else {
        return false
    }
    return scalar == halfOrder || scalar.lexicographicallyPrecedes(halfOrder)
}

private func utf8Precedes(_ lhs: String, _ rhs: String) -> Bool {
    Array(lhs.utf8).lexicographicallyPrecedes(Array(rhs.utf8))
}

private func isControlCharacter(_ scalar: UnicodeScalar) -> Bool {
    scalar.value <= 0x1F || (0x7F...0x9F).contains(scalar.value)
}

private func stringMember(
    _ name: String,
    in object: [(String, V3JSONValue)]
) -> String? {
    optionalMember(name, in: object)?.stringValue
}

private func integerMember(
    _ name: String,
    in object: [(String, V3JSONValue)]
) -> UInt64? {
    optionalMember(name, in: object)?.integerValue
}

private func optionalMember(
    _ name: String,
    in object: [(String, V3JSONValue)]
) -> V3JSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func requiredMember(
    _ name: String,
    in object: [(String, V3JSONValue)],
    path: String
) throws -> V3JSONValue {
    guard let value = optionalMember(name, in: object) else {
        throw V3ManifestError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func object(
    _ value: V3JSONValue,
    path: String
) throws -> [(String, V3JSONValue)] {
    guard let object = value.objectValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return object
}

private func array(
    _ value: V3JSONValue,
    path: String
) throws -> [V3JSONValue] {
    guard let array = value.arrayValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return array
}

private func string(
    _ value: V3JSONValue,
    path: String
) throws -> String {
    guard let string = value.stringValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return string
}

private func integer(
    _ value: V3JSONValue,
    path: String
) throws -> UInt64 {
    guard let integer = value.integerValue else {
        throw V3ManifestError.invalidStructure(path)
    }
    return integer
}

private func requireFields(
    _ object: [(String, V3JSONValue)],
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
    value: V3JSONValue,
    path: String
) throws {
    guard value.stringValue == expected else {
        throw V3ManifestError.invalidStructure(path)
    }
}

private func requireConstant(
    _ expected: UInt64,
    value: V3JSONValue,
    path: String
) throws {
    guard value.integerValue == expected else {
        throw V3ManifestError.invalidStructure(path)
    }
}

private func uuidString(
    _ value: V3JSONValue,
    path: String
) throws -> String {
    let string = try string(value, path: path)
    let characters = Array(string.utf8)
    guard characters.count == 36,
          characters.enumerated().allSatisfy({ index, byte in
              if [8, 13, 18, 23].contains(index) {
                  return byte == CharacterByteForBase64.hyphen
              }
              return (byte >= CharacterByteForBase64.zero && byte <= CharacterByteForBase64.nine)
                  || (byte >= CharacterByteForBase64.lowerA && byte <= CharacterByteForBase64.lowerF)
          }),
          UUID(uuidString: string) != nil
    else {
        throw V3ManifestError.invalidStructure(path)
    }
    return string
}

private func base64URLString(
    _ value: V3JSONValue,
    length: Int? = nil,
    path: String
) throws -> String {
    let string = try string(value, path: path)
    guard !string.isEmpty,
          length.map({ string.utf8.count == $0 }) ?? true,
          string.utf8.allSatisfy({
              ($0 >= CharacterByteForBase64.upperA && $0 <= CharacterByteForBase64.upperZ)
                  || ($0 >= CharacterByteForBase64.lowerA && $0 <= CharacterByteForBase64.lowerZ)
                  || ($0 >= CharacterByteForBase64.zero && $0 <= CharacterByteForBase64.nine)
                  || $0 == CharacterByteForBase64.hyphen
                  || $0 == CharacterByteForBase64.underscore
          })
    else {
        throw V3ManifestError.invalidStructure(path)
    }
    return string
}

private enum CharacterByteForBase64 {
    static let upperA = UInt8(ascii: "A")
    static let upperZ = UInt8(ascii: "Z")
    static let lowerA = UInt8(ascii: "a")
    static let lowerF = UInt8(ascii: "f")
    static let lowerZ = UInt8(ascii: "z")
    static let zero = UInt8(ascii: "0")
    static let nine = UInt8(ascii: "9")
    static let hyphen = UInt8(ascii: "-")
    static let underscore = UInt8(ascii: "_")
}
