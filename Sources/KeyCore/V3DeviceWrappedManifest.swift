import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3DeviceWrappedManifestError: Error, Equatable, LocalizedError {
    case invalidEncoding
    case invalidJSON
    case nonCanonicalJSON
    case invalidStructure(String)
    case unsupportedProfileVersion(UInt64)
    case semanticViolation(String)

    var errorDescription: String? {
        switch self {
        case .invalidEncoding:
            "The permanent version 3 manifest is not valid UTF-8."
        case .invalidJSON:
            "The permanent version 3 manifest is not valid JSON."
        case .nonCanonicalJSON:
            "The permanent version 3 manifest is not canonical JSON."
        case let .invalidStructure(path):
            "The permanent version 3 manifest has an invalid value at '\(path)'."
        case let .unsupportedProfileVersion(version):
            "Device-wrapped vault profile version \(version) requires a newer version of Key."
        case let .semanticViolation(field):
            "The permanent version 3 manifest violates the '\(field)' invariant."
        }
    }
}

/// One authenticated roster member in the permanent device-wrapped profile.
struct V3DeviceWrappedManifestDevice: Equatable, Sendable {
    let identity: V3EnrollmentDeviceIdentity
    let role: V3DeviceRole
    let status: V3DeviceStatus
}

/// One RFC 9180 output addressed to an active device in the roster.
struct V3DeviceWrappedManifestKey: Equatable, Sendable {
    let recipientDeviceID: String
    let wrappedKey: V3HPKEWrappedVaultKey

    init(
        recipientDeviceID: String,
        wrappedKey: V3HPKEWrappedVaultKey
    ) throws {
        guard let deviceID = Base64URL.decodeCanonical(recipientDeviceID),
              deviceID.count == 32
        else {
            throw V3DeviceWrappedManifestError.invalidStructure(
                "wrappedKeys.recipientDeviceID"
            )
        }
        self.recipientDeviceID = recipientDeviceID
        self.wrappedKey = wrappedKey
    }
}

/// Exact permanent-profile manifest body.
///
/// This type deliberately remains separate from the released-alpha manifest
/// model. A later integration increment can therefore reject the old profile
/// explicitly instead of accidentally interpreting it as this format.
struct V3DeviceWrappedManifestBody: Equatable, Sendable {
    static let format = "key-vault-manifest"
    static let version: UInt64 = 3
    static let profile = V3VaultKeyHPKEContext.profile
    static let profileVersion = V3VaultKeyHPKEContext.profileVersion

    let vaultID: String
    let keyID: V3VaultKeyID
    let authorityTransitionID: String
    let devices: [V3DeviceWrappedManifestDevice]
    let wrappedKeys: [V3DeviceWrappedManifestKey]
    let entries: [V3ManifestEntry]

    init(
        vaultID: String,
        keyID: V3VaultKeyID,
        authorityTransitionID: String,
        devices: [V3DeviceWrappedManifestDevice],
        wrappedKeys: [V3DeviceWrappedManifestKey],
        entries: [V3ManifestEntry]
    ) throws {
        guard isValidV3UUID(vaultID) else {
            throw V3DeviceWrappedManifestError.invalidStructure("vaultID")
        }
        guard isValidV3UUID(authorityTransitionID) else {
            throw V3DeviceWrappedManifestError.invalidStructure(
                "authorityTransitionID"
            )
        }

        self.vaultID = vaultID
        self.keyID = keyID
        self.authorityTransitionID = authorityTransitionID
        self.devices = devices
        self.wrappedKeys = wrappedKeys
        self.entries = entries
        try validateSemantics()
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(canonicalValue)
    }

    var canonicalValue: CanonicalJSONValue {
        .object([
            ("format", .string(Self.format)),
            ("version", .integer(Self.version)),
            ("profile", .string(Self.profile)),
            ("profileVersion", .integer(Self.profileVersion)),
            ("vaultID", .string(vaultID)),
            ("keyID", .string(keyID.rawValue)),
            ("authorityTransitionID", .string(authorityTransitionID)),
            ("hpkeSuite", .object([
                ("mode", .integer(V3VaultKeyHPKEContext.hpkeMode)),
                ("kem", .integer(V3VaultKeyHPKEContext.hpkeKEM)),
                ("kdf", .integer(V3VaultKeyHPKEContext.hpkeKDF)),
                ("aead", .integer(V3VaultKeyHPKEContext.hpkeAEAD)),
            ])),
            ("devices", .array(devices.map(Self.canonicalDevice))),
            ("wrappedKeys", .array(wrappedKeys.map(Self.canonicalWrappedKey))),
            ("entries", .array(entries.map(Self.canonicalEntry))),
        ])
    }

    private func validateSemantics() throws {
        guard !devices.isEmpty else {
            throw V3DeviceWrappedManifestError.semanticViolation("devices.empty")
        }

        var previousDeviceID: String?
        var deviceIDs = Set<String>()
        var publicKeys = Set<Data>()
        for device in devices {
            let deviceID = device.identity.deviceID
            guard deviceIDs.insert(deviceID).inserted,
                  previousDeviceID.map({ v3UTF8Precedes($0, deviceID) }) ?? true
            else {
                throw V3DeviceWrappedManifestError.semanticViolation(
                    "devices.order"
                )
            }
            guard publicKeys.insert(device.identity.signingPublicKey).inserted,
                  publicKeys.insert(device.identity.wrappingPublicKey).inserted
            else {
                throw V3DeviceWrappedManifestError.semanticViolation(
                    "devices.publicKeyReuse"
                )
            }
            previousDeviceID = deviceID
        }

        guard devices.contains(where: {
            $0.role == .owner && $0.status == .active
        }) else {
            throw V3DeviceWrappedManifestError.semanticViolation(
                "devices.activeOwner"
            )
        }

        let activeDeviceIDs = devices.compactMap {
            $0.status == .active ? $0.identity.deviceID : nil
        }
        guard wrappedKeys.map(\.recipientDeviceID) == activeDeviceIDs else {
            throw V3DeviceWrappedManifestError.semanticViolation(
                "wrappedKeys.coverage"
            )
        }

        var previousEntry: V3ManifestEntry?
        var entryIDs = Set<String>()
        var entryNames = Set<Data>()
        for entry in entries {
            guard isValidV3UUID(entry.entryID),
                  isValidV3EntryName(entry.name),
                  entry.revision > 0,
                  entry.revision <= v3MaximumSafeInteger,
                  entry.keyID == keyID,
                  Base64URL.decodeCanonical(entry.ciphertextDigest)?.count == 32,
                  entryIDs.insert(entry.entryID).inserted,
                  entryNames.insert(Data(entry.name.utf8)).inserted,
                  previousEntry.map({ v3ManifestEntryPrecedes($0, entry) }) ?? true
            else {
                throw V3DeviceWrappedManifestError.semanticViolation("entries")
            }
            previousEntry = entry
        }
    }

    private static func canonicalDevice(
        _ device: V3DeviceWrappedManifestDevice
    ) -> CanonicalJSONValue {
        .object([
            ("deviceID", .string(device.identity.deviceID)),
            ("displayName", .string(device.identity.displayName)),
            ("role", .string(device.role.rawValue)),
            ("status", .string(device.status.rawValue)),
            ("signingPublicKey", .object([
                ("algorithm", .string("P-256-ECDSA")),
                ("encoding", .string("x963")),
                (
                    "value",
                    .string(Base64URL.encode(device.identity.signingPublicKey))
                ),
            ])),
            ("wrappingPublicKey", .object([
                ("algorithm", .string("P-256-ECDH")),
                ("encoding", .string("x963")),
                (
                    "value",
                    .string(Base64URL.encode(device.identity.wrappingPublicKey))
                ),
            ])),
        ])
    }

    private static func canonicalWrappedKey(
        _ wrapped: V3DeviceWrappedManifestKey
    ) -> CanonicalJSONValue {
        .object([
            ("recipientDeviceID", .string(wrapped.recipientDeviceID)),
            (
                "encapsulatedKey",
                .string(Base64URL.encode(wrapped.wrappedKey.encapsulatedKey))
            ),
            (
                "ciphertext",
                .string(Base64URL.encode(wrapped.wrappedKey.ciphertext))
            ),
        ])
    }

    private static func canonicalEntry(
        _ entry: V3ManifestEntry
    ) -> CanonicalJSONValue {
        .object([
            ("entryID", .string(entry.entryID)),
            ("name", .string(entry.name)),
            ("type", .string(entry.type.rawValue)),
            ("revision", .integer(entry.revision)),
            ("keyID", .string(entry.keyID.rawValue)),
            ("ciphertextDigest", .string(entry.ciphertextDigest)),
        ])
    }
}

struct V3DeviceWrappedManifestCodec: Sendable {
    func parseCanonicalBody(_ data: Data) throws -> V3DeviceWrappedManifestBody {
        let value: CanonicalJSONValue
        do {
            value = try CanonicalJSON.parse(data)
        } catch CanonicalJSONError.invalidEncoding {
            throw V3DeviceWrappedManifestError.invalidEncoding
        } catch CanonicalJSONError.invalidJSON {
            throw V3DeviceWrappedManifestError.invalidJSON
        } catch CanonicalJSONError.duplicateProperty {
            throw V3DeviceWrappedManifestError.invalidJSON
        }
        guard CanonicalJSON.encode(value) == data else {
            throw V3DeviceWrappedManifestError.nonCanonicalJSON
        }
        return try decodeBody(value)
    }

    func decodeBody(
        _ value: CanonicalJSONValue,
        path: String = "$"
    ) throws -> V3DeviceWrappedManifestBody {
        let body = try v3PermanentObject(value, path: path)
        try v3PermanentConstant(
            V3DeviceWrappedManifestBody.format,
            member: "format",
            in: body,
            path: path
        )
        try v3PermanentConstant(
            V3DeviceWrappedManifestBody.version,
            member: "version",
            in: body,
            path: path
        )
        try v3PermanentConstant(
            V3DeviceWrappedManifestBody.profile,
            member: "profile",
            in: body,
            path: path
        )
        let profileVersion = try v3PermanentInteger(
            "profileVersion",
            in: body,
            path: path
        )
        guard profileVersion <= V3DeviceWrappedManifestBody.profileVersion else {
            throw V3DeviceWrappedManifestError.unsupportedProfileVersion(
                profileVersion
            )
        }
        guard profileVersion == V3DeviceWrappedManifestBody.profileVersion else {
            throw V3DeviceWrappedManifestError.invalidStructure(
                "\(path).profileVersion"
            )
        }
        // Dispatch on the permanent-profile discriminator before enforcing
        // version-specific fields. A newer profile can evolve its schema and
        // must be reported as requiring an upgrade, not as corrupt input.
        try v3PermanentFields(
            body,
            names: [
                "authorityTransitionID", "devices", "entries", "format",
                "hpkeSuite", "keyID", "profile", "profileVersion",
                "vaultID", "version", "wrappedKeys",
            ],
            path: path
        )
        try decodeHPKESuite(
            v3PermanentMember("hpkeSuite", in: body, path: path),
            path: "\(path).hpkeSuite"
        )

        let keyID: V3VaultKeyID
        do {
            keyID = try V3VaultKeyID(rawValue: v3PermanentString(
                "keyID",
                in: body,
                path: path
            ))
        } catch {
            throw V3DeviceWrappedManifestError.invalidStructure(
                "\(path).keyID"
            )
        }

        let devices = try v3PermanentArray(
            "devices",
            in: body,
            path: path
        ).enumerated().map {
            try decodeDevice($0.element, path: "\(path).devices[\($0.offset)]")
        }
        let wrappedKeys = try v3PermanentArray(
            "wrappedKeys",
            in: body,
            path: path
        ).enumerated().map {
            try decodeWrappedKey(
                $0.element,
                path: "\(path).wrappedKeys[\($0.offset)]"
            )
        }
        let entries = try v3PermanentArray(
            "entries",
            in: body,
            path: path
        ).enumerated().map {
            try decodeEntry($0.element, path: "\(path).entries[\($0.offset)]")
        }

        return try V3DeviceWrappedManifestBody(
            vaultID: v3PermanentString("vaultID", in: body, path: path),
            keyID: keyID,
            authorityTransitionID: v3PermanentString(
                "authorityTransitionID",
                in: body,
                path: path
            ),
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: entries
        )
    }

    private func decodeHPKESuite(
        _ value: CanonicalJSONValue,
        path: String
    ) throws {
        let suite = try v3PermanentObject(value, path: path)
        try v3PermanentFields(
            suite,
            names: ["aead", "kdf", "kem", "mode"],
            path: path
        )
        try v3PermanentConstant(
            V3VaultKeyHPKEContext.hpkeMode,
            member: "mode",
            in: suite,
            path: path
        )
        try v3PermanentConstant(
            V3VaultKeyHPKEContext.hpkeKEM,
            member: "kem",
            in: suite,
            path: path
        )
        try v3PermanentConstant(
            V3VaultKeyHPKEContext.hpkeKDF,
            member: "kdf",
            in: suite,
            path: path
        )
        try v3PermanentConstant(
            V3VaultKeyHPKEContext.hpkeAEAD,
            member: "aead",
            in: suite,
            path: path
        )
    }

    private func decodeDevice(
        _ value: CanonicalJSONValue,
        path: String
    ) throws -> V3DeviceWrappedManifestDevice {
        let device = try v3PermanentObject(value, path: path)
        try v3PermanentFields(
            device,
            names: [
                "deviceID", "displayName", "role", "signingPublicKey",
                "status", "wrappingPublicKey",
            ],
            path: path
        )
        let roleValue = try v3PermanentString("role", in: device, path: path)
        let statusValue = try v3PermanentString("status", in: device, path: path)
        guard let role = V3DeviceRole(rawValue: roleValue) else {
            throw V3DeviceWrappedManifestError.invalidStructure("\(path).role")
        }
        guard let status = V3DeviceStatus(rawValue: statusValue) else {
            throw V3DeviceWrappedManifestError.invalidStructure("\(path).status")
        }

        let identityValue = CanonicalJSONValue.object(
            device.filter { !["role", "status"].contains($0.0) }
        )
        let identity: V3EnrollmentDeviceIdentity
        do {
            identity = try decodeEnrollmentDevice(identityValue)
        } catch {
            throw V3DeviceWrappedManifestError.invalidStructure(path)
        }
        return V3DeviceWrappedManifestDevice(
            identity: identity,
            role: role,
            status: status
        )
    }

    private func decodeWrappedKey(
        _ value: CanonicalJSONValue,
        path: String
    ) throws -> V3DeviceWrappedManifestKey {
        let wrapped = try v3PermanentObject(value, path: path)
        try v3PermanentFields(
            wrapped,
            names: ["ciphertext", "encapsulatedKey", "recipientDeviceID"],
            path: path
        )
        do {
            return try V3DeviceWrappedManifestKey(
                recipientDeviceID: v3PermanentString(
                    "recipientDeviceID",
                    in: wrapped,
                    path: path
                ),
                wrappedKey: V3HPKEWrappedVaultKey(
                    encapsulatedKey: try v3PermanentData(
                        "encapsulatedKey",
                        byteCount: V3HPKEWrappedVaultKey
                            .encapsulatedKeyByteCount,
                        in: wrapped,
                        path: path
                    ),
                    ciphertext: try v3PermanentData(
                        "ciphertext",
                        byteCount: V3HPKEWrappedVaultKey.ciphertextByteCount,
                        in: wrapped,
                        path: path
                    )
                )
            )
        } catch let error as V3DeviceWrappedManifestError {
            throw error
        } catch {
            throw V3DeviceWrappedManifestError.invalidStructure(path)
        }
    }

    private func decodeEntry(
        _ value: CanonicalJSONValue,
        path: String
    ) throws -> V3ManifestEntry {
        let entry = try v3PermanentObject(value, path: path)
        try v3PermanentFields(
            entry,
            names: [
                "ciphertextDigest", "entryID", "keyID", "name", "revision",
                "type",
            ],
            path: path
        )
        let typeValue = try v3PermanentString("type", in: entry, path: path)
        guard let type = SecretEntryType(rawValue: typeValue) else {
            throw V3DeviceWrappedManifestError.invalidStructure("\(path).type")
        }
        let keyID: V3VaultKeyID
        do {
            keyID = try V3VaultKeyID(rawValue: v3PermanentString(
                "keyID",
                in: entry,
                path: path
            ))
        } catch {
            throw V3DeviceWrappedManifestError.invalidStructure("\(path).keyID")
        }
        return V3ManifestEntry(
            entryID: try v3PermanentString("entryID", in: entry, path: path),
            name: try v3PermanentString("name", in: entry, path: path),
            type: type,
            revision: try v3PermanentInteger("revision", in: entry, path: path),
            keyID: keyID,
            ciphertextDigest: try v3PermanentString(
                "ciphertextDigest",
                in: entry,
                path: path
            )
        )
    }
}

private func v3PermanentMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> CanonicalJSONValue {
    guard let value = object.first(where: { $0.0 == name })?.1 else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func v3PermanentObject(
    _ value: CanonicalJSONValue,
    path: String
) throws -> [(String, CanonicalJSONValue)] {
    guard let object = value.objectValue else {
        throw V3DeviceWrappedManifestError.invalidStructure(path)
    }
    return object
}

private func v3PermanentFields(
    _ object: [(String, CanonicalJSONValue)],
    names: Set<String>,
    path: String
) throws {
    guard Set(object.map(\.0)) == names else {
        throw V3DeviceWrappedManifestError.invalidStructure(path)
    }
}

private func v3PermanentString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> String {
    guard let value = try v3PermanentMember(
        name,
        in: object,
        path: path
    ).stringValue else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func v3PermanentInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> UInt64 {
    guard let value = try v3PermanentMember(
        name,
        in: object,
        path: path
    ).integerValue else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func v3PermanentArray(
    _ name: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> [CanonicalJSONValue] {
    guard let value = try v3PermanentMember(
        name,
        in: object,
        path: path
    ).arrayValue else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(name)")
    }
    return value
}

private func v3PermanentData(
    _ name: String,
    byteCount: Int,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws -> Data {
    let encoded = try v3PermanentString(name, in: object, path: path)
    guard let data = Base64URL.decodeCanonical(encoded),
          data.count == byteCount
    else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(name)")
    }
    return data
}

private func v3PermanentConstant(
    _ expected: String,
    member: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws {
    guard try v3PermanentString(member, in: object, path: path) == expected else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(member)")
    }
}

private func v3PermanentConstant(
    _ expected: UInt64,
    member: String,
    in object: [(String, CanonicalJSONValue)],
    path: String
) throws {
    guard try v3PermanentInteger(member, in: object, path: path) == expected else {
        throw V3DeviceWrappedManifestError.invalidStructure("\(path).\(member)")
    }
}

private func v3UTF8Precedes(_ lhs: String, _ rhs: String) -> Bool {
    Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
}
