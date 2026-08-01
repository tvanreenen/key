import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3EnrollmentProtocolError: Error, Equatable, LocalizedError {
    case invalidFormat
    case invalidDeviceIdentity
    case unsupportedMessageVersion(UInt64)
    case unsupportedVaultFormatVersion(UInt64)
    case invitationMismatch
    case sameDevice
    case publicKeyReuse
    case expired

    var errorDescription: String? {
        switch self {
        case .invalidFormat:
            "The version 3 device-enrollment message is invalid."
        case .invalidDeviceIdentity:
            "The version 3 device-enrollment message contains an invalid device identity."
        case .unsupportedMessageVersion(let version):
            "Device-enrollment message version \(version) requires a newer version of Key."
        case .unsupportedVaultFormatVersion(let version):
            "Vault format version \(version) is not supported by this version of Key."
        case .invitationMismatch:
            "The join request does not answer this exact device invitation."
        case .sameDevice:
            "A device cannot enroll itself as a second device."
        case .publicKeyReuse:
            "Enrollment requires distinct signing and wrapping keys for both devices."
        case .expired:
            "The device invitation has expired. Create a new invitation and try again."
        }
    }
}

/// Public identity proposed by one side of a version 3 enrollment ceremony.
///
/// The two private keys are intentionally absent. Later enrollment increments
/// store them in the Secure Enclave and use this value only as canonical,
/// non-secret transcript input.
struct V3EnrollmentDeviceIdentity: Equatable, Sendable {
    let deviceID: String
    let displayName: String
    let signingPublicKey: Data
    let wrappingPublicKey: Data

    init(
        displayName: String,
        signingPublicKey: Data,
        wrappingPublicKey: Data
    ) throws {
        try self.init(
            deviceID: V3ManifestAuthenticator.deviceID(
                signingPublicKey: signingPublicKey,
                wrappingPublicKey: wrappingPublicKey
            ),
            displayName: displayName,
            signingPublicKey: signingPublicKey,
            wrappingPublicKey: wrappingPublicKey
        )
    }

    fileprivate init(
        deviceID: String,
        displayName: String,
        signingPublicKey: Data,
        wrappingPublicKey: Data
    ) throws {
        guard isValidV3DeviceDisplayName(displayName),
            signingPublicKey.count == 65,
            wrappingPublicKey.count == 65,
            signingPublicKey.first == 0x04,
            wrappingPublicKey.first == 0x04,
            signingPublicKey != wrappingPublicKey,
            deviceID
                == V3ManifestAuthenticator.deviceID(
                    signingPublicKey: signingPublicKey,
                    wrappingPublicKey: wrappingPublicKey
                )
        else {
            throw V3EnrollmentProtocolError.invalidDeviceIdentity
        }

        do {
            _ = try P256.Signing.PublicKey(
                x963Representation: signingPublicKey
            )
            _ = try P256.KeyAgreement.PublicKey(
                x963Representation: wrappingPublicKey
            )
        } catch {
            throw V3EnrollmentProtocolError.invalidDeviceIdentity
        }

        self.deviceID = deviceID
        self.displayName = displayName
        self.signingPublicKey = signingPublicKey
        self.wrappingPublicKey = wrappingPublicKey
    }

    fileprivate var canonicalValue: CanonicalJSONValue {
        .object([
            ("deviceID", .string(deviceID)),
            ("displayName", .string(displayName)),
            (
                "signingPublicKey",
                .object([
                    ("algorithm", .string("P-256-ECDSA")),
                    ("encoding", .string("x963")),
                    ("value", .string(Base64URL.encode(signingPublicKey))),
                ])
            ),
            (
                "wrappingPublicKey",
                .object([
                    ("algorithm", .string("P-256-ECDH")),
                    ("encoding", .string("x963")),
                    ("value", .string(Base64URL.encode(wrappingPublicKey))),
                ])
            ),
        ])
    }
}

/// One short-lived invitation created by a device that currently trusts the
/// exact parent manifest named here.
struct V3EnrollmentInvitation: Equatable, Sendable {
    static let maximumBytes = 16 * 1_024
    static let supportedVaultFormatVersion: UInt64 = 3

    let vaultID: String
    let vaultFormatVersion: UInt64
    let parentManifestDigest: Data
    let invitingDevice: V3EnrollmentDeviceIdentity
    let invitedRole: V3DeviceRole
    let nonce: Data
    let expiresAt: UInt64

    init(
        vaultID: String,
        vaultFormatVersion: UInt64 = Self.supportedVaultFormatVersion,
        parentManifestDigest: Data,
        invitingDevice: V3EnrollmentDeviceIdentity,
        invitedRole: V3DeviceRole,
        nonce: Data,
        expiresAt: UInt64
    ) throws {
        guard isValidV3UUID(vaultID),
            parentManifestDigest.count == 32,
            nonce.count == 32,
            expiresAt > 0,
            expiresAt <= v3MaximumSafeInteger
        else {
            throw V3EnrollmentProtocolError.invalidFormat
        }
        guard vaultFormatVersion == Self.supportedVaultFormatVersion else {
            throw V3EnrollmentProtocolError.unsupportedVaultFormatVersion(
                vaultFormatVersion
            )
        }
        self.vaultID = vaultID
        self.vaultFormatVersion = vaultFormatVersion
        self.parentManifestDigest = parentManifestDigest
        self.invitingDevice = invitingDevice
        self.invitedRole = invitedRole
        self.nonce = nonce
        self.expiresAt = expiresAt
    }

    init(canonicalBytes: Data) throws {
        let root = try parseEnrollmentObject(
            canonicalBytes,
            maximumBytes: Self.maximumBytes,
            fields: [
                "expiresAt", "format", "invitedRole", "invitingDevice",
                "nonce", "parentManifestDigest", "vaultFormatVersion",
                "vaultID", "version",
            ],
            format: "key-vault-enrollment-invitation"
        )
        guard let vaultID = enrollmentString("vaultID", in: root),
            let vaultFormatVersion = enrollmentInteger(
                "vaultFormatVersion",
                in: root
            ),
            let parentManifestDigest = enrollmentData(
                "parentManifestDigest",
                byteCount: 32,
                in: root
            ),
            let invitingDeviceValue = enrollmentMember(
                "invitingDevice",
                in: root
            ),
            let invitedRoleValue = enrollmentString(
                "invitedRole",
                in: root
            ),
            let invitedRole = V3DeviceRole(rawValue: invitedRoleValue),
            let nonce = enrollmentData("nonce", byteCount: 32, in: root),
            let expiresAt = enrollmentInteger("expiresAt", in: root)
        else {
            throw V3EnrollmentProtocolError.invalidFormat
        }
        let invitingDevice = try decodeEnrollmentDevice(
            invitingDeviceValue
        )
        try self.init(
            vaultID: vaultID,
            vaultFormatVersion: vaultFormatVersion,
            parentManifestDigest: parentManifestDigest,
            invitingDevice: invitingDevice,
            invitedRole: invitedRole,
            nonce: nonce,
            expiresAt: expiresAt
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(canonicalValue)
    }

    var digest: Data {
        Data(SHA256.hash(data: canonicalBytes))
    }

    func requireUnexpired(at unixTime: UInt64) throws {
        guard unixTime <= expiresAt else {
            throw V3EnrollmentProtocolError.expired
        }
    }

    fileprivate var canonicalValue: CanonicalJSONValue {
        .object([
            ("format", .string("key-vault-enrollment-invitation")),
            ("version", .integer(1)),
            ("vaultID", .string(vaultID)),
            ("vaultFormatVersion", .integer(vaultFormatVersion)),
            (
                "parentManifestDigest",
                .string(Base64URL.encode(parentManifestDigest))
            ),
            ("invitingDevice", invitingDevice.canonicalValue),
            ("invitedRole", .string(invitedRole.rawValue)),
            ("nonce", .string(Base64URL.encode(nonce))),
            ("expiresAt", .integer(expiresAt)),
        ])
    }
}

/// The joining device's answer to one exact invitation.
struct V3EnrollmentJoinRequest: Equatable, Sendable {
    static let maximumBytes = 16 * 1_024

    let invitationDigest: Data
    let joiningDevice: V3EnrollmentDeviceIdentity
    let nonce: Data

    init(
        invitationDigest: Data,
        joiningDevice: V3EnrollmentDeviceIdentity,
        nonce: Data
    ) throws {
        guard invitationDigest.count == 32, nonce.count == 32 else {
            throw V3EnrollmentProtocolError.invalidFormat
        }
        self.invitationDigest = invitationDigest
        self.joiningDevice = joiningDevice
        self.nonce = nonce
    }

    init(canonicalBytes: Data) throws {
        let root = try parseEnrollmentObject(
            canonicalBytes,
            maximumBytes: Self.maximumBytes,
            fields: [
                "format", "invitationDigest", "joiningDevice", "nonce",
                "version",
            ],
            format: "key-vault-enrollment-join-request"
        )
        guard
            let invitationDigest = enrollmentData(
                "invitationDigest",
                byteCount: 32,
                in: root
            ),
            let joiningDeviceValue = enrollmentMember(
                "joiningDevice",
                in: root
            ),
            let nonce = enrollmentData("nonce", byteCount: 32, in: root)
        else {
            throw V3EnrollmentProtocolError.invalidFormat
        }
        let joiningDevice = try decodeEnrollmentDevice(
            joiningDeviceValue
        )
        try self.init(
            invitationDigest: invitationDigest,
            joiningDevice: joiningDevice,
            nonce: nonce
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(canonicalValue)
    }

    var digest: Data {
        Data(SHA256.hash(data: canonicalBytes))
    }

    fileprivate var canonicalValue: CanonicalJSONValue {
        .object([
            ("format", .string("key-vault-enrollment-join-request")),
            ("version", .integer(1)),
            (
                "invitationDigest",
                .string(Base64URL.encode(invitationDigest))
            ),
            ("joiningDevice", joiningDevice.canonicalValue),
            ("nonce", .string(Base64URL.encode(nonce))),
        ])
    }
}

/// Exact public input both devices compare before either grants authority.
///
/// The compact code is a user-presence check over this complete transcript,
/// not a replacement for signatures, manifest authentication, or the exact
/// wrapped-key checks added by later enrollment increments.
struct V3EnrollmentTranscript: Equatable, Sendable {
    private static let digestDomain = Data(
        "work.tvr.key/v3/enrollment-transcript".utf8
    )

    let invitation: V3EnrollmentInvitation
    let joinRequest: V3EnrollmentJoinRequest

    init(
        invitation: V3EnrollmentInvitation,
        joinRequest: V3EnrollmentJoinRequest
    ) throws {
        guard joinRequest.invitationDigest == invitation.digest else {
            throw V3EnrollmentProtocolError.invitationMismatch
        }
        guard
            invitation.invitingDevice.deviceID
                != joinRequest.joiningDevice.deviceID
        else {
            throw V3EnrollmentProtocolError.sameDevice
        }

        let publicKeys = [
            invitation.invitingDevice.signingPublicKey,
            invitation.invitingDevice.wrappingPublicKey,
            joinRequest.joiningDevice.signingPublicKey,
            joinRequest.joiningDevice.wrappingPublicKey,
        ]
        guard Set(publicKeys).count == publicKeys.count else {
            throw V3EnrollmentProtocolError.publicKeyReuse
        }

        self.invitation = invitation
        self.joinRequest = joinRequest
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-enrollment-transcript")),
                ("version", .integer(1)),
                (
                    "invitationDigest",
                    .string(Base64URL.encode(invitation.digest))
                ),
                (
                    "joinRequestDigest",
                    .string(Base64URL.encode(joinRequest.digest))
                ),
            ]))
    }

    var digest: Data {
        var input = Self.digestDomain
        input.append(0)
        input.append(canonicalBytes)
        return Data(SHA256.hash(data: input))
    }

    /// An 80-bit short authentication string, rendered as five readable
    /// hexadecimal groups. Both devices must display the same value.
    var comparisonCode: String {
        let characters = v3LowercaseHex(Data(digest.prefix(10)))
        return stride(from: 0, to: characters.count, by: 4).map { offset in
            let start = characters.index(
                characters.startIndex,
                offsetBy: offset
            )
            let end = characters.index(
                start,
                offsetBy: min(4, characters.count - offset)
            )
            return String(characters[start..<end])
        }.joined(separator: "-")
    }
}

private func parseEnrollmentObject(
    _ canonicalBytes: Data,
    maximumBytes: Int,
    fields: Set<String>,
    format: String
) throws -> [(String, CanonicalJSONValue)] {
    guard canonicalBytes.count <= maximumBytes else {
        throw V3EnrollmentProtocolError.invalidFormat
    }
    let value: CanonicalJSONValue
    do {
        value = try CanonicalJSON.parse(canonicalBytes)
    } catch {
        throw V3EnrollmentProtocolError.invalidFormat
    }
    guard CanonicalJSON.encode(value) == canonicalBytes,
        let object = value.objectValue,
        enrollmentString("format", in: object) == format,
        let version = enrollmentInteger("version", in: object)
    else {
        throw V3EnrollmentProtocolError.invalidFormat
    }
    if version > 1 {
        throw V3EnrollmentProtocolError.unsupportedMessageVersion(version)
    }
    guard version == 1, Set(object.map(\.0)) == fields else {
        throw V3EnrollmentProtocolError.invalidFormat
    }
    return object
}

private func decodeEnrollmentDevice(
    _ value: CanonicalJSONValue
) throws -> V3EnrollmentDeviceIdentity {
    guard let object = value.objectValue,
        Set(object.map(\.0))
            == Set([
                "deviceID", "displayName", "signingPublicKey",
                "wrappingPublicKey",
            ]),
        let deviceID = enrollmentString("deviceID", in: object),
        let displayName = enrollmentString("displayName", in: object),
        let signingPublicKey = decodeEnrollmentPublicKey(
            enrollmentMember("signingPublicKey", in: object),
            algorithm: "P-256-ECDSA"
        ),
        let wrappingPublicKey = decodeEnrollmentPublicKey(
            enrollmentMember("wrappingPublicKey", in: object),
            algorithm: "P-256-ECDH"
        )
    else {
        throw V3EnrollmentProtocolError.invalidDeviceIdentity
    }
    return try V3EnrollmentDeviceIdentity(
        deviceID: deviceID,
        displayName: displayName,
        signingPublicKey: signingPublicKey,
        wrappingPublicKey: wrappingPublicKey
    )
}

private func decodeEnrollmentPublicKey(
    _ value: CanonicalJSONValue?,
    algorithm: String
) -> Data? {
    guard let object = value?.objectValue,
        Set(object.map(\.0)) == Set(["algorithm", "encoding", "value"]),
        enrollmentString("algorithm", in: object) == algorithm,
        enrollmentString("encoding", in: object) == "x963",
        let encoded = enrollmentString("value", in: object),
        let decoded = Base64URL.decodeCanonical(encoded),
        decoded.count == 65
    else {
        return nil
    }
    return decoded
}

private func enrollmentMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func enrollmentString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    enrollmentMember(name, in: object)?.stringValue
}

private func enrollmentInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    enrollmentMember(name, in: object)?.integerValue
}

private func enrollmentData(
    _ name: String,
    byteCount: Int,
    in object: [(String, CanonicalJSONValue)]
) -> Data? {
    guard let value = enrollmentString(name, in: object),
        let data = Base64URL.decodeCanonical(value),
        data.count == byteCount
    else {
        return nil
    }
    return data
}
