import CryptoKit
import Foundation
internal import JSONCanonicalization
import LocalAuthentication
import Security

enum V3EnrollmentDeviceIdentityStoreError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidRecord
    case invalidIdentityRequest
    case identityAlreadyExists
    case identityMismatch
    case secureEnclaveUnavailable
    case authenticationCancelled
    case invalidConfiguration
    case keyOperationFailed
    case keychainStatus(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidRecord:
            "The device-local version 3 enrollment identity is invalid."
        case .invalidIdentityRequest:
            "The version 3 enrollment identity request is invalid."
        case .identityAlreadyExists:
            "This device already has a version 3 enrollment identity for the vault."
        case .identityMismatch:
            "The stored Secure Enclave keys do not match the device enrollment identity."
        case .secureEnclaveUnavailable:
            "The Secure Enclave is unavailable on this Mac."
        case .authenticationCancelled:
            "Device authentication was cancelled or is not currently available."
        case .invalidConfiguration:
            "Version 3 enrollment identity storage is not configured."
        case .keyOperationFailed:
            "The Secure Enclave enrollment key operation failed."
        case .keychainStatus(let status):
            "Version 3 enrollment identity Keychain operation failed (\(status))."
        }
    }
}

struct V3EnrollmentDeviceKeyRecord: Equatable, Sendable {
    static let maximumBytes = 64 * 1_024
    private static let maximumKeyRepresentationBytes = 16 * 1_024

    let vaultID: String
    let identity: V3EnrollmentDeviceIdentity
    let signingKeyRepresentation: Data
    let wrappingKeyRepresentation: Data

    init(
        vaultID: String,
        identity: V3EnrollmentDeviceIdentity,
        signingKeyRepresentation: Data,
        wrappingKeyRepresentation: Data
    ) throws {
        guard isValidV3UUID(vaultID),
            !signingKeyRepresentation.isEmpty,
            signingKeyRepresentation.count
                <= Self.maximumKeyRepresentationBytes,
            !wrappingKeyRepresentation.isEmpty,
            wrappingKeyRepresentation.count
                <= Self.maximumKeyRepresentationBytes,
            signingKeyRepresentation != wrappingKeyRepresentation
        else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        self.vaultID = vaultID
        self.identity = identity
        self.signingKeyRepresentation = signingKeyRepresentation
        self.wrappingKeyRepresentation = wrappingKeyRepresentation
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= Self.maximumBytes else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        let value: CanonicalJSONValue
        do {
            value = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        guard CanonicalJSON.encode(value) == canonicalBytes,
            let object = value.objectValue,
            Set(object.map(\.0))
                == Set([
                    "format", "identity", "signingKeyRepresentation",
                    "vaultID", "version", "wrappingKeyRepresentation",
                ]),
            identityRecordString("format", in: object)
                == "key-vault-device-private-identity",
            identityRecordInteger("version", in: object) == 1,
            let vaultID = identityRecordString("vaultID", in: object),
            let identityValue = identityRecordMember("identity", in: object),
            let signingKeyRepresentation = identityRecordData(
                "signingKeyRepresentation",
                maximumBytes: Self.maximumKeyRepresentationBytes,
                in: object
            ),
            let wrappingKeyRepresentation = identityRecordData(
                "wrappingKeyRepresentation",
                maximumBytes: Self.maximumKeyRepresentationBytes,
                in: object
            )
        else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        let identity: V3EnrollmentDeviceIdentity
        do {
            identity = try decodeEnrollmentDevice(identityValue)
        } catch {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        try self.init(
            vaultID: vaultID,
            identity: identity,
            signingKeyRepresentation: signingKeyRepresentation,
            wrappingKeyRepresentation: wrappingKeyRepresentation
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-device-private-identity")),
                ("version", .integer(1)),
                ("vaultID", .string(vaultID)),
                ("identity", identity.canonicalValue),
                (
                    "signingKeyRepresentation",
                    .string(Base64URL.encode(signingKeyRepresentation))
                ),
                (
                    "wrappingKeyRepresentation",
                    .string(Base64URL.encode(wrappingKeyRepresentation))
                ),
            ]))
    }
}

protocol V3EnrollmentDeviceKeyRecordStoring: Sendable {
    func loadRecord(vaultID: String) throws -> Data?
    func insertRecord(_ record: Data, vaultID: String) throws
}

final class V3EnrollmentDeviceKeyRecordKeychainStore:
    V3EnrollmentDeviceKeyRecordStoring,
    @unchecked Sendable
{
    private let configuration: RuntimeConfiguration
    private let lock = NSLock()

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func loadRecord(vaultID: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }

        var query = try baseQuery(vaultID: vaultID)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        // SAFETY: Security.framework writes one retained result into the
        // stack-local optional for the duration of this synchronous call.
        let status = unsafe SecItemCopyMatching(
            query as CFDictionary,
            &item
        )
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw V3EnrollmentDeviceIdentityStoreError.keychainStatus(
                status == errSecSuccess ? errSecInternalError : status
            )
        }
        return data
    }

    func insertRecord(_ record: Data, vaultID: String) throws {
        let decoded = try V3EnrollmentDeviceKeyRecord(
            canonicalBytes: record
        )
        guard decoded.vaultID == vaultID else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }

        lock.lock()
        defer { lock.unlock() }
        var attributes = try baseQuery(vaultID: vaultID)
        attributes[kSecAttrLabel as String] =
            "key v3 Secure Enclave enrollment identity"
        attributes[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        attributes[kSecValueData as String] = record
        let status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            throw V3EnrollmentDeviceIdentityStoreError
                .identityAlreadyExists
        }
        guard status == errSecSuccess else {
            throw V3EnrollmentDeviceIdentityStoreError.keychainStatus(status)
        }
    }

    private func baseQuery(vaultID: String) throws -> [String: Any] {
        guard isValidV3UUID(vaultID),
            !configuration.vaultService.isEmpty,
            let accessGroup = configuration.keychainAccessGroup,
            !accessGroup.isEmpty
        else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidConfiguration
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String:
                "\(configuration.vaultService).v3-enrollment-identity",
            kSecAttrAccount as String: vaultID,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false,
        ]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }
}

struct V3EnrollmentGeneratedDeviceKeys: Equatable, Sendable {
    let signingPublicKey: Data
    let wrappingPublicKey: Data
    let signingKeyRepresentation: Data
    let wrappingKeyRepresentation: Data
}

protocol V3EnrollmentDeviceKeyOperating: Sendable {
    var isAvailable: Bool { get }

    func generateDeviceKeys(
        reason: String
    ) throws -> V3EnrollmentGeneratedDeviceKeys

    func publicKeys(
        signingKeyRepresentation: Data,
        wrappingKeyRepresentation: Data,
        reason: String
    ) throws -> (signing: Data, wrapping: Data)

    func signature(
        for input: Data,
        signingKeyRepresentation: Data,
        reason: String
    ) throws -> Data

    func sharedSecret(
        with publicKey: P256.KeyAgreement.PublicKey,
        wrappingKeyRepresentation: Data,
        reason: String
    ) throws -> SharedSecret

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        wrappingKeyRepresentation: Data,
        reason: String
    ) throws -> Data
}

struct V3SecureEnclaveEnrollmentDeviceKeyOperations:
    V3EnrollmentDeviceKeyOperating,
    Sendable
{
    var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    func generateDeviceKeys(
        reason: String
    ) throws -> V3EnrollmentGeneratedDeviceKeys {
        guard !reason.isEmpty else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard isAvailable else {
            throw V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        }
        do {
            let accessControl = try makeAccessControl()
            let context = makeAuthenticationContext(reason: reason)
            let signingKey = try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: accessControl,
                authenticationContext: context
            )
            let wrappingKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: accessControl,
                authenticationContext: context
            )
            return V3EnrollmentGeneratedDeviceKeys(
                signingPublicKey:
                    signingKey.publicKey.x963Representation,
                wrappingPublicKey:
                    wrappingKey.publicKey.x963Representation,
                signingKeyRepresentation: signingKey.dataRepresentation,
                wrappingKeyRepresentation: wrappingKey.dataRepresentation
            )
        } catch let error as V3EnrollmentDeviceIdentityStoreError {
            throw error
        } catch {
            throw v3EnrollmentKeyOperationError(for: error)
        }
    }

    func publicKeys(
        signingKeyRepresentation: Data,
        wrappingKeyRepresentation: Data,
        reason: String
    ) throws -> (signing: Data, wrapping: Data) {
        guard !reason.isEmpty else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard isAvailable else {
            throw V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        }
        do {
            let context = makeAuthenticationContext(reason: reason)
            let signingKey = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: signingKeyRepresentation,
                authenticationContext: context
            )
            let wrappingKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: wrappingKeyRepresentation,
                authenticationContext: context
            )
            return (
                signingKey.publicKey.x963Representation,
                wrappingKey.publicKey.x963Representation
            )
        } catch {
            throw v3EnrollmentKeyOperationError(for: error)
        }
    }

    func signature(
        for input: Data,
        signingKeyRepresentation: Data,
        reason: String
    ) throws -> Data {
        guard !reason.isEmpty else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard isAvailable else {
            throw V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: signingKeyRepresentation,
                authenticationContext: makeAuthenticationContext(
                    reason: reason
                )
            )
            return try key.signature(for: input).rawRepresentation
        } catch {
            throw v3EnrollmentKeyOperationError(for: error)
        }
    }

    func sharedSecret(
        with publicKey: P256.KeyAgreement.PublicKey,
        wrappingKeyRepresentation: Data,
        reason: String
    ) throws -> SharedSecret {
        guard !reason.isEmpty else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard isAvailable else {
            throw V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: wrappingKeyRepresentation,
                authenticationContext: makeAuthenticationContext(
                    reason: reason
                )
            )
            return try key.sharedSecretFromKeyAgreement(with: publicKey)
        } catch {
            throw v3EnrollmentKeyOperationError(for: error)
        }
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        wrappingKeyRepresentation: Data,
        reason: String
    ) throws -> Data {
        guard !reason.isEmpty else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard isAvailable else {
            throw V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: wrappingKeyRepresentation,
                authenticationContext: makeAuthenticationContext(
                    reason: reason
                )
            )
            return try V3VaultKeyHPKE().unwrap(
                wrappedKey,
                recipientPrivateKey: key,
                context: context
            )
        } catch {
            throw v3EnrollmentKeyOperationError(for: error)
        }
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var accessControlError: Unmanaged<CFError>?
        guard
            let accessControl = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence],
                &accessControlError
            )
        else {
            _ = accessControlError?.takeRetainedValue()
            throw V3EnrollmentDeviceIdentityStoreError.keyOperationFailed
        }
        return accessControl
    }

    private func makeAuthenticationContext(reason: String) -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        return context
    }
}

func v3EnrollmentKeyOperationError(
    for error: Error
) -> V3EnrollmentDeviceIdentityStoreError {
    var current = error as NSError
    for _ in 0..<4 {
        if current.domain == LAError.errorDomain,
           let code = LAError.Code(rawValue: current.code)
        {
            switch code {
            case .authenticationFailed, .userCancel, .userFallback,
                    .systemCancel, .biometryLockout, .appCancel,
                    .notInteractive:
                return .authenticationCancelled
            default:
                break
            }
        }
        if current.domain == NSOSStatusErrorDomain {
            switch OSStatus(current.code) {
            case errSecAuthFailed, errSecUserCanceled,
                    errSecInteractionNotAllowed:
                return .authenticationCancelled
            default:
                break
            }
        }
        guard let underlying = current.userInfo[NSUnderlyingErrorKey]
                as? NSError,
              underlying !== current
        else {
            break
        }
        current = underlying
    }
    return .keyOperationFailed
}

struct V3EnrollmentDevicePrivateIdentity:
    V3EnrollmentMessageSigning,
    V3EnrollmentVaultKeyUnwrapping,
    V3DeviceWrappedVaultKeyUnwrapping,
    Sendable
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let signingKeyRepresentation: Data
    private let wrappingKeyRepresentation: Data
    private let keyOperations: any V3EnrollmentDeviceKeyOperating

    fileprivate init(
        record: V3EnrollmentDeviceKeyRecord,
        keyOperations: any V3EnrollmentDeviceKeyOperating
    ) {
        vaultID = record.vaultID
        publicIdentity = record.identity
        signingKeyRepresentation = record.signingKeyRepresentation
        wrappingKeyRepresentation = record.wrappingKeyRepresentation
        self.keyOperations = keyOperations
    }

    func signature(
        for input: Data,
        reason: String
    ) throws -> Data {
        try keyOperations.signature(
            for: input,
            signingKeyRepresentation: signingKeyRepresentation,
            reason: reason
        )
    }

    func unwrapVaultKey(
        _ ciphertext: Data,
        context: V3EnrollmentVaultKeyWrapContext,
        reason: String
    ) throws -> Data {
        guard context.vaultID == vaultID,
            context.recipientDeviceID == publicIdentity.deviceID,
            !reason.isEmpty
        else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        return try V3EnrollmentVaultKeyWrapper().unwrap(
            ciphertext,
            context: context
        ) { publicKey in
            try keyOperations.sharedSecret(
                with: publicKey,
                wrappingKeyRepresentation: wrappingKeyRepresentation,
                reason: reason
            )
        }
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data {
        guard context.vaultID == vaultID,
              context.recipientDeviceID == publicIdentity.deviceID,
              !reason.isEmpty
        else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        return try keyOperations.unwrapDeviceWrappedVaultKey(
            wrappedKey,
            context: context,
            wrappingKeyRepresentation: wrappingKeyRepresentation,
            reason: reason
        )
    }
}

struct V3EnrollmentDeviceIdentityManager: Sendable {
    private let recordStore: any V3EnrollmentDeviceKeyRecordStoring
    private let keyOperations: any V3EnrollmentDeviceKeyOperating

    init(
        recordStore: any V3EnrollmentDeviceKeyRecordStoring,
        keyOperations: any V3EnrollmentDeviceKeyOperating
    ) {
        self.recordStore = recordStore
        self.keyOperations = keyOperations
    }

    func createIdentity(
        vaultID: String,
        displayName: String,
        reason: String
    ) throws -> V3EnrollmentDevicePrivateIdentity {
        guard isValidV3UUID(vaultID),
            isValidV3DeviceDisplayName(displayName),
            !reason.isEmpty
        else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard try recordStore.loadRecord(vaultID: vaultID) == nil else {
            throw V3EnrollmentDeviceIdentityStoreError
                .identityAlreadyExists
        }
        guard keyOperations.isAvailable else {
            throw V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        }
        let generated = try keyOperations.generateDeviceKeys(reason: reason)
        let identity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: generated.signingPublicKey,
            wrappingPublicKey: generated.wrappingPublicKey
        )
        let record = try V3EnrollmentDeviceKeyRecord(
            vaultID: vaultID,
            identity: identity,
            signingKeyRepresentation: generated.signingKeyRepresentation,
            wrappingKeyRepresentation: generated.wrappingKeyRepresentation
        )
        try recordStore.insertRecord(
            record.canonicalBytes,
            vaultID: vaultID
        )
        return V3EnrollmentDevicePrivateIdentity(
            record: record,
            keyOperations: keyOperations
        )
    }

    func loadIdentity(
        vaultID: String,
        reason: String
    ) throws -> V3EnrollmentDevicePrivateIdentity? {
        guard isValidV3UUID(vaultID), !reason.isEmpty else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard let bytes = try recordStore.loadRecord(vaultID: vaultID) else {
            return nil
        }
        let record = try V3EnrollmentDeviceKeyRecord(canonicalBytes: bytes)
        guard record.vaultID == vaultID else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        let publicKeys = try keyOperations.publicKeys(
            signingKeyRepresentation: record.signingKeyRepresentation,
            wrappingKeyRepresentation: record.wrappingKeyRepresentation,
            reason: reason
        )
        let reconstructed = try V3EnrollmentDeviceIdentity(
            displayName: record.identity.displayName,
            signingPublicKey: publicKeys.signing,
            wrappingPublicKey: publicKeys.wrapping
        )
        guard reconstructed == record.identity else {
            throw V3EnrollmentDeviceIdentityStoreError.identityMismatch
        }
        return V3EnrollmentDevicePrivateIdentity(
            record: record,
            keyOperations: keyOperations
        )
    }

    /// Reads only the public identity recorded for this Mac.
    ///
    /// This is sufficient to label device inventory. Private-key operations
    /// still reconstruct and validate the Secure Enclave keys through
    /// `loadIdentity(vaultID:reason:)` before they can grant authority.
    func loadRecordedPublicIdentity(
        vaultID: String
    ) throws -> V3EnrollmentDeviceIdentity? {
        guard isValidV3UUID(vaultID) else {
            throw V3EnrollmentDeviceIdentityStoreError
                .invalidIdentityRequest
        }
        guard let bytes = try recordStore.loadRecord(vaultID: vaultID) else {
            return nil
        }
        let record = try V3EnrollmentDeviceKeyRecord(canonicalBytes: bytes)
        guard record.vaultID == vaultID else {
            throw V3EnrollmentDeviceIdentityStoreError.invalidRecord
        }
        return record.identity
    }
}

private func identityRecordMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func identityRecordString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    identityRecordMember(name, in: object)?.stringValue
}

private func identityRecordInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    identityRecordMember(name, in: object)?.integerValue
}

private func identityRecordData(
    _ name: String,
    maximumBytes: Int,
    in object: [(String, CanonicalJSONValue)]
) -> Data? {
    guard let encoded = identityRecordString(name, in: object),
        let data = Base64URL.decodeCanonical(encoded),
        !data.isEmpty,
        data.count <= maximumBytes
    else {
        return nil
    }
    return data
}
