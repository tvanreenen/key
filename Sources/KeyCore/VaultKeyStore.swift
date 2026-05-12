import CryptoKit
import Foundation
import LocalAuthentication
import MultipeerConnectivity
import Security

public struct EnclaveDeviceRecord: Codable, Equatable, Sendable {
    public let deviceID: String
    public let deviceName: String
    public let publicKey: String
    public let addedAt: Date
    public let status: String

    public init(deviceID: String, deviceName: String, publicKey: String, addedAt: Date, status: String) {
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.publicKey = publicKey
        self.addedAt = addedAt
        self.status = status
    }
}

public struct EnclaveWrappedKeyRecord: Codable, Equatable, Sendable {
    public let deviceID: String
    public let epoch: Int
    public let algorithm: String
    public let ciphertext: String

    public init(deviceID: String, epoch: Int, algorithm: String, ciphertext: String) {
        self.deviceID = deviceID
        self.epoch = epoch
        self.algorithm = algorithm
        self.ciphertext = ciphertext
    }
}

public struct EnclaveVaultMetadata: Codable, Equatable, Sendable {
    public let version: Int
    public let securityMode: SecurityMode
    public let vaultID: String
    public let epoch: Int
    public var devices: [EnclaveDeviceRecord]
    public var wrappedKeys: [EnclaveWrappedKeyRecord]

    public init(
        version: Int = 1,
        securityMode: SecurityMode = .enclave,
        vaultID: String,
        epoch: Int,
        devices: [EnclaveDeviceRecord],
        wrappedKeys: [EnclaveWrappedKeyRecord]
    ) {
        self.version = version
        self.securityMode = securityMode
        self.vaultID = vaultID
        self.epoch = epoch
        self.devices = devices
        self.wrappedKeys = wrappedKeys
    }
}

public struct DeviceRegistrationResult: Equatable, Sendable {
    public let message: String

    public init(message: String) {
        self.message = message
    }
}

public enum VaultAccessState: String, Equatable, Sendable {
    case localReady = "local-ready"
    case localMissingKey = "local-missing-key"
    case enclaveMissingIdentity = "enclave-missing-identity"
    case enclaveNotApproved = "enclave-not-approved"
    case enclaveWaitingForWrappedKey = "enclave-waiting-for-wrapped-key"
    case enclaveReady = "enclave-ready"
    case stale = "stale"
}

public struct VaultStatusReport: Equatable, Sendable {
    public let vaultRootPath: String
    public let isICloudBacked: Bool
    public let securityMode: SecurityMode
    public let hasEncryptedEntries: Bool
    public let metadataExists: Bool
    public let deviceID: String?
    public let accessState: VaultAccessState
    public let detail: String

    public init(
        vaultRootPath: String,
        isICloudBacked: Bool,
        securityMode: SecurityMode,
        hasEncryptedEntries: Bool,
        metadataExists: Bool,
        deviceID: String?,
        accessState: VaultAccessState,
        detail: String
    ) {
        self.vaultRootPath = vaultRootPath
        self.isICloudBacked = isICloudBacked
        self.securityMode = securityMode
        self.hasEncryptedEntries = hasEncryptedEntries
        self.metadataExists = metadataExists
        self.deviceID = deviceID
        self.accessState = accessState
        self.detail = detail
    }
}

private struct DeviceIdentity {
    let privateKey: SecKey
    let publicKeyData: Data
    let deviceID: String
    let deviceName: String
}

private struct DeviceEnrollmentRequest: Codable, Equatable {
    let version: Int
    let vaultID: String
    let deviceID: String
    let deviceName: String
    let publicKey: String
    let requestedAt: Date
    let verificationCode: String
    let signature: String
}

private struct PendingDeviceApproval {
    let request: DeviceEnrollmentRequest
}

private enum MetadataInspection {
    case absent
    case readable(EnclaveVaultMetadata)
    case unreadable
}

public protocol VaultKeyStoring {
    func loadKey(mode: SecurityMode, vaultRootURL: URL, reason: String, createIfMissing: Bool) throws -> Data
    func keyExists(mode: SecurityMode, vaultRootURL: URL) throws -> Bool
    func storeKey(_ keyData: Data, mode: SecurityMode, overwriteExisting: Bool) throws
    func deleteKey(mode: SecurityMode) throws
    func inspectVault(vaultRootURL: URL, securityMode: SecurityMode, hasEncryptedEntries: Bool) throws -> VaultStatusReport
    func migrateLocalVaultToEnclave(vaultRootURL: URL, reason: String) throws
    func registerDevice(vaultRootURL: URL, manual: Bool) throws -> DeviceRegistrationResult
    func prepareNearbyDeviceApproval(vaultRootURL: URL) throws -> DeviceApprovalInfo
    func prepareManualDeviceApproval(vaultRootURL: URL, requestData: Data) throws -> DeviceApprovalInfo
    func confirmDeviceApproval(vaultRootURL: URL, verificationCode: String) throws
    func syncDevice(vaultRootURL: URL) throws -> String
    func leaveEnclaveVault(vaultRootURL: URL, reason: String) throws -> String
    func removeEnclaveArtifacts(vaultRootURL: URL) throws -> String?
    func invalidate()
}

public final class VaultKeyStore: VaultKeyStoring {
    private static let metadataFilename = ".key-vault.json"
    private static let wrappingAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private static let signingAlgorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

    private let configuration: RuntimeConfiguration
    private let fileManager: FileManager
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let stateQueue = DispatchQueue(label: "work.tvr.key.vault-key-store")
    private var advertiser: NearbyEnrollmentAdvertiser?
    private var pendingApproval: PendingDeviceApproval?

    public init(configuration: RuntimeConfiguration, fileManager: FileManager = .default) {
        self.configuration = configuration
        self.fileManager = fileManager
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.decoder.dateDecodingStrategy = .iso8601
        self.encoder.dateEncodingStrategy = .iso8601
    }

    public func loadKey(mode: SecurityMode, vaultRootURL: URL, reason: String, createIfMissing: Bool) throws -> Data {
        switch mode {
        case .local:
            return try loadLocalVaultKey(reason: reason, createIfMissing: createIfMissing)
        case .enclave:
            guard createIfMissing == false else {
                throw AppError.operationRefused("Enclave vault mode must be initialized before it can create a vault key on demand.")
            }
            return try loadEnclaveVaultKey(vaultRootURL: vaultRootURL, reason: reason)
        }
    }

    public func keyExists(mode: SecurityMode, vaultRootURL: URL) throws -> Bool {
        switch mode {
        case .local:
            return try localKeyExists()
        case .enclave:
            guard let metadata = try loadMetadataIfPresent(vaultRootURL: vaultRootURL) else {
                return false
            }
            guard let identity = try loadDeviceIdentityIfPresent(reason: "Unlock device identity.", allowInteraction: false) else {
                return false
            }
            return metadata.wrappedKeys.contains { $0.deviceID == identity.deviceID && $0.epoch == metadata.epoch }
        }
    }

    public func storeKey(_ keyData: Data, mode: SecurityMode, overwriteExisting: Bool) throws {
        switch mode {
        case .local:
            try storeLocalVaultKey(keyData, overwriteExisting: overwriteExisting)
        case .enclave:
            throw AppError.operationRefused("Raw vault keys are not stored directly in Keychain in enclave mode.")
        }
    }

    public func deleteKey(mode: SecurityMode) throws {
        switch mode {
        case .local:
            try deleteLocalKeyIfPresent()
        case .enclave:
            break
        }
    }

    public func inspectVault(vaultRootURL: URL, securityMode: SecurityMode, hasEncryptedEntries: Bool) throws -> VaultStatusReport {
        let metadataState = inspectMetadata(vaultRootURL: vaultRootURL)
        let metadataExists: Bool
        switch metadataState {
        case .absent:
            metadataExists = false
        case .readable, .unreadable:
            metadataExists = true
        }

        let isICloudBacked = fileManager.isUbiquitousItem(at: vaultRootURL)
        let path = vaultRootURL.path(percentEncoded: false)

        switch securityMode {
        case .local:
            if case .unreadable = metadataState {
                return VaultStatusReport(
                    vaultRootPath: path,
                    isICloudBacked: isICloudBacked,
                    securityMode: .local,
                    hasEncryptedEntries: hasEncryptedEntries,
                    metadataExists: true,
                    deviceID: nil,
                    accessState: .stale,
                    detail: "Vault metadata exists but is unreadable. This vault should be treated as local-only until the stale metadata is removed."
                )
            }

            let localKeyExists = (try? localKeyExists()) ?? false
            if localKeyExists {
                return VaultStatusReport(
                    vaultRootPath: path,
                    isICloudBacked: isICloudBacked,
                    securityMode: .local,
                    hasEncryptedEntries: hasEncryptedEntries,
                    metadataExists: metadataExists,
                    deviceID: nil,
                    accessState: .localReady,
                    detail: metadataExists
                        ? "This vault is using a local-only key, but enclave metadata is still present in the vault folder."
                        : "This vault uses a local-only Keychain vault key on this Mac."
                )
            }

            return VaultStatusReport(
                vaultRootPath: path,
                isICloudBacked: isICloudBacked,
                securityMode: .local,
                hasEncryptedEntries: hasEncryptedEntries,
                metadataExists: metadataExists,
                deviceID: nil,
                accessState: .localMissingKey,
                detail: hasEncryptedEntries
                    ? "Encrypted vault files are present, but this Mac does not have the matching local Keychain vault key."
                    : "This local vault has not created a Keychain vault key yet."
            )
        case .enclave:
            switch metadataState {
            case .absent:
                return VaultStatusReport(
                    vaultRootPath: path,
                    isICloudBacked: isICloudBacked,
                    securityMode: .enclave,
                    hasEncryptedEntries: hasEncryptedEntries,
                    metadataExists: false,
                    deviceID: nil,
                    accessState: .stale,
                    detail: "This vault is configured for enclave mode, but enclave metadata is missing."
                )
            case .unreadable:
                return VaultStatusReport(
                    vaultRootPath: path,
                    isICloudBacked: isICloudBacked,
                    securityMode: .enclave,
                    hasEncryptedEntries: hasEncryptedEntries,
                    metadataExists: true,
                    deviceID: nil,
                    accessState: .stale,
                    detail: "Enclave metadata exists but is unreadable or corrupt."
                )
            case let .readable(metadata):
                guard let identity = try loadDeviceIdentityIfPresent(reason: "Inspect device identity.", allowInteraction: false) else {
                    return VaultStatusReport(
                        vaultRootPath: path,
                        isICloudBacked: isICloudBacked,
                        securityMode: .enclave,
                        hasEncryptedEntries: hasEncryptedEntries,
                        metadataExists: true,
                        deviceID: nil,
                        accessState: .enclaveMissingIdentity,
                        detail: "This Mac can see the shared vault metadata, but it does not yet have a local Secure Enclave device identity for this vault."
                    )
                }

                let approved = metadata.devices.contains { $0.deviceID == identity.deviceID }
                let hasWrappedKey = metadata.wrappedKeys.contains { $0.deviceID == identity.deviceID && $0.epoch == metadata.epoch }

                if !approved {
                    return VaultStatusReport(
                        vaultRootPath: path,
                        isICloudBacked: isICloudBacked,
                        securityMode: .enclave,
                        hasEncryptedEntries: hasEncryptedEntries,
                        metadataExists: true,
                        deviceID: identity.deviceID,
                        accessState: .enclaveNotApproved,
                        detail: "This Mac can see the shared vault, but it has not been approved for enclave access."
                    )
                }

                if !hasWrappedKey {
                    return VaultStatusReport(
                        vaultRootPath: path,
                        isICloudBacked: isICloudBacked,
                        securityMode: .enclave,
                        hasEncryptedEntries: hasEncryptedEntries,
                        metadataExists: true,
                        deviceID: identity.deviceID,
                        accessState: .enclaveWaitingForWrappedKey,
                        detail: "This Mac is approved for the shared vault, but its wrapped vault key has not arrived in synced metadata yet."
                    )
                }

                return VaultStatusReport(
                    vaultRootPath: path,
                    isICloudBacked: isICloudBacked,
                    securityMode: .enclave,
                    hasEncryptedEntries: hasEncryptedEntries,
                    metadataExists: true,
                    deviceID: identity.deviceID,
                    accessState: .enclaveReady,
                    detail: "This Mac is authorized to unwrap the shared vault key for the current metadata epoch."
                )
            }
        }
    }

    public func migrateLocalVaultToEnclave(vaultRootURL: URL, reason: String) throws {
        if let metadata = try loadMetadataIfPresent(vaultRootURL: vaultRootURL) {
            guard metadata.securityMode == .enclave else {
                throw AppError.invalidConfiguration("Vault metadata at '\(metadataURL(for: vaultRootURL).path(percentEncoded: false))' is not an enclave vault.")
            }
            _ = try loadOrCreateDeviceIdentity(reason: reason)
            return
        }

        let localKey = try loadLocalVaultKey(reason: reason, createIfMissing: true)
        let identity = try loadOrCreateDeviceIdentity(reason: reason)
        try preflightWrappedKeySupport(publicKeyData: identity.publicKeyData, privateKey: identity.privateKey)

        let wrappedKey = try wrapVaultKey(localKey, publicKeyData: identity.publicKeyData)
        let metadata = EnclaveVaultMetadata(
            vaultID: UUID().uuidString.lowercased(),
            epoch: 1,
            devices: [
                EnclaveDeviceRecord(
                    deviceID: identity.deviceID,
                    deviceName: identity.deviceName,
                    publicKey: identity.publicKeyData.base64EncodedString(),
                    addedAt: Date(),
                    status: "authorized"
                )
            ],
            wrappedKeys: [
                EnclaveWrappedKeyRecord(
                    deviceID: identity.deviceID,
                    epoch: 1,
                    algorithm: String(describing: Self.wrappingAlgorithm),
                    ciphertext: wrappedKey.base64EncodedString()
                )
            ]
        )
        try saveMetadata(metadata, vaultRootURL: vaultRootURL)

        let verified = try loadEnclaveVaultKey(vaultRootURL: vaultRootURL, reason: reason)
        guard verified == localKey else {
            throw AppError.service("Secure Enclave migration verification failed for vault at '\(vaultRootURL.path(percentEncoded: false))'.")
        }

        try deleteLocalKeyIfPresent()
    }

    public func registerDevice(vaultRootURL: URL, manual: Bool) throws -> DeviceRegistrationResult {
        let metadata = try loadMetadata(vaultRootURL: vaultRootURL)
        let identity = try loadOrCreateDeviceIdentity(reason: "Unlock device identity to prepare enrollment.")
        let request = try makeEnrollmentRequest(vaultID: metadata.vaultID, identity: identity)

        let codeLine = "Verification code: \(request.verificationCode)\nDevice fingerprint: \(request.deviceID)\n"
        if manual {
            let outputURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent("key-enrollment-\(request.deviceID).json", isDirectory: false)
            let data = try encoder.encode(request)
            try data.write(to: outputURL, options: .atomic)
            return DeviceRegistrationResult(
                message: "Wrote enrollment request to \(outputURL.path(percentEncoded: false))\n\(codeLine)"
            )
        }

        let data = try encoder.encode(request)
        try stateQueue.sync {
            advertiser?.stop()
            let advertiser = NearbyEnrollmentAdvertiser(
                serviceType: configuration.nearbyPairingServiceType,
                requestData: data,
                displayName: identity.deviceName
            )
            try advertiser.start()
            self.advertiser = advertiser
        }

        return DeviceRegistrationResult(
            message: "Advertising enrollment request for vault '\(metadata.vaultID)'.\n\(codeLine)"
        )
    }

    public func prepareNearbyDeviceApproval(vaultRootURL: URL) throws -> DeviceApprovalInfo {
        _ = try loadMetadata(vaultRootURL: vaultRootURL)
        let browser = NearbyEnrollmentBrowser(serviceType: configuration.nearbyPairingServiceType)
        let data = try browser.discoverSingleRequest(timeout: 15)
        let request = try decodeAndValidateEnrollmentRequest(data, vaultRootURL: vaultRootURL)
        return try stagePendingApproval(request)
    }

    public func prepareManualDeviceApproval(vaultRootURL: URL, requestData: Data) throws -> DeviceApprovalInfo {
        let request = try decodeAndValidateEnrollmentRequest(requestData, vaultRootURL: vaultRootURL)
        return try stagePendingApproval(request)
    }

    public func confirmDeviceApproval(vaultRootURL: URL, verificationCode: String) throws {
        let staged = try stateQueue.sync {
            guard let pendingApproval else {
                throw AppError.operationRefused("No pending device approval is staged.")
            }
            return pendingApproval
        }

        guard verificationCode == staged.request.verificationCode else {
            throw AppError.operationRefused("Verification code did not match the pending device approval request.")
        }

        let keyData = try loadEnclaveVaultKey(
            vaultRootURL: vaultRootURL,
            reason: "Unlock key vault to approve device '\(staged.request.deviceName)'."
        )
        var metadata = try loadMetadata(vaultRootURL: vaultRootURL)
        let wrapped = try wrapVaultKey(keyData, publicKeyData: Data(base64Encoded: staged.request.publicKey) ?? Data())
        let device = EnclaveDeviceRecord(
            deviceID: staged.request.deviceID,
            deviceName: staged.request.deviceName,
            publicKey: staged.request.publicKey,
            addedAt: staged.request.requestedAt,
            status: "authorized"
        )
        metadata.devices.removeAll { $0.deviceID == device.deviceID }
        metadata.devices.append(device)
        metadata.wrappedKeys.removeAll { $0.deviceID == device.deviceID }
        metadata.wrappedKeys.append(
            EnclaveWrappedKeyRecord(
                deviceID: device.deviceID,
                epoch: metadata.epoch,
                algorithm: String(describing: Self.wrappingAlgorithm),
                ciphertext: wrapped.base64EncodedString()
            )
        )
        try saveMetadata(metadata, vaultRootURL: vaultRootURL)

        stateQueue.sync {
            pendingApproval = nil
        }
    }

    public func syncDevice(vaultRootURL: URL) throws -> String {
        let metadata = try loadMetadata(vaultRootURL: vaultRootURL)
        let identity = try loadOrCreateDeviceIdentity(reason: "Unlock device identity to sync vault authorization.")
        guard metadata.devices.contains(where: { $0.deviceID == identity.deviceID }) else {
            throw AppError.operationRefused("This Mac has not been approved for enclave access to '\(vaultRootURL.path(percentEncoded: false))'.")
        }
        guard metadata.wrappedKeys.contains(where: { $0.deviceID == identity.deviceID && $0.epoch == metadata.epoch }) else {
            throw AppError.operationRefused("Vault metadata for '\(vaultRootURL.path(percentEncoded: false))' does not yet contain a wrapped key for this Mac.")
        }
        return "Device '\(identity.deviceName)' is authorized for vault '\(metadata.vaultID)'.\n"
    }

    public func leaveEnclaveVault(vaultRootURL: URL, reason: String) throws -> String {
        _ = try loadEnclaveVaultKey(vaultRootURL: vaultRootURL, reason: reason)
        var metadata = try loadMetadata(vaultRootURL: vaultRootURL)
        guard let identity = try loadDeviceIdentityIfPresent(reason: reason, allowInteraction: true) else {
            throw AppError.operationRefused("This Mac does not have a local Secure Enclave identity for vault '\(vaultRootURL.path(percentEncoded: false))'.")
        }

        guard metadata.devices.contains(where: { $0.deviceID == identity.deviceID }) else {
            throw AppError.operationRefused("This Mac is not currently authorized for shared access to '\(vaultRootURL.path(percentEncoded: false))'.")
        }

        let remainingAuthorizedDevices = metadata.devices.filter { $0.deviceID != identity.deviceID }
        guard !remainingAuthorizedDevices.isEmpty else {
            throw AppError.operationRefused("Refusing to leave the shared vault because this is the last authorized device. Use `key vault unshare` if you want to convert the vault back to local-only mode.")
        }

        metadata.devices = remainingAuthorizedDevices
        metadata.wrappedKeys.removeAll { $0.deviceID == identity.deviceID }
        try saveMetadata(metadata, vaultRootURL: vaultRootURL)
        try deleteDeviceIdentityIfPresent()
        return "This Mac has left shared vault '\(metadata.vaultID)'.\n"
    }

    public func removeEnclaveArtifacts(vaultRootURL: URL) throws -> String? {
        let metadataURL = metadataURL(for: vaultRootURL)
        if fileManager.fileExists(atPath: metadataURL.path(percentEncoded: false)) {
            do {
                try fileManager.removeItem(at: metadataURL)
            } catch {
                let metadata = try? loadMetadata(vaultRootURL: vaultRootURL)
                if let metadata {
                    try saveInvalidatedMetadata(metadata, vaultRootURL: vaultRootURL)
                    try? deleteDeviceIdentityIfPresent()
                    return "Converted vault to local mode, but stale shared-vault metadata had to be invalidated instead of removed.\n"
                }
                throw AppError.io("Failed to remove shared vault metadata at '\(metadataURL.path(percentEncoded: false))': \(error.localizedDescription)")
            }
        }

        try? deleteDeviceIdentityIfPresent()
        return nil
    }

    public func invalidate() {
        stateQueue.sync {
            advertiser?.stop()
            advertiser = nil
            pendingApproval = nil
        }
    }

    func storageAttributes(for mode: SecurityMode) throws -> [String: Any] {
        switch mode {
        case .local:
            var accessControlError: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                nil,
                accessibilityClass(for: mode),
                .userPresence,
                &accessControlError
            ) else {
                let message = (accessControlError?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
                throw AppError.keychain("Failed to create vault key access control: \(message)")
            }
            return [kSecAttrAccessControl as String: accessControl]
        case .enclave:
            return [:]
        }
    }

    private func loadLocalVaultKey(reason: String, createIfMissing: Bool) throws -> Data {
        if try localKeyExists() {
            return try loadExistingLocalVaultKey(reason: reason)
        }

        guard createIfMissing else {
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }

        let keyData = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
        try storeLocalVaultKey(keyData, overwriteExisting: false)
        return keyData
    }

    private func localKeyExists() throws -> Bool {
        var query = try baseLocalQuery()
        let context = makeAuthenticationContext()
        context.interactionNotAllowed = true
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
        case errSecSuccess, errSecInteractionNotAllowed:
            return true
        case errSecItemNotFound:
            return false
        default:
            throw AppError.keychain("Failed to query Keychain (\(status)).")
        }
    }

    private func storeLocalVaultKey(_ keyData: Data, overwriteExisting: Bool) throws {
        if overwriteExisting {
            try deleteLocalKeyIfPresent()
        }

        var query = try baseLocalQuery()
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount,
            kSecAttrLabel as String: "key vault key",
            kSecValueData as String: keyData
        ]) { _, new in new }
        try query.merge(storageAttributes(for: .local)) { _, new in new }

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem, overwriteExisting {
            throw AppError.keychain("Failed to replace vault key in Keychain (\(status)).")
        }
        guard status == errSecSuccess else {
            throw AppError.keychain("Failed to store vault key in Keychain (\(status)).")
        }
    }

    private func loadExistingLocalVaultKey(reason: String) throws -> Data {
        var query = try baseLocalQuery()
        let context = makeAuthenticationContext()
        context.localizedReason = reason
        var item: CFTypeRef?
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw AppError.entryNotFound("Vault key does not exist yet.")
            }
            if status == errSecAuthFailed || status == errSecUserCanceled {
                throw AppError.authFailed("Authentication was cancelled or failed.")
            }
            throw AppError.keychain("Failed to load vault key from Keychain (\(status)).")
        }

        guard let data = item as? Data else {
            throw AppError.keychain("Keychain returned an unexpected vault key payload.")
        }

        return data
    }

    private func deleteLocalKeyIfPresent() throws {
        var query = try baseLocalQuery()
        query.merge([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: configuration.vaultService,
            kSecAttrAccount as String: configuration.vaultAccount
        ]) { _, new in new }

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppError.keychain("Failed to replace vault key in Keychain (\(status)).")
        }
    }

    private func loadEnclaveVaultKey(vaultRootURL: URL, reason: String) throws -> Data {
        let metadata = try loadMetadata(vaultRootURL: vaultRootURL)
        let identity = try loadOrCreateDeviceIdentity(reason: reason)
        guard let wrappedKey = metadata.wrappedKeys.first(where: { $0.deviceID == identity.deviceID && $0.epoch == metadata.epoch }) else {
            throw AppError.operationRefused("This Mac is not authorized to unlock enclave vault '\(vaultRootURL.path(percentEncoded: false))'.")
        }
        guard let ciphertext = Data(base64Encoded: wrappedKey.ciphertext) else {
            throw AppError.invalidConfiguration("Vault metadata at '\(metadataURL(for: vaultRootURL).path(percentEncoded: false))' contains an invalid wrapped key payload.")
        }

        return try decryptWrappedVaultKey(ciphertext, privateKey: identity.privateKey)
    }

    private func loadMetadata(vaultRootURL: URL) throws -> EnclaveVaultMetadata {
        guard let metadata = try loadMetadataIfPresent(vaultRootURL: vaultRootURL) else {
            throw AppError.invalidConfiguration("Vault '\(vaultRootURL.path(percentEncoded: false))' is not initialized for enclave mode.")
        }
        guard metadata.securityMode == .enclave else {
            throw AppError.invalidConfiguration("Vault metadata at '\(metadataURL(for: vaultRootURL).path(percentEncoded: false))' does not describe an enclave vault.")
        }
        return metadata
    }

    private func loadMetadataIfPresent(vaultRootURL: URL) throws -> EnclaveVaultMetadata? {
        let url = metadataURL(for: vaultRootURL)
        guard fileManager.fileExists(atPath: url.path(percentEncoded: false)) else {
            return nil
        }

        do {
            let data = try Data(contentsOf: url)
            return try decoder.decode(EnclaveVaultMetadata.self, from: data)
        } catch {
            throw AppError.invalidConfiguration("Vault metadata at '\(url.path(percentEncoded: false))' is unreadable.")
        }
    }

    private func inspectMetadata(vaultRootURL: URL) -> MetadataInspection {
        let url = metadataURL(for: vaultRootURL)
        guard fileManager.fileExists(atPath: url.path(percentEncoded: false)) else {
            return .absent
        }

        do {
            let data = try Data(contentsOf: url)
            let metadata = try decoder.decode(EnclaveVaultMetadata.self, from: data)
            return .readable(metadata)
        } catch {
            return .unreadable
        }
    }

    private func saveMetadata(_ metadata: EnclaveVaultMetadata, vaultRootURL: URL) throws {
        let url = metadataURL(for: vaultRootURL)
        let directory = url.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        let tempURL = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        defer { try? fileManager.removeItem(at: tempURL) }

        do {
            let data = try encoder.encode(metadata)
            try data.write(to: tempURL, options: .atomic)
            if fileManager.fileExists(atPath: url.path(percentEncoded: false)) {
                _ = try fileManager.replaceItemAt(url, withItemAt: tempURL)
            } else {
                try fileManager.moveItem(at: tempURL, to: url)
            }
        } catch let error as AppError {
            throw error
        } catch {
            throw AppError.io("Failed to store vault metadata at '\(url.path(percentEncoded: false))': \(error.localizedDescription)")
        }
    }

    private func saveInvalidatedMetadata(_ metadata: EnclaveVaultMetadata, vaultRootURL: URL) throws {
        let invalidated = EnclaveVaultMetadata(
            version: metadata.version,
            securityMode: .local,
            vaultID: metadata.vaultID,
            epoch: metadata.epoch,
            devices: [],
            wrappedKeys: []
        )
        try saveMetadata(invalidated, vaultRootURL: vaultRootURL)
    }

    private func metadataURL(for vaultRootURL: URL) -> URL {
        vaultRootURL.appendingPathComponent(Self.metadataFilename, isDirectory: false)
    }

    private func loadOrCreateDeviceIdentity(reason: String) throws -> DeviceIdentity {
        if let identity = try loadDeviceIdentityIfPresent(reason: reason, allowInteraction: true) {
            return identity
        }
        return try createDeviceIdentity(reason: reason)
    }

    private func loadDeviceIdentityIfPresent(reason: String, allowInteraction: Bool) throws -> DeviceIdentity? {
        var query = try baseDeviceKeyQuery()
        let context = makeAuthenticationContext()
        context.localizedReason = reason
        context.interactionNotAllowed = !allowInteraction
        query.merge([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(configuration.deviceKeyApplicationTag.utf8),
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]) { _, new in new }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let privateKey = item as! SecKey?,
                  let publicKey = SecKeyCopyPublicKey(privateKey),
                  let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                throw AppError.keychain("Secure Enclave device identity is incomplete.")
            }
            return DeviceIdentity(
                privateKey: privateKey,
                publicKeyData: publicData,
                deviceID: deviceID(for: publicData),
                deviceName: currentDeviceName()
            )
        case errSecItemNotFound:
            return nil
        case errSecInteractionNotAllowed:
            return nil
        case errSecAuthFailed, errSecUserCanceled:
            throw AppError.authFailed("Authentication was cancelled or failed.")
        default:
            throw AppError.keychain("Failed to load Secure Enclave device identity (\(status)).")
        }
    }

    private func createDeviceIdentity(reason: String) throws -> DeviceIdentity {
        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessControlError
        ) else {
            let message = (accessControlError?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.keychain("Failed to create Secure Enclave access control: \(message)")
        }

        var privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(configuration.deviceKeyApplicationTag.utf8),
            kSecAttrAccessControl as String: accessControl
        ]
        if let accessGroup = configuration.keychainAccessGroup, !accessGroup.isEmpty {
            privateKeyAttributes[kSecAttrAccessGroup as String] = accessGroup
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttributes
        ]
        if configuration.useDataProtectionKeychain {
            attributes[kSecUseDataProtectionKeychain as String] = true
        }

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.authUnavailable("Failed to create Secure Enclave device identity: \(message)")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw AppError.keychain("Failed to derive a public key from the Secure Enclave device identity.")
        }
        _ = reason
        return DeviceIdentity(
            privateKey: privateKey,
            publicKeyData: publicData,
            deviceID: deviceID(for: publicData),
            deviceName: currentDeviceName()
        )
    }

    private func deleteDeviceIdentityIfPresent() throws {
        var query = try baseDeviceKeyQuery()
        query.merge([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: Data(configuration.deviceKeyApplicationTag.utf8)
        ]) { _, new in new }

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AppError.keychain("Failed to remove the local Secure Enclave device identity (\(status)).")
        }
    }

    private func makeEnrollmentRequest(vaultID: String, identity: DeviceIdentity) throws -> DeviceEnrollmentRequest {
        let verificationCode = String(format: "%06d", Int.random(in: 0..<1_000_000))
        let requestTemplate = DeviceEnrollmentRequest(
            version: 1,
            vaultID: vaultID,
            deviceID: identity.deviceID,
            deviceName: identity.deviceName,
            publicKey: identity.publicKeyData.base64EncodedString(),
            requestedAt: Date(),
            verificationCode: verificationCode,
            signature: ""
        )
        let payload = try encoder.encode(requestTemplate)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            identity.privateKey,
            Self.signingAlgorithm,
            payload as CFData,
            &error
        ) as Data? else {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.authUnavailable("Failed to sign device enrollment request: \(message)")
        }

        return DeviceEnrollmentRequest(
            version: requestTemplate.version,
            vaultID: requestTemplate.vaultID,
            deviceID: requestTemplate.deviceID,
            deviceName: requestTemplate.deviceName,
            publicKey: requestTemplate.publicKey,
            requestedAt: requestTemplate.requestedAt,
            verificationCode: requestTemplate.verificationCode,
            signature: signature.base64EncodedString()
        )
    }

    private func decodeAndValidateEnrollmentRequest(_ data: Data, vaultRootURL: URL) throws -> DeviceEnrollmentRequest {
        let request: DeviceEnrollmentRequest
        do {
            request = try decoder.decode(DeviceEnrollmentRequest.self, from: data)
        } catch {
            throw AppError.invalidConfiguration("Device enrollment request is unreadable.")
        }

        let metadata = try loadMetadata(vaultRootURL: vaultRootURL)
        guard request.vaultID == metadata.vaultID else {
            throw AppError.invalidConfiguration("Device enrollment request targets a different vault.")
        }

        guard let publicKeyData = Data(base64Encoded: request.publicKey),
              let signatureData = Data(base64Encoded: request.signature) else {
            throw AppError.invalidConfiguration("Device enrollment request contains invalid key material.")
        }

        let unsignedRequest = DeviceEnrollmentRequest(
            version: request.version,
            vaultID: request.vaultID,
            deviceID: request.deviceID,
            deviceName: request.deviceName,
            publicKey: request.publicKey,
            requestedAt: request.requestedAt,
            verificationCode: request.verificationCode,
            signature: ""
        )
        let unsignedData = try encoder.encode(unsignedRequest)
        let publicKey = try makePublicKey(from: publicKeyData)
        guard SecKeyVerifySignature(publicKey, Self.signingAlgorithm, unsignedData as CFData, signatureData as CFData, nil) else {
            throw AppError.invalidConfiguration("Device enrollment request signature verification failed.")
        }
        guard deviceID(for: publicKeyData) == request.deviceID else {
            throw AppError.invalidConfiguration("Device enrollment request fingerprint does not match the advertised public key.")
        }

        return request
    }

    private func stagePendingApproval(_ request: DeviceEnrollmentRequest) throws -> DeviceApprovalInfo {
        stateQueue.sync {
            pendingApproval = PendingDeviceApproval(request: request)
            return DeviceApprovalInfo(
                deviceName: request.deviceName,
                deviceID: request.deviceID,
                verificationCode: request.verificationCode
            )
        }
    }

    private func wrapVaultKey(_ keyData: Data, publicKeyData: Data) throws -> Data {
        let publicKey = try makePublicKey(from: publicKeyData)
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            Self.wrappingAlgorithm,
            keyData as CFData,
            &error
        ) as Data? else {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.keychain("Failed to wrap the vault key for an authorized device: \(message)")
        }
        return encrypted
    }

    private func decryptWrappedVaultKey(_ ciphertext: Data, privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            privateKey,
            Self.wrappingAlgorithm,
            ciphertext as CFData,
            &error
        ) as Data? else {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.authUnavailable("Failed to unwrap the enclave vault key: \(message)")
        }
        return decrypted
    }

    private func preflightWrappedKeySupport(publicKeyData: Data, privateKey: SecKey) throws {
        let publicKey = try makePublicKey(from: publicKeyData)
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, Self.wrappingAlgorithm) else {
            throw AppError.authUnavailable("This Mac does not support the configured Secure Enclave wrapping algorithm for vault enrollment.")
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, Self.wrappingAlgorithm) else {
            throw AppError.authUnavailable("This Mac does not support the configured Secure Enclave unwrap algorithm for vault enrollment.")
        }
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, Self.signingAlgorithm) else {
            throw AppError.authUnavailable("This Mac does not support signing enrollment requests with the Secure Enclave device identity.")
        }
    }

    private func makePublicKey(from data: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
            let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "Unknown error."
            throw AppError.invalidConfiguration("Failed to decode an enrolled device public key: \(message)")
        }
        return key
    }

    private func baseLocalQuery() throws -> [String: Any] {
        guard !configuration.vaultService.isEmpty, !configuration.vaultAccount.isEmpty else {
            throw AppError.invalidConfiguration("Vault key service configuration is missing.")
        }
        guard let accessGroup = configuration.keychainAccessGroup, !accessGroup.isEmpty else {
            throw AppError.invalidConfiguration("This build is not configured with a shared keychain access group.")
        }

        var query: [String: Any] = [:]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        query[kSecAttrAccessGroup as String] = accessGroup
        return query
    }

    private func baseDeviceKeyQuery() throws -> [String: Any] {
        guard let accessGroup = configuration.keychainAccessGroup, !accessGroup.isEmpty else {
            throw AppError.invalidConfiguration("This build is not configured with a shared keychain access group.")
        }

        var query: [String: Any] = [:]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        query[kSecAttrAccessGroup as String] = accessGroup
        return query
    }

    private func accessibilityClass(for mode: SecurityMode) -> CFString {
        switch mode {
        case .local:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .enclave:
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }

    private func deviceID(for publicKeyData: Data) -> String {
        SHA256.hash(data: publicKeyData).map { String(format: "%02x", $0) }.joined()
    }

    private func currentDeviceName() -> String {
        Host.current().localizedName ?? ProcessInfo.processInfo.hostName
    }

    private func makeAuthenticationContext() -> LAContext {
        LAContext()
    }
}

private final class NearbyEnrollmentAdvertiser: NSObject, MCNearbyServiceAdvertiserDelegate, MCSessionDelegate {
    private let requestData: Data
    private let peerID: MCPeerID
    private let serviceType: String
    private lazy var session = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
    private lazy var advertiser = MCNearbyServiceAdvertiser(peer: peerID, discoveryInfo: nil, serviceType: serviceType)

    init(serviceType: String, requestData: Data, displayName: String) {
        self.serviceType = serviceType
        self.requestData = requestData
        self.peerID = MCPeerID(displayName: String(displayName.prefix(63)))
        super.init()
    }

    func start() throws {
        session.delegate = self
        advertiser.delegate = self
        advertiser.startAdvertisingPeer()
    }

    func stop() {
        advertiser.stopAdvertisingPeer()
        session.disconnect()
    }

    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        invitationHandler(true, session)
    }

    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        guard state == .connected else { return }
        try? session.send(requestData, toPeers: [peerID], with: .reliable)
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
    func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: @escaping (Bool) -> Void) {
        certificateHandler(true)
    }
}

private final class NearbyEnrollmentBrowser: NSObject, MCNearbyServiceBrowserDelegate, MCSessionDelegate {
    private let serviceType: String
    private let peerID = MCPeerID(displayName: UUID().uuidString)
    private lazy var session = MCSession(peer: peerID, securityIdentity: nil, encryptionPreference: .required)
    private lazy var browser = MCNearbyServiceBrowser(peer: peerID, serviceType: serviceType)
    private let queue = DispatchQueue(label: "work.tvr.key.nearby-browser")
    private let semaphore = DispatchSemaphore(value: 0)
    private var receivedData: Data?
    private var receivedError: Error?
    private var invitedPeerID: MCPeerID?

    init(serviceType: String) {
        self.serviceType = serviceType
        super.init()
    }

    func discoverSingleRequest(timeout: TimeInterval) throws -> Data {
        session.delegate = self
        browser.delegate = self
        browser.startBrowsingForPeers()
        let result = semaphore.wait(timeout: .now() + timeout)
        browser.stopBrowsingForPeers()
        session.disconnect()

        if let receivedError {
            throw receivedError
        }
        guard result == .success, let receivedData else {
            throw AppError.operationRefused("No nearby device enrollment requests were discovered.")
        }
        return receivedData
    }

    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String : String]?) {
        queue.sync {
            guard invitedPeerID == nil else { return }
            invitedPeerID = peerID
            browser.invitePeer(peerID, to: session, withContext: nil, timeout: 10)
        }
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {}

    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {}

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        queue.sync {
            guard receivedData == nil else { return }
            receivedData = data
            semaphore.signal()
        }
    }

    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
    func session(_ session: MCSession, didReceiveCertificate certificate: [Any]?, fromPeer peerID: MCPeerID, certificateHandler: @escaping (Bool) -> Void) {
        certificateHandler(true)
    }
}
