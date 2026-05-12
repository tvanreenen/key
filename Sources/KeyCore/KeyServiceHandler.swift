import CryptoKit
import Foundation

public final class KeyServiceHandler {
    private static let defaultSessionTimeout: TimeInterval = 15 * 60

    private let keyStore: VaultKeyStoring
    private let entryStore: EntryStore
    private let configStore: KeyConfigStore?
    private let cipher: VaultCipher
    private let now: () -> Date
    private let stateQueue = DispatchQueue(label: "work.tvr.key.service-handler")
    private var currentSecurityMode: SecurityMode

    public init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        securityMode: SecurityMode = .local,
        configStore: KeyConfigStore? = nil,
        cipher: VaultCipher = VaultCipher(),
        now: @escaping () -> Date = Date.init
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.configStore = configStore
        self.cipher = cipher
        self.now = now
        self.currentSecurityMode = securityMode
    }

    public static func live(bundle: Bundle = .main) throws -> KeyServiceHandler {
        let configStore = KeyConfigStore()
        let keyConfiguration = try configStore.load()
        let rootURL = keyConfiguration.vaultDirectoryURL
        let configuration = RuntimeConfiguration.live(bundle: bundle)
        return KeyServiceHandler(
            keyStore: VaultKeyStore(configuration: configuration),
            entryStore: EntryStore(rootURL: rootURL),
            securityMode: keyConfiguration.securityMode,
            configStore: configStore
        )
    }

    public func handle(_ request: KeyServiceRequest) -> KeyServiceResponse {
        do {
            switch request {
            case .unlock:
                _ = try loadVaultKey(
                    reason: "Unlock key vault.",
                    createIfMissing: true
                )
                return .success()
            case .lock:
                keyStore.invalidate()
                return .success()
            case .status:
                let helperStatus = (keyStore as? KeySessionStatusReporting)?
                    .sessionStatus(at: nil) ?? .locked(inactivityTimeoutSeconds: Self.defaultSessionTimeout)
                return .success(helperStatus: helperStatus)
            case .list:
                let entries = try entryStore.listEntries()
                guard !entries.isEmpty else {
                    return .success()
                }
                return .success(entries.joined(separator: "\n") + "\n")
            case .vaultStatus:
                let report = try keyStore.inspectVault(
                    vaultRootURL: entryStore.rootURL,
                    securityMode: securityMode(),
                    hasEncryptedEntries: try vaultContainsEntries()
                )
                return .success(renderVaultStatus(report))
            case .shareVault:
                try ensureLocalMode()
                try keyStore.migrateLocalVaultToEnclave(
                    vaultRootURL: entryStore.rootURL,
                    reason: "Unlock key vault to share this vault."
                )
                try persistSecurityMode(.enclave)
                return .success("Vault is now shared in enclave mode.\n")
            case let .joinVault(manual):
                let result = try keyStore.registerDevice(vaultRootURL: entryStore.rootURL, manual: manual)
                try persistSecurityMode(.enclave)
                return .success(result.message)
            case .prepareNearbyVaultApproval:
                try ensureEnclaveMode()
                let info = try keyStore.prepareNearbyDeviceApproval(vaultRootURL: entryStore.rootURL)
                return .success(
                    "Discovered enrollment request from '\(info.deviceName)' (\(info.deviceID)).\n",
                    deviceApprovalInfo: info
                )
            case let .prepareManualVaultApproval(requestData):
                try ensureEnclaveMode()
                let info = try keyStore.prepareManualDeviceApproval(vaultRootURL: entryStore.rootURL, requestData: requestData)
                return .success(
                    "Loaded enrollment request from '\(info.deviceName)' (\(info.deviceID)).\n",
                    deviceApprovalInfo: info
                )
            case let .confirmVaultApproval(verificationCode):
                try ensureEnclaveMode()
                try keyStore.confirmDeviceApproval(vaultRootURL: entryStore.rootURL, verificationCode: verificationCode)
                return .success()
            case .syncVault:
                try ensureEnclaveMode()
                return .success(try keyStore.syncDevice(vaultRootURL: entryStore.rootURL))
            case .leaveVault:
                try ensureEnclaveMode()
                return .success(try keyStore.leaveEnclaveVault(
                    vaultRootURL: entryStore.rootURL,
                    reason: "Unlock key vault to leave this shared vault."
                ))
            case .unshareVault:
                try ensureEnclaveMode()
                return .success(try unshareVault())
            case let .get(name):
                let encrypted = try entryStore.load(name)
                let keyData = try loadVaultKey(
                    reason: "Unlock key vault to read '\(name)'.",
                    createIfMissing: false
                )
                let decrypted = try decryptSecret(encrypted, named: name, keyData: keyData)
                return .success(try renderValue(for: encrypted.type, decryptedValue: decrypted))
            case let .addManual(name, secret, type):
                try storeAddedSecret(secret, as: name, type: type)
                return .success()
            case let .editManual(name, secret, type):
                try storeEditedSecret(secret, as: name, type: type)
                return .success()
            case let .copyEntry(source, destination, force):
                try entryStore.copyEntry(from: source, to: destination, overwrite: force)
                return .success()
            case let .moveEntry(source, destination, force):
                try entryStore.moveEntry(from: source, to: destination, overwrite: force)
                return .success()
            case let .removeEntry(name):
                try entryStore.removeEntry(name)
                return .success()
            }
        } catch let error as AppError {
            return .failure(error.localizedDescription)
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    private func storeAddedSecret(_ secret: String, as name: String, type: SecretEntryType) throws {
        let keyData = try loadVaultKey(
            reason: "Unlock key vault to store '\(name)'.",
            createIfMissing: true
        )
        let normalized = try normalizeSecret(secret, for: type)
        let encrypted = try cipher.encrypt(normalized, type: type, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: false)
    }

    private func storeEditedSecret(_ secret: String, as name: String, type: SecretEntryType) throws {
        guard try entryStore.exists(name) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }

        let existing = try entryStore.load(name)
        let keyData = try loadVaultKey(
            reason: "Unlock key vault to update '\(name)'.",
            createIfMissing: false
        )
        _ = try decryptSecret(existing, named: name, keyData: keyData)
        let normalized = try normalizeSecret(secret, for: type)
        let encrypted = try cipher.encrypt(normalized, type: type, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: true)
    }

    private func loadVaultKey(reason: String, createIfMissing: Bool) throws -> Data {
        switch securityMode() {
        case .local:
            return try loadVaultKeyFromLocal(reason: reason, createIfMissing: createIfMissing)
        case .enclave:
            return try loadVaultKeyFromEnclave(reason: reason)
        }
    }

    private func loadVaultKeyFromLocal(reason: String, createIfMissing: Bool) throws -> Data {
        let keyExists = try keyStore.keyExists(mode: .local, vaultRootURL: entryStore.rootURL)
        if createIfMissing, !keyExists, try vaultContainsEntries() {
            throw missingVaultKeyForExistingVaultError()
        }

        do {
            return try keyStore.loadKey(
                mode: .local,
                vaultRootURL: entryStore.rootURL,
                reason: reason,
                createIfMissing: createIfMissing
            )
        } catch AppError.entryNotFound {
            if try vaultContainsEntries() {
                throw missingVaultKeyForExistingVaultError()
            }
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
    }

    private func loadVaultKeyFromEnclave(reason: String) throws -> Data {
        try keyStore.loadKey(
            mode: .enclave,
            vaultRootURL: entryStore.rootURL,
            reason: reason,
            createIfMissing: false
        )
    }

    private func ensureEnclaveMode() throws {
        guard securityMode() == .enclave else {
            throw AppError.operationRefused("This vault command is only available when the vault is shared in enclave mode.")
        }
    }

    private func ensureLocalMode() throws {
        guard securityMode() == .local else {
            throw AppError.operationRefused("This vault command is only available when the vault is in local-only mode.")
        }
    }

    private func decryptSecret(_ file: SecretFile, named name: String, keyData: Data) throws -> String {
        do {
            return try cipher.decrypt(file, keyData: keyData)
        } catch CryptoKitError.authenticationFailure {
            throw mismatchedVaultKeyError(for: name)
        } catch {
            throw error
        }
    }

    private func vaultContainsEntries() throws -> Bool {
        !(try entryStore.listEntries().isEmpty)
    }

    private func missingVaultKeyForExistingVaultError() -> AppError {
        AppError.vaultKeyMismatch(
            "Encrypted secrets already exist in '\(entryStore.rootURL.path(percentEncoded: false))', but no matching vault key was found in Keychain. Refusing to create a new vault key because that would make the existing secrets unreadable."
        )
    }

    private func mismatchedVaultKeyError(for name: String) -> AppError {
        switch securityMode() {
        case .local:
            return AppError.vaultKeyMismatch(
                "The local Keychain vault key cannot decrypt '\(name)'. This usually means this Mac is using a different vault key than the one that originally encrypted the vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
            )
        case .enclave:
            return AppError.vaultKeyMismatch(
                "The enclave-wrapped vault key for this Mac cannot decrypt '\(name)'. This usually means the synced vault metadata at '\(entryStore.rootURL.path(percentEncoded: false))' is missing or corrupt for this device."
            )
        }
    }

    private func persistSecurityMode(_ mode: SecurityMode) throws {
        if let configStore {
            _ = try configStore.setValue(mode.rawValue, for: .securityMode)
        }
        keyStore.invalidate()
        stateQueue.sync {
            currentSecurityMode = mode
        }
    }

    private func renderVaultStatus(_ report: VaultStatusReport) -> String {
        let deviceID = report.deviceID ?? "n/a"
        let iCloudValue = report.isICloudBacked ? "yes" : "no"
        let metadataValue = report.metadataExists ? "yes" : "no"
        let entriesValue = report.hasEncryptedEntries ? "yes" : "no"
        return """
        path=\(report.vaultRootPath)
        icloud-backed=\(iCloudValue)
        mode=\(report.securityMode.rawValue)
        entries-present=\(entriesValue)
        metadata-present=\(metadataValue)
        device-id=\(deviceID)
        state=\(report.accessState.rawValue)
        detail=\(report.detail)

        """
    }

    private func unshareVault() throws -> String {
        let oldKey = try loadVaultKeyFromEnclave(reason: "Unlock key vault to convert this shared vault back to local-only mode.")
        let entryNames = try entryStore.listEntries()
        let existingFiles = try Dictionary(uniqueKeysWithValues: entryNames.map { name in
            (name, try entryStore.load(name))
        })
        let plaintexts = try Dictionary(uniqueKeysWithValues: entryNames.map { name in
            guard let file = existingFiles[name] else {
                throw AppError.service("Missing in-memory secret file for '\(name)' during vault unshare.")
            }
            let plaintext = try decryptSecret(file, named: name, keyData: oldKey)
            return (name, (plaintext, file.type))
        })

        let newLocalKey = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
        let rewrittenFiles = try Dictionary(uniqueKeysWithValues: entryNames.map { name in
            guard let payload = plaintexts[name] else {
                throw AppError.service("Missing in-memory decrypted payload for '\(name)' during vault unshare.")
            }
            return (name, try cipher.encrypt(payload.0, type: payload.1, keyData: newLocalKey))
        })

        try keyStore.storeKey(newLocalKey, mode: .local, overwriteExisting: true)

        var rewrittenEntryNames: [String] = []
        do {
            for name in entryNames {
                guard let rewritten = rewrittenFiles[name] else { continue }
                try entryStore.save(rewritten, as: name, overwrite: true)
                rewrittenEntryNames.append(name)
            }
        } catch {
            try rollbackUnshare(rewrittenEntryNames: rewrittenEntryNames, existingFiles: existingFiles)
            try? keyStore.deleteKey(mode: .local)
            throw error
        }

        try persistSecurityMode(.local)
        let cleanupMessage = try keyStore.removeEnclaveArtifacts(vaultRootURL: entryStore.rootURL)
        return cleanupMessage ?? "Vault is now local-only.\n"
    }

    private func rollbackUnshare(
        rewrittenEntryNames: [String],
        existingFiles: [String: SecretFile]
    ) throws {
        for name in rewrittenEntryNames.reversed() {
            guard let original = existingFiles[name] else { continue }
            try entryStore.save(original, as: name, overwrite: true)
        }
    }

    private func securityMode() -> SecurityMode {
        stateQueue.sync {
            currentSecurityMode
        }
    }

    private func normalizeSecret(_ secret: String, for type: SecretEntryType) throws -> String {
        switch type {
        case .secret:
            return secret
        case .totp:
            return try TOTPGenerator.normalizeBase32Seed(secret)
        }
    }

    private func renderValue(for type: SecretEntryType, decryptedValue: String) throws -> String {
        switch type {
        case .secret:
            return decryptedValue
        case .totp:
            return try TOTPGenerator.generateCode(fromBase32Seed: decryptedValue, at: now())
        }
    }
}
