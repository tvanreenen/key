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
    private var currentKeychainMode: KeychainMode

    public init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        keychainMode: KeychainMode = .local,
        configStore: KeyConfigStore? = nil,
        cipher: VaultCipher = VaultCipher(),
        now: @escaping () -> Date = Date.init
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.configStore = configStore
        self.cipher = cipher
        self.now = now
        self.currentKeychainMode = keychainMode
    }

    public static func live(bundle: Bundle = .main) throws -> KeyServiceHandler {
        let configStore = KeyConfigStore()
        let keyConfiguration = try configStore.load()
        let rootURL = keyConfiguration.vaultDirectoryURL
        let configuration = RuntimeConfiguration.live(bundle: bundle)
        return KeyServiceHandler(
            keyStore: VaultKeyStore(configuration: configuration),
            entryStore: EntryStore(rootURL: rootURL),
            keychainMode: keyConfiguration.keychainMode,
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
            case .migrationPreflight:
                return migrationPreflightResponse()
            case let .setKeychainMode(mode):
                try setKeychainMode(mode)
                return .success()
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

    private func migrationPreflightResponse() -> KeyServiceResponse {
        do {
            let report = try V2MigrationPreflight(
                entryStore: entryStore,
                cipher: cipher
            ).inspect {
                try keyStore.loadKey(
                    mode: keychainMode(),
                    reason: "Unlock key vault to check migration readiness.",
                    createIfMissing: false
                )
            }
            if report.isReady {
                return .success(report.rendered + "\n")
            }
            return .failure(report.rendered)
        } catch {
            return .failure(V2MigrationPreflightReport.blockedInspection(error))
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
        switch keychainMode() {
        case .local:
            return try loadVaultKeyFromLocal(reason: reason, createIfMissing: createIfMissing)
        case .icloud:
            return try loadVaultKeyFromICloud(reason: reason, createIfMissing: createIfMissing)
        }
    }

    private func loadVaultKeyFromLocal(reason: String, createIfMissing: Bool) throws -> Data {
        let keyExists = try keyStore.keyExists(mode: .local)
        if createIfMissing, !keyExists, try vaultContainsEntries() {
            throw missingVaultKeyForExistingVaultError()
        }

        do {
            return try keyStore.loadKey(mode: .local, reason: reason, createIfMissing: createIfMissing)
        } catch AppError.entryNotFound {
            if try vaultContainsEntries() {
                throw missingVaultKeyForExistingVaultError()
            }
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
    }

    private func loadVaultKeyFromICloud(reason: String, createIfMissing: Bool) throws -> Data {
        let iCloudKeyExists = try keyStore.keyExists(mode: .icloud)
        let hasEntries = try vaultContainsEntries()

        if !iCloudKeyExists {
            if createIfMissing {
                if hasEntries {
                    throw waitingForICloudVaultKeyError()
                }

                let keyData = try keyStore.loadKey(mode: .icloud, reason: reason, createIfMissing: true)
                try keyStore.storeKey(keyData, mode: .local, overwriteExisting: true)
                return keyData
            }

            if hasEntries {
                throw waitingForICloudVaultKeyError()
            }

            throw AppError.entryNotFound("Vault key does not exist yet.")
        }

        let keyData = try keyStore.loadKey(mode: .icloud, reason: reason, createIfMissing: false)
        try verifyVaultKeyMatchesExistingEntries(keyData, sourceMode: .icloud)
        try keyStore.storeKey(keyData, mode: .local, overwriteExisting: true)
        return keyData
    }

    private func setKeychainMode(_ mode: KeychainMode) throws {
        switch mode {
        case .local:
            try switchToLocalMode()
        case .icloud:
            try switchToICloudMode()
        }
    }

    private func switchToICloudMode() throws {
        let hasEntries = try vaultContainsEntries()

        if try keyStore.keyExists(mode: .icloud) {
            let iCloudKey = try keyStore.loadKey(
                mode: .icloud,
                reason: "Unlock key vault to enable iCloud Keychain mode.",
                createIfMissing: false
            )
            try verifyVaultKeyMatchesExistingEntries(iCloudKey, sourceMode: .icloud)
            try keyStore.storeKey(iCloudKey, mode: .local, overwriteExisting: true)
            try persistKeychainMode(.icloud)
            return
        }

        if try keyStore.keyExists(mode: .local) {
            let localKey = try keyStore.loadKey(
                mode: .local,
                reason: "Unlock key vault to enable iCloud Keychain mode.",
                createIfMissing: false
            )

            do {
                try verifyVaultKeyMatchesExistingEntries(localKey, sourceMode: .local)
            } catch AppError.vaultKeyMismatch {
                if hasEntries {
                    throw waitingForICloudVaultKeyError()
                }
                throw errorForLocalKeyMismatch()
            }

            try keyStore.storeKey(localKey, mode: .icloud, overwriteExisting: false)
            try persistKeychainMode(.icloud)
            return
        }

        if hasEntries {
            throw waitingForICloudVaultKeyError()
        }

        try persistKeychainMode(.icloud)
    }

    private func switchToLocalMode() throws {
        if try keyStore.keyExists(mode: .local) {
            let localKey = try keyStore.loadKey(
                mode: .local,
                reason: "Unlock key vault to enable local Keychain mode.",
                createIfMissing: false
            )
            do {
                try verifyVaultKeyMatchesExistingEntries(localKey, sourceMode: .local)
                try persistKeychainMode(.local)
                return
            } catch AppError.vaultKeyMismatch {
                // Fall through and attempt repair from iCloud.
            }
        }

        if try keyStore.keyExists(mode: .icloud) {
            let iCloudKey = try keyStore.loadKey(
                mode: .icloud,
                reason: "Unlock key vault to enable local Keychain mode.",
                createIfMissing: false
            )
            try verifyVaultKeyMatchesExistingEntries(iCloudKey, sourceMode: .icloud)
            try keyStore.storeKey(iCloudKey, mode: .local, overwriteExisting: true)
            try persistKeychainMode(.local)
            return
        }

        if try vaultContainsEntries() {
            throw missingVaultKeyForExistingVaultError()
        }

        try persistKeychainMode(.local)
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

    private func verifyVaultKeyMatchesExistingEntries(_ keyData: Data, sourceMode: KeychainMode) throws {
        guard let sampleName = try entryStore.listEntries().first else {
            return
        }

        let file = try entryStore.load(sampleName)
        do {
            _ = try cipher.decrypt(file, keyData: keyData)
        } catch CryptoKitError.authenticationFailure {
            throw mismatchError(for: sourceMode)
        } catch {
            throw error
        }
    }

    private func mismatchError(for mode: KeychainMode) -> AppError {
        switch mode {
        case .local:
            return errorForLocalKeyMismatch()
        case .icloud:
            return AppError.vaultKeyMismatch(
                "The iCloud Keychain vault key does not match the encrypted vault at '\(entryStore.rootURL.path(percentEncoded: false))'. Use a Mac that can already unlock this vault to publish the correct iCloud Keychain key first."
            )
        }
    }

    private func missingVaultKeyForExistingVaultError() -> AppError {
        AppError.vaultKeyMismatch(
            "Encrypted secrets already exist in '\(entryStore.rootURL.path(percentEncoded: false))', but no matching vault key was found in Keychain. Refusing to create a new vault key because that would make the existing secrets unreadable."
        )
    }

    private func waitingForICloudVaultKeyError() -> AppError {
        AppError.vaultKeyMismatch(
            "No matching iCloud Keychain vault key is available yet for '\(entryStore.rootURL.path(percentEncoded: false))'. Run `key config set keychain-mode icloud` on a Mac that can already unlock this vault, then wait for iCloud Keychain sync to finish."
        )
    }

    private func errorForLocalKeyMismatch() -> AppError {
        AppError.vaultKeyMismatch(
            "The local Keychain vault key does not match the encrypted vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
        )
    }

    private func mismatchedVaultKeyError(for name: String) -> AppError {
        switch keychainMode() {
        case .local:
            return AppError.vaultKeyMismatch(
                "The local Keychain vault key cannot decrypt '\(name)'. This usually means this Mac is using a different vault key than the one that originally encrypted the vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
            )
        case .icloud:
            return AppError.vaultKeyMismatch(
                "The iCloud Keychain vault key cannot decrypt '\(name)'. This usually means the shared iCloud Keychain key does not match the encrypted vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
            )
        }
    }

    private func persistKeychainMode(_ mode: KeychainMode) throws {
        if let configStore {
            _ = try configStore.setValue(mode.rawValue, for: .keychainMode)
        }
        keyStore.invalidate()
        stateQueue.sync {
            currentKeychainMode = mode
        }
    }

    private func keychainMode() -> KeychainMode {
        stateQueue.sync {
            currentKeychainMode
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
