import CryptoKit
import Foundation

public final class KeyServiceHandler {
    private static let defaultSessionTimeout: TimeInterval = 15 * 60

    private let keyStore: VaultKeyStoring
    private let entryStore: EntryStore
    private let cipher: VaultCipher
    private let now: () -> Date

    public init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        cipher: VaultCipher = VaultCipher(),
        now: @escaping () -> Date = Date.init
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.cipher = cipher
        self.now = now
    }

    public static func live(bundle: Bundle = .main) throws -> KeyServiceHandler {
        let rootURL = try EntryStore.defaultRootURL()
        let configuration = RuntimeConfiguration.live(bundle: bundle)
        return KeyServiceHandler(
            keyStore: VaultKeyStore(configuration: configuration),
            entryStore: EntryStore(rootURL: rootURL)
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
        let keyExists = try keyStore.keyExists()
        if createIfMissing, !keyExists, try vaultContainsEntries() {
            throw missingVaultKeyForExistingVaultError()
        }

        do {
            return try keyStore.loadKey(reason: reason, createIfMissing: createIfMissing)
        } catch AppError.entryNotFound {
            if try vaultContainsEntries() {
                throw missingVaultKeyForExistingVaultError()
            }
            throw AppError.entryNotFound("Vault key does not exist yet.")
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
        AppError.vaultKeyMismatch(
            "The current vault key in Keychain cannot decrypt '\(name)'. This usually means the installed app is using a different vault key than the one that originally encrypted the vault at '\(entryStore.rootURL.path(percentEncoded: false))'."
        )
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
