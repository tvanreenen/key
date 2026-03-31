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
                _ = try keyStore.loadKey(
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
                let keyData = try keyStore.loadKey(
                    reason: "Unlock key vault to read '\(name)'.",
                    createIfMissing: false
                )
                let decrypted = try cipher.decrypt(encrypted, keyData: keyData)
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
        let keyData = try keyStore.loadKey(reason: "Unlock key vault to store '\(name)'.", createIfMissing: true)
        let normalized = try normalizeSecret(secret, for: type)
        let encrypted = try cipher.encrypt(normalized, type: type, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: false)
    }

    private func storeEditedSecret(_ secret: String, as name: String, type: SecretEntryType) throws {
        guard try entryStore.exists(name) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }

        let keyData = try keyStore.loadKey(
            reason: "Unlock key vault to update '\(name)'.",
            createIfMissing: false
        )
        let normalized = try normalizeSecret(secret, for: type)
        let encrypted = try cipher.encrypt(normalized, type: type, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: true)
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
