import Foundation

public final class KeyServiceHandler {
    private let keyStore: VaultKeyStoring
    private let entryStore: EntryStore
    private let cipher: VaultCipher

    public init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        cipher: VaultCipher = VaultCipher()
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.cipher = cipher
    }

    public static func live(bundle: Bundle = .main) -> KeyServiceHandler {
        let rootURL = (try? EntryStore.defaultRootURL()) ?? URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/key/vault", isDirectory: true)
        let configuration = RuntimeConfiguration.live(bundle: bundle)
        return KeyServiceHandler(
            keyStore: VaultKeyStore(configuration: configuration),
            entryStore: EntryStore(rootURL: rootURL)
        )
    }

    public func handle(_ request: KeyServiceRequest) -> KeyServiceResponse {
        do {
            switch request {
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
                return .success(decrypted)
            case let .addManual(name, secret):
                try storeAddedSecret(secret, as: name)
                return .success()
            case let .editManual(name, secret):
                try storeEditedSecret(secret, as: name)
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

    private func storeAddedSecret(_ secret: String, as name: String) throws {
        let keyData = try keyStore.loadKey(
            reason: "Unlock key vault to store '\(name)'.",
            createIfMissing: true
        )
        let encrypted = try cipher.encrypt(secret, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: false)
    }

    private func storeEditedSecret(_ secret: String, as name: String) throws {
        guard try entryStore.exists(name) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }

        let keyData = try keyStore.loadKey(
            reason: "Unlock key vault to update '\(name)'.",
            createIfMissing: false
        )
        let encrypted = try cipher.encrypt(secret, keyData: keyData)
        try entryStore.save(encrypted, as: name, overwrite: true)
    }
}
