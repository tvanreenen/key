import Foundation

public final class KeyServiceHandler {
    private let keyStore: VaultKeyStoring
    private let entryStore: EntryStore
    private let cipher: VaultCipher
    private let generator: SecretGenerator

    public init(
        keyStore: VaultKeyStoring,
        entryStore: EntryStore,
        cipher: VaultCipher = VaultCipher(),
        generator: SecretGenerator = SecretGenerator()
    ) {
        self.keyStore = keyStore
        self.entryStore = entryStore
        self.cipher = cipher
        self.generator = generator
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
            case let .putManual(name, secret, force):
                let keyData = try keyStore.loadKey(
                    reason: "Unlock key vault to store '\(name)'.",
                    createIfMissing: true
                )
                let encrypted = try cipher.encrypt(secret, keyData: keyData)
                try entryStore.save(encrypted, as: name, overwrite: force)
                return .success()
            case let .putGenerated(name, length, force, revealMode):
                let secret = try generator.generate(length: length)
                let keyData = try keyStore.loadKey(
                    reason: "Unlock key vault to store '\(name)'.",
                    createIfMissing: true
                )
                let encrypted = try cipher.encrypt(secret, keyData: keyData)
                try entryStore.save(encrypted, as: name, overwrite: force)
                return revealMode == .none ? .success() : .success(secret)
            }
        } catch let error as AppError {
            return .failure(error.localizedDescription)
        } catch {
            return .failure(error.localizedDescription)
        }
    }
}
