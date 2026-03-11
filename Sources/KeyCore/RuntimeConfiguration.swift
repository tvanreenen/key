import Foundation

public struct RuntimeConfiguration: Equatable {
    public let vaultService: String
    public let vaultAccount: String
    public let keychainAccessGroup: String?
    public let xpcServiceIdentifier: String
    public let useDataProtectionKeychain: Bool

    public init(
        vaultService: String,
        vaultAccount: String,
        keychainAccessGroup: String?,
        xpcServiceIdentifier: String,
        useDataProtectionKeychain: Bool
    ) {
        self.vaultService = vaultService
        self.vaultAccount = vaultAccount
        self.keychainAccessGroup = keychainAccessGroup
        self.xpcServiceIdentifier = xpcServiceIdentifier
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    public static func live(bundle: Bundle = .main) -> RuntimeConfiguration {
        RuntimeConfiguration(
            vaultService: bundle.object(forInfoDictionaryKey: "VaultKeyService") as? String ?? "work.tvr.key.secure-vault",
            vaultAccount: bundle.object(forInfoDictionaryKey: "VaultKeyAccount") as? String ?? "default-vault",
            keychainAccessGroup: bundle.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String,
            xpcServiceIdentifier: bundle.object(forInfoDictionaryKey: "XPCServiceIdentifier") as? String ?? "work.tvr.key.xpc",
            useDataProtectionKeychain: true
        )
    }
}
