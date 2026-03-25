import Foundation

public struct RuntimeConfiguration: Equatable {
    public let vaultService: String
    public let vaultAccount: String
    public let keychainAccessGroup: String?
    public let helperMachServiceName: String
    public let launchAgentPlistName: String
    public let useDataProtectionKeychain: Bool

    public init(
        vaultService: String,
        vaultAccount: String,
        keychainAccessGroup: String?,
        helperMachServiceName: String,
        launchAgentPlistName: String,
        useDataProtectionKeychain: Bool
    ) {
        self.vaultService = vaultService
        self.vaultAccount = vaultAccount
        self.keychainAccessGroup = keychainAccessGroup
        self.helperMachServiceName = helperMachServiceName
        self.launchAgentPlistName = launchAgentPlistName
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    public static func live(bundle: Bundle = .main) -> RuntimeConfiguration {
        RuntimeConfiguration(
            vaultService: bundle.object(forInfoDictionaryKey: "VaultKeyService") as? String ?? "work.tvr.key.secure-vault",
            vaultAccount: bundle.object(forInfoDictionaryKey: "VaultKeyAccount") as? String ?? "default-vault",
            keychainAccessGroup: bundle.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String,
            helperMachServiceName: bundle.object(forInfoDictionaryKey: "HelperMachServiceName") as? String ?? "work.tvr.key.agent",
            launchAgentPlistName: bundle.object(forInfoDictionaryKey: "LaunchAgentPlistName") as? String ?? "work.tvr.key.agent.plist",
            useDataProtectionKeychain: true
        )
    }
}
