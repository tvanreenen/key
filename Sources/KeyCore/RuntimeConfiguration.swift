import Foundation

public struct RuntimeConfiguration: Equatable, Sendable {
    public let vaultService: String
    public let vaultAccount: String
    public let keychainAccessGroup: String?
    public let helperMachServiceName: String
    public let helperBundleIdentifier: String
    public let launchAgentPlistName: String
    public let useDataProtectionKeychain: Bool
    public let deviceKeyApplicationTag: String
    public let nearbyPairingServiceType: String

    public init(
        vaultService: String,
        vaultAccount: String,
        keychainAccessGroup: String?,
        helperMachServiceName: String,
        helperBundleIdentifier: String,
        launchAgentPlistName: String,
        useDataProtectionKeychain: Bool,
        deviceKeyApplicationTag: String,
        nearbyPairingServiceType: String
    ) {
        self.vaultService = vaultService
        self.vaultAccount = vaultAccount
        self.keychainAccessGroup = keychainAccessGroup
        self.helperMachServiceName = helperMachServiceName
        self.helperBundleIdentifier = helperBundleIdentifier
        self.launchAgentPlistName = launchAgentPlistName
        self.useDataProtectionKeychain = useDataProtectionKeychain
        self.deviceKeyApplicationTag = deviceKeyApplicationTag
        self.nearbyPairingServiceType = nearbyPairingServiceType
    }

    public static func live(bundle: Bundle = .main) -> RuntimeConfiguration {
        RuntimeConfiguration(
            vaultService: bundle.object(forInfoDictionaryKey: "VaultKeyService") as? String ?? "work.tvr.key.secure-vault",
            vaultAccount: bundle.object(forInfoDictionaryKey: "VaultKeyAccount") as? String ?? "default-vault",
            keychainAccessGroup: bundle.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String,
            helperMachServiceName: bundle.object(forInfoDictionaryKey: "HelperMachServiceName") as? String ?? "work.tvr.key.agent",
            helperBundleIdentifier: bundle.object(forInfoDictionaryKey: "HelperBundleIdentifier") as? String ?? "work.tvr.key.xpc",
            launchAgentPlistName: bundle.object(forInfoDictionaryKey: "LaunchAgentPlistName") as? String ?? "work.tvr.key.agent.plist",
            useDataProtectionKeychain: true,
            deviceKeyApplicationTag: bundle.object(forInfoDictionaryKey: "DeviceKeyApplicationTag") as? String ?? "work.tvr.key.device-identity",
            nearbyPairingServiceType: bundle.object(forInfoDictionaryKey: "NearbyPairingServiceType") as? String ?? "keyvault"
        )
    }
}
