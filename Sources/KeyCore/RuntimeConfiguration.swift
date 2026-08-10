import Foundation

public struct RuntimeConfiguration: Equatable, Sendable {
    public let productIdentity: KeyProductIdentity
    public let vaultAccount: String
    public let useDataProtectionKeychain: Bool

    public var vaultService: String {
        productIdentity.vaultKeyService
    }

    public var keychainAccessGroup: String? {
        productIdentity.keychainAccessGroup
    }

    public var helperMachServiceName: String {
        productIdentity.helperMachServiceName
    }

    public var helperBundleIdentifier: String {
        productIdentity.helperBundleIdentifier
    }

    public var launchAgentPlistName: String {
        productIdentity.launchAgentPlistName
    }

    public var helperStatusMachServiceName: String {
        productIdentity.helperStatusMachServiceName
    }

    public init(
        productIdentity: KeyProductIdentity,
        vaultAccount: String = "default-vault",
        useDataProtectionKeychain: Bool = true
    ) {
        self.productIdentity = productIdentity
        self.vaultAccount = vaultAccount
        self.useDataProtectionKeychain = useDataProtectionKeychain
    }

    public static func live(bundle: Bundle = .main) -> RuntimeConfiguration {
        let productIdentity: KeyProductIdentity
        if let rawVariant = bundle.object(forInfoDictionaryKey: "KeyProductVariant") as? String {
            guard let variant = KeyProductVariant(rawValue: rawVariant) else {
                preconditionFailure("Unsupported KeyProductVariant '\(rawVariant)'.")
            }
            productIdentity = .identity(for: variant)
        } else {
            #if SWIFT_PACKAGE
            productIdentity = .stable
            #else
            preconditionFailure("The shipping product is missing KeyProductVariant.")
            #endif
        }

        return RuntimeConfiguration(
            productIdentity: productIdentity,
            vaultAccount: bundle.object(forInfoDictionaryKey: "VaultKeyAccount") as? String ?? "default-vault",
            useDataProtectionKeychain: true
        )
    }
}
