import Foundation

public struct RuntimeConfiguration: Equatable, Sendable {
    public let productIdentity: KeyProductIdentity
    public let vaultAccount: String
    public let useDataProtectionKeychain: Bool
    public let qualificationNamespace: String?

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
        useDataProtectionKeychain: Bool = true,
        qualificationNamespace: String? = nil
    ) {
        self.productIdentity = productIdentity
        self.vaultAccount = vaultAccount
        self.useDataProtectionKeychain = useDataProtectionKeychain
        self.qualificationNamespace = qualificationNamespace
    }

    public static func live(bundle: Bundle = .main) -> RuntimeConfiguration {
        var productIdentity: KeyProductIdentity
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

        var qualificationNamespace: String?
        #if DEBUG
        if let rawNamespace = bundle.object(
            forInfoDictionaryKey: "KeyQualificationNamespace"
        ) as? String,
           !rawNamespace.isEmpty
        {
            guard isValidQualificationNamespace(rawNamespace) else {
                preconditionFailure(
                    "Unsupported KeyQualificationNamespace '\(rawNamespace)'."
                )
            }
            qualificationNamespace = rawNamespace
            productIdentity = productIdentity.qualificationIdentity(
                namespace: rawNamespace
            )
        }
        #endif

        return RuntimeConfiguration(
            productIdentity: productIdentity,
            vaultAccount: qualificationNamespace.map {
                "qualification-\($0)"
            } ?? bundle.object(forInfoDictionaryKey: "VaultKeyAccount") as? String
                ?? "default-vault",
            useDataProtectionKeychain: true,
            qualificationNamespace: qualificationNamespace
        )
    }
}

#if DEBUG
private func isValidQualificationNamespace(_ value: String) -> Bool {
    guard (1...40).contains(value.utf8.count),
          let first = value.utf8.first,
          isLowercaseASCIIAlphanumeric(first)
    else {
        return false
    }
    return value.utf8.allSatisfy {
        isLowercaseASCIIAlphanumeric($0) || $0 == 45
    }
}

private func isLowercaseASCIIAlphanumeric(_ byte: UInt8) -> Bool {
    (97...122).contains(byte) || (48...57).contains(byte)
}
#endif
