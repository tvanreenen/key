public enum KeyProductVariant: String, CaseIterable, Sendable {
    case stable
    case preview
}

/// Namespaces every identity that must differ between side-by-side installs.
///
/// These values deliberately do not include version 3 format identifiers. Stable
/// and Preview are separate installed products that speak the same vault format.
public struct KeyProductIdentity: Equatable, Sendable {
    public let variant: KeyProductVariant
    public let appName: String
    public let appBundleIdentifier: String
    public let cliExecutableName: String
    public let cliSigningIdentifier: String
    public let helperName: String
    public let helperBundleIdentifier: String
    public let helperMachServiceName: String
    public let keychainAccessGroup: String
    public let vaultKeyService: String
    public let applicationSupportDirectoryName: String
    public let defaultVaultDirectoryName: String

    public var helperStatusMachServiceName: String {
        "\(helperMachServiceName).status"
    }

    public var launchAgentPlistName: String {
        "\(helperMachServiceName).plist"
    }

    public init(
        variant: KeyProductVariant,
        appName: String,
        appBundleIdentifier: String,
        cliExecutableName: String,
        cliSigningIdentifier: String,
        helperName: String,
        helperBundleIdentifier: String,
        helperMachServiceName: String,
        keychainAccessGroup: String,
        vaultKeyService: String,
        applicationSupportDirectoryName: String,
        defaultVaultDirectoryName: String
    ) {
        self.variant = variant
        self.appName = appName
        self.appBundleIdentifier = appBundleIdentifier
        self.cliExecutableName = cliExecutableName
        self.cliSigningIdentifier = cliSigningIdentifier
        self.helperName = helperName
        self.helperBundleIdentifier = helperBundleIdentifier
        self.helperMachServiceName = helperMachServiceName
        self.keychainAccessGroup = keychainAccessGroup
        self.vaultKeyService = vaultKeyService
        self.applicationSupportDirectoryName = applicationSupportDirectoryName
        self.defaultVaultDirectoryName = defaultVaultDirectoryName
    }

    public static let stable = KeyProductIdentity(
        variant: .stable,
        appName: "Key",
        appBundleIdentifier: "work.tvr.key.app",
        cliExecutableName: "key",
        cliSigningIdentifier: "work.tvr.key.cli",
        helperName: "Key Agent",
        helperBundleIdentifier: "work.tvr.key.xpc",
        helperMachServiceName: "work.tvr.key.agent",
        keychainAccessGroup: "9Q355KSV85.work.tvr.key.shared",
        vaultKeyService: "work.tvr.key.secure-vault",
        applicationSupportDirectoryName: "Key",
        defaultVaultDirectoryName: ".key"
    )

    public static let preview = KeyProductIdentity(
        variant: .preview,
        appName: "Key Preview",
        appBundleIdentifier: "work.tvr.key.preview.app",
        cliExecutableName: "key-preview",
        cliSigningIdentifier: "work.tvr.key.preview.cli",
        helperName: "Key Preview Agent",
        helperBundleIdentifier: "work.tvr.key.preview.xpc",
        helperMachServiceName: "work.tvr.key.preview.agent",
        keychainAccessGroup: "9Q355KSV85.work.tvr.key.preview.shared",
        vaultKeyService: "work.tvr.key.preview.secure-vault",
        applicationSupportDirectoryName: "Key Preview",
        defaultVaultDirectoryName: ".key-preview"
    )

    public static func identity(for variant: KeyProductVariant) -> KeyProductIdentity {
        switch variant {
        case .stable:
            .stable
        case .preview:
            .preview
        }
    }

    /// Returns a non-shipping identity for installed qualification work.
    ///
    /// The qualification app keeps the CLI signing identity and Keychain
    /// access group of its base product. Everything that can select, encrypt,
    /// or launch mutable vault state receives a separate namespace, including
    /// the helper identity macOS uses to resolve its containing application.
    /// This lets a Debug build exercise the real helper, Keychain, and Secure
    /// Enclave without repointing an enrolled Stable or Preview installation.
    func qualificationIdentity(namespace: String) -> KeyProductIdentity {
        KeyProductIdentity(
            variant: variant,
            appName: "\(appName) Migration Qualification",
            appBundleIdentifier:
                "\(appBundleIdentifier).qualification.\(namespace)",
            cliExecutableName: cliExecutableName,
            cliSigningIdentifier: cliSigningIdentifier,
            helperName: helperName,
            helperBundleIdentifier:
                "\(helperBundleIdentifier).qualification.\(namespace)",
            helperMachServiceName:
                "\(helperMachServiceName).qualification.\(namespace)",
            keychainAccessGroup: keychainAccessGroup,
            vaultKeyService:
                "\(vaultKeyService).qualification.\(namespace)",
            applicationSupportDirectoryName:
                "\(applicationSupportDirectoryName) Qualification \(namespace)",
            defaultVaultDirectoryName:
                "\(defaultVaultDirectoryName)-qualification-\(namespace)"
        )
    }
}
