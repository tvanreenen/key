import Foundation
import Testing
@testable import KeyCore

struct KeyProductIdentityTests {
    @Test
    func stableIdentityPreservesTheShippingProduct() {
        let identity = KeyProductIdentity.stable

        #expect(identity.variant == .stable)
        #expect(identity.appName == "Key")
        #expect(identity.appBundleIdentifier == "work.tvr.key.app")
        #expect(identity.cliExecutableName == "key")
        #expect(identity.cliSigningIdentifier == "work.tvr.key.cli")
        #expect(identity.helperName == "Key Agent")
        #expect(identity.helperBundleIdentifier == "work.tvr.key.xpc")
        #expect(identity.helperMachServiceName == "work.tvr.key.agent")
        #expect(identity.helperStatusMachServiceName == "work.tvr.key.agent.status")
        #expect(identity.launchAgentPlistName == "work.tvr.key.agent.plist")
        #expect(identity.keychainAccessGroup == "9Q355KSV85.work.tvr.key.shared")
        #expect(identity.vaultKeyService == "work.tvr.key.secure-vault")
        #expect(identity.applicationSupportDirectoryName == "Key")
        #expect(identity.defaultVaultDirectoryName == ".key")
    }

    @Test
    func previewIdentityUsesACompleteIndependentNamespace() {
        let stable = KeyProductIdentity.stable
        let preview = KeyProductIdentity.preview
        let runtime = RuntimeConfiguration(productIdentity: preview)

        #expect(preview.variant == .preview)
        #expect(preview.appName == "Key Preview")
        #expect(preview.cliExecutableName == "key-preview")
        #expect(preview.helperName == "Key Preview Agent")

        #expect(preview.appBundleIdentifier != stable.appBundleIdentifier)
        #expect(preview.cliSigningIdentifier != stable.cliSigningIdentifier)
        #expect(preview.helperBundleIdentifier != stable.helperBundleIdentifier)
        #expect(preview.helperMachServiceName != stable.helperMachServiceName)
        #expect(preview.helperStatusMachServiceName != stable.helperStatusMachServiceName)
        #expect(preview.launchAgentPlistName != stable.launchAgentPlistName)
        #expect(preview.keychainAccessGroup != stable.keychainAccessGroup)
        #expect(preview.vaultKeyService != stable.vaultKeyService)
        #expect(preview.applicationSupportDirectoryName != stable.applicationSupportDirectoryName)
        #expect(preview.defaultVaultDirectoryName != stable.defaultVaultDirectoryName)
        #expect(runtime.helperMachServiceName == preview.helperMachServiceName)
        #expect(runtime.helperBundleIdentifier == preview.helperBundleIdentifier)
        #expect(runtime.keychainAccessGroup == preview.keychainAccessGroup)
        #expect(runtime.vaultService == preview.vaultKeyService)
    }

    @Test(arguments: KeyProductVariant.allCases)
    func lookupReturnsTheMatchingIdentity(variant: KeyProductVariant) {
        #expect(KeyProductIdentity.identity(for: variant).variant == variant)
    }

    @Test
    func qualificationIdentitySeparatesEveryMutableRuntimeNamespace() {
        let stable = KeyProductIdentity.stable
        let qualification = stable.qualificationIdentity(namespace: "migration")

        #expect(qualification.variant == stable.variant)
        #expect(qualification.appBundleIdentifier != stable.appBundleIdentifier)
        #expect(qualification.cliSigningIdentifier == stable.cliSigningIdentifier)
        #expect(qualification.helperBundleIdentifier != stable.helperBundleIdentifier)
        #expect(qualification.keychainAccessGroup == stable.keychainAccessGroup)

        #expect(qualification.helperMachServiceName != stable.helperMachServiceName)
        #expect(qualification.launchAgentPlistName != stable.launchAgentPlistName)
        #expect(qualification.vaultKeyService != stable.vaultKeyService)
        #expect(
            qualification.applicationSupportDirectoryName
                != stable.applicationSupportDirectoryName
        )
        #expect(
            qualification.defaultVaultDirectoryName
                != stable.defaultVaultDirectoryName
        )

        let cliRequirement = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .fullCLI,
            productIdentity: qualification,
            policy: .development
        )
        let appRequirement = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .utilityStatus,
            productIdentity: qualification,
            policy: .development
        )
        let helperRequirement = KeyXPCSecurityPolicy
            .helperCodeSigningRequirement(
                productIdentity: qualification,
                policy: .development
            )
        #expect(cliRequirement.contains("identifier \"work.tvr.key.cli\""))
        #expect(
            appRequirement.contains(
                "identifier \"work.tvr.key.app.qualification.migration\""
            )
        )
        #expect(
            helperRequirement.contains(
                "identifier \"work.tvr.key.xpc.qualification.migration\""
            )
        )
    }

    @Test
    func previewSigningRequirementsBindOnlyPreviewExecutables() {
        let cli = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .fullCLI,
            productIdentity: .preview,
            policy: .production
        )
        let app = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .utilityStatus,
            productIdentity: .preview,
            policy: .production
        )
        let helper = KeyXPCSecurityPolicy.helperCodeSigningRequirement(
            productIdentity: .preview,
            policy: .production
        )

        #expect(cli.contains("identifier \"work.tvr.key.preview.cli\""))
        #expect(!cli.contains("identifier \"work.tvr.key.cli\""))
        #expect(app.contains("identifier \"work.tvr.key.preview.app\""))
        #expect(!app.contains("identifier \"work.tvr.key.app\""))
        #expect(helper.contains("identifier \"work.tvr.key.preview.xpc\""))
        #expect(!helper.contains("identifier \"work.tvr.key.xpc\""))
    }

    @Test
    func stableAndPreviewUseSeparateDeviceLocalStorage() throws {
        let homeDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: homeDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let stable = try EntryStore.defaultLocation(
            productIdentity: .stable,
            homeDirectoryURL: homeDirectory
        )
        let preview = try EntryStore.defaultLocation(
            productIdentity: .preview,
            homeDirectoryURL: homeDirectory
        )

        #expect(
            stable.configFileURL == homeDirectory
                .appendingPathComponent("Library", isDirectory: true)
                .appendingPathComponent("Application Support", isDirectory: true)
                .appendingPathComponent("Key", isDirectory: true)
                .appendingPathComponent("config.toml", isDirectory: false)
        )
        #expect(
            preview.configFileURL == homeDirectory
                .appendingPathComponent("Library", isDirectory: true)
                .appendingPathComponent("Application Support", isDirectory: true)
                .appendingPathComponent("Key Preview", isDirectory: true)
                .appendingPathComponent("config.toml", isDirectory: false)
        )
        #expect(
            stable.rootURL.standardizedFileURL == homeDirectory
                .appendingPathComponent(".key", isDirectory: true)
                .standardizedFileURL
        )
        #expect(
            preview.rootURL.standardizedFileURL == homeDirectory
                .appendingPathComponent(".key-preview", isDirectory: true)
                .standardizedFileURL
        )
        #expect(stable.configFileURL != preview.configFileURL)
        #expect(stable.rootURL != preview.rootURL)
    }
}
