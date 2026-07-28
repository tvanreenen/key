import Foundation
import Security
import Testing
@testable import KeyCore

struct XPCSecurityPolicyTests {
    private let allRequests: [KeyServiceRequest] = [
        .unlock,
        .lock,
        .status,
        .list,
        .migrationPreflight,
        .setVaultDirectory(path: "/tmp/vault"),
        .setKeychainMode(.local),
        .get(name: "entry"),
        .addManual(name: "entry", secret: "secret", type: .secret),
        .editManual(name: "entry", secret: "secret", type: .secret),
        .copyEntry(source: "source", destination: "destination", force: false),
        .moveEntry(source: "source", destination: "destination", force: false),
        .removeEntry(name: "entry")
    ]

    @Test
    func fullCLIRoleAuthorizesEveryRequest() {
        for request in allRequests {
            #expect(KeyXPCClientRole.fullCLI.authorizes(request))
        }
    }

    @Test
    func utilityRoleAuthorizesOnlyStatusAndLock() {
        for request in allRequests {
            let expected = request == .status || request == .lock
            #expect(KeyXPCClientRole.utilityStatus.authorizes(request) == expected)
        }
    }

    @Test
    func machServiceNamesKeepFullAndUtilityAuthoritySeparate() {
        let configuration = RuntimeConfiguration(
            vaultService: "vault",
            vaultAccount: "account",
            keychainAccessGroup: nil,
            helperMachServiceName: "work.tvr.key.agent",
            helperBundleIdentifier: "work.tvr.key.xpc",
            launchAgentPlistName: "work.tvr.key.agent.plist",
            useDataProtectionKeychain: true
        )

        #expect(configuration.helperMachServiceName == "work.tvr.key.agent")
        #expect(configuration.helperStatusMachServiceName == "work.tvr.key.agent.status")
    }

    @Test
    func productionRequirementsBindRoleIdentifierAndTeam() {
        let cli = KeyXPCSecurityPolicy.codeSigningRequirement(for: .fullCLI, policy: .production)
        let utility = KeyXPCSecurityPolicy.codeSigningRequirement(for: .utilityStatus, policy: .production)

        #expect(cli.contains("identifier \"work.tvr.key.cli\""))
        #expect(cli.contains("anchor apple generic"))
        #expect(cli.contains("9Q355KSV85"))
        #expect(cli.contains("1.2.840.113635.100.6.2.6"))
        #expect(cli.contains("1.2.840.113635.100.6.1.13"))
        #expect(utility.contains("identifier \"work.tvr.key.app\""))
        #expect(utility.contains("anchor apple generic"))
        #expect(utility.contains("9Q355KSV85"))
        #expect(validRequirement(cli))
        #expect(validRequirement(utility))
    }

    @Test
    func developmentRequirementsRemainRoleAndTeamSpecific() {
        let cli = KeyXPCSecurityPolicy.codeSigningRequirement(for: .fullCLI, policy: .development)
        let utility = KeyXPCSecurityPolicy.codeSigningRequirement(for: .utilityStatus, policy: .development)

        #expect(cli.contains("identifier \"work.tvr.key.cli\""))
        #expect(utility.contains("identifier \"work.tvr.key.app\""))
        #expect(cli.contains("anchor apple generic"))
        #expect(utility.contains("anchor apple generic"))
        #expect(cli.contains("9Q355KSV85"))
        #expect(utility.contains("9Q355KSV85"))
        #expect(!cli.contains("1.2.840.113635.100.6.1.13"))
        #expect(!utility.contains("1.2.840.113635.100.6.1.13"))
        #expect(validRequirement(cli))
        #expect(validRequirement(utility))
    }

    @Test
    func clientsAuthenticateTheExpectedHelperIdentifierAndTeam() {
        let development = KeyXPCSecurityPolicy.helperCodeSigningRequirement(policy: .development)
        let production = KeyXPCSecurityPolicy.helperCodeSigningRequirement(policy: .production)

        #expect(development.contains("identifier \"work.tvr.key.xpc\""))
        #expect(development.contains("9Q355KSV85"))
        #expect(production.contains("identifier \"work.tvr.key.xpc\""))
        #expect(production.contains("9Q355KSV85"))
        #expect(production.contains("1.2.840.113635.100.6.1.13"))
        #expect(validRequirement(development))
        #expect(validRequirement(production))
    }

    @Test
    func authenticationAwareOperationsHaveLongerTimeouts() {
        #expect(KeyServiceRequest.status.responseTimeoutSeconds == 5)
        #expect(KeyServiceRequest.lock.responseTimeoutSeconds == 5)
        #expect(KeyServiceRequest.unlock.responseTimeoutSeconds == 120)
        #expect(KeyServiceRequest.get(name: "entry").responseTimeoutSeconds == 120)
        #expect(KeyServiceRequest.migrationPreflight.responseTimeoutSeconds == 120)
        #expect(KeyServiceRequest.list.responseTimeoutSeconds == 30)
        #expect(
            KeyServiceRequest.setVaultDirectory(path: "/tmp/vault")
                .responseTimeoutSeconds == nil
        )
    }

    @Test
    func migrationPreflightRequestRoundTripsAcrossXPCEncoding() throws {
        let encoded = try JSONEncoder().encode(KeyServiceRequest.migrationPreflight)
        let decoded = try JSONDecoder().decode(KeyServiceRequest.self, from: encoded)

        #expect(decoded == .migrationPreflight)
    }

    @Test
    func vaultDirectoryRequestRoundTripsAndRequiresHelperRestart() throws {
        let request = KeyServiceRequest.setVaultDirectory(
            path: "~/Secrets"
        )
        let encoded = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(
            KeyServiceRequest.self,
            from: encoded
        )

        #expect(decoded == request)
        #expect(request.requiresHelperShutdownAfterSuccess)
        #expect(KeyServiceRequest.lock.requiresHelperShutdownAfterSuccess)
        #expect(!KeyServiceRequest.setKeychainMode(.local)
            .requiresHelperShutdownAfterSuccess)
    }

    @Test
    func mutationsWaitForDefinitiveCompletion() {
        #expect(
            KeyServiceRequest.setVaultDirectory(path: "/tmp/vault")
                .responseTimeoutSeconds == nil
        )
        #expect(KeyServiceRequest.setKeychainMode(.local).responseTimeoutSeconds == nil)
        #expect(KeyServiceRequest.addManual(name: "entry", secret: "secret", type: .secret).responseTimeoutSeconds == nil)
        #expect(KeyServiceRequest.editManual(name: "entry", secret: "secret", type: .secret).responseTimeoutSeconds == nil)
        #expect(KeyServiceRequest.copyEntry(source: "a", destination: "b", force: false).responseTimeoutSeconds == nil)
        #expect(KeyServiceRequest.moveEntry(source: "a", destination: "b", force: false).responseTimeoutSeconds == nil)
        #expect(KeyServiceRequest.removeEntry(name: "entry").responseTimeoutSeconds == nil)
    }

    @Test
    func authenticatedReplyWinsOverLaterConnectionInterruption() {
        let state = KeyXPCReplyState()
        let responseData = Data("response".utf8)

        state.complete(data: responseData, error: nil)
        state.complete(data: nil, error: "Connection interrupted.")

        #expect(state.semaphore.wait(timeout: .now()) == .success)
        #expect(state.semaphore.wait(timeout: .now()) == .timedOut)
        #expect(state.result().data == responseData)
        #expect(state.result().error == nil)
    }

    @Test
    func activeRequestPreventsIdleShutdown() {
        let idle = DispatchSemaphore(value: 0)
        let lifecycle = HelperLifecycleController(idleTimeout: 0.05) {
            idle.signal()
        }

        lifecycle.start()
        lifecycle.beginRequest(extendsIdleDeadline: true)
        #expect(idle.wait(timeout: .now() + 0.1) == .timedOut)

        lifecycle.endRequest(extendsIdleDeadline: true)
        #expect(idle.wait(timeout: .now() + 0.2) == .success)
    }

    @Test
    func statusRequestDoesNotExtendOriginalIdleDeadline() {
        let idle = DispatchSemaphore(value: 0)
        let lifecycle = HelperLifecycleController(idleTimeout: 0.05) {
            idle.signal()
        }

        lifecycle.start()
        lifecycle.beginRequest(extendsIdleDeadline: false)
        Thread.sleep(forTimeInterval: 0.08)
        #expect(idle.wait(timeout: .now()) == .timedOut)

        lifecycle.endRequest(extendsIdleDeadline: false)
        #expect(idle.wait(timeout: .now() + 0.1) == .success)
    }

    private func validRequirement(_ value: String) -> Bool {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(value as CFString, [], &requirement)
        return status == errSecSuccess && requirement != nil
    }
}
