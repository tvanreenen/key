import Foundation
import Security
import Testing
@testable import KeyCore

struct XPCSecurityPolicyTests {
    private let allRequests: [KeyServiceRequest] = [
        .unlock,
        .lock,
        .status,
        .vaultStatus,
        .listConflicts,
        .showConflict(id: "c-123"),
        .getConflictValue(id: "c-123", versionID: "abc123"),
        .resolveConflicts([
            VaultConflictResolution(
                conflictID: "c-123",
                versionID: "abc123"
            )
        ]),
        .share(.devices),
        .share(.reviewRevocation(deviceID: "member")),
        .share(.revoke(
            deviceID: "member",
            confirmationToken: String(repeating: "a", count: 64)
        )),
        .share(.reviewReplacement),
        .share(.replaceCurrentDevice(
            confirmationToken: String(repeating: "b", count: 64)
        )),
        .share(.invitations),
        .list,
        .migrationPreflight,
        .migrationApply,
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
            productIdentity: .stable,
            vaultAccount: "account"
        )

        #expect(configuration.helperMachServiceName == "work.tvr.key.agent")
        #expect(configuration.helperStatusMachServiceName == "work.tvr.key.agent.status")
    }

    @Test
    func productionRequirementsBindRoleIdentifierAndTeam() {
        let cli = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .fullCLI,
            productIdentity: .stable,
            policy: .production
        )
        let utility = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .utilityStatus,
            productIdentity: .stable,
            policy: .production
        )

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
        let cli = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .fullCLI,
            productIdentity: .stable,
            policy: .development
        )
        let utility = KeyXPCSecurityPolicy.codeSigningRequirement(
            for: .utilityStatus,
            productIdentity: .stable,
            policy: .development
        )

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
        let development = KeyXPCSecurityPolicy.helperCodeSigningRequirement(
            productIdentity: .stable,
            policy: .development
        )
        let production = KeyXPCSecurityPolicy.helperCodeSigningRequirement(
            productIdentity: .stable,
            policy: .production
        )

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
        #expect(KeyServiceRequest.migrationApply.responseTimeoutSeconds == nil)
        #expect(KeyServiceRequest.list.responseTimeoutSeconds == 30)
        #expect(KeyServiceRequest.vaultStatus.responseTimeoutSeconds == 30)
        #expect(
            KeyServiceRequest.share(.devices).responseTimeoutSeconds == 30
        )
        #expect(
            KeyServiceRequest.resolveConflicts([])
                .responseTimeoutSeconds == nil
        )
        #expect(
            KeyServiceRequest.share(
                .reviewRevocation(deviceID: "member")
            ).responseTimeoutSeconds == nil
        )
        #expect(
            KeyServiceRequest.share(.revoke(
                deviceID: "member",
                confirmationToken: String(repeating: "a", count: 64)
            )).responseTimeoutSeconds == nil
        )
        #expect(
            KeyServiceRequest.share(.reviewReplacement)
                .responseTimeoutSeconds == nil
        )
        #expect(
            KeyServiceRequest.share(.replaceCurrentDevice(
                confirmationToken: String(repeating: "b", count: 64)
            )).responseTimeoutSeconds == nil
        )
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
    func migrationApplyRequestRoundTripsAndRestartsTheHelper() throws {
        let encoded = try JSONEncoder().encode(KeyServiceRequest.migrationApply)
        let decoded = try JSONDecoder().decode(
            KeyServiceRequest.self,
            from: encoded
        )

        #expect(decoded == .migrationApply)
        #expect(decoded.requiresHelperShutdownAfterSuccess)
    }

    @Test
    func sharingRequestsRoundTripAndRuntimeChangesRestartTheHelper() throws {
        let requests: [KeyServiceRequest] = [
            .share(.devices),
            .share(.invite(deviceName: "Office Mac")),
            .share(.compare(
                vaultID: "vault",
                invitationID: "invite",
                joinRequestID: "request"
            )),
            .share(.reviewReplacement),
            .share(.replaceCurrentDevice(
                confirmationToken: String(repeating: "b", count: 64)
            )),
            .share(.accept(
                vaultID: "vault",
                invitationID: "invite",
                comparisonCode: "1234-5678-9abc-def0-1234"
            ))
        ]
        for request in requests {
            let encoded = try JSONEncoder().encode(request)
            #expect(
                try JSONDecoder().decode(
                    KeyServiceRequest.self,
                    from: encoded
                ) == request
            )
        }
        #expect(!requests[0].requiresHelperShutdownAfterSuccess)
        #expect(!requests[1].requiresHelperShutdownAfterSuccess)
        #expect(!requests[2].requiresHelperShutdownAfterSuccess)
        #expect(!requests[3].requiresHelperShutdownAfterSuccess)
        #expect(requests[4].requiresHelperShutdownAfterSuccess)
        #expect(requests[5].requiresHelperShutdownAfterSuccess)
    }

    @Test
    func deviceInventoryResponseRoundTripsAcrossXPCEncoding() throws {
        let response = KeyServiceResponse.deviceInventory(
            V3VaultDeviceInventory(
                vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
                mode: .shared,
                currentDeviceID: "owner",
                devices: [
                    V3VaultDeviceSummary(
                        deviceID: "owner",
                        displayName: "Office Mac",
                        status: .active
                    )
                ]
            )
        )
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(
            KeyServiceResponse.self,
            from: encoded
        )

        #expect(decoded == response)
    }

    @Test
    func deviceRevocationReviewRoundTripsAcrossXPCEncoding() throws {
        let owner = V3VaultDeviceSummary(
            deviceID: "owner",
            displayName: "Office Mac",
            status: .active
        )
        let response = KeyServiceResponse.deviceRevocationReview(
            V3VaultDeviceRevocationReview(
                vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
                checkpointID: String(repeating: "a", count: 64),
                confirmationToken: String(repeating: "b", count: 64),
                authorizingDevice: owner,
                revokedDevice: V3VaultDeviceSummary(
                    deviceID: "member",
                    displayName: "Laptop",
                    status: .active
                ),
                remainingActiveDevices: [owner]
            )
        )
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(
            KeyServiceResponse.self,
            from: encoded
        )

        #expect(decoded == response)
    }

    @Test
    func deviceReplacementReviewRoundTripsAcrossXPCEncoding() throws {
        let response = KeyServiceResponse.deviceReplacementReview(
            V3VaultDeviceReplacementReview(
                vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
                checkpointID: String(repeating: "a", count: 64),
                confirmationToken: String(repeating: "b", count: 64),
                replacedDevice: V3VaultDeviceSummary(
                    deviceID: "retired-mac",
                    displayName: "Retired Mac",
                    status: .revoked
                ),
                authorityKind: .survivingDevice,
                authorizingDevice: V3VaultDeviceSummary(
                    deviceID: "owner",
                    displayName: "Office Mac",
                    status: .active
                ),
                revocationManifestID: String(repeating: "c", count: 64)
            )
        )
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(
            KeyServiceResponse.self,
            from: encoded
        )

        #expect(decoded == response)
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
        #expect(KeyServiceRequest.migrationApply.responseTimeoutSeconds == nil)
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
        #expect(
            KeyServiceRequest.resolveConflicts([])
                .responseTimeoutSeconds == nil
        )
    }

    @Test
    func vaultUXRequestsRoundTripAcrossXPCEncoding() throws {
        let requests: [KeyServiceRequest] = [
            .vaultStatus,
            .listConflicts,
            .showConflict(id: "c-123"),
            .getConflictValue(id: "c-123", versionID: "abc123"),
            .resolveConflicts([
                VaultConflictResolution(
                    conflictID: "c-123",
                    versionID: "abc123"
                )
            ]),
            .get(name: "entry", allowStale: true)
        ]

        for request in requests {
            let encoded = try JSONEncoder().encode(request)
            let decoded = try JSONDecoder().decode(
                KeyServiceRequest.self,
                from: encoded
            )
            #expect(decoded == request)
        }
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
    func connectionEndStateSignalsExactlyOnce() {
        let state = KeyXPCConnectionEndState()

        state.complete()
        state.complete()

        #expect(state.wait(timeoutSeconds: 0))
        #expect(!state.wait(timeoutSeconds: 0))
    }

    @Test
    func delayedHelperTerminationExceedsTheBoundedClientWait() {
        let state = KeyXPCConnectionEndState()

        #expect(KeyXPCClientTransport.helperShutdownTimeoutSeconds == 30)
        do {
            try KeyXPCClientTransport.requireHelperTermination(
                state,
                after: .share(.replaceCurrentDevice(
                    confirmationToken: String(repeating: "b", count: 64)
                )),
                helperName: "Key Agent",
                timeoutSeconds: 0
            )
            Issue.record("The missing connection-end signal was accepted.")
        } catch let error as AppError {
            #expect(error.localizedDescription.contains(
                "revoked-device cleanup completed"
            ))
            #expect(error.localizedDescription.contains(
                "Run the same command again"
            ))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        state.complete()
        #expect(throws: Never.self) {
            try KeyXPCClientTransport.requireHelperTermination(
                state,
                after: .lock,
                helperName: "Key Agent",
                timeoutSeconds: 0
            )
        }
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
