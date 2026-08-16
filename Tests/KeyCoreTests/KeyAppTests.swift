import Foundation
import Testing
@testable import KeyCore

struct KeyCLIApplicationTests {
    @Test
    func currentProcessVersionResolvesThroughSymlinkIntoAppBundle() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let appURL = root.appendingPathComponent("Key.app", isDirectory: true)
        let contentsURL = appURL.appendingPathComponent("Contents", isDirectory: true)
        let macOSURL = contentsURL.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOSURL, withIntermediateDirectories: true)

        let executableURL = macOSURL.appendingPathComponent("key", isDirectory: false)
        FileManager.default.createFile(atPath: executableURL.path, contents: Data(), attributes: nil)

        let infoPlistURL = contentsURL.appendingPathComponent("Info.plist", isDirectory: false)
        let infoPlist: NSDictionary = [
            "CFBundleIdentifier": "work.tvr.key.test",
            "CFBundleName": "Key",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "45",
            "KeyProductVariant": "preview"
        ]
        #expect(infoPlist.write(to: infoPlistURL, atomically: true))

        let fallbackAppURL = root.appendingPathComponent("Fallback.app", isDirectory: true)
        let fallbackContentsURL = fallbackAppURL.appendingPathComponent("Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: fallbackContentsURL, withIntermediateDirectories: true)
        let fallbackInfoPlistURL = fallbackContentsURL.appendingPathComponent("Info.plist", isDirectory: false)
        let fallbackInfoPlist: NSDictionary = [
            "CFBundleIdentifier": "work.tvr.key.fallback",
            "CFBundleName": "Fallback",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "9.9.9",
            "CFBundleVersion": "99"
        ]
        #expect(fallbackInfoPlist.write(to: fallbackInfoPlistURL, atomically: true))

        let symlinkURL = root.appendingPathComponent("bin/key", isDirectory: false)
        try FileManager.default.createDirectory(at: symlinkURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: executableURL)

        let fallbackBundle = try #require(Bundle(url: fallbackAppURL))
        let version = KeyVersionInfo.currentProcess(mainBundle: fallbackBundle, executableURL: symlinkURL)
        let processBundle = KeyVersionInfo.currentProcessBundle(
            mainBundle: fallbackBundle,
            executableURL: symlinkURL
        )
        let configuration = RuntimeConfiguration.live(bundle: processBundle)

        #expect(version == KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45"))
        #expect(configuration.productIdentity == .preview)
    }

    @Test
    func helpPrintsUsage() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for help")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["help"]) == EXIT_SUCCESS)
        #expect(io.stdout == CLIParser.usageText + "\n")
        #expect(io.stderr == "")
    }

    @Test
    func versionPrintsHumanReadableVersion() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for version")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            version: KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45")
        )

        #expect(app.run(arguments: ["version"]) == EXIT_SUCCESS)
        #expect(io.stdout == "1.2.3 (45)\n")
        #expect(io.stderr == "")
    }

    @Test
    func versionPrintsJSONVersion() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for version")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            version: KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45")
        )

        #expect(app.run(arguments: ["version", "--json"]) == EXIT_SUCCESS)

        let data = try #require(io.stdout.data(using: .utf8))
        let decoded = try JSONDecoder().decode(KeyVersionInfo.self, from: data)
        #expect(decoded == KeyVersionInfo(marketingVersion: "1.2.3", buildVersion: "45"))
    }

    @Test
    func configGetPrintsEffectiveVaultDirectoryWithoutTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for config get")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: KeyConfigStore(homeDirectoryURL: homeDirectory)
        )

        #expect(app.run(arguments: ["config", "get", "vault-dir"]) == EXIT_SUCCESS)
        #expect(io.stdout == "\(homeDirectory.appendingPathComponent(".key", isDirectory: true).standardizedFileURL.path(percentEncoded: false))\n")
        #expect(io.stderr == "")
    }

    @Test
    func configSetVaultDirectoryUsesTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { request in
            #expect(
                request == .setVaultDirectory(path: "~/Secrets Vault")
            )
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: configStore
        )

        #expect(app.run(arguments: ["config", "set", "vault-dir", "~/Secrets Vault"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
        #expect(
            transport.requests == [
                .setVaultDirectory(path: "~/Secrets Vault")
            ]
        )
        #expect(
            try configStore.getValue(for: .vaultDir)
                == homeDirectory
                    .appendingPathComponent(".key", isDirectory: true)
                    .standardizedFileURL
                    .path(percentEncoded: false)
        )
    }

    @Test
    func configListPrintsShellFriendlyOutputWithoutTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for config list")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: KeyConfigStore(homeDirectoryURL: homeDirectory)
        )

        #expect(app.run(arguments: ["config", "list"]) == EXIT_SUCCESS)
        #expect(io.stdout == "vault-dir=\(homeDirectory.appendingPathComponent(".key", isDirectory: true).standardizedFileURL.path(percentEncoded: false))\nkeychain-mode=local\n")
        #expect(io.stderr == "")
    }

    @Test
    func configGetPrintsKeychainModeWithoutTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for config get")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: KeyConfigStore(homeDirectoryURL: homeDirectory)
        )

        #expect(app.run(arguments: ["config", "get", "keychain-mode"]) == EXIT_SUCCESS)
        #expect(io.stdout == "local\n")
        #expect(io.stderr == "")
    }

    @Test
    func configSetKeychainModeUsesTransport() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: homeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let transport = MemoryTransport { request in
            #expect(request == .setKeychainMode(.icloud))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: clipboard,
            configStore: configStore
        )

        #expect(app.run(arguments: ["config", "set", "keychain-mode", "icloud"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
        #expect(transport.requests == [.setKeychainMode(.icloud)])
        #expect(try configStore.getValue(for: .keychainMode) == "local")
    }

    @Test
    func migrationPreflightPrintsTheHelperReport() throws {
        let report = """
        Migration preflight passed.
        Entries checked: 2 (1 secret, 1 TOTP entry).
        No files or Keychain items were changed. Migration has not started.

        """
        let transport = MemoryTransport { request in
            #expect(request == .migrationPreflight)
            return .success(report)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["migrate", "--check"]) == EXIT_SUCCESS)
        #expect(io.stdout == report)
        #expect(io.stderr == "")
        #expect(transport.requests == [.migrationPreflight])
    }

    @Test
    func migrationApplyPrintsTheVerifiedHelperReport() throws {
        let report = """
        Migration completed.
        Entries migrated: 2 (1 secret, 1 TOTP entry).
        This Mac now uses authenticated version 3 vault '018f4d38-7d5a-7b20-b0f1-97d6e96c44b3'.
        The version 2 source files were retained unchanged. No cleanup was performed.
        After Key Agent restarts, ordinary entry commands publish guarded version 3 history.
        Other devices remain on version 2 and their later changes are not copied into this snapshot. To enroll a second Mac into this v3 vault, start with `key share invite --name <device-name>`.

        """
        let transport = MemoryTransport { request in
            #expect(request == .migrationApply)
            return .success(report)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["migrate", "--apply"]) == EXIT_SUCCESS)
        #expect(io.stdout == report)
        #expect(io.stderr == "")
        #expect(transport.requests == [.migrationApply])
    }

    @Test
    func shareAcceptSendsOnlyPublicCeremonyInputsAndPrintsReport() {
        let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        let invitationID = String(repeating: "ab", count: 32)
        let code = "1234-5678-9abc-def0-1234"
        let transport = MemoryTransport { request in
            #expect(request == .share(.accept(
                vaultID: vaultID,
                invitationID: invitationID,
                comparisonCode: code
            )))
            return .success("Enrollment completed.\n")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "accept", vaultID, invitationID, code
        ]) == EXIT_SUCCESS)
        #expect(io.stdout == "Enrollment completed.\n")
        #expect(io.stderr.isEmpty)
    }

    @Test
    func shareDevicesPrintsAuthenticatedInventoryForPeople() {
        let inventory = deviceInventoryFixture()
        let transport = MemoryTransport { request in
            #expect(request == .share(.devices))
            return .deviceInventory(inventory)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["share", "devices"]) == EXIT_SUCCESS)
        #expect(io.stdout == """
        Devices in the authenticated vault record:
        Office Mac — active (this Mac)
          ID: owner-device-id
        Laptop — active
          ID: member-device-id

        Continuity: 2 active devices.
        A surviving enrolled Mac can authorize a replacement if another is lost.

        """)
        #expect(io.stderr.isEmpty)
    }

    @Test
    func shareDevicesWarnsWhenOnlyOneActiveDeviceRemains() {
        let inventory = V3VaultDeviceInventory(
            vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
            mode: .shared,
            currentDeviceID: "office-device-id",
            devices: [
                V3VaultDeviceSummary(
                    deviceID: "office-device-id",
                    displayName: "Office Mac",
                    status: .active
                ),
                V3VaultDeviceSummary(
                    deviceID: "retired-device-id",
                    displayName: "Retired Mac",
                    status: .revoked
                ),
            ]
        )
        let transport = MemoryTransport { request in
            #expect(request == .share(.devices))
            return .deviceInventory(inventory)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["share", "devices"]) == EXIT_SUCCESS)
        #expect(io.stdout.contains("Continuity: 1 active device."))
        #expect(io.stdout.contains(
            "Attention: add another Mac. If the only active device is lost, synchronized vault files cannot recover the vault."
        ))
        #expect(inventory.activeDeviceCount == 1)
        #expect(io.stderr.isEmpty)
    }

    @Test
    func shareDevicesPrintsStableJSONInventory() throws {
        let inventory = deviceInventoryFixture()
        let transport = MemoryTransport { request in
            #expect(request == .share(.devices))
            return .deviceInventory(inventory)
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "devices", "--json"
        ]) == EXIT_SUCCESS)
        #expect(io.stdout == """
        {"currentDeviceID":"owner-device-id","devices":[{"deviceID":"owner-device-id","displayName":"Office Mac","status":"active"},{"deviceID":"member-device-id","displayName":"Laptop","status":"active"}],"mode":"shared","vaultID":"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"}

        """)
        let data = try #require(io.stdout.data(using: .utf8))
        #expect(
            try JSONDecoder().decode(
                V3VaultDeviceInventory.self,
                from: data
            ) == inventory
        )
        #expect(io.stderr.isEmpty)
    }

    @Test
    func shareRevokeReviewsBeforeSendingTheBoundConfirmation() {
        let review = deviceRevocationReviewFixture()
        let transport = MemoryTransport { request in
            switch request {
            case .share(.reviewRevocation(deviceID: "member-device-id")):
                return .deviceRevocationReview(review)
            case .share(.revoke(
                deviceID: "member-device-id",
                confirmationToken: review.confirmationToken
            )):
                return .success("Device revoked.\n")
            default:
                Issue.record("Unexpected request: \(request)")
                return .failure("Unexpected request.")
            }
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "REVOKE")
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "revoke", "member-device-id"
        ]) == EXIT_SUCCESS)
        #expect(transport.requests == [
            .share(.reviewRevocation(deviceID: "member-device-id")),
            .share(.revoke(
                deviceID: "member-device-id",
                confirmationToken: review.confirmationToken
            ))
        ])
        #expect(io.stdout == """
        Review device revocation:
        Device: Laptop
          ID: member-device-id
        Authorized by: Office Mac

        This permanently removes the device from future vault versions.
        Key will rotate the vault key and re-encrypt the current vault for the remaining active devices.
        Remaining active devices: 1
          Office Mac

        WARNING: This will leave Office Mac as the vault's only active device.
        If that Mac is lost, synchronized vault files cannot recover the vault.
        Device revoked.

        """)
        #expect(io.stderr ==
            "Type REVOKE to rotate the vault key and continue: ")
    }

    @Test
    func shareRevokeRefusesNoninteractiveUseBeforeReview() {
        let transport = MemoryTransport { request in
            Issue.record("Unexpected request: \(request)")
            return .failure("Unexpected request.")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "revoke", "member-device-id"
        ]) == KeyExitCode.failure.rawValue)
        #expect(transport.requests.isEmpty)
        #expect(io.stdout.isEmpty)
        #expect(io.stderr ==
            "Device revocation requires interactive confirmation.\n")
    }

    @Test
    func shareJoinGuidesARevokedMacThroughRejoinAndRetriesJoin() {
        let review = deviceReplacementReviewFixture()
        let invitationID = String(repeating: "a", count: 64)
        var joinAttempts = 0
        let transport = MemoryTransport { request in
            switch request {
            case .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )):
                joinAttempts += 1
                if joinAttempts <= 2 {
                    return .deviceReplacementReview(review)
                }
                return .success("Join request published.\n")
            case .share(.replaceCurrentDevice(
                confirmationToken: review.confirmationToken
            )):
                return .success(
                    "Revoked device state removed. This Mac is ready to create a new enrollment identity.\n"
                )
            default:
                Issue.record("Unexpected request: \(request)")
                return .failure("Unexpected request.")
            }
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "REJOIN")
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == EXIT_SUCCESS)
        #expect(transport.requests == [
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )),
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )),
            .share(.replaceCurrentDevice(
                confirmationToken: review.confirmationToken
            )),
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            ))
        ])
        #expect(io.stdout == """
        This Mac previously belonged to this vault and has been revoked.
        Review rejoin:
        Vault ID: 018f4d38-7d5a-7b20-b0f1-97d6e96c44b3
        Previous identity: Laptop
          ID: member-device-id
        Revoked by: Office Mac

        Rejoining removes this Mac's unusable local enrollment identity and trusted checkpoint, then creates a new identity through this invitation.
        Synchronized vault files will not be changed.
        The other active Mac must still compare and approve the new identity.
        Revoked device state removed. This Mac is ready to create a new enrollment identity.
        Join request published.

        """)
        #expect(io.stderr ==
            "Type REJOIN to replace the revoked identity and continue: ")
    }

    @Test
    func shareJoinKeepsTheOrdinaryNewMacPathDirect() {
        let invitationID = String(repeating: "a", count: 64)
        let request = KeyServiceRequest.share(.join(
            invitationID: invitationID,
            deviceName: "Laptop"
        ))
        let transport = MemoryTransport { received in
            #expect(received == request)
            return .success("Join request published.\n")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == EXIT_SUCCESS)
        #expect(transport.requests == [request])
        #expect(io.stdout == "Join request published.\n")
        #expect(io.stderr.isEmpty)
    }

    @Test
    func shareJoinRefusesNoninteractiveRejoinBeforeReview() {
        let invitationID = String(repeating: "a", count: 64)
        let transport = MemoryTransport { request in
            #expect(request == .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )))
            return .deviceReplacementReview(
                deviceReplacementReviewFixture()
            )
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == KeyExitCode.failure.rawValue)
        #expect(transport.requests == [.share(.join(
            invitationID: invitationID,
            deviceName: "Laptop"
        ))])
        #expect(io.stdout.isEmpty)
        #expect(io.stderr ==
            "Rejoining a revoked Mac requires interactive confirmation.\n")
    }

    @Test
    func shareJoinCancellationKeepsRevokedLocalState() {
        let review = deviceReplacementReviewFixture()
        let invitationID = String(repeating: "a", count: 64)
        let transport = MemoryTransport { request in
            switch request {
            case .share(.join):
                return .deviceReplacementReview(review)
            default:
                Issue.record("Unexpected request: \(request)")
                return .failure("Unexpected request.")
            }
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "cancel")
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == KeyExitCode.failure.rawValue)
        #expect(transport.requests == [
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            ))
        ])
        #expect(io.stdout.contains("Synchronized vault files will not be changed."))
        #expect(io.stderr.hasSuffix("Device rejoin cancelled.\n"))
    }

    @Test
    func shareJoinStopsWhenRejoinCleanupFails() {
        let review = deviceReplacementReviewFixture()
        let invitationID = String(repeating: "a", count: 64)
        let transport = MemoryTransport { request in
            switch request {
            case .share(.join):
                return .deviceReplacementReview(review)
            case .share(.replaceCurrentDevice):
                return .failure("Cleanup failed safely.")
            default:
                Issue.record("Unexpected request: \(request)")
                return .failure("Unexpected request.")
            }
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "REJOIN")
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == KeyExitCode.failure.rawValue)
        #expect(transport.requests == [
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )),
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )),
            .share(.replaceCurrentDevice(
                confirmationToken: review.confirmationToken
            ))
        ])
        #expect(io.stdout.contains("Review rejoin:"))
        #expect(io.stderr.hasSuffix("Cleanup failed safely.\n"))
    }

    @Test
    func shareJoinDoesNotCleanUpWhenInvitationExpiresAtConfirmation() {
        let review = deviceReplacementReviewFixture()
        let invitationID = String(repeating: "a", count: 64)
        var joinAttempts = 0
        let transport = MemoryTransport { request in
            guard case .share(.join) = request else {
                Issue.record("Unexpected request: \(request)")
                return .failure("Unexpected request.")
            }
            joinAttempts += 1
            if joinAttempts == 1 {
                return .deviceReplacementReview(review)
            }
            return .failure("The selected enrollment invitation expired.")
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "REJOIN")
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == KeyExitCode.failure.rawValue)
        #expect(transport.requests == [
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            )),
            .share(.join(
                invitationID: invitationID,
                deviceName: "Laptop"
            ))
        ])
        #expect(io.stderr.hasSuffix(
            "The selected enrollment invitation expired.\n"
        ))
    }

    @Test
    func shareJoinDoesNotCleanUpWhenTheReviewedStateChanges() {
        let initialReview = deviceReplacementReviewFixture()
        let changedReview = deviceReplacementReviewFixture(
            checkpointID: String(repeating: "f", count: 64),
            confirmationToken: String(repeating: "e", count: 64)
        )
        let invitationID = String(repeating: "a", count: 64)
        var joinAttempts = 0
        let transport = MemoryTransport { request in
            guard case .share(.join) = request else {
                Issue.record("Unexpected request: \(request)")
                return .failure("Unexpected request.")
            }
            joinAttempts += 1
            return .deviceReplacementReview(
                joinAttempts == 1 ? initialReview : changedReview
            )
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "REJOIN")
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: [
            "share", "join", invitationID, "--name", "Laptop"
        ]) == KeyExitCode.failure.rawValue)
        #expect(transport.requests.count == 2)
        #expect(io.stderr.hasSuffix(
            "The vault's replacement state changed while awaiting confirmation. Review the current state by running the join command again.\n"
        ))
    }

    @Test
    func blockedMigrationPreflightPrintsOnlyToStderr() throws {
        let transport = MemoryTransport { request in
            #expect(request == .migrationPreflight)
            return .failure("Migration preflight blocked.\nMigration has not started.")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let app = KeyCLIApplication(
            transport: transport,
            io: io,
            clipboard: MemoryClipboard()
        )

        #expect(app.run(arguments: ["migrate", "--check"]) == EXIT_FAILURE)
        #expect(io.stdout == "")
        #expect(io.stderr == "Migration preflight blocked.\nMigration has not started.\n")
    }

    @Test
    func unlockSendsUnlockRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .unlock)
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["unlock"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func lockSendsLockRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .lock)
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["lock"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func getAddsTrailingNewlineForTerminalOutput() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "demo/test"))
            return .success("k9W2mQ7pL4xR")
        }
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: true)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["get", "demo/test"]) == EXIT_SUCCESS)
        #expect(io.stdout == "k9W2mQ7pL4xR\n")
    }

    @Test
    func getPreservesExactOutputWhenStdoutIsNotATerminal() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "demo/test"))
            return .success("k9W2mQ7pL4xR")
        }
        let io = MemoryIO(stdinIsTTY: false, stdoutIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["get", "demo/test"]) == EXIT_SUCCESS)
        #expect(io.stdout == "k9W2mQ7pL4xR")
    }

    @Test
    func copyWritesToClipboardWithoutStdout() throws {
        let transport = MemoryTransport { request in
            #expect(request == .get(name: "mail/personal"))
            return .success("hunter2")
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["copy", "mail/personal"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(clipboard.copiedText == "hunter2")
    }

    @Test
    func manualAddReadsPipedInputAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .addManual(name: "aws/prod/token", secret: "hunter2", type: .secret))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: "hunter2")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "aws/prod/token"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func manualAddTOTPReadsPipedInputNormalizesSeedAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .addManual(name: "aws/prod/token", secret: "JBSWY3DPEHPK3PXP", type: .totp))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: " jbsw y3dp ehpk 3pxp ")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "--totp", "aws/prod/token"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func manualAddTOTPRejectsInvalidBase32BeforeSendingRequest() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called for invalid TOTP seeds")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: "not base32!")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["add", "--totp", "aws/prod/token"]) == EXIT_FAILURE)
        #expect(io.stderr == "TOTP seed must be valid Base32.\n")
    }

    @Test
    func manualEditReadsPipedInputAndSendsItToService() throws {
        let transport = MemoryTransport { request in
            #expect(request == .editManual(name: "aws/prod/token", secret: "hunter2", type: .secret))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false, pipedInput: "hunter2")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["edit", "aws/prod/token"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func duplicateSendsEncryptedCopyRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .copyEntry(source: "src/token", destination: "dst/token", force: true))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["duplicate", "src/token", "dst/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func renameSendsEncryptedMoveRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .moveEntry(source: "src/token", destination: "dst/token", force: true))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["rename", "src/token", "dst/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stdout == "")
        #expect(io.stderr == "")
    }

    @Test
    func removePromptsOnTTYAndSendsDeleteRequest() throws {
        let transport = MemoryTransport { request in
            #expect(request == .removeEntry(name: "src/token"))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: true, lineInput: "y")
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["remove", "src/token"]) == EXIT_SUCCESS)
        #expect(io.stderr == "Remove 'src/token'? [y/N]: ")
    }

    @Test
    func removeRequiresForceWhenNonInteractive() throws {
        let transport = MemoryTransport { _ in
            Issue.record("transport should not be called")
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["remove", "src/token"]) == EXIT_FAILURE)
        #expect(io.stderr.contains("without --force in non-interactive mode") == true)
    }

    @Test
    func removeForceSkipsPrompt() throws {
        let transport = MemoryTransport { request in
            #expect(request == .removeEntry(name: "src/token"))
            return .success()
        }
        let io = MemoryIO(stdinIsTTY: false)
        let clipboard = MemoryClipboard()
        let app = KeyCLIApplication(transport: transport, io: io, clipboard: clipboard)

        #expect(app.run(arguments: ["remove", "src/token", "--force"]) == EXIT_SUCCESS)
        #expect(io.stderr == "")
    }
}

struct KeyServiceHandlerTests {
    @Test
    func vaultStatusReportsCurrentVersion2StateWithoutLoadingTheKey() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let keyStore = MemoryVaultKeyStore()
        let entryStore = EntryStore(rootURL: root)
        try entryStore.save(
            SecretFile(
                version: 2,
                type: .secret,
                alg: "AES.GCM",
                nonce: "AA==",
                ciphertext: "AA=="
            ),
            as: "one",
            overwrite: false
        )
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: entryStore
        )

        let response = handler.handle(.vaultStatus)

        #expect(
            response.vaultStatus == VaultStatus(
                format: .version2,
                health: .ready,
                entries: .effective(1)
            )
        )
        #expect(response.exitCode == EXIT_SUCCESS)
        #expect(keyStore.loadCount == 0)
    }

    @Test
    func unlockAuthenticatesWithoutReturningOutput() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.unlock) == .success())
        #expect(keyStore.loadCount == 1)
        #expect(keyStore.requests.last?.createIfMissing == true)
        #expect(keyStore.requests.last?.mode == .local)
    }

    @Test
    func lockInvalidatesSessionWithoutReturningOutput() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.lock) == .success())
        #expect(keyStore.invalidateCount == 1)
    }

    @Test
    func statusReturnsLockedHelperStateWhenNoSessionIsActive() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = SessionVaultKeyStore(underlying: MemoryVaultKeyStore(), inactivityTimeout: 120)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.status) == .success(helperStatus: .locked(inactivityTimeoutSeconds: 120)))
    }

    @Test
    func statusReturnsUnlockedHelperStateWhenSessionIsWarm() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = SessionVaultKeyStore(underlying: MemoryVaultKeyStore(), inactivityTimeout: 120)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.unlock) == .success())

        let response = handler.handle(.status)
        #expect(response.exitCode == EXIT_SUCCESS)
        #expect(response.helperStatus?.isUnlocked == true)
        #expect(response.helperStatus?.inactivityTimeoutSeconds == 120)
    }

    @Test
    func addThenGetRoundTripsSecret() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        let putResponse = handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret))
        #expect(putResponse == .success())

        let getResponse = handler.handle(.get(name: "mail/personal"))
        #expect(getResponse == .success("hunter2"))
        #expect(keyStore.loadCount == 2)
    }

    @Test
    func unlockRefusesToCreateNewVaultKeyWhenEntriesAlreadyExist() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let existingKey = Data((100..<132).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: existingKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.unlock)
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("Refusing to create a new vault key") == true)
        #expect(keyStore.loadCount == 0)
    }

    @Test
    func getReturnsFriendlyErrorWhenCurrentVaultKeyCannotDecryptEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let existingKey = Data((0..<32).map(UInt8.init))
        let wrongKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: existingKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.keyData = wrongKey
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.get(name: "mail/personal"))
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("cannot decrypt 'mail/personal'") == true)
    }

    @Test
    func switchingToICloudPublishesWorkingLocalKeyAndUpdatesConfig() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: vaultDirectory),
            configStore: configStore
        )

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret)) == .success())
        let localKey = try #require(keyStore.localKeyData)

        #expect(handler.handle(.setKeychainMode(.icloud)) == .success())
        #expect(keyStore.iCloudKeyData == localKey)
        #expect(try configStore.getValue(for: .keychainMode) == "icloud")
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
    }

    @Test
    func switchingToICloudWaitsWhenOnlyStaleLocalKeyExists() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let store = EntryStore(rootURL: vaultDirectory)
        let originalKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: originalKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            configStore: configStore
        )

        let response = handler.handle(.setKeychainMode(.icloud))
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("wait for iCloud Keychain sync") == true)
        #expect(keyStore.iCloudKeyData == nil)
        #expect(try configStore.getValue(for: .keychainMode) == "local")
    }

    @Test
    func switchingToICloudAdoptsExistingSyncedKeyAndRepairsLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let store = EntryStore(rootURL: vaultDirectory)
        let sharedKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: sharedKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            configStore: configStore
        )

        #expect(handler.handle(.setKeychainMode(.icloud)) == .success())
        #expect(keyStore.localKeyData == sharedKey)
        #expect(try configStore.getValue(for: .keychainMode) == "icloud")
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
    }

    @Test
    func switchingBackToLocalRepairsMissingLocalMirrorFromICloud() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let store = EntryStore(rootURL: vaultDirectory)
        let sharedKey = Data((0..<32).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: sharedKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        #expect(handler.handle(.setKeychainMode(.local)) == .success())
        #expect(keyStore.localKeyData == sharedKey)
        #expect(try configStore.getValue(for: .keychainMode) == "local")
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
    }

    @Test
    func iCloudModeReadsRepairAStaleLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let store = EntryStore(rootURL: vaultDirectory)
        let sharedKey = Data((0..<32).map(UInt8.init))
        let staleLocalKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("hunter2", keyData: sharedKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
        #expect(keyStore.localKeyData == sharedKey)
    }

    @Test
    func switchingToICloudRejectsMixedKeyVaultBeforeRepairingLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)

        let sharedKey = Data((0..<32).map(UInt8.init))
        let otherEntryKey = Data((32..<64).map(UInt8.init))
        let staleLocalKey = Data((64..<96).map(UInt8.init))
        let store = EntryStore(rootURL: vaultDirectory)
        try saveMixedKeyEntries(in: store, acceptedKey: sharedKey, otherKey: otherEntryKey)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = staleLocalKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            configStore: configStore
        )

        let response = handler.handle(.setKeychainMode(.icloud))

        #expect(response.errorCode == .vaultKeyMismatch)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == staleLocalKey)
        #expect(try configStore.getValue(for: .keychainMode) == "local")
    }

    @Test
    func switchingBackToLocalRejectsMixedKeyVaultBeforeRepairingLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let sharedKey = Data((0..<32).map(UInt8.init))
        let otherEntryKey = Data((32..<64).map(UInt8.init))
        let store = EntryStore(rootURL: vaultDirectory)
        try saveMixedKeyEntries(in: store, acceptedKey: sharedKey, otherKey: otherEntryKey)

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = otherEntryKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        let response = handler.handle(.setKeychainMode(.local))

        #expect(response.errorCode == .vaultKeyMismatch)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == otherEntryKey)
        #expect(try configStore.getValue(for: .keychainMode) == "icloud")
    }

    @Test
    func iCloudModeReadRejectsMixedKeyVaultHiddenEntryBeforeRepairingLocalMirror() throws {
        let homeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultDirectory = homeDirectory.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: vaultDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: homeDirectory) }

        let configStore = KeyConfigStore(homeDirectoryURL: homeDirectory)
        _ = try configStore.setValue(vaultDirectory.path(percentEncoded: false), for: .vaultDir)
        _ = try configStore.setValue("icloud", for: .keychainMode)

        let sharedKey = Data((0..<32).map(UInt8.init))
        let otherEntryKey = Data((32..<64).map(UInt8.init))
        let store = EntryStore(rootURL: vaultDirectory)
        try saveMixedKeyEntries(
            in: store,
            acceptedKey: sharedKey,
            otherKey: otherEntryKey,
            otherName: "zeta/.other"
        )

        let keyStore = MemoryVaultKeyStore()
        keyStore.localKeyData = otherEntryKey
        keyStore.iCloudKeyData = sharedKey
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: store,
            keychainMode: .icloud,
            configStore: configStore
        )

        let response = handler.handle(.get(name: "alpha/matching"))

        #expect(response.errorCode == .vaultKeyMismatch)
        #expect(keyStore.storeCount == 0)
        #expect(keyStore.localKeyData == otherEntryKey)
    }

    @Test
    func rejectsOverwriteWithoutForce() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: tempDirectory)
        )

        #expect(handler.handle(.addManual(name: "dup", secret: "one", type: .secret)) == .success())

        let secondResponse = handler.handle(.addManual(name: "dup", secret: "two", type: .secret))
        #expect(secondResponse.exitCode == KeyExitCode.conflict.rawValue)
        #expect(secondResponse.errorMessage?.contains("already exists") == true)
    }

    @Test
    func editUpdatesExistingSecretAndFailsForMissingEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        #expect(handler.handle(.editManual(name: "mail/personal", secret: "two", type: .secret)) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("two"))

        let missingResponse = handler.handle(.editManual(name: "missing", secret: "value", type: .secret))
        #expect(missingResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)
    }

    @Test
    func editRefusesToOverwriteWhenCurrentVaultKeyCannotDecryptExistingEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let originalKey = Data((0..<32).map(UInt8.init))
        let wrongKey = Data((32..<64).map(UInt8.init))
        let encrypted = try VaultCipher().encrypt("one", keyData: originalKey)
        try store.save(encrypted, as: "mail/personal", overwrite: false)

        let keyStore = MemoryVaultKeyStore()
        keyStore.keyData = wrongKey
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        let response = handler.handle(.editManual(name: "mail/personal", secret: "two", type: .secret))
        #expect(response.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(response.errorMessage?.contains("cannot decrypt 'mail/personal'") == true)

        let persisted = try store.load("mail/personal")
        let decrypted = try VaultCipher().decrypt(persisted, keyData: originalKey)
        #expect(decrypted == "one")
    }

    @Test
    func addThenGetReturnsCurrentTOTPCode() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            now: { Date(timeIntervalSince1970: 59) }
        )

        let addResponse = handler.handle(.addManual(
            name: "mail/mfa",
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            type: .totp
        ))
        #expect(addResponse == .success())
        #expect(handler.handle(.get(name: "mail/mfa")) == .success("287082"))
    }

    @Test
    func editCanConvertExistingSecretIntoTOTPEntry() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            now: { Date(timeIntervalSince1970: 59) }
        )

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        #expect(handler.handle(.editManual(
            name: "mail/personal",
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            type: .totp
        )) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("287082"))
    }

    @Test
    func copyDuplicatesEncryptedEntryWithoutKeyAccess() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        let loadCountBeforeCopy = keyStore.loadCount

        #expect(handler.handle(.copyEntry(source: "mail/personal", destination: "mail/work", force: false)) == .success())
        #expect(keyStore.loadCount == loadCountBeforeCopy)
        #expect(handler.handle(.get(name: "mail/work")) == .success("one"))

        let conflictResponse = handler.handle(.copyEntry(source: "mail/personal", destination: "mail/work", force: false))
        #expect(conflictResponse.exitCode == KeyExitCode.conflict.rawValue)
        #expect(conflictResponse.errorMessage?.contains("already exists") == true)
    }

    @Test
    func moveRenamesEncryptedEntryWithoutKeyAccess() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        let loadCountBeforeMove = keyStore.loadCount

        #expect(handler.handle(.moveEntry(source: "mail/personal", destination: "mail/work", force: false)) == .success())
        #expect(keyStore.loadCount == loadCountBeforeMove)
        #expect(handler.handle(.get(name: "mail/work")) == .success("one"))

        let oldResponse = handler.handle(.get(name: "mail/personal"))
        #expect(oldResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(oldResponse.errorMessage?.contains("was not found") == true)

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "two", type: .secret)) == .success())
        let conflictResponse = handler.handle(.moveEntry(source: "mail/personal", destination: "mail/work", force: false))
        #expect(conflictResponse.exitCode == KeyExitCode.conflict.rawValue)
        #expect(conflictResponse.errorMessage?.contains("already exists") == true)
    }

    @Test
    func copiedAndMovedTOTPEntriesPreserveTheirType() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let handler = KeyServiceHandler(
            keyStore: keyStore,
            entryStore: EntryStore(rootURL: tempDirectory),
            now: { Date(timeIntervalSince1970: 59) }
        )

        #expect(handler.handle(.addManual(
            name: "mail/mfa",
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            type: .totp
        )) == .success())
        #expect(handler.handle(.copyEntry(source: "mail/mfa", destination: "mail/mfa-copy", force: false)) == .success())
        #expect(handler.handle(.moveEntry(source: "mail/mfa-copy", destination: "mail/mfa-moved", force: false)) == .success())
        #expect(handler.handle(.get(name: "mail/mfa-moved")) == .success("287082"))
    }

    @Test
    func removeDeletesEntryWithoutKeyAccessAndCleansEmptyDirectories() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let keyStore = MemoryVaultKeyStore()
        let store = EntryStore(rootURL: tempDirectory)
        let handler = KeyServiceHandler(keyStore: keyStore, entryStore: store)

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "one", type: .secret)) == .success())
        let loadCountBeforeRemove = keyStore.loadCount

        #expect(handler.handle(.removeEntry(name: "mail/personal")) == .success())
        #expect(keyStore.loadCount == loadCountBeforeRemove)

        let missingResponse = handler.handle(.get(name: "mail/personal"))
        #expect(missingResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)

        let parentDirectory = tempDirectory.appendingPathComponent("mail", isDirectory: true)
        #expect(FileManager.default.fileExists(atPath: parentDirectory.path(percentEncoded: false)) == false)
    }

    @Test
    func missingAndCorruptedFilesFail() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let store = EntryStore(rootURL: tempDirectory)
        let handler = KeyServiceHandler(keyStore: MemoryVaultKeyStore(), entryStore: store)

        let missingResponse = handler.handle(.get(name: "missing"))
        #expect(missingResponse.exitCode == KeyExitCode.notFound.rawValue)
        #expect(missingResponse.errorCode == .entryNotFound)
        #expect(missingResponse.errorMessage?.contains("was not found") == true)

        let brokenURL = try store.url(for: "broken")
        try FileManager.default.createDirectory(at: brokenURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("not-json".utf8).write(to: brokenURL)

        let corruptResponse = handler.handle(.get(name: "broken"))
        #expect(corruptResponse.exitCode == KeyExitCode.securityFailure.rawValue)
        #expect(corruptResponse.errorCode == .invalidSecretFile)
        #expect(corruptResponse.errorMessage?.contains("unreadable") == true)
    }

    @Test
    func listPrintsSortedEntryNames() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: tempDirectory)
        )

        #expect(handler.handle(.addManual(name: "zeta/one", secret: "one", type: .secret)) == .success())
        #expect(handler.handle(.addManual(name: "alpha/two", secret: "two", type: .secret)) == .success())

        let listResponse = handler.handle(.list)
        #expect(listResponse == .success("alpha/two\nzeta/one\n"))
    }

    private func saveMixedKeyEntries(
        in store: EntryStore,
        acceptedKey: Data,
        otherKey: Data,
        otherName: String = "zeta/other"
    ) throws {
        let cipher = VaultCipher()
        try store.save(
            cipher.encrypt("matching", keyData: acceptedKey),
            as: "alpha/matching",
            overwrite: false
        )
        try store.save(
            cipher.encrypt("other", keyData: otherKey),
            as: otherName,
            overwrite: false
        )
    }
}

struct SessionVaultKeyStoreTests {
    @Test
    func reusesUnlockedSessionWithinTimeout() throws {
        let underlying = MemoryVaultKeyStore()
        let start = Date(timeIntervalSince1970: 1_000)
        var currentTime = start
        let store = SessionVaultKeyStore(
            underlying: underlying,
            inactivityTimeout: 60,
            now: { currentTime }
        )

        _ = try store.loadKey(mode: .local, reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(30)
        _ = try store.loadKey(mode: .local, reason: "second", createIfMissing: false)

        #expect(underlying.loadCount == 1)
        #expect(store.isUnlocked(at: currentTime) == true)
    }

    @Test
    func reauthenticatesAfterExpiry() throws {
        let underlying = MemoryVaultKeyStore()
        let start = Date(timeIntervalSince1970: 2_000)
        var currentTime = start
        let store = SessionVaultKeyStore(
            underlying: underlying,
            inactivityTimeout: 60,
            now: { currentTime }
        )

        _ = try store.loadKey(mode: .local, reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(61)
        _ = try store.loadKey(mode: .local, reason: "second", createIfMissing: false)

        #expect(underlying.loadCount == 2)
    }

    @Test
    func sessionStatusReflectsExpiryWithoutRefreshingTheSession() throws {
        let underlying = MemoryVaultKeyStore()
        let start = Date(timeIntervalSince1970: 2_000)
        var currentTime = start
        let store = SessionVaultKeyStore(
            underlying: underlying,
            inactivityTimeout: 60,
            now: { currentTime }
        )

        _ = try store.loadKey(mode: .local, reason: "first", createIfMissing: true)
        currentTime = start.addingTimeInterval(61)

        let status = store.sessionStatus(at: currentTime)
        #expect(status == .locked(inactivityTimeoutSeconds: 60))
        #expect(store.isUnlocked(at: currentTime) == false)
    }

    @Test
    func addThenGetReusesSessionAcrossHandlerRequests() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret)) == .success())
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
        #expect(underlying.loadCount == 1)
    }

    @Test
    func lockForcesNextKeyBackedRequestToReauthenticate() throws {
        let tempDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)
        let handler = KeyServiceHandler(keyStore: store, entryStore: EntryStore(rootURL: tempDirectory))

        #expect(handler.handle(.addManual(name: "mail/personal", secret: "hunter2", type: .secret)) == .success())
        #expect(handler.handle(.lock) == .success())
        #expect(store.isUnlocked() == false)
        #expect(handler.handle(.get(name: "mail/personal")) == .success("hunter2"))
        #expect(underlying.loadCount == 2)
    }

    @Test
    func authFailureDoesNotLeaveSessionUnlocked() throws {
        let underlying = MemoryVaultKeyStore()
        underlying.error = AppError.authFailed("Authentication was cancelled or failed.")
        let store = SessionVaultKeyStore(underlying: underlying)

        #expect(throws: AppError.authFailed("Authentication was cancelled or failed.")) {
            _ = try store.loadKey(mode: .local, reason: "unlock", createIfMissing: false)
        }
        #expect(store.isUnlocked() == false)
    }

    @Test
    func invalidateClearsSession() throws {
        let underlying = MemoryVaultKeyStore()
        let store = SessionVaultKeyStore(underlying: underlying)

        _ = try store.loadKey(mode: .local, reason: "unlock", createIfMissing: true)
        #expect(store.isUnlocked() == true)

        store.invalidate()

        #expect(store.isUnlocked() == false)
    }
}

struct KeyAppDiagnosticsCollectorTests {
    @Test
    func doesNotQueryHelperStatusWhenHelperIsNotRunning() {
        var helperStatusProbeCount = 0
        let collector = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                helperStatusProbeCount += 1
                return .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            },
            now: {
                Date(timeIntervalSince1970: 10_000)
            }
        )

        let snapshot = collector.load()
        #expect(snapshot.isHelperRunning == false)
        #expect(snapshot.helperStatus == nil)
        #expect(helperStatusProbeCount == 0)
    }

    @Test
    func recordsHelperStatusErrorsWhenHelperStatusProbeFails() {
        let collector = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                true
            },
            helperStatusProbe: {
                throw AppError.service("Key Agent returned no helper status.")
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            }
        )

        let snapshot = collector.load()
        #expect(snapshot.helperStatus == nil)
        #expect(snapshot.helperStatusErrorDescription == "Key Agent returned no helper status.")
    }

    @Test
    func reportsVersionMismatchAgainstShellCLI() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/usr/local/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "2")
                )
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .mismatch)
        #expect(snapshot.hero.title == "Welcome to Key")
        #expect(snapshot.callout?.title == "CLI version mismatch")
    }

    @Test
    func previewGuidanceNeverDirectsUsersToTheStableProduct() {
        let context = KeyAppDiagnosticsContext(
            productIdentity: .preview,
            appVersion: KeyVersionInfo(marketingVersion: "0.2.0-alpha.6", buildVersion: "11"),
            bundledCLIPath: "/Applications/Key Preview.app/Contents/MacOS/key-preview",
            helperAppPath: "/Applications/Key Preview.app/Contents/Helpers/Key Preview Agent.app",
            helperExecutablePath: "/Applications/Key Preview.app/Contents/Helpers/Key Preview Agent.app/Contents/MacOS/Key Preview Agent",
            launchAgentPlistPath: "/Applications/Key Preview.app/Contents/Library/LaunchAgents/work.tvr.key.preview.agent.plist",
            machServiceName: "work.tvr.key.preview.agent",
            configFilePath: "/Users/test/Library/Application Support/Key Preview/config.toml",
            vaultDirectoryPath: "/Users/test/.key-preview",
            vaultLocationSource: "App Support config (default)"
        )
        let snapshot = KeyAppDiagnosticsCollector(
            context: context,
            registrationProbe: {
                .requiresApproval(detail: "Allow Key Preview so Key Preview Agent can launch.")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key-preview",
                    version: nil,
                    versionErrorDescription: "Command failed"
                )
            }
        ).load()

        #expect(snapshot.hero.title == "Welcome to Key Preview")
        #expect(snapshot.hero.detail.contains("Key Preview Agent"))
        #expect(snapshot.callout?.detail.contains("Key Preview") == true)

        let registeredSnapshot = KeyAppDiagnosticsCollector(
            context: context,
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key-preview",
                    version: nil,
                    versionErrorDescription: "Command failed"
                )
            }
        ).load()

        #expect(registeredSnapshot.callout?.guidance.first?.command == "key-preview version")
    }

    @Test
    func reportsMatchingShellCLIVersion() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1"),
                    resolutionSource: .homebrewInstall
                )
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .matches)
        #expect(snapshot.shellCLIStatus.resolutionSummary == "Homebrew install path")
        #expect(snapshot.callout == nil)
    }

    @Test
    func reportsBundledCLIGuidanceWhenShellCLIMissing() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(resolvedPath: nil, version: nil)
            }
        ).load()

        #expect(snapshot.shellCLIStatus.matchState(appVersion: snapshot.context.appVersion) == .missing)
        #expect(snapshot.callout?.title == "External CLI not found")
        #expect(snapshot.callout?.guidance.first?.command == "\"/Applications/Key.app/Contents/MacOS/key\" unlock")
    }

    @Test
    func compressesLegacyShellCLIVersionHelpIntoConciseCallout() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                false
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/usr/local/bin/key",
                    version: nil,
                    versionErrorDescription: "Unknown command 'version'.\n\n\(CLIParser.usageText)"
                )
            }
        ).load()

        #expect(snapshot.callout?.title == "CLI version unavailable")
        #expect(snapshot.callout?.detail.contains("Usage:") == false)
        #expect(snapshot.callout?.detail.contains("does not support `key version` yet.") == true)
        #expect(snapshot.callout?.guidance.first?.command == "\"/Applications/Key.app/Contents/MacOS/key\" version")
    }

    @Test
    func includesDefaultVaultLocationSource() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                true
            },
            helperStatusProbe: {
                KeyHelperStatus(
                    isUnlocked: true,
                    sessionExpiresAt: Date(timeIntervalSince1970: 10_600),
                    inactivityTimeoutSeconds: 900
                )
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            },
            now: {
                Date(timeIntervalSince1970: 10_000)
            }
        ).load()

        #expect(snapshot.context.configFilePath == "/Users/test/Library/Application Support/Key/config.toml")
        #expect(snapshot.context.vaultDirectoryPath == "/Users/test/.key")
        #expect(snapshot.context.vaultLocationSource == "App Support config (default)")
        #expect(snapshot.hero.title == "Welcome to Key")
        #expect(snapshot.callout == nil)
    }

    @Test
    func heroRemainsInformationalWhenHelperIsLockedButHealthy() {
        let snapshot = KeyAppDiagnosticsCollector(
            context: .testFixture(),
            registrationProbe: {
                .registered(detail: "ready")
            },
            runningProbe: {
                true
            },
            helperStatusProbe: {
                .locked(inactivityTimeoutSeconds: 900)
            },
            shellCLIProbe: {
                ShellCLIStatus(
                    resolvedPath: "/opt/homebrew/bin/key",
                    version: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1")
                )
            }
        ).load()

        #expect(snapshot.hero.title == "Welcome to Key")
        #expect(snapshot.callout == nil)
    }
}

private extension KeyAppDiagnosticsContext {
    static func testFixture() -> KeyAppDiagnosticsContext {
        KeyAppDiagnosticsContext(
            appVersion: KeyVersionInfo(marketingVersion: "0.1.0", buildVersion: "1"),
            bundledCLIPath: "/Applications/Key.app/Contents/MacOS/key",
            helperAppPath: "/Applications/Key.app/Contents/Helpers/Key Agent.app",
            helperExecutablePath: "/Applications/Key.app/Contents/Helpers/Key Agent.app/Contents/MacOS/Key Agent",
            launchAgentPlistPath: "/Applications/Key.app/Contents/Library/LaunchAgents/work.tvr.key.agent.plist",
            machServiceName: "work.tvr.key.agent",
            configFilePath: "/Users/test/Library/Application Support/Key/config.toml",
            vaultDirectoryPath: "/Users/test/.key",
            vaultLocationSource: "App Support config (default)"
        )
    }
}

private func deviceInventoryFixture() -> V3VaultDeviceInventory {
    V3VaultDeviceInventory(
        vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        mode: .shared,
        currentDeviceID: "owner-device-id",
        devices: [
            V3VaultDeviceSummary(
                deviceID: "owner-device-id",
                displayName: "Office Mac",
                status: .active
            ),
            V3VaultDeviceSummary(
                deviceID: "member-device-id",
                displayName: "Laptop",
                status: .active
            )
        ]
    )
}

private func deviceRevocationReviewFixture()
    -> V3VaultDeviceRevocationReview
{
    V3VaultDeviceRevocationReview(
        vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        checkpointID: String(repeating: "a", count: 64),
        confirmationToken: String(repeating: "b", count: 64),
        authorizingDevice: V3VaultDeviceSummary(
            deviceID: "owner-device-id",
            displayName: "Office Mac",
            status: .active
        ),
        revokedDevice: V3VaultDeviceSummary(
            deviceID: "member-device-id",
            displayName: "Laptop",
            status: .active
        ),
        remainingActiveDevices: [V3VaultDeviceSummary(
            deviceID: "owner-device-id",
            displayName: "Office Mac",
            status: .active
        )]
    )
}

private func deviceReplacementReviewFixture(
    checkpointID: String = String(repeating: "c", count: 64),
    confirmationToken: String = String(repeating: "d", count: 64)
)
    -> V3VaultDeviceReplacementReview
{
    V3VaultDeviceReplacementReview(
        vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
        checkpointID: checkpointID,
        confirmationToken: confirmationToken,
        replacedDevice: V3VaultDeviceSummary(
            deviceID: "member-device-id",
            displayName: "Laptop",
            status: .revoked
        ),
        authorityKind: .survivingDevice,
        authorizingDevice: V3VaultDeviceSummary(
            deviceID: "owner-device-id",
            displayName: "Office Mac",
            status: .active
        ),
        revocationManifestID: String(repeating: "e", count: 64)
    )
}
