import Foundation

public final class KeyCLIApplication {
    private let transport: KeyServiceTransport
    private let io: InputOutput
    private let clipboard: ClipboardWriting
    private let configStore: KeyConfigStore
    private let version: KeyVersionInfo

    public init(
        transport: KeyServiceTransport,
        io: InputOutput,
        clipboard: ClipboardWriting,
        configStore: KeyConfigStore = KeyConfigStore(),
        version: KeyVersionInfo = KeyVersionInfo.currentProcess()
    ) {
        self.transport = transport
        self.io = io
        self.clipboard = clipboard
        self.configStore = configStore
        self.version = version
    }

    @discardableResult
    public func run(arguments: [String]) -> Int32 {
        do {
            let command = try CLIParser.parse(arguments: arguments)
            return try execute(command)
        } catch let error as AppError {
            io.writeStderr("\(error.localizedDescription)\n")
            return error.exitCode.rawValue
        } catch {
            io.writeStderr("\(error.localizedDescription)\n")
            return EXIT_FAILURE
        }
    }

    private func execute(_ command: Command) throws -> Int32 {
        let response: KeyServiceResponse

        switch command {
        case .help:
            io.writeStdout(CLIParser.usageText + "\n")
            return EXIT_SUCCESS
        case let .version(json):
            writeVersion(json: json)
            return EXIT_SUCCESS
        case let .config(configCommand):
            return try executeConfigCommand(configCommand)
        case .migrationPreflight:
            response = try transport.send(.migrationPreflight)
            return try handle(response, for: command)
        case .migrationApply:
            response = try transport.send(.migrationApply)
            return try handle(response, for: command)
        case let .status(json, verbose):
            response = try transport.send(.vaultStatus)
            if response.vaultStatus == nil,
               response.errorMessage != nil {
                return try handle(response, for: command)
            }
            let status = try requiredServicePayload(
                response.vaultStatus,
                operation: "vault status"
            )
            try writeStatus(status, json: json, verbose: verbose)
            return response.exitCode
        case let .conflict(conflictCommand):
            return try executeConflictCommand(conflictCommand)
        case let .share(shareCommand):
            return try executeShareCommand(shareCommand)
        case .unlock:
            response = try transport.send(.unlock)
            return try handle(response, for: command)
        case .lock:
            response = try transport.send(.lock)
            return try handle(response, for: command)
        case .list:
            response = try transport.send(.list)
            return try handle(response, for: command)
        case let .get(name, allowStale):
            response = try transport.send(
                .get(name: name, allowStale: allowStale)
            )
            return try handle(response, for: command)
        case let .copy(name, allowStale):
            response = try transport.send(
                .get(name: name, allowStale: allowStale)
            )
            let exitCode = try handle(response, for: command)
            guard exitCode == EXIT_SUCCESS, let value = response.value else {
                return exitCode
            }
            try clipboard.copy(value)
            return EXIT_SUCCESS
        case let .add(name, type):
            let secret = try readSecretFromInput(type: type)
            response = try transport.send(.addManual(name: name, secret: secret, type: type))
            return try handle(response, for: command)
        case let .edit(name, type):
            let secret = try readSecretFromInput(type: type)
            response = try transport.send(.editManual(name: name, secret: secret, type: type))
            return try handle(response, for: command)
        case let .duplicate(source, destination, force):
            response = try transport.send(.copyEntry(source: source, destination: destination, force: force))
            return try handle(response, for: command)
        case let .rename(source, destination, force):
            response = try transport.send(.moveEntry(source: source, destination: destination, force: force))
            return try handle(response, for: command)
        case let .remove(name, force):
            try confirmRemovalIfNeeded(name: name, force: force)
            response = try transport.send(.removeEntry(name: name))
            return try handle(response, for: command)
        }
    }

    private func handle(_ response: KeyServiceResponse, for command: Command) throws -> Int32 {
        if response.exitCode != EXIT_SUCCESS {
            if let errorMessage = response.errorMessage {
                io.writeStderr("\(errorMessage)\n")
            }
            return response.exitCode
        }

        switch command {
        case .help:
            break
        case .version(json: _):
            break
        case .config:
            break
        case .migrationPreflight, .migrationApply, .share,
            .unlock, .lock, .list:
            if let value = response.value, !value.isEmpty {
                io.writeStdout(value)
            }
        case .get(name: _, allowStale: _):
            if let value = response.value {
                io.writeStdout(formattedGetOutput(value))
            }
        case .status, .conflict:
            break
        case .copy(name: _, allowStale: _), .add, .edit, .duplicate,
            .rename, .remove:
            break
        }

        return response.exitCode
    }

    private func executeShareCommand(
        _ command: ShareCommand
    ) throws -> Int32 {
        switch command {
        case let .revoke(deviceID):
            return try executeDeviceRevocation(deviceID: deviceID)
        case let .devices(json):
            let response = try transport.send(.share(.devices))
            guard response.exitCode == EXIT_SUCCESS else {
                return try handle(response, for: .share(command))
            }
            let inventory = try requiredServicePayload(
                response.deviceInventory,
                operation: "device inventory"
            )
            if json {
                try writeJSON(inventory)
            } else {
                writeDeviceInventory(inventory)
            }
            return response.exitCode
        case .invitations:
            return try executeSimpleShareCommand(command, request: .invitations)
        case let .invite(deviceName):
            return try executeSimpleShareCommand(
                command,
                request: .invite(deviceName: deviceName)
            )
        case let .join(invitationID, deviceName):
            return try executeJoin(
                invitationID: invitationID,
                deviceName: deviceName
            )
        case let .requests(invitationID):
            return try executeSimpleShareCommand(
                command,
                request: .requests(invitationID: invitationID)
            )
        case let .compare(vaultID, invitationID, joinRequestID):
            return try executeSimpleShareCommand(
                command,
                request: .compare(
                    vaultID: vaultID,
                    invitationID: invitationID,
                    joinRequestID: joinRequestID
                )
            )
        case let .approve(vaultID, invitationID, comparisonCode):
            return try executeSimpleShareCommand(
                command,
                request: .approve(
                    vaultID: vaultID,
                    invitationID: invitationID,
                    comparisonCode: comparisonCode
                )
            )
        case let .accept(vaultID, invitationID, comparisonCode):
            return try executeSimpleShareCommand(
                command,
                request: .accept(
                    vaultID: vaultID,
                    invitationID: invitationID,
                    comparisonCode: comparisonCode
                )
            )
        }
    }

    private func executeSimpleShareCommand(
        _ command: ShareCommand,
        request: KeyShareRequest
    ) throws -> Int32 {
        try handle(
            transport.send(.share(request)),
            for: .share(command)
        )
    }

    private func executeDeviceRevocation(deviceID: String) throws -> Int32 {
        guard io.stdinIsTTY else {
            throw AppError.operationRefused(
                "Device revocation requires interactive confirmation."
            )
        }
        let reviewResponse = try transport.send(.share(
            .reviewRevocation(deviceID: deviceID)
        ))
        guard reviewResponse.exitCode == EXIT_SUCCESS else {
            return try handle(
                reviewResponse,
                for: .share(.revoke(deviceID: deviceID))
            )
        }
        let review = try requiredServicePayload(
            reviewResponse.deviceRevocationReview,
            operation: "device revocation review"
        )
        writeDeviceRevocationReview(review)
        try confirmDeviceRevocation()

        let response = try transport.send(.share(.revoke(
            deviceID: deviceID,
            confirmationToken: review.confirmationToken
        )))
        return try handle(
            response,
            for: .share(.revoke(deviceID: deviceID))
        )
    }

    private func writeDeviceRevocationReview(
        _ review: V3VaultDeviceRevocationReview
    ) {
        var lines = [
            "Review device revocation:",
            "Device: \(review.revokedDevice.displayName)",
            "  ID: \(review.revokedDevice.deviceID)",
            "Authorized by: \(review.authorizingDevice.displayName)",
            "",
            "This permanently removes the device from future vault versions.",
            "Key will rotate the vault key and re-encrypt the current vault for the remaining active devices.",
            "Remaining active devices: \(review.remainingActiveDevices.count)"
        ]
        lines.append(contentsOf: review.remainingActiveDevices.map {
            "  \($0.displayName)"
        })
        if review.remainingActiveDevices.count == 1,
           let remainingDevice = review.remainingActiveDevices.first
        {
            lines.append("")
            lines.append(
                "WARNING: This will leave \(remainingDevice.displayName) as the vault's only active device."
            )
            lines.append(
                "If that Mac is lost, synchronized vault files cannot recover the vault."
            )
        }
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func confirmDeviceRevocation() throws {
        let answer = try io.readLine(
            prompt: "Type REVOKE to rotate the vault key and continue: "
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        guard answer == "REVOKE" else {
            throw AppError.operationRefused("Device revocation cancelled.")
        }
    }

    private func executeJoin(
        invitationID: String,
        deviceName: String
    ) throws -> Int32 {
        let command = ShareCommand.join(
            invitationID: invitationID,
            deviceName: deviceName
        )
        let request = KeyShareRequest.join(
            invitationID: invitationID,
            deviceName: deviceName
        )
        let initialResponse = try transport.send(.share(request))
        guard let review = initialResponse.deviceReplacementReview else {
            return try handle(initialResponse, for: .share(command))
        }
        guard io.stdinIsTTY else {
            throw AppError.operationRefused(
                "Rejoining a revoked Mac requires interactive confirmation."
            )
        }

        writeDeviceRejoinReview(review)
        try confirmDeviceRejoin()

        let revalidationResponse = try transport.send(.share(request))
        guard revalidationResponse.exitCode == EXIT_SUCCESS else {
            return try handle(
                revalidationResponse,
                for: .share(command)
            )
        }
        let currentReview = try requiredServicePayload(
            revalidationResponse.deviceReplacementReview,
            operation: "device rejoin revalidation"
        )
        guard currentReview == review else {
            throw AppError.operationRefused(
                "The vault's replacement state changed while awaiting confirmation. Review the current state by running the join command again."
            )
        }

        let cleanupResponse = try transport.send(.share(.replaceCurrentDevice(
            invitationID: invitationID,
            confirmationToken: currentReview.confirmationToken
        )))
        let cleanupExitCode = try handle(
            cleanupResponse,
            for: .share(command)
        )
        guard cleanupExitCode == EXIT_SUCCESS else {
            return cleanupExitCode
        }

        return try handle(
            transport.send(.share(request)),
            for: .share(command)
        )
    }

    private func writeDeviceRejoinReview(
        _ review: V3VaultDeviceReplacementReview
    ) {
        var lines = [
            "This Mac previously belonged to this vault and has been revoked.",
            "Review rejoin:",
            "Vault ID: \(review.vaultID)",
            "Previous identity: \(review.replacedDevice.displayName)",
            "  ID: \(review.replacedDevice.deviceID)"
        ]
        switch review.authorityKind {
        case .trustedCheckpoint:
            lines.append(
                "Revocation source: this Mac's authenticated trusted checkpoint"
            )
        case .survivingDevice:
            if let authorizingDevice = review.authorizingDevice {
                lines.append(
                    "Revoked by: \(authorizingDevice.displayName)"
                )
            }
        }
        lines.append(contentsOf: [
            "",
            "Rejoining removes this Mac's unusable local enrollment identity and trusted checkpoint, then creates a new identity through this invitation.",
            "Synchronized vault files will not be changed.",
            "The other active Mac must still compare and approve the new identity."
        ])
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func confirmDeviceRejoin() throws {
        let answer = try io.readLine(
            prompt: "Type REJOIN to replace the revoked identity and continue: "
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        guard answer == "REJOIN" else {
            throw AppError.operationRefused("Device rejoin cancelled.")
        }
    }

    private func formattedGetOutput(_ value: String) -> String {
        guard io.stdoutIsTTY, !value.hasSuffix("\n") else {
            return value
        }

        return value + "\n"
    }

    private func readSecretFromInput(type: SecretEntryType) throws -> String {
        let prompt = type == .totp ? "TOTP seed: " : "Secret: "
        let secret: String
        if io.stdinIsTTY {
            secret = try io.readSecureLine(prompt: prompt)
        } else {
            secret = try io.readPipedInput()
        }

        switch type {
        case .secret:
            return secret
        case .totp:
            return try TOTPGenerator.normalizeBase32Seed(secret)
        }
    }

    private func confirmRemovalIfNeeded(name: String, force: Bool) throws {
        guard !force else {
            return
        }

        guard io.stdinIsTTY else {
            throw AppError.operationRefused("Refusing to remove '\(name)' without --force in non-interactive mode.")
        }

        let answer = try io.readLine(prompt: "Remove '\(name)'? [y/N]: ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard answer == "y" || answer == "yes" else {
            throw AppError.operationRefused("Removal cancelled.")
        }
    }

    private func writeVersion(json: Bool) {
        if json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            if let data = try? encoder.encode(version),
               let string = String(data: data, encoding: .utf8) {
                io.writeStdout(string + "\n")
                return
            }
        }

        io.writeStdout(version.displayString + "\n")
    }

    private func executeConflictCommand(
        _ command: ConflictCommand
    ) throws -> Int32 {
        switch command {
        case let .list(json):
            let response = try transport.send(.listConflicts)
            guard response.exitCode == EXIT_SUCCESS else {
                return try handle(response, for: .conflict(command))
            }
            let conflicts = try requiredServicePayload(
                response.conflicts,
                operation: "conflict list"
            )
            if json {
                try writeJSON(conflicts)
            } else {
                writeConflictList(conflicts)
            }
            return response.exitCode
        case let .show(id, json):
            let response = try transport.send(.showConflict(id: id))
            guard response.exitCode == EXIT_SUCCESS else {
                return try handle(response, for: .conflict(command))
            }
            let conflict = try requiredServicePayload(
                response.conflict,
                operation: "conflict show"
            )
            if json {
                try writeJSON(conflict)
            } else {
                writeConflict(conflict)
            }
            return response.exitCode
        case let .get(id, versionID):
            let response = try transport.send(
                .getConflictValue(id: id, versionID: versionID)
            )
            guard response.exitCode == EXIT_SUCCESS else {
                return try handle(response, for: .conflict(command))
            }
            let value = try requiredServicePayload(
                response.value,
                operation: "conflict get"
            )
            io.writeStdout(formattedGetOutput(value))
            return response.exitCode
        case let .copy(id, versionID):
            let response = try transport.send(
                .getConflictValue(id: id, versionID: versionID)
            )
            guard response.exitCode == EXIT_SUCCESS else {
                return try handle(response, for: .conflict(command))
            }
            let value = try requiredServicePayload(
                response.value,
                operation: "conflict copy"
            )
            try clipboard.copy(value)
            return response.exitCode
        case let .resolve(resolutions):
            let response = try transport.send(
                .resolveConflicts(resolutions)
            )
            return try handle(response, for: .conflict(command))
        }
    }

    private func writeStatus(
        _ status: VaultStatus,
        json: Bool,
        verbose: Bool
    ) throws {
        if json {
            try writeJSON(status)
            return
        }

        let headline = switch status.health {
        case .ready:
            "Vault is ready."
        case .incomplete:
            "Vault files are still arriving."
        case .contentConflicted:
            "Vault has content conflicts that need your choice."
        case .securityConflicted:
            "Vault authority differs between authenticated versions."
        case .rollbackDetected:
            "Vault contains an authenticated revision rollback."
        case .recoveryRequired:
            "Vault needs recovery before it can be changed safely."
        }
        let entryLabel = switch status.entries.basis {
        case .effective:
            "Entries"
        case .lastTrusted:
            "Last trusted entries"
        }
        var lines = [
            headline,
            "Format: \(status.format == .version2 ? "version 2" : "version 3")",
            "\(entryLabel): \(status.entries.count)"
        ]
        if status.conflictCount > 0 {
            lines.append("Conflicts: \(status.conflictCount)")
            switch status.health {
            case .contentConflicted:
                lines.append("Next: run `key conflict list`.")
            case .rollbackDetected:
                lines.append(
                    "Next: inspect with `key conflict list`, then recover from a known-good state."
                )
            case .ready, .incomplete, .securityConflicted,
                .recoveryRequired:
                break
            }
        }
        if verbose, let trustedVersionID = status.trustedVersionID {
            lines.append(
                "Previously trusted on this Mac: \(trustedVersionID)"
            )
        }
        lines.append(contentsOf: status.issues.map {
            "Attention: \($0.message)"
        })
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func writeConflictList(
        _ conflicts: [VaultConflictSummary]
    ) {
        guard !conflicts.isEmpty else {
            io.writeStdout("No unresolved content conflicts.\n")
            return
        }

        let lines = conflicts.map { conflict in
            let name = conflict.entryName ?? "(deleted or renamed)"
            return "\(conflict.id)  \(name)  \(humanConflictKind(conflict.kind))  \(conflict.versionCount) versions"
        }
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func writeDeviceInventory(
        _ inventory: V3VaultDeviceInventory
    ) {
        guard inventory.mode == .shared else {
            io.writeStdout("This version 3 vault has not been shared yet.\n")
            return
        }

        var lines = ["Devices in the authenticated vault record:"]
        for device in inventory.devices {
            let current = device.deviceID == inventory.currentDeviceID
                ? " (this Mac)"
                : ""
            lines.append(
                "\(device.displayName) — \(device.status.rawValue)\(current)"
            )
            lines.append("  ID: \(device.deviceID)")
        }
        lines.append("")
        if inventory.activeDeviceCount == 1 {
            lines.append("Continuity: 1 active device.")
            lines.append(
                "Attention: add another Mac. If the only active device is lost, synchronized vault files cannot recover the vault."
            )
        } else {
            lines.append(
                "Continuity: \(inventory.activeDeviceCount) active devices."
            )
            lines.append(
                "A surviving enrolled Mac can authorize a replacement if another is lost."
            )
        }
        if let currentDeviceID = inventory.currentDeviceID,
           !inventory.devices.contains(where: {
               $0.deviceID == currentDeviceID
           }) {
            lines.append(
                "Attention: this Mac's recorded identity is not authorized by the current vault."
            )
        } else if inventory.currentDeviceID == nil {
            lines.append(
                "Attention: this Mac has no recorded enrollment identity for the vault."
            )
        }
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func writeConflict(_ conflict: VaultConflictDetail) {
        var lines = [
            "Conflict: \(conflict.summary.id)",
            "Entry: \(conflict.summary.entryName ?? "(deleted or renamed)")",
            "Reason: \(humanConflictKind(conflict.summary.kind))",
            "Authenticated versions:"
        ]
        for version in conflict.versions {
            var description = "  \(version.id)  "
            if let name = version.entryName {
                description += name
                if let revision = version.revision {
                    description += "  revision \(revision)"
                }
            } else {
                description += "(deleted)"
            }
            if version.previouslyTrustedOnThisMac {
                description += "  previously trusted on this Mac"
            }
            lines.append(description)
        }
        switch conflict.summary.kind.resolutionPolicy {
        case .chooseVersion:
            lines.append(
                "Resolve only after reviewing every conflict shown by `key conflict list`."
            )
        case .recoveryRequired:
            lines.append(
                "This rollback cannot be resolved with `key conflict resolve`. Recover from a known-good state."
            )
        }
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func writeJSON<Value: Encodable>(_ value: Value) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw AppError.io("Failed to encode JSON output.")
        }
        io.writeStdout(string + "\n")
    }

    private func requiredServicePayload<Value>(
        _ value: Value?,
        operation: String
    ) throws -> Value {
        guard let value else {
            throw AppError.service(
                "Key service returned an invalid \(operation) response."
            )
        }
        return value
    }

    private func humanConflictKind(_ kind: VaultConflictKind) -> String {
        switch kind {
        case .concurrentCreation:
            "created differently"
        case .editEdit:
            "edited differently"
        case .deleteEdit:
            "deleted on one version and edited on another"
        case .renameEdit:
            "renamed on one version and edited on another"
        case .conflictingRename:
            "renamed differently"
        case .destinationCollision:
            "multiple entries use the same name"
        case .revisionRollback:
            "an older entry revision reappeared"
        case .conflictingRevision:
            "same revision contains different content"
        }
    }

    private func executeConfigCommand(_ command: ConfigCommand) throws -> Int32 {
        switch command {
        case let .get(key):
            io.writeStdout(try configStore.getValue(for: key) + "\n")
        case let .set(key, value):
            switch key {
            case .vaultDir:
                let response = try transport.send(
                    .setVaultDirectory(path: value)
                )
                return try handle(response, for: .config(command))
            case .keychainMode:
                guard let mode = KeychainMode(rawValue: value) else {
                    throw AppError.invalidConfiguration("Unsupported keychain mode '\(value)'. Expected 'local' or 'icloud'.")
                }
                let response = try transport.send(.setKeychainMode(mode))
                return try handle(response, for: .config(command))
            }
        case .list:
            let values = try configStore.listValues()
            let output = values
                .map { "\($0.key.rawValue)=\($0.value)" }
                .joined(separator: "\n")
            if !output.isEmpty {
                io.writeStdout(output + "\n")
            }
        }

        return EXIT_SUCCESS
    }
}
