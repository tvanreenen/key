import Foundation

public final class KeyCLIApplication {
    private let transport: KeyServiceTransport
    private let io: InputOutput
    private let clipboard: ClipboardWriting
    private let configStore: KeyConfigStore
    private let version: KeyVersionInfo
    private let currentDirectory: () -> URL

    public init(
        transport: KeyServiceTransport,
        io: InputOutput,
        clipboard: ClipboardWriting,
        configStore: KeyConfigStore = KeyConfigStore(),
        version: KeyVersionInfo = KeyVersionInfo.currentProcess(),
        currentDirectory: @escaping () -> URL = {
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true)
        }
    ) {
        self.transport = transport
        self.io = io
        self.clipboard = clipboard
        self.configStore = configStore
        self.version = version
        self.currentDirectory = currentDirectory
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
        case let .help(text):
            io.writeStdout(text + "\n")
            return EXIT_SUCCESS
        case let .version(json):
            writeVersion(json: json)
            return EXIT_SUCCESS
        case let .config(configCommand):
            return try executeConfigCommand(configCommand)
        case let .initializeVault(path):
            let directory = path.map {
                URL(fileURLWithPath: $0, isDirectory: true, relativeTo: currentDirectory())
            } ?? currentDirectory()
            io.writeStderr("Creating a new vault at '\(directory.standardizedFileURL.path)'. To use a vault from another Mac, join it with `key share` instead. If every enrolled Mac is lost, this vault cannot currently be recovered.\n")
            response = try transport.send(.initializeVault(path: directory.standardizedFileURL.path))
            return try handle(response, for: command)
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
        case let .share(shareCommand, vaultDirectory):
            return try executeShareCommand(shareCommand, vaultDirectory: vaultDirectory)
        case let .recovery(request):
            return try executeRecovery(request)
        case let .recoveryReview(request, json):
            return try executeRecoveryReview(request, json: json)
        case let .recoveryRegistration(request, exportPath, json):
            return try executeRecoveryRegistration(request, exportPath: exportPath, json: json)
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
        case .initializeVault, .migrationPreflight, .migrationApply, .share, .recovery,
            .unlock, .lock, .list:
            if let value = response.value, !value.isEmpty {
                io.writeStdout(value)
            }
        case .get(name: _, allowStale: _):
            if let value = response.value {
                io.writeStdout(formattedGetOutput(value))
            }
        case .status, .conflict, .recoveryReview, .recoveryRegistration:
            break
        case .copy(name: _, allowStale: _), .add, .edit, .duplicate,
            .rename, .remove:
            break
        }

        return response.exitCode
    }

    private func executeRecoveryReview(_ request: KeyRecoveryReviewRequest, json: Bool) throws -> Int32 {
        let resolved: KeyRecoveryReviewRequest
        switch request {
        case .tokens:
            resolved = .tokens
        case .credential:
            resolved = request
        case .source(let path, let token):
            let base = URL(fileURLWithPath: currentDirectory().path, isDirectory: true)
            resolved = .source(
                path: URL(fileURLWithPath: path, isDirectory: true, relativeTo: base).standardizedFileURL.path,
                tokenID: token
            )
        }
        try resolved.validate()
        let response = try transport.send(.recoveryReview(resolved))
        guard response.exitCode == EXIT_SUCCESS else {
            return try handle(response, for: .recoveryReview(resolved, json: json))
        }
        let result = try requiredServicePayload(response.recoveryReview, operation: "public recovery review")
        switch (resolved, result) {
        case (.tokens, .tokens): break
        case let (.credential(token), .credential(credential)) where credential.token.tokenID == token: break
        case let (.source(path, token), .source(source))
            where source.path == path && source.token.tokenID == token: break
        default:
            throw AppError.service("Key service returned a mismatched public recovery review response.")
        }
        if json {
            try writeJSON(result)
        } else {
            writeRecoveryReview(result)
        }
        return response.exitCode
    }

    private func writeRecoveryReview(_ result: KeyRecoveryReviewResult) {
        switch result {
        case .credential(let credential):
            io.writeStdout("Public recovery credential:\nToken ID: \(credential.token.tokenID)\nReader: \(credential.token.readerSlotName)\nRecipient ID: \(credential.recipientID)\nSlot: 9d; P-256; reported generated origin, PIN always, touch always.\nAnchor: \(credential.anchorState.rawValue)\nPublic observation only. This does not prove possession, protected administration or recovery readiness. No PIN/touch operation was requested.\n")
        case .tokens(let tokens):
            var lines = [tokens.isEmpty ? "No connected token candidates found." : "Public connected-token candidates:"]
            for token in tokens {
                lines.append("Token ID: \(token.tokenID)")
                lines.append("  Reader: \(token.readerSlotName)")
            }
            lines.append("Listing does not select a key or read its recovery credential, prove possession or establish recovery protection.")
            io.writeStdout(lines.joined(separator: "\n") + "\n")
        case .source(let source):
            io.writeStdout("""
            Public recovery source review:
            Source: \(String(reflecting: source.path))
            Token ID: \(source.token.tokenID)
            Reader: \(source.token.readerSlotName)
            Recipient ID: \(source.recipientID)
            Slot: 9d; P-256; reported PIN \(source.reportedPINPolicy), touch \(source.reportedTouchPolicy), origin \(source.reportedKeyOrigin).
            Vault ID: \(source.vaultID)
            Registration ID: \(source.registrationID)
            Registration manifest: \(source.registrationManifestDigest)
            Observed head: \(source.observedHeadDigest)
            Listed entries (not content-verified): \(source.listedEntryCount)
            Observed manifests: \(source.observedManifestCount)
            Public history checks passed for the files observed. No entry objects were opened.
            This does not prove possession, protected token administration, PIN/touch enforcement, restorable contents or provider freshness. No saved attempt or restore approval was created.

            """)
        }
    }

    private func executeRecoveryRegistration(
        _ request: KeyRecoveryRegistrationRequest, exportPath: String?, json: Bool
    ) throws -> Int32 {
        try request.validate()
        let confirmation: String?
        switch request {
        case .prepare: confirmation = "PREPARE"
        case .finish: confirmation = "REGISTER"
        case .adopt, .resumeAdoption: confirmation = "ADOPT"
        case .status, .resumeExport: confirmation = nil
        }
        if let confirmation {
            guard io.stdinIsTTY else {
                throw AppError.operationRefused("Recovery setup requires an interactive terminal. No setup request was sent.")
            }
            io.writeStderr("Recovery setup is experimental and gated. Preserve a backup and coordinate Mac upgrades. Key never provisions or writes the token; its external administration must be secured separately. Preparation/export does not activate recovery.\n")
            guard try io.readLine(prompt: "Type \(confirmation) to continue this explicit recovery setup step: ").trimmingCharacters(in: .whitespacesAndNewlines) == confirmation else {
                throw AppError.operationRefused("Recovery setup cancelled. No request was sent.")
            }
        }
        if case .finish = request {
            io.writeStderr("If possession verification is reached, enter PIN only in the macOS dialog and physically touch the key when it flashes. Cancel unexpected prompts. No automatic retry is made.\n")
        }
        do {
            let response = try transport.send(.recoveryRegistration(request))
            guard response.exitCode == EXIT_SUCCESS else {
                if let message = response.errorMessage { io.writeStderr(message + "\n") }
                writeRegistrationFailureGuidance()
                return response.exitCode
            }
            let result = try requiredServicePayload(response.recoveryRegistration, operation: "recovery registration")
            switch (request, result) {
            case (.status, .status(let state, let vaultID, let recipients, let committed)):
                guard isValidV3UUID(vaultID), recipients.count <= 64,
                      recipients.allSatisfy({ (try? V3RecoveryRecipientID(rawValue: $0)) != nil }) else {
                    throw AppError.service("Invalid recovery registration status response.")
                }
                if json { try writeJSON(result) }
                else { io.writeStdout("Recovery registration: \(state.rawValue)\nVault ID: \(vaultID)\nActive recipients: \(recipients.count)\nPending activation committed: \(committed)\nThis authenticates local registration state, not hardware qualification or provider freshness.\n") }
                return state == .attentionRequired ? EXIT_FAILURE : EXIT_SUCCESS
            case (.prepare(_, let expected), .export(let operation, let vault, let recipient, let encoded)),
                 (.resumeExport(_, let expected), .export(let operation, let vault, let recipient, let encoded)):
                guard let exportPath, recipient == expected, isValidV3UUID(vault),
                      (try? VaultTransactionOperationID(validating: operation)) != nil,
                      encoded.utf8.count <= 1_368, let bytes = Base64URL.decodeCanonical(encoded),
                      let anchor = try? V3RecoveryAnchorCodec().parseCanonical(bytes),
                      anchor.floor.vaultID == vault, anchor.recipientID.rawValue == recipient else {
                    throw AppError.service("Invalid or mismatched recovery anchor export response.")
                }
                let base = URL(fileURLWithPath: currentDirectory().path, isDirectory: true)
                let url = URL(fileURLWithPath: exportPath, relativeTo: base).standardizedFileURL
                // Insert only: existing files and links are never replaced. If
                // this fails, the locally owned preparation remains resumable.
                try bytes.write(to: url, options: .withoutOverwriting)
                io.writeStdout("Public anchor exported to '\(url.path)'.\nOperation ID: \(operation)\nRecipient ID: \(recipient)\nRecovery is not active. Use the documented vendor-tool procedure to install these exact bytes, then run recovery register finish with the same selectors.\n")
                return EXIT_SUCCESS
            case (.finish, .completed(let vault, let digest, let pending)),
                 (.adopt, .completed(let vault, let digest, let pending)),
                 (.resumeAdoption, .completed(let vault, let digest, let pending)):
                guard isValidV3UUID(vault), Base64URL.decodeCanonical(digest)?.count == 32 else {
                    throw AppError.service("Invalid recovery setup completion response.")
                }
                io.writeStdout("Recovery setup committed.\nVault ID: \(vault)\nManifest: \(digest)\nCleanup pending: \(pending)\nCheck registration status after the helper restarts. Format adoption alone does not register a recovery key.\n")
                return EXIT_SUCCESS
            default: throw AppError.service("Mismatched recovery setup response.")
            }
        } catch {
            writeRegistrationFailureGuidance()
            throw error
        }
    }

    private func writeRegistrationFailureGuidance() {
        io.writeStderr("Preserve token, vault files and local setup records. A failed or lost reply does not prove nothing committed. Do not create replacement setup or rewrite the token. Inspect status after restart; explicitly resume-export or finish the owned registration, or resume adoption with its original operation ID. Export failures require a new output filename, not a new preparation.\n")
    }

    private func executeRecovery(_ request: KeyRecoveryRequest) throws -> Int32 {
        // Resolve both explicit paths against one captured working directory.
        // Configuration and provider files cannot supply a missing selector.
        let base = URL(fileURLWithPath: currentDirectory().path, isDirectory: true)
        func path(_ value: String) -> String {
            URL(fileURLWithPath: value, isDirectory: true, relativeTo: base).standardizedFileURL.path
        }
        let resolved: KeyRecoveryRequest
        switch request {
        case .restore(let source, let destination, let token, let recipient, let name):
            resolved = .restore(
                source: path(source), destination: path(destination), tokenID: token,
                recipientID: recipient, deviceName: name
            )
        case .resume(let source, let destination, let token, let recipient):
            resolved = .resume(
                source: path(source), destination: path(destination), tokenID: token,
                recipientID: recipient
            )
        }
        try resolved.validate()
        io.writeStderr("If source authentication is reached, Key requests one source-key hardware operation. Enter PIN only in the macOS dialog; physically touch the key when it flashes. Cancel unexpected prompts. No automatic retry will be made.\n")
        do {
            let response = try transport.send(.recovery(resolved))
            let result = try handle(response, for: .recovery(resolved))
            if result != EXIT_SUCCESS { writeRecoveryFailureGuidance() }
            return result
        } catch {
            writeRecoveryFailureGuidance()
            throw error
        }
    }

    private func writeRecoveryFailureGuidance() {
        io.writeStderr("Leave source, destination, local records and configuration intact. Do not start another restore or delete state to retry. A failed or lost reply does not establish whether selection completed. Use `key recovery resume` with the exact original selectors if a saved attempt remains; if resume refuses, preserve state for inspection. See `key recovery resume --help`.\n")
    }

    private func executeShareCommand(
        _ command: ShareCommand,
        vaultDirectory: String?
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
            return try executeSimpleShareCommand(command, request: .invitations, vaultDirectory: vaultDirectory)
        case let .invite(deviceName):
            return try executeSimpleShareCommand(
                command,
                request: .invite(deviceName: deviceName)
            )
        case let .join(invitationID, deviceName):
            return try executeJoin(
                invitationID: invitationID,
                deviceName: deviceName,
                vaultDirectory: vaultDirectory
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
                ),
                vaultDirectory: vaultDirectory
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
                ),
                vaultDirectory: vaultDirectory
            )
        }
    }

    private func executeSimpleShareCommand(
        _ command: ShareCommand,
        request: KeyShareRequest,
        vaultDirectory: String? = nil
    ) throws -> Int32 {
        try handle(
            transport.send(shareServiceRequest(request, vaultDirectory: vaultDirectory)),
            for: .share(command)
        )
    }

    private func shareServiceRequest(
        _ request: KeyShareRequest,
        vaultDirectory: String?
    ) throws -> KeyServiceRequest {
        guard request.supportsDirectorySelection else { return .share(request) }
        let directory: URL
        if let vaultDirectory {
            let base = URL(fileURLWithPath: currentDirectory().path, isDirectory: true)
            directory = URL(fileURLWithPath: vaultDirectory, isDirectory: true, relativeTo: base)
        } else if try configStore.hasConfiguration() {
            directory = try configStore.load().vaultDirectoryURL
        } else {
            directory = currentDirectory()
        }
        let path = directory.standardizedFileURL.path
        io.writeStderr("Vault folder: '\(path)'.\n")
        if case .join = request {
            io.writeStderr("Key will set up this Mac's access credentials and send a request to join. This does not create a new vault or change any hardware security key.\n")
        }
        return .shareInDirectory(request: request, path: path)
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
            "Review removal of vault access:",
            "Device: \(review.revokedDevice.displayName)",
            "  ID: \(review.revokedDevice.deviceID)",
            "Authorized by: \(review.authorizingDevice.displayName)",
            "",
            "This removes the Mac's access to the current vault and future changes. It cannot erase secrets or older vault data the Mac already obtained.",
            "Key will change the encryption key and encrypt the vault again for the Macs that keep access.",
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
                "If that Mac is lost, a backup of the vault folder alone cannot restore access."
            )
        }
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func confirmDeviceRevocation() throws {
        let answer = try io.readLine(
            prompt: "Type REVOKE to remove the reviewed Mac's access and change the encryption key: "
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        guard answer == "REVOKE" else {
            throw AppError.operationRefused("Device revocation cancelled.")
        }
    }

    private func executeJoin(
        invitationID: String,
        deviceName: String,
        vaultDirectory: String?
    ) throws -> Int32 {
        let command = ShareCommand.join(
            invitationID: invitationID,
            deviceName: deviceName
        )
        let request = KeyShareRequest.join(
            invitationID: invitationID,
            deviceName: deviceName
        )
        let serviceRequest = try shareServiceRequest(request, vaultDirectory: vaultDirectory)
        let initialResponse = try transport.send(serviceRequest)
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

        let revalidationResponse = try transport.send(serviceRequest)
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
            transport.send(serviceRequest),
            for: .share(command)
        )
    }

    private func writeDeviceRejoinReview(
        _ review: V3VaultDeviceReplacementReview
    ) {
        var lines = [
            "This Mac previously had access to this vault, but its access was removed.",
            "Review rejoin:",
            "Vault ID: \(review.vaultID)",
            "Previous identity: \(review.replacedDevice.displayName)",
            "  ID: \(review.replacedDevice.deviceID)"
        ]
        switch review.authorityKind {
        case .trustedCheckpoint:
            lines.append(
                "Confirmed by: this Mac's last verified vault record"
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
            "Rejoining replaces this Mac's old access credentials and local vault record. Key creates new credentials for this invitation.",
            "Synchronized vault files will not be changed.",
            "The other Mac must still compare the code and approve this Mac's new access."
        ])
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func confirmDeviceRejoin() throws {
        let answer = try io.readLine(
            prompt: "Type REJOIN to replace this Mac's old access credentials: "
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
        let prompt = type == .totp ? "Authenticator setup secret (Base32): " : "Secret: "
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
            "Some required vault files are unavailable on this Mac."
        case .contentConflicted:
            "Some entries have conflicting changes. Choose which versions to keep."
        case .securityConflicted:
            "Vault history contains conflicting changes to device access or encryption keys."
        case .rollbackDetected:
            "Vault history includes an older entry revision. Key has blocked the rollback."
        case .recoveryRequired:
            "Key cannot safely use this vault until its state has been investigated."
        }
        let entryLabel = switch status.entries.basis {
        case .effective:
            "Entries"
        case .lastTrusted:
            "Last trusted entries"
        }
        var lines = [
            headline,
            "\(entryLabel): \(status.entries.count)"
        ]
        if verbose {
            lines.append("Storage format: \(status.format == .version2 ? "version 2" : "version 3")")
        }
        if status.conflictCount > 0 {
            lines.append("Conflicts: \(status.conflictCount)")
            switch status.health {
            case .contentConflicted:
                lines.append("Next: run `key conflict list`.")
            case .rollbackDetected:
                lines.append(
                    "Next: inspect with `key conflict list`. Keep vault files and local records intact; ordinary conflict resolution cannot accept this rollback."
                )
            case .ready, .incomplete, .securityConflicted,
                .recoveryRequired:
                break
            }
        }
        switch status.health {
        case .incomplete:
            lines.append("Next: check that your sync provider has downloaded the vault files, then run `key status` again.")
        case .securityConflicted, .recoveryRequired:
            lines.append("Keep vault files and local records intact for investigation. Do not delete them or run init to bypass this check.")
        case .ready, .contentConflicted, .rollbackDetected:
            break
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
        if status.format == .version2 {
            writeV2DeprecationWarning()
        }
    }

    /// Warn only on explicit, terminal-facing inspection. Never probe config
    /// or contact the helper just to add a warning to an ordinary command.
    private func writeV2DeprecationWarning() {
        guard io.stdoutIsTTY else { return }
        io.writeStderr(
            "Warning: this vault uses the older storage format (v2), which is deprecated. Reading and saving secrets still work. Run `key migrate --check` to check migration readiness without changing the vault. Before migrating, review `key help migrate` for other-Mac setup and recovery limits.\n"
        )
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
            io.writeStdout("This vault does not have an enrolled-device list yet.\n")
            return
        }

        var lines = ["Macs recorded for this vault:"]
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
            lines.append("Only one Mac currently has access.")
            lines.append(
                "Attention: add another Mac. If the only Mac with access is lost, the vault folder alone cannot restore access."
            )
        } else {
            lines.append(
                "Macs with access: \(inventory.activeDeviceCount)."
            )
            lines.append(
                "A Mac that still has access can add a replacement if another is lost."
            )
        }
        if let currentDeviceID = inventory.currentDeviceID,
           !inventory.devices.contains(where: {
               $0.deviceID == currentDeviceID
           }) {
            lines.append(
                "Attention: this Mac's access credentials are not recognized by the current vault."
            )
        } else if inventory.currentDeviceID == nil {
            lines.append(
                "Attention: this Mac has no saved access credentials for this vault."
            )
        }
        io.writeStdout(lines.joined(separator: "\n") + "\n")
    }

    private func writeConflict(_ conflict: VaultConflictDetail) {
        var lines = [
            "Conflict: \(conflict.summary.id)",
            "Entry: \(conflict.summary.entryName ?? "(deleted or renamed)")",
            "Reason: \(humanConflictKind(conflict.summary.kind))",
            "Verified versions:"
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
                "This older revision cannot be accepted with `key conflict resolve`. Keep vault files and local records intact for investigation. Do not delete them or run init to bypass this check."
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
            let configuration = try configStore.load()
            io.writeStdout(configuration.value(for: key) + "\n")
            if key == .keychainMode, case .v3 = configuration.authority {
                io.writeStderr(
                    "keychain-mode does not control access or file synchronization for this vault. Key retains it for compatibility. vault-dir specifies the folder used to store and synchronize vault files.\n"
                )
            }
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
            let configuration = try configStore.load()
            let output = configuration.listedValues
                .map { "\($0.key.rawValue)=\($0.value)" }
                .joined(separator: "\n")
            if !output.isEmpty {
                io.writeStdout(output + "\n")
            }
            if case .v2 = configuration.authority {
                writeV2DeprecationWarning()
            }
        }

        return EXIT_SUCCESS
    }
}
