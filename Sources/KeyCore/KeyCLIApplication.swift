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
            return EXIT_FAILURE
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
        case let .vault(vaultCommand):
            return try executeVaultCommand(vaultCommand)
        case .unlock:
            response = try transport.send(.unlock)
            return try handle(response, for: command)
        case .lock:
            response = try transport.send(.lock)
            return try handle(response, for: command)
        case .list:
            response = try transport.send(.list)
            return try handle(response, for: command)
        case let .get(name):
            response = try transport.send(.get(name: name))
            return try handle(response, for: command)
        case let .copy(name):
            response = try transport.send(.get(name: name))
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
        case .vault:
            if let value = response.value, !value.isEmpty {
                io.writeStdout(value)
            }
        case .unlock, .lock, .list:
            if let value = response.value, !value.isEmpty {
                io.writeStdout(value)
            }
        case .get(name: _):
            if let value = response.value {
                io.writeStdout(formattedGetOutput(value))
            }
        case .copy(name: _), .add, .edit, .duplicate, .rename, .remove:
            break
        }

        return response.exitCode
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

    private func executeVaultCommand(_ command: VaultCommand) throws -> Int32 {
        switch command {
        case .status:
            let response = try transport.send(.vaultStatus)
            return try handle(response, for: .vault(command))
        case let .path(pathCommand):
            switch pathCommand {
            case .get:
                io.writeStdout(try configStore.getValue(for: .vaultDir) + "\n")
            case let .set(path):
                _ = try configStore.setValue(path, for: .vaultDir)
            }
            return EXIT_SUCCESS
        case .share:
            let response = try transport.send(.shareVault)
            return try handle(response, for: .vault(command))
        case let .join(manual):
            let response = try transport.send(.joinVault(manual: manual))
            return try handle(response, for: .vault(command))
        case let .approve(requestFile):
            let prepareResponse: KeyServiceResponse
            if let requestFile {
                let requestData = try Data(contentsOf: URL(fileURLWithPath: requestFile))
                prepareResponse = try transport.send(.prepareManualVaultApproval(requestData: requestData))
            } else {
                prepareResponse = try transport.send(.prepareNearbyVaultApproval)
            }

            let prepareExitCode = try handle(prepareResponse, for: .vault(command))
            guard prepareExitCode == EXIT_SUCCESS else {
                return prepareExitCode
            }
            guard let approvalInfo = prepareResponse.deviceApprovalInfo else {
                return EXIT_SUCCESS
            }

            guard io.stdinIsTTY else {
                throw AppError.operationRefused("Vault approval requires an interactive terminal so you can confirm the verification code.")
            }

            let enteredCode = try io.readLine(
                prompt: "Approve device '\(approvalInfo.deviceName)' (\(approvalInfo.deviceID)) by typing code \(approvalInfo.verificationCode): "
            ).trimmingCharacters(in: .whitespacesAndNewlines)
            let confirmResponse = try transport.send(.confirmVaultApproval(verificationCode: enteredCode))
            return try handle(confirmResponse, for: .vault(command))
        case .sync:
            let response = try transport.send(.syncVault)
            return try handle(response, for: .vault(command))
        case .leave:
            let response = try transport.send(.leaveVault)
            return try handle(response, for: .vault(command))
        case .unshare:
            let response = try transport.send(.unshareVault)
            return try handle(response, for: .vault(command))
        }
    }
}
