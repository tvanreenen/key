import Foundation

public final class KeyCLIApplication {
    private let transport: KeyServiceTransport
    private let io: InputOutput
    private let clipboard: ClipboardWriting

    public init(
        transport: KeyServiceTransport,
        io: InputOutput,
        clipboard: ClipboardWriting
    ) {
        self.transport = transport
        self.io = io
        self.clipboard = clipboard
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
        case .list:
            response = try transport.send(.list)
            return try handle(response, for: command)
        case let .show(name, copy):
            response = try transport.send(.get(name: name))
            let exitCode = try handle(response, for: command)
            guard exitCode == EXIT_SUCCESS, copy, let value = response.value else {
                return exitCode
            }
            try clipboard.copy(value)
            return EXIT_SUCCESS
        case let .add(name):
            let secret = try readSecretFromInput()
            response = try transport.send(.addManual(name: name, secret: secret))
            return try handle(response, for: command)
        case let .edit(name):
            let secret = try readSecretFromInput()
            response = try transport.send(.editManual(name: name, secret: secret))
            return try handle(response, for: command)
        case let .copy(source, destination, force):
            response = try transport.send(.copyEntry(source: source, destination: destination, force: force))
            return try handle(response, for: command)
        case let .move(source, destination, force):
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
        case .list:
            if let value = response.value, !value.isEmpty {
                io.writeStdout(value)
            }
        case let .show(_, copy):
            if !copy, let value = response.value {
                io.writeStdout(value)
            }
        case .add, .edit, .copy, .move, .remove:
            break
        }

        return response.exitCode
    }

    private func readSecretFromInput() throws -> String {
        if io.stdinIsTTY {
            return try io.readSecureLine(prompt: "Secret: ")
        }
        return try io.readPipedInput()
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
}
