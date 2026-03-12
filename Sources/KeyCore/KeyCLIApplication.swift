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
        case let .add(name, mode):
            switch mode {
            case .manual:
                let secret = try readSecretFromInput()
                response = try transport.send(.addManual(name: name, secret: secret))
            case let .generated(length, revealMode):
                response = try transport.send(
                    .addGenerated(name: name, length: length, revealMode: revealMode)
                )
            }

            let exitCode = try handle(response, for: command)
            guard exitCode == EXIT_SUCCESS else {
                return exitCode
            }

            if case let .add(_, .generated(_, revealMode)) = command,
               let value = response.value {
                switch revealMode {
                case .none:
                    break
                case .show:
                    io.writeStdout(value)
                case .copy:
                    try clipboard.copy(value)
                }
            }

            return EXIT_SUCCESS
        case let .edit(name, mode):
            switch mode {
            case .manual:
                let secret = try readSecretFromInput()
                response = try transport.send(.editManual(name: name, secret: secret))
            case let .generated(length, revealMode):
                response = try transport.send(
                    .editGenerated(name: name, length: length, revealMode: revealMode)
                )
            }

            let exitCode = try handle(response, for: command)
            guard exitCode == EXIT_SUCCESS else {
                return exitCode
            }

            if case let .edit(_, .generated(_, revealMode)) = command,
               let value = response.value {
                switch revealMode {
                case .none:
                    break
                case .show:
                    io.writeStdout(value)
                case .copy:
                    try clipboard.copy(value)
                }
            }

            return EXIT_SUCCESS
        case let .copy(source, destination, force):
            response = try transport.send(.copyEntry(source: source, destination: destination, force: force))
            return try handle(response, for: command)
        case let .move(source, destination, force):
            response = try transport.send(.moveEntry(source: source, destination: destination, force: force))
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
        case .add, .edit, .copy, .move:
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
}
