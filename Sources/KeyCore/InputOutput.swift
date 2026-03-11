import Darwin
import Foundation

public protocol InputOutput {
    var stdinIsTTY: Bool { get }
    func readPipedInput() throws -> String
    func readSecureLine(prompt: String) throws -> String
    func writeStdout(_ text: String)
    func writeStderr(_ text: String)
}

public final class SystemIO: InputOutput {
    public init() {}

    public var stdinIsTTY: Bool {
        isatty(STDIN_FILENO) == 1
    }

    public func readPipedInput() throws -> String {
        let data = FileHandle.standardInput.readDataToEndOfFile()
        guard let string = String(data: data, encoding: .utf8) else {
            throw AppError.io("Standard input is not valid UTF-8.")
        }
        return string
    }

    public func readSecureLine(prompt: String) throws -> String {
        writeStderr(prompt)

        guard let originalState = currentTerminalState() else {
            throw AppError.io("Unable to configure terminal for secure input.")
        }

        var hiddenState = originalState
        hiddenState.c_lflag &= ~UInt(ECHO)

        guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &hiddenState) == 0 else {
            throw AppError.io("Unable to disable terminal echo.")
        }

        defer {
            var restored = originalState
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &restored)
            writeStderr("\n")
        }

        guard let line = Swift.readLine(strippingNewline: true) else {
            throw AppError.io("No input received.")
        }

        return line
    }

    public func writeStdout(_ text: String) {
        if let data = text.data(using: .utf8) {
            try? FileHandle.standardOutput.write(contentsOf: data)
        }
    }

    public func writeStderr(_ text: String) {
        if let data = text.data(using: .utf8) {
            try? FileHandle.standardError.write(contentsOf: data)
        }
    }

    private func currentTerminalState() -> termios? {
        var state = termios()
        return tcgetattr(STDIN_FILENO, &state) == 0 ? state : nil
    }
}
