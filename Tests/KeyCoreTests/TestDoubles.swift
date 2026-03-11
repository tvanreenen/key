import Foundation
@testable import KeyCore

final class MemoryVaultKeyStore: VaultKeyStoring {
    var keyData: Data?
    var loadCount = 0

    func loadKey(reason: String, createIfMissing: Bool) throws -> Data {
        loadCount += 1
        if let keyData {
            return keyData
        }
        guard createIfMissing else {
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
        let generated = Data((0..<32).map(UInt8.init))
        keyData = generated
        return generated
    }
}

final class MemoryIO: InputOutput {
    let stdinIsTTY: Bool
    var pipedInput: String
    var secureInput: String
    private(set) var stdout = ""
    private(set) var stderr = ""

    init(stdinIsTTY: Bool, pipedInput: String = "", secureInput: String = "") {
        self.stdinIsTTY = stdinIsTTY
        self.pipedInput = pipedInput
        self.secureInput = secureInput
    }

    func readPipedInput() throws -> String {
        pipedInput
    }

    func readSecureLine(prompt: String) throws -> String {
        stderr += prompt
        return secureInput
    }

    func writeStdout(_ text: String) {
        stdout += text
    }

    func writeStderr(_ text: String) {
        stderr += text
    }
}

final class MemoryClipboard: ClipboardWriting {
    private(set) var copiedText: String?

    func copy(_ text: String) throws {
        copiedText = text
    }
}

final class MemoryTransport: KeyServiceTransport {
    private let handler: (KeyServiceRequest) throws -> KeyServiceResponse
    private(set) var requests: [KeyServiceRequest] = []

    init(handler: @escaping (KeyServiceRequest) throws -> KeyServiceResponse) {
        self.handler = handler
    }

    func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse {
        requests.append(request)
        return try handler(request)
    }
}
