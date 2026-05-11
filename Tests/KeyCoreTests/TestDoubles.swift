import Foundation
@testable import KeyCore

final class MemoryVaultKeyStore: VaultKeyStoring {
    var localKeyData: Data?
    var iCloudKeyData: Data?
    var error: Error?
    var loadCount = 0
    var invalidateCount = 0
    private(set) var requests: [(mode: KeychainMode, reason: String, createIfMissing: Bool)] = []

    var keyData: Data? {
        get { localKeyData }
        set { localKeyData = newValue }
    }

    func loadKey(mode: KeychainMode, reason: String, createIfMissing: Bool) throws -> Data {
        loadCount += 1
        requests.append((mode, reason, createIfMissing))
        if let error {
            throw error
        }
        switch mode {
        case .local:
            if let localKeyData {
                return localKeyData
            }
        case .icloud:
            if let iCloudKeyData {
                return iCloudKeyData
            }
        }
        guard createIfMissing else {
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
        let generated = Data((0..<32).map(UInt8.init))
        switch mode {
        case .local:
            localKeyData = generated
        case .icloud:
            iCloudKeyData = generated
        }
        return generated
    }

    func keyExists(mode: KeychainMode) throws -> Bool {
        if let error {
            throw error
        }
        switch mode {
        case .local:
            return localKeyData != nil
        case .icloud:
            return iCloudKeyData != nil
        }
    }

    func storeKey(_ keyData: Data, mode: KeychainMode, overwriteExisting: Bool) throws {
        if let error {
            throw error
        }

        switch mode {
        case .local:
            if !overwriteExisting, localKeyData != nil {
                throw AppError.keychain("Failed to store vault key in Keychain (\(errSecDuplicateItem)).")
            }
            localKeyData = keyData
        case .icloud:
            if !overwriteExisting, iCloudKeyData != nil {
                throw AppError.keychain("Failed to store vault key in Keychain (\(errSecDuplicateItem)).")
            }
            iCloudKeyData = keyData
        }
    }

    func invalidate() {
        invalidateCount += 1
    }
}

final class MemoryIO: InputOutput {
    let stdinIsTTY: Bool
    let stdoutIsTTY: Bool
    var pipedInput: String
    var lineInput: String
    var secureInput: String
    private(set) var stdout = ""
    private(set) var stderr = ""

    init(
        stdinIsTTY: Bool,
        stdoutIsTTY: Bool? = nil,
        pipedInput: String = "",
        lineInput: String = "",
        secureInput: String = ""
    ) {
        self.stdinIsTTY = stdinIsTTY
        self.stdoutIsTTY = stdoutIsTTY ?? stdinIsTTY
        self.pipedInput = pipedInput
        self.lineInput = lineInput
        self.secureInput = secureInput
    }

    func readPipedInput() throws -> String {
        pipedInput
    }

    func readLine(prompt: String) throws -> String {
        stderr += prompt
        return lineInput
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
