import Foundation
@testable import KeyCore

final class MemoryVaultKeyStore: VaultKeyStoring {
    var localKeyData: Data?
    var enclaveKeyData: Data?
    var enclaveDevices: [EnclaveDeviceRecord] = []
    var syncMessage = "Device is authorized.\n"
    var leaveMessage = "This Mac has left the shared vault.\n"
    var removeArtifactsMessage: String?
    var nextApprovalInfo = DeviceApprovalInfo(deviceName: "Nearby Mac", deviceID: "device-123", verificationCode: "123456")
    var error: Error?
    var loadCount = 0
    var invalidateCount = 0
    var statusReport: VaultStatusReport?
    private(set) var requests: [(mode: SecurityMode, reason: String, createIfMissing: Bool)] = []
    private(set) var registeredModes: [Bool] = []
    private(set) var approvedVerificationCodes: [String] = []
    private(set) var migratedVaultURLs: [URL] = []
    private(set) var leftVaultURLs: [URL] = []
    private(set) var removedArtifactVaultURLs: [URL] = []

    var keyData: Data? {
        get { localKeyData }
        set { localKeyData = newValue }
    }

    func loadKey(mode: SecurityMode, vaultRootURL: URL, reason: String, createIfMissing: Bool) throws -> Data {
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
        case .enclave:
            if let enclaveKeyData {
                return enclaveKeyData
            }
        }
        guard createIfMissing else {
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
        let generated = Data((0..<32).map(UInt8.init))
        switch mode {
        case .local:
            localKeyData = generated
        case .enclave:
            enclaveKeyData = generated
        }
        return generated
    }

    func keyExists(mode: SecurityMode, vaultRootURL: URL) throws -> Bool {
        if let error {
            throw error
        }
        switch mode {
        case .local:
            return localKeyData != nil
        case .enclave:
            return enclaveKeyData != nil
        }
    }

    func storeKey(_ keyData: Data, mode: SecurityMode, overwriteExisting: Bool) throws {
        if let error {
            throw error
        }

        switch mode {
        case .local:
            if !overwriteExisting, localKeyData != nil {
                throw AppError.keychain("Failed to store vault key in Keychain (\(errSecDuplicateItem)).")
            }
            localKeyData = keyData
        case .enclave:
            throw AppError.operationRefused("Raw vault keys are not stored directly in enclave mode.")
        }
    }

    func deleteKey(mode: SecurityMode) throws {
        if let error {
            throw error
        }
        switch mode {
        case .local:
            localKeyData = nil
        case .enclave:
            enclaveKeyData = nil
        }
    }

    func inspectVault(vaultRootURL: URL, securityMode: SecurityMode, hasEncryptedEntries: Bool) throws -> VaultStatusReport {
        if let error {
            throw error
        }
        if let statusReport {
            return statusReport
        }
        return VaultStatusReport(
            vaultRootPath: vaultRootURL.path(percentEncoded: false),
            isICloudBacked: false,
            securityMode: securityMode,
            hasEncryptedEntries: hasEncryptedEntries,
            metadataExists: securityMode == .enclave,
            deviceID: securityMode == .enclave ? "device-123" : nil,
            accessState: securityMode == .enclave ? .enclaveReady : .localReady,
            detail: securityMode == .enclave ? "Shared vault is ready." : "Local vault is ready."
        )
    }

    func migrateLocalVaultToEnclave(vaultRootURL: URL, reason: String) throws {
        if let error {
            throw error
        }
        migratedVaultURLs.append(vaultRootURL)
        if let localKeyData {
            enclaveKeyData = localKeyData
            self.localKeyData = nil
        } else if enclaveKeyData == nil {
            enclaveKeyData = Data((0..<32).map(UInt8.init))
        }
        if enclaveDevices.isEmpty {
            enclaveDevices = [
                EnclaveDeviceRecord(
                    deviceID: "device-123",
                    deviceName: "Test Mac",
                    publicKey: Data("public".utf8).base64EncodedString(),
                    addedAt: Date(timeIntervalSince1970: 0),
                    status: "authorized"
                )
            ]
        }
    }

    func registerDevice(vaultRootURL: URL, manual: Bool) throws -> DeviceRegistrationResult {
        if let error {
            throw error
        }
        registeredModes.append(manual)
        return DeviceRegistrationResult(message: manual ? "Wrote enrollment request.\n" : "Advertising enrollment request.\n")
    }

    func prepareNearbyDeviceApproval(vaultRootURL: URL) throws -> DeviceApprovalInfo {
        if let error {
            throw error
        }
        return nextApprovalInfo
    }

    func prepareManualDeviceApproval(vaultRootURL: URL, requestData: Data) throws -> DeviceApprovalInfo {
        if let error {
            throw error
        }
        return nextApprovalInfo
    }

    func confirmDeviceApproval(vaultRootURL: URL, verificationCode: String) throws {
        if let error {
            throw error
        }
        approvedVerificationCodes.append(verificationCode)
    }

    func syncDevice(vaultRootURL: URL) throws -> String {
        if let error {
            throw error
        }
        return syncMessage
    }

    func leaveEnclaveVault(vaultRootURL: URL, reason: String) throws -> String {
        if let error {
            throw error
        }
        leftVaultURLs.append(vaultRootURL)
        return leaveMessage
    }

    func removeEnclaveArtifacts(vaultRootURL: URL) throws -> String? {
        if let error {
            throw error
        }
        removedArtifactVaultURLs.append(vaultRootURL)
        return removeArtifactsMessage
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
