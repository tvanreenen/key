import Foundation

public enum KeyServiceRequest: Codable, Equatable {
    case unlock
    case lock
    case status
    case list
    case vaultStatus
    case shareVault
    case joinVault(manual: Bool)
    case prepareNearbyVaultApproval
    case prepareManualVaultApproval(requestData: Data)
    case confirmVaultApproval(verificationCode: String)
    case syncVault
    case leaveVault
    case unshareVault
    case get(name: String)
    case addManual(name: String, secret: String, type: SecretEntryType)
    case editManual(name: String, secret: String, type: SecretEntryType)
    case copyEntry(source: String, destination: String, force: Bool)
    case moveEntry(source: String, destination: String, force: Bool)
    case removeEntry(name: String)

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case source
        case destination
        case secret
        case type
        case force
        case manual
        case requestData
        case verificationCode
    }

    private enum Kind: String, Codable {
        case unlock
        case lock
        case status
        case list
        case vaultStatus
        case shareVault
        case joinVault
        case prepareNearbyVaultApproval
        case prepareManualVaultApproval
        case confirmVaultApproval
        case syncVault
        case leaveVault
        case unshareVault
        case get
        case addManual
        case editManual
        case copyEntry
        case moveEntry
        case removeEntry
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .unlock:
            self = .unlock
        case .lock:
            self = .lock
        case .status:
            self = .status
        case .list:
            self = .list
        case .vaultStatus:
            self = .vaultStatus
        case .shareVault:
            self = .shareVault
        case .joinVault:
            self = .joinVault(manual: try container.decode(Bool.self, forKey: .manual))
        case .prepareNearbyVaultApproval:
            self = .prepareNearbyVaultApproval
        case .prepareManualVaultApproval:
            self = .prepareManualVaultApproval(requestData: try container.decode(Data.self, forKey: .requestData))
        case .confirmVaultApproval:
            self = .confirmVaultApproval(verificationCode: try container.decode(String.self, forKey: .verificationCode))
        case .syncVault:
            self = .syncVault
        case .leaveVault:
            self = .leaveVault
        case .unshareVault:
            self = .unshareVault
        case .get:
            self = .get(name: try container.decode(String.self, forKey: .name))
        case .addManual:
            self = .addManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret),
                type: try container.decode(SecretEntryType.self, forKey: .type)
            )
        case .editManual:
            self = .editManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret),
                type: try container.decode(SecretEntryType.self, forKey: .type)
            )
        case .copyEntry:
            self = .copyEntry(
                source: try container.decode(String.self, forKey: .source),
                destination: try container.decode(String.self, forKey: .destination),
                force: try container.decode(Bool.self, forKey: .force)
            )
        case .moveEntry:
            self = .moveEntry(
                source: try container.decode(String.self, forKey: .source),
                destination: try container.decode(String.self, forKey: .destination),
                force: try container.decode(Bool.self, forKey: .force)
            )
        case .removeEntry:
            self = .removeEntry(name: try container.decode(String.self, forKey: .name))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .unlock:
            try container.encode(Kind.unlock, forKey: .kind)
        case .lock:
            try container.encode(Kind.lock, forKey: .kind)
        case .status:
            try container.encode(Kind.status, forKey: .kind)
        case .list:
            try container.encode(Kind.list, forKey: .kind)
        case .vaultStatus:
            try container.encode(Kind.vaultStatus, forKey: .kind)
        case .shareVault:
            try container.encode(Kind.shareVault, forKey: .kind)
        case let .joinVault(manual):
            try container.encode(Kind.joinVault, forKey: .kind)
            try container.encode(manual, forKey: .manual)
        case .prepareNearbyVaultApproval:
            try container.encode(Kind.prepareNearbyVaultApproval, forKey: .kind)
        case let .prepareManualVaultApproval(requestData):
            try container.encode(Kind.prepareManualVaultApproval, forKey: .kind)
            try container.encode(requestData, forKey: .requestData)
        case let .confirmVaultApproval(verificationCode):
            try container.encode(Kind.confirmVaultApproval, forKey: .kind)
            try container.encode(verificationCode, forKey: .verificationCode)
        case .syncVault:
            try container.encode(Kind.syncVault, forKey: .kind)
        case .leaveVault:
            try container.encode(Kind.leaveVault, forKey: .kind)
        case .unshareVault:
            try container.encode(Kind.unshareVault, forKey: .kind)
        case let .get(name):
            try container.encode(Kind.get, forKey: .kind)
            try container.encode(name, forKey: .name)
        case let .addManual(name, secret, type):
            try container.encode(Kind.addManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
            try container.encode(type, forKey: .type)
        case let .editManual(name, secret, type):
            try container.encode(Kind.editManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
            try container.encode(type, forKey: .type)
        case let .copyEntry(source, destination, force):
            try container.encode(Kind.copyEntry, forKey: .kind)
            try container.encode(source, forKey: .source)
            try container.encode(destination, forKey: .destination)
            try container.encode(force, forKey: .force)
        case let .moveEntry(source, destination, force):
            try container.encode(Kind.moveEntry, forKey: .kind)
            try container.encode(source, forKey: .source)
            try container.encode(destination, forKey: .destination)
            try container.encode(force, forKey: .force)
        case let .removeEntry(name):
            try container.encode(Kind.removeEntry, forKey: .kind)
            try container.encode(name, forKey: .name)
        }
    }
}

public struct DeviceApprovalInfo: Codable, Equatable, Sendable {
    public let deviceName: String
    public let deviceID: String
    public let verificationCode: String

    public init(deviceName: String, deviceID: String, verificationCode: String) {
        self.deviceName = deviceName
        self.deviceID = deviceID
        self.verificationCode = verificationCode
    }
}

public struct KeyServiceResponse: Codable, Equatable {
    public let exitCode: Int32
    public let value: String?
    public let errorMessage: String?
    public let helperStatus: KeyHelperStatus?
    public let deviceApprovalInfo: DeviceApprovalInfo?

    public init(
        exitCode: Int32,
        value: String?,
        errorMessage: String?,
        helperStatus: KeyHelperStatus? = nil,
        deviceApprovalInfo: DeviceApprovalInfo? = nil
    ) {
        self.exitCode = exitCode
        self.value = value
        self.errorMessage = errorMessage
        self.helperStatus = helperStatus
        self.deviceApprovalInfo = deviceApprovalInfo
    }

    public static func success(
        _ value: String? = nil,
        helperStatus: KeyHelperStatus? = nil,
        deviceApprovalInfo: DeviceApprovalInfo? = nil
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: EXIT_SUCCESS,
            value: value,
            errorMessage: nil,
            helperStatus: helperStatus,
            deviceApprovalInfo: deviceApprovalInfo
        )
    }

    public static func failure(_ message: String) -> KeyServiceResponse {
        KeyServiceResponse(exitCode: EXIT_FAILURE, value: nil, errorMessage: message, helperStatus: nil, deviceApprovalInfo: nil)
    }
}

public protocol KeyServiceTransport {
    func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse
}
