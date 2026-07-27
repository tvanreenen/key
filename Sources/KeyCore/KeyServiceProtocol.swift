import Foundation

public enum KeyServiceRequest: Codable, Equatable {
    case unlock
    case lock
    case status
    case list
    case migrationPreflight
    case setKeychainMode(KeychainMode)
    case get(name: String)
    case addManual(name: String, secret: String, type: SecretEntryType)
    case editManual(name: String, secret: String, type: SecretEntryType)
    case copyEntry(source: String, destination: String, force: Bool)
    case moveEntry(source: String, destination: String, force: Bool)
    case removeEntry(name: String)

    public var responseTimeoutSeconds: Int? {
        switch self {
        case .status, .lock:
            5
        case .unlock, .get, .migrationPreflight:
            120
        case .list:
            30
        case .setKeychainMode, .addManual, .editManual, .copyEntry, .moveEntry, .removeEntry:
            nil
        }
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case source
        case destination
        case secret
        case type
        case force
        case keychainMode
    }

    private enum Kind: String, Codable {
        case unlock
        case lock
        case status
        case list
        case migrationPreflight
        case setKeychainMode
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
        case .migrationPreflight:
            self = .migrationPreflight
        case .setKeychainMode:
            self = .setKeychainMode(try container.decode(KeychainMode.self, forKey: .keychainMode))
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
        case .migrationPreflight:
            try container.encode(Kind.migrationPreflight, forKey: .kind)
        case let .setKeychainMode(mode):
            try container.encode(Kind.setKeychainMode, forKey: .kind)
            try container.encode(mode, forKey: .keychainMode)
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

public enum KeyXPCClientRole: String, Equatable, Sendable {
    case fullCLI
    case utilityStatus

    public func authorizes(_ request: KeyServiceRequest) -> Bool {
        switch self {
        case .fullCLI:
            true
        case .utilityStatus:
            request == .status || request == .lock
        }
    }
}

public enum KeyXPCCodeSigningPolicy: Equatable, Sendable {
    case development
    case production
}

public enum KeyXPCSecurityPolicy {
    public static let teamIdentifier = "9Q355KSV85"
    public static let cliSigningIdentifier = "work.tvr.key.cli"
    public static let utilityAppSigningIdentifier = "work.tvr.key.app"
    public static let helperSigningIdentifier = "work.tvr.key.xpc"

    public static func codeSigningRequirement(
        for role: KeyXPCClientRole,
        policy: KeyXPCCodeSigningPolicy
    ) -> String {
        let identifier = switch role {
        case .fullCLI:
            cliSigningIdentifier
        case .utilityStatus:
            utilityAppSigningIdentifier
        }

        return requirement(signingIdentifier: identifier, policy: policy)
    }

    public static func helperCodeSigningRequirement(policy: KeyXPCCodeSigningPolicy) -> String {
        requirement(signingIdentifier: helperSigningIdentifier, policy: policy)
    }

    private static func requirement(
        signingIdentifier: String,
        policy: KeyXPCCodeSigningPolicy
    ) -> String {
        let teamRequirement = """
        identifier "\(signingIdentifier)" and anchor apple generic and \
        certificate leaf[subject.OU] = "\(teamIdentifier)"
        """

        return switch policy {
        case .development:
            teamRequirement
        case .production:
            """
            \(teamRequirement) and \
            certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
            certificate leaf[field.1.2.840.113635.100.6.1.13] exists
            """
        }
    }
}

public struct KeyServiceResponse: Codable, Equatable {
    public let exitCode: Int32
    public let value: String?
    public let errorMessage: String?
    public let helperStatus: KeyHelperStatus?

    public init(
        exitCode: Int32,
        value: String?,
        errorMessage: String?,
        helperStatus: KeyHelperStatus? = nil
    ) {
        self.exitCode = exitCode
        self.value = value
        self.errorMessage = errorMessage
        self.helperStatus = helperStatus
    }

    public static func success(
        _ value: String? = nil,
        helperStatus: KeyHelperStatus? = nil
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: EXIT_SUCCESS,
            value: value,
            errorMessage: nil,
            helperStatus: helperStatus
        )
    }

    public static func failure(_ message: String) -> KeyServiceResponse {
        KeyServiceResponse(exitCode: EXIT_FAILURE, value: nil, errorMessage: message, helperStatus: nil)
    }
}

public protocol KeyServiceTransport {
    func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse
}
