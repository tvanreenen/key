import Foundation

public enum KeyServiceRequest: Codable, Equatable {
    case unlock
    case lock
    case status
    case list
    case get(name: String)
    case addManual(name: String, secret: String)
    case editManual(name: String, secret: String)
    case copyEntry(source: String, destination: String, force: Bool)
    case moveEntry(source: String, destination: String, force: Bool)
    case removeEntry(name: String)

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case source
        case destination
        case secret
        case force
    }

    private enum Kind: String, Codable {
        case unlock
        case lock
        case status
        case list
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
        case .get:
            self = .get(name: try container.decode(String.self, forKey: .name))
        case .addManual:
            self = .addManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret)
            )
        case .editManual:
            self = .editManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret)
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
        case let .get(name):
            try container.encode(Kind.get, forKey: .kind)
            try container.encode(name, forKey: .name)
        case let .addManual(name, secret):
            try container.encode(Kind.addManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
        case let .editManual(name, secret):
            try container.encode(Kind.editManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
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
