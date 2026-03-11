import Foundation

public enum RevealMode: String, Codable, Equatable, Sendable {
    case none
    case show
    case copy
}

public enum PutMode: Equatable {
    case manual
    case generated(length: Int, revealMode: RevealMode)
}

public enum KeyServiceRequest: Codable, Equatable {
    case list
    case get(name: String)
    case putManual(name: String, secret: String, force: Bool)
    case putGenerated(name: String, length: Int, force: Bool, revealMode: RevealMode)

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case secret
        case force
        case length
        case revealMode
    }

    private enum Kind: String, Codable {
        case list
        case get
        case putManual
        case putGenerated
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .list:
            self = .list
        case .get:
            self = .get(name: try container.decode(String.self, forKey: .name))
        case .putManual:
            self = .putManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret),
                force: try container.decode(Bool.self, forKey: .force)
            )
        case .putGenerated:
            self = .putGenerated(
                name: try container.decode(String.self, forKey: .name),
                length: try container.decode(Int.self, forKey: .length),
                force: try container.decode(Bool.self, forKey: .force),
                revealMode: try container.decode(RevealMode.self, forKey: .revealMode)
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .list:
            try container.encode(Kind.list, forKey: .kind)
        case let .get(name):
            try container.encode(Kind.get, forKey: .kind)
            try container.encode(name, forKey: .name)
        case let .putManual(name, secret, force):
            try container.encode(Kind.putManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
            try container.encode(force, forKey: .force)
        case let .putGenerated(name, length, force, revealMode):
            try container.encode(Kind.putGenerated, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(length, forKey: .length)
            try container.encode(force, forKey: .force)
            try container.encode(revealMode, forKey: .revealMode)
        }
    }
}

public struct KeyServiceResponse: Codable, Equatable {
    public let exitCode: Int32
    public let value: String?
    public let errorMessage: String?

    public init(exitCode: Int32, value: String?, errorMessage: String?) {
        self.exitCode = exitCode
        self.value = value
        self.errorMessage = errorMessage
    }

    public static func success(_ value: String? = nil) -> KeyServiceResponse {
        KeyServiceResponse(exitCode: EXIT_SUCCESS, value: value, errorMessage: nil)
    }

    public static func failure(_ message: String) -> KeyServiceResponse {
        KeyServiceResponse(exitCode: EXIT_FAILURE, value: nil, errorMessage: message)
    }
}

public protocol KeyServiceTransport {
    func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse
}
