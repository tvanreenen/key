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
    case addManual(name: String, secret: String)
    case addGenerated(name: String, length: Int, revealMode: RevealMode)
    case editManual(name: String, secret: String)
    case editGenerated(name: String, length: Int, revealMode: RevealMode)
    case copyEntry(source: String, destination: String, force: Bool)

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case source
        case destination
        case secret
        case force
        case length
        case revealMode
    }

    private enum Kind: String, Codable {
        case list
        case get
        case addManual
        case addGenerated
        case editManual
        case editGenerated
        case copyEntry
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .list:
            self = .list
        case .get:
            self = .get(name: try container.decode(String.self, forKey: .name))
        case .addManual:
            self = .addManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret)
            )
        case .addGenerated:
            self = .addGenerated(
                name: try container.decode(String.self, forKey: .name),
                length: try container.decode(Int.self, forKey: .length),
                revealMode: try container.decode(RevealMode.self, forKey: .revealMode)
            )
        case .editManual:
            self = .editManual(
                name: try container.decode(String.self, forKey: .name),
                secret: try container.decode(String.self, forKey: .secret)
            )
        case .editGenerated:
            self = .editGenerated(
                name: try container.decode(String.self, forKey: .name),
                length: try container.decode(Int.self, forKey: .length),
                revealMode: try container.decode(RevealMode.self, forKey: .revealMode)
            )
        case .copyEntry:
            self = .copyEntry(
                source: try container.decode(String.self, forKey: .source),
                destination: try container.decode(String.self, forKey: .destination),
                force: try container.decode(Bool.self, forKey: .force)
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
        case let .addManual(name, secret):
            try container.encode(Kind.addManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
        case let .addGenerated(name, length, revealMode):
            try container.encode(Kind.addGenerated, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(length, forKey: .length)
            try container.encode(revealMode, forKey: .revealMode)
        case let .editManual(name, secret):
            try container.encode(Kind.editManual, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(secret, forKey: .secret)
        case let .editGenerated(name, length, revealMode):
            try container.encode(Kind.editGenerated, forKey: .kind)
            try container.encode(name, forKey: .name)
            try container.encode(length, forKey: .length)
            try container.encode(revealMode, forKey: .revealMode)
        case let .copyEntry(source, destination, force):
            try container.encode(Kind.copyEntry, forKey: .kind)
            try container.encode(source, forKey: .source)
            try container.encode(destination, forKey: .destination)
            try container.encode(force, forKey: .force)
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
