import Foundation

public enum KeyServiceRequest: Codable, Equatable {
    case unlock
    case lock
    case status
    case vaultStatus
    case listConflicts
    case showConflict(id: String)
    case getConflictValue(id: String, versionID: String)
    case resolveConflicts([VaultConflictResolution])
    case list
    case migrationPreflight
    case setVaultDirectory(path: String)
    case setKeychainMode(KeychainMode)
    case get(name: String, allowStale: Bool)
    case addManual(name: String, secret: String, type: SecretEntryType)
    case editManual(name: String, secret: String, type: SecretEntryType)
    case copyEntry(source: String, destination: String, force: Bool)
    case moveEntry(source: String, destination: String, force: Bool)
    case removeEntry(name: String)

    public var responseTimeoutSeconds: Int? {
        switch self {
        case .status, .lock:
            5
        case .vaultStatus, .listConflicts, .showConflict:
            30
        case .unlock, .get, .getConflictValue, .migrationPreflight:
            120
        case .list:
            30
        case .setVaultDirectory, .setKeychainMode, .addManual, .editManual,
            .copyEntry, .moveEntry, .removeEntry, .resolveConflicts:
            nil
        }
    }

    /// Whether the XPC client must complete the post-reply shutdown handshake.
    public var requiresHelperShutdownAfterSuccess: Bool {
        switch self {
        case .lock, .setVaultDirectory:
            true
        default:
            false
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
        case vaultDirectory
        case keychainMode
        case allowStale
        case conflictID
        case versionID
        case resolutions
    }

    private enum Kind: String, Codable {
        case unlock
        case lock
        case status
        case vaultStatus
        case listConflicts
        case showConflict
        case getConflictValue
        case resolveConflicts
        case list
        case migrationPreflight
        case setVaultDirectory
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
        case .vaultStatus:
            self = .vaultStatus
        case .listConflicts:
            self = .listConflicts
        case .showConflict:
            self = .showConflict(
                id: try container.decode(String.self, forKey: .conflictID)
            )
        case .getConflictValue:
            self = .getConflictValue(
                id: try container.decode(String.self, forKey: .conflictID),
                versionID: try container.decode(
                    String.self,
                    forKey: .versionID
                )
            )
        case .resolveConflicts:
            self = .resolveConflicts(
                try container.decode(
                    [VaultConflictResolution].self,
                    forKey: .resolutions
                )
            )
        case .list:
            self = .list
        case .migrationPreflight:
            self = .migrationPreflight
        case .setVaultDirectory:
            self = .setVaultDirectory(
                path: try container.decode(
                    String.self,
                    forKey: .vaultDirectory
                )
            )
        case .setKeychainMode:
            self = .setKeychainMode(try container.decode(KeychainMode.self, forKey: .keychainMode))
        case .get:
            self = .get(
                name: try container.decode(String.self, forKey: .name),
                allowStale: try container.decodeIfPresent(
                    Bool.self,
                    forKey: .allowStale
                ) ?? false
            )
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
        case .vaultStatus:
            try container.encode(Kind.vaultStatus, forKey: .kind)
        case .listConflicts:
            try container.encode(Kind.listConflicts, forKey: .kind)
        case let .showConflict(id):
            try container.encode(Kind.showConflict, forKey: .kind)
            try container.encode(id, forKey: .conflictID)
        case let .getConflictValue(id, versionID):
            try container.encode(Kind.getConflictValue, forKey: .kind)
            try container.encode(id, forKey: .conflictID)
            try container.encode(versionID, forKey: .versionID)
        case let .resolveConflicts(resolutions):
            try container.encode(Kind.resolveConflicts, forKey: .kind)
            try container.encode(resolutions, forKey: .resolutions)
        case .list:
            try container.encode(Kind.list, forKey: .kind)
        case .migrationPreflight:
            try container.encode(Kind.migrationPreflight, forKey: .kind)
        case let .setVaultDirectory(path):
            try container.encode(Kind.setVaultDirectory, forKey: .kind)
            try container.encode(path, forKey: .vaultDirectory)
        case let .setKeychainMode(mode):
            try container.encode(Kind.setKeychainMode, forKey: .kind)
            try container.encode(mode, forKey: .keychainMode)
        case let .get(name, allowStale):
            try container.encode(Kind.get, forKey: .kind)
            try container.encode(name, forKey: .name)
            if allowStale {
                try container.encode(true, forKey: .allowStale)
            }
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

public extension KeyServiceRequest {
    static func get(name: String) -> KeyServiceRequest {
        .get(name: name, allowStale: false)
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
    public let errorCode: KeyServiceErrorCode?
    public let helperStatus: KeyHelperStatus?
    public let vaultStatus: VaultStatus?
    public let conflicts: [VaultConflictSummary]?
    public let conflict: VaultConflictDetail?

    public init(
        exitCode: Int32,
        value: String?,
        errorMessage: String?,
        errorCode: KeyServiceErrorCode? = nil,
        helperStatus: KeyHelperStatus? = nil,
        vaultStatus: VaultStatus? = nil,
        conflicts: [VaultConflictSummary]? = nil,
        conflict: VaultConflictDetail? = nil
    ) {
        self.exitCode = exitCode
        self.value = value
        self.errorMessage = errorMessage
        self.errorCode = errorCode
        self.helperStatus = helperStatus
        self.vaultStatus = vaultStatus
        self.conflicts = conflicts
        self.conflict = conflict
    }

    public static func success(
        _ value: String? = nil,
        helperStatus: KeyHelperStatus? = nil
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: EXIT_SUCCESS,
            value: value,
            errorMessage: nil,
            errorCode: nil,
            helperStatus: helperStatus
        )
    }

    public static func vaultStatus(
        _ status: VaultStatus
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: status.health.exitCode.rawValue,
            value: nil,
            errorMessage: nil,
            vaultStatus: status
        )
    }

    public static func conflicts(
        _ conflicts: [VaultConflictSummary]
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: EXIT_SUCCESS,
            value: nil,
            errorMessage: nil,
            conflicts: conflicts
        )
    }

    public static func conflict(
        _ conflict: VaultConflictDetail
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: EXIT_SUCCESS,
            value: nil,
            errorMessage: nil,
            conflict: conflict
        )
    }

    public static func failure(
        _ message: String,
        code: KeyServiceErrorCode = .serviceFailure
    ) -> KeyServiceResponse {
        KeyServiceResponse(
            exitCode: code.exitCode.rawValue,
            value: nil,
            errorMessage: message,
            errorCode: code
        )
    }

    static func failure(_ error: AppError) -> KeyServiceResponse {
        failure(
            error.localizedDescription,
            code: error.serviceErrorCode
        )
    }

    static func failure(_ error: VaultUXServiceError) -> KeyServiceResponse {
        let code: KeyServiceErrorCode
        switch error {
        case .vaultIncomplete:
            code = .vaultIncomplete
        case .contentConflict:
            code = .contentConflict
        case .securityConflict:
            code = .securityConflict
        case .rollbackDetected:
            code = .rollbackDetected
        case .recoveryRequired:
            code = .recoveryRequired
        case .conflictNotFound:
            code = .conflictNotFound
        case .conflictVersionNotFound:
            code = .conflictVersionNotFound
        case .expectedHeadsChanged:
            code = .expectedHeadsChanged
        case .unavailableForCurrentFormat:
            code = .operationRefused
        }
        return failure(error.localizedDescription, code: code)
    }
}

public protocol KeyServiceTransport {
    func send(_ request: KeyServiceRequest) throws -> KeyServiceResponse
}
