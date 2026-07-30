import Foundation

public enum AppError: Error, LocalizedError, Equatable {
    case usage(String)
    case invalidEntryName(String)
    case invalidSecret(String)
    case entryExists(String)
    case entryNotFound(String)
    case invalidSecretFile(String)
    case vaultKeyMismatch(String)
    case authUnavailable(String)
    case authFailed(String)
    case invalidConfiguration(String)
    case keychain(String)
    case io(String)
    case service(String)
    case operationRefused(String)

    public var errorDescription: String? {
        switch self {
        case let .usage(message),
            let .invalidEntryName(message),
            let .invalidSecret(message),
            let .entryExists(message),
            let .entryNotFound(message),
            let .invalidSecretFile(message),
            let .vaultKeyMismatch(message),
            let .authUnavailable(message),
            let .authFailed(message),
            let .invalidConfiguration(message),
            let .keychain(message),
            let .io(message),
            let .service(message),
            let .operationRefused(message):
            return message
        }
    }

    public var serviceErrorCode: KeyServiceErrorCode {
        switch self {
        case .usage:
            .invalidUsage
        case .invalidEntryName:
            .invalidEntryName
        case .invalidSecret:
            .invalidSecret
        case .entryExists:
            .entryExists
        case .entryNotFound:
            .entryNotFound
        case .invalidSecretFile:
            .invalidSecretFile
        case .vaultKeyMismatch:
            .vaultKeyMismatch
        case .authUnavailable:
            .authenticationUnavailable
        case .authFailed:
            .authenticationFailed
        case .invalidConfiguration:
            .invalidConfiguration
        case .keychain:
            .keychainFailure
        case .io:
            .ioFailure
        case .service:
            .serviceFailure
        case .operationRefused:
            .operationRefused
        }
    }

    public var exitCode: KeyExitCode {
        serviceErrorCode.exitCode
    }
}
