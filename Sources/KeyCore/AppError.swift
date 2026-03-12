import Foundation

public enum AppError: Error, LocalizedError, Equatable {
    case usage(String)
    case invalidEntryName(String)
    case invalidLength(String)
    case entryExists(String)
    case entryNotFound(String)
    case invalidSecretFile(String)
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
            let .invalidLength(message),
            let .entryExists(message),
            let .entryNotFound(message),
            let .invalidSecretFile(message),
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
}
