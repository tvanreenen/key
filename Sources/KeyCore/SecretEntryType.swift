import Foundation

public enum SecretEntryType: String, Codable, Equatable, Sendable {
    case secret
    case totp
}
