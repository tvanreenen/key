import Foundation

public enum SecretEntryType:
    String,
    Codable,
    Equatable,
    Hashable,
    Sendable
{
    case secret
    case totp
}
