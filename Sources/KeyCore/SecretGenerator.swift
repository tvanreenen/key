import Foundation
import Security

public struct SecretGenerator {
    public let alphabet: [UInt8]

    public init(alphabet: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") {
        self.alphabet = Array(alphabet.utf8)
    }

    public func generate(length: Int) throws -> String {
        guard length > 0 else {
            throw AppError.invalidLength("Length must be a positive integer.")
        }
        guard !alphabet.isEmpty else {
            throw AppError.invalidLength("Alphabet must not be empty.")
        }

        var randomBytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        guard status == errSecSuccess else {
            throw AppError.keychain("Failed to generate random bytes (\(status)).")
        }

        let scalars = randomBytes.map { alphabet[Int($0) % alphabet.count] }
        return String(decoding: scalars, as: UTF8.self)
    }
}
