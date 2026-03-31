import CryptoKit
import Foundation

/// Minimal TOTP implementation for Key's current scope.
///
/// Behavior follows RFC 6238 using the RFC 4226 dynamic truncation step:
/// Base32 seed -> HMAC-SHA1(counter) -> 6-digit code with a 30 second period.
///
/// We intentionally keep this implementation local for now instead of pulling in
/// a dependency such as SwiftOTP. For the current feature set that keeps the CLI
/// small, easy to audit, and free of extra package/transitive dependency surface.
/// If OTP support grows beyond manual Base32 seeds and fixed SHA1/6-digit/30s
/// defaults, re-evaluate replacing this with a small trusted library.
public enum TOTPGenerator {
    public static let defaultDigits = 6
    public static let defaultPeriod: TimeInterval = 30

    public static func normalizeBase32Seed(_ seed: String) throws -> String {
        let trimmed = seed.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalized = trimmed
            .replacingOccurrences(of: " ", with: "")
            .uppercased()

        guard !normalized.isEmpty else {
            throw AppError.invalidSecret("TOTP seed must not be empty.")
        }

        _ = try decodeBase32Seed(normalized)
        return normalized
    }

    public static func generateCode(
        fromBase32Seed seed: String,
        at date: Date,
        digits: Int = defaultDigits,
        period: TimeInterval = defaultPeriod
    ) throws -> String {
        let key = try decodeBase32Seed(seed)
        let counter = UInt64(floor(date.timeIntervalSince1970 / period))
        return generateCode(
            key: key,
            counter: counter,
            digits: digits
        )
    }

    private static func generateCode(
        key: Data,
        counter: UInt64,
        digits: Int
    ) -> String {
        // RFC 4226 dynamic truncation over the HMAC result.
        var bigEndianCounter = counter.bigEndian
        let counterData = Data(bytes: &bigEndianCounter, count: MemoryLayout<UInt64>.size)
        let key = SymmetricKey(data: key)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key)
        let hash = Array(hmac)

        let offset = Int(hash[hash.count - 1] & 0x0f)
        let binary = (UInt32(hash[offset] & 0x7f) << 24)
            | (UInt32(hash[offset + 1]) << 16)
            | (UInt32(hash[offset + 2]) << 8)
            | UInt32(hash[offset + 3])
        let modulus = UInt32(pow(10, Double(digits)))
        let code = binary % modulus

        return String(format: "%0*u", digits, code)
    }

    private static func decodeBase32Seed(_ seed: String) throws -> Data {
        let alphabet: [Character: UInt8] = [
            "A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6, "H": 7,
            "I": 8, "J": 9, "K": 10, "L": 11, "M": 12, "N": 13, "O": 14, "P": 15,
            "Q": 16, "R": 17, "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23,
            "Y": 24, "Z": 25, "2": 26, "3": 27, "4": 28, "5": 29, "6": 30, "7": 31
        ]

        var output = Data()
        var buffer: UInt32 = 0
        var bitsLeft = 0

        for character in seed {
            if character == "=" {
                break
            }

            guard let value = alphabet[character] else {
                throw AppError.invalidSecret("TOTP seed must be valid Base32.")
            }

            buffer = (buffer << 5) | UInt32(value)
            bitsLeft += 5

            while bitsLeft >= 8 {
                let byte = UInt8((buffer >> UInt32(bitsLeft - 8)) & 0xff)
                output.append(byte)
                bitsLeft -= 8
            }
        }

        guard !output.isEmpty else {
            throw AppError.invalidSecret("TOTP seed must be valid Base32.")
        }

        return output
    }
}
