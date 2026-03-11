import Foundation

public struct SecretFile: Codable, Equatable {
    public let version: Int
    public let alg: String
    public let nonce: String
    public let ciphertext: String

    public init(version: Int = 1, alg: String = "AES.GCM", nonce: String, ciphertext: String) {
        self.version = version
        self.alg = alg
        self.nonce = nonce
        self.ciphertext = ciphertext
    }

    public var nonceData: Data? {
        Data(base64Encoded: nonce)
    }

    public var ciphertextData: Data? {
        Data(base64Encoded: ciphertext)
    }
}
