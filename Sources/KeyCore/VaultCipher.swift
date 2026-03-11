import CryptoKit
import Foundation

public struct VaultCipher {
    public init() {}

    public func encrypt(_ plaintext: String, keyData: Data) throws -> SecretFile {
        let key = SymmetricKey(data: keyData)
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(Data(plaintext.utf8), using: key, nonce: nonce)
        let payload = sealedBox.ciphertext + sealedBox.tag
        return SecretFile(
            nonce: Data(nonce).base64EncodedString(),
            ciphertext: payload.base64EncodedString()
        )
    }

    public func decrypt(_ file: SecretFile, keyData: Data) throws -> String {
        guard file.version == 1, file.alg == "AES.GCM" else {
            throw AppError.invalidSecretFile("Unsupported secret file format.")
        }
        guard let nonceData = file.nonceData, let ciphertextData = file.ciphertextData else {
            throw AppError.invalidSecretFile("Secret file is not valid base64.")
        }
        guard ciphertextData.count >= 16 else {
            throw AppError.invalidSecretFile("Secret file ciphertext is invalid.")
        }

        let ciphertext = ciphertextData.dropLast(16)
        let tag = ciphertextData.suffix(16)

        let key = SymmetricKey(data: keyData)
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonceData),
            ciphertext: ciphertext,
            tag: tag
        )
        let plaintext = try AES.GCM.open(sealedBox, using: key)
        guard let decoded = String(data: plaintext, encoding: .utf8) else {
            throw AppError.invalidSecretFile("Decrypted secret is not valid UTF-8.")
        }

        return decoded
    }
}
