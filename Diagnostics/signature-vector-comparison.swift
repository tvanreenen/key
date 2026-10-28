import CryptoKit
import Foundation
import Security

let entries = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [[String: String]]
var failures = 0
for entry in entries {
    func bytes(_ name: String) -> Data { Data(base64Encoded: entry[name]!)! }
    let keyBytes = bytes("verifiedPublicKey")
    let input = bytes("verifiedInput")
    let raw = bytes("verifiedSignature")
    let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
    let digest = SHA256.hash(data: input)
    let digestBytes = Data(digest)
    var changed = input
    changed[changed.startIndex] ^= 1
    var error: Unmanaged<CFError>?
    guard let securityKey = SecKeyCreateWithData(keyBytes as CFData, [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits: 256,
    ] as CFDictionary, &error) else { fatalError("Public key import failed: \(String(describing: error))") }
    var passes: [String: Int] = [:]
    let count = 1024
    for _ in 0 ..< count {
        let key = try P256.Signing.PublicKey(x963Representation: keyBytes)
        let copied = Data(Array(input))
        let checks: [(String, Bool)] = [
            ("CryptoKit data", key.isValidSignature(signature, for: input)),
            ("CryptoKit copied data", key.isValidSignature(signature, for: copied)),
            ("CryptoKit SHA256 digest", key.isValidSignature(signature, for: digest)),
            ("CryptoKit DER roundtrip", key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: signature.derRepresentation), for: input)),
            ("Public key roundtrip", key.x963Representation == keyBytes),
            ("Security message SHA256", SecKeyVerifySignature(securityKey, .ecdsaSignatureMessageX962SHA256, input as CFData, signature.derRepresentation as CFData, nil)),
            ("Security digest SHA256", SecKeyVerifySignature(securityKey, .ecdsaSignatureDigestX962SHA256, digestBytes as CFData, signature.derRepresentation as CFData, nil)),
            ("Reject changed message (CryptoKit)", !key.isValidSignature(signature, for: changed)),
            ("Reject changed message (Security)", !SecKeyVerifySignature(securityKey, .ecdsaSignatureMessageX962SHA256, changed as CFData, signature.derRepresentation as CFData, nil)),
        ]
        for (name, passed) in checks {
            passes[name, default: 0] += passed ? 1 : 0
            if !passed { failures += 1 }
        }
    }
    let report: [String: Any] = ["repetitions": count, "passes": passes]
    let encoded = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted])
    print(String(decoding: encoded, as: UTF8.self))
}
if failures > 0 { exit(1) }
