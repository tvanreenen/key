import CryptoKit
import Foundation
import Security

let expected = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: String]
func bytes(_ name: String) -> Data { Data(base64Encoded: expected[name]!)! }
func hex(_ value: some Sequence<UInt8>) -> String { value.map { String(format: "%02x", $0) }.joined() }
let keyBytes = bytes("publicKey")
let input = bytes("input")
let raw = bytes("signatureRaw")
let independentDER = bytes("signatureDER")
let digestHex = expected["sha256Hex"]!
let expectedDigest = Data(stride(from: 0, to: digestHex.count, by: 2).map { offset in
    let start = digestHex.index(digestHex.startIndex, offsetBy: offset)
    return UInt8(digestHex[start ..< digestHex.index(start, offsetBy: 2)], radix: 16)!
})
let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
let independentSignature = try P256.Signing.ECDSASignature(derRepresentation: independentDER)
let digest = SHA256.hash(data: input)
var changed = input
changed[changed.startIndex] ^= 1
var error: Unmanaged<CFError>?
guard let securityKey = SecKeyCreateWithData(keyBytes as CFData, [
    kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeyClass: kSecAttrKeyClassPublic,
    kSecAttrKeySizeInBits: 256,
] as CFDictionary, &error) else { fatalError("Public key import failed: \(String(describing: error))") }
let external = SecKeyCopyExternalRepresentation(securityKey, &error) as Data?
var firstErrors: [String: String] = [:]
func securityVerify(_ name: String, _ algorithm: SecKeyAlgorithm, _ message: Data, _ der: Data) -> Bool {
    var failure: Unmanaged<CFError>?
    let valid = SecKeyVerifySignature(securityKey, algorithm, message as CFData, der as CFData, &failure)
    if let failure {
        let description = String(describing: failure.takeRetainedValue())
        if firstErrors[name] == nil { firstErrors[name] = description }
    }
    return valid
}
var passes: [String: Int] = [:]
let repetitions = 32
for _ in 0 ..< repetitions {
    let key = try P256.Signing.PublicKey(x963Representation: keyBytes)
    let checks: [(String, Bool)] = [
        ("SHA256 matches independent hash", hex(digest) == digestHex),
        ("DER matches independent encoding", signature.derRepresentation == independentDER),
        ("Independent DER raw roundtrip", independentSignature.rawRepresentation == raw),
        ("CryptoKit public key roundtrip", key.x963Representation == keyBytes),
        ("Security public key roundtrip", external == keyBytes),
        ("CryptoKit data", key.isValidSignature(signature, for: input)),
        ("CryptoKit digest", key.isValidSignature(signature, for: digest)),
        ("CryptoKit independent DER", key.isValidSignature(independentSignature, for: input)),
        ("Security Apple DER message", securityVerify("Apple DER message", .ecdsaSignatureMessageX962SHA256, input, signature.derRepresentation)),
        ("Security independent DER message", securityVerify("Independent DER message", .ecdsaSignatureMessageX962SHA256, input, independentDER)),
        ("Security independent digest and DER", securityVerify("Independent digest and DER", .ecdsaSignatureDigestX962SHA256, expectedDigest, independentDER)),
        ("Reject changed message (CryptoKit)", !key.isValidSignature(signature, for: changed)),
        ("Reject changed message (Security)", !securityVerify("Changed message", .ecdsaSignatureMessageX962SHA256, changed, independentDER)),
    ]
    for (name, valid) in checks { passes[name, default: 0] += valid ? 1 : 0 }
}
let report: [String: Any] = [
    "repetitions": repetitions,
    "passes": passes,
    "appleSHA256Hex": hex(digest),
    "referenceSHA256Hex": digestHex,
    "appleDER": signature.derRepresentation.base64EncodedString(),
    "referenceDER": independentDER.base64EncodedString(),
    "firstSecurityErrors": firstErrors,
]
let encoded = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted])
print(String(decoding: encoded, as: UTF8.self))
if passes.values.contains(where: { $0 != repetitions }) { exit(1) }
