import CryptoKit
import Foundation
import Security

@main
struct SignatureKeyPatternDiagnostic {
    static func main() throws {
        let expected = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [String: String]
        func bytes(_ name: String) -> Data { Data(base64Encoded: expected[name]!)! }
        let input = bytes("input")
        let publicKey = try P256.Signing.PublicKey(x963Representation: bytes("publicKey"))
        let raw = try P256.Signing.ECDSASignature(rawRepresentation: bytes("signatureRaw"))
        let opposite = try P256.Signing.ECDSASignature(rawRepresentation: bytes("oppositeSignatureRaw"))
        var changed = input
        changed[changed.startIndex] ^= 1
        let captured: [String: Bool] = [
            "originalSignatureValid": publicKey.isValidSignature(raw, for: input),
            "oppositeSValid": publicKey.isValidSignature(opposite, for: input),
            "originalRejectsChangedMessage": !publicKey.isValidSignature(raw, for: changed),
            "oppositeRejectsChangedMessage": !publicKey.isValidSignature(opposite, for: changed),
        ]
        var patterns: [(String, Data)] = [0x11, 0x21, 0x31, 0x41].map { value in
            var key = Data(repeating: 0, count: 32)
            key[31] = UInt8(value)
            return (String(format: "small-fixture-%02x", value), key)
        }
        for seed: UInt8 in [1, 3, 0x11, 0x21, 0x31, 0x41] {
            let key = Data(SHA256.hash(data: Data([seed])))
            patterns.append((String(format: "fixture-seed-%02x", seed), key))
        }
        var reports: [[String: Any]] = []
        for (name, material) in patterns {
            let count = name.hasPrefix("fixture-seed-") ? 2048 : 256
            let signer = try P256.Signing.PrivateKey(rawRepresentation: material)
            var rawRejected = 0
            var canonicalRejected = 0
            var generatedObjectRejected = 0
            var sample: [String: String] = [:]
            for _ in 0 ..< count {
                let generated = try signer.signature(for: input)
                let rawBytes = generated.rawRepresentation
                let rawValue = try P256.Signing.ECDSASignature(rawRepresentation: rawBytes)
                let canonical = try V3P256Signature.canonicalize(rawBytes)
                let canonicalValue = try P256.Signing.ECDSASignature(rawRepresentation: canonical)
                let key = try P256.Signing.PublicKey(x963Representation: signer.publicKey.x963Representation)
                let rawValid = key.isValidSignature(rawValue, for: input)
                let canonicalValid = key.isValidSignature(canonicalValue, for: input)
                if !rawValid { rawRejected += 1 }
                if !canonicalValid { canonicalRejected += 1 }
                if !signer.publicKey.isValidSignature(generated, for: input) { generatedObjectRejected += 1 }
                if (!rawValid || !canonicalValid) && sample.isEmpty {
                    sample = ["publicKey": key.x963Representation.base64EncodedString(),
                              "input": input.base64EncodedString(),
                              "rawSignature": rawBytes.base64EncodedString(),
                              "canonicalSignature": canonical.base64EncodedString()]
                }
            }
            reports.append(["keyPattern": name, "repetitions": count,
                            "rawRejected": rawRejected, "canonicalRejected": canonicalRejected,
                            "generatedObjectRejected": generatedObjectRejected, "firstPublicFailure": sample])
        }
        let report: [String: Any] = ["capturedVector": captured, "patterns": reports]
        let encoded = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted])
        print(String(decoding: encoded, as: UTF8.self))
        let proposed = reports.filter { ($0["keyPattern"] as! String).hasPrefix("fixture-seed-") }
        guard proposed.count == 6 else { exit(2) }
        let rejected = proposed.contains {
            ($0["canonicalRejected"] as! Int) > 0 || ($0["rawRejected"] as! Int) > 0 || ($0["generatedObjectRejected"] as! Int) > 0
        }
        // Small-key controls retain the reproducer; success checks the proposed fixtures.
        if rejected || !captured["originalRejectsChangedMessage"]! || !captured["oppositeRejectsChangedMessage"]! { exit(1) }
    }
}
