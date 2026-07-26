import Foundation

struct Device: Codable {
    let deviceID: String
    let deviceName: String
    let publicKey: String
    let addedAt: Date
    let status: String
}

struct WrappedKey: Codable {
    let deviceID: String
    let epoch: Int
    let algorithm: String
    let ciphertext: String
}

struct Metadata: Codable {
    let version: Int
    let securityMode: String
    let vaultID: String
    let epoch: Int
    let devices: [Device]
    let wrappedKeys: [WrappedKey]
}

enum ValidationError: Error {
    case missingActiveMembership
    case missingAuthenticatedManifest
    case ambiguousWrappedKey
}

// Faithful to the vulnerable selection predicate in loadEnclaveVaultKey.
func currentWrappedKeySelection(
    metadata: Metadata,
    deviceID: String
) -> WrappedKey? {
    metadata.wrappedKeys.first {
        $0.deviceID == deviceID && $0.epoch == metadata.epoch
    }
}

// A defensive structural precondition. Production code must additionally
// verify a cryptographic authenticator and locally pinned monotonic state.
func defensiveWrappedKeySelection(
    metadata: Metadata,
    rawObject: [String: Any],
    deviceID: String
) throws -> WrappedKey {
    guard rawObject["metadataMAC"] != nil else {
        throw ValidationError.missingAuthenticatedManifest
    }
    guard metadata.devices.contains(where: {
        $0.deviceID == deviceID && $0.status == "authorized"
    }) else {
        throw ValidationError.missingActiveMembership
    }
    let matches = metadata.wrappedKeys.filter {
        $0.deviceID == deviceID && $0.epoch == metadata.epoch
    }
    guard matches.count == 1, let match = matches.first else {
        throw ValidationError.ambiguousWrappedKey
    }
    return match
}

let fixtureURL = URL(fileURLWithPath: "inconsistent-metadata.json")
let data = try Data(contentsOf: fixtureURL)
let decoder = JSONDecoder()
decoder.dateDecodingStrategy = .iso8601
let metadata = try decoder.decode(Metadata.self, from: data)
let rawObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]
let targetDevice = "device-b"

print("[+] decoded metadata: vault=\(metadata.vaultID) epoch=\(metadata.epoch)")
print("[+] active device IDs: \(metadata.devices.map(\.deviceID).sorted())")
print("[+] metadata has authenticator: \(rawObject["metadataMAC"] != nil)")

if currentWrappedKeySelection(metadata: metadata, deviceID: targetDevice) != nil {
    print("[!] current selector accepts device-b's wrapped key without active membership")
} else {
    fatalError("fixture no longer reaches the current selection predicate")
}

do {
    _ = try defensiveWrappedKeySelection(
        metadata: metadata,
        rawObject: rawObject,
        deviceID: targetDevice
    )
    fatalError("defensive selector unexpectedly accepted inconsistent metadata")
} catch {
    print("[+] defensive selector rejected metadata: \(error)")
}
