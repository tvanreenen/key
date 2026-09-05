import Foundation

public enum ConfigKey: String, Equatable, Sendable {
    case vaultDir = "vault-dir"
    case keychainMode = "keychain-mode"
}

public enum KeychainMode: String, Codable, Equatable, Sendable, CaseIterable {
    case local
    case icloud
}

public enum ConfigCommand: Equatable, Sendable {
    case get(key: ConfigKey)
    case set(key: ConfigKey, value: String)
    case list
}

public enum ConflictCommand: Equatable, Sendable {
    case list(json: Bool)
    case show(id: String, json: Bool)
    case get(id: String, versionID: String)
    case copy(id: String, versionID: String)
    case resolve([VaultConflictResolution])
}

public enum ShareCommand: Equatable, Sendable {
    case devices(json: Bool)
    case revoke(deviceID: String)
    case invitations
    case invite(deviceName: String)
    case join(invitationID: String, deviceName: String)
    case requests(invitationID: String)
    case compare(
        vaultID: String,
        invitationID: String,
        joinRequestID: String?
    )
    case approve(
        vaultID: String,
        invitationID: String,
        comparisonCode: String
    )
    case accept(
        vaultID: String,
        invitationID: String,
        comparisonCode: String
    )
}

public enum Command: Equatable {
    case help
    case version(json: Bool)
    case config(ConfigCommand)
    case initializeVault(path: String?)
    case migrationPreflight
    case migrationApply
    case status(json: Bool, verbose: Bool)
    case conflict(ConflictCommand)
    case share(ShareCommand)
    case unlock
    case lock
    case get(name: String, allowStale: Bool)
    case copy(name: String, allowStale: Bool)
    case add(name: String, type: SecretEntryType)
    case edit(name: String, type: SecretEntryType)
    case duplicate(source: String, destination: String, force: Bool)
    case rename(source: String, destination: String, force: Bool)
    case remove(name: String, force: Bool)
    case list
}

public extension Command {
    static func get(name: String) -> Command {
        .get(name: name, allowStale: false)
    }

    static func copy(name: String) -> Command {
        .copy(name: name, allowStale: false)
    }
}
