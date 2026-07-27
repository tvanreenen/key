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

public enum Command: Equatable {
    case help
    case version(json: Bool)
    case config(ConfigCommand)
    case migrationPreflight
    case unlock
    case lock
    case get(name: String)
    case copy(name: String)
    case add(name: String, type: SecretEntryType)
    case edit(name: String, type: SecretEntryType)
    case duplicate(source: String, destination: String, force: Bool)
    case rename(source: String, destination: String, force: Bool)
    case remove(name: String, force: Bool)
    case list
}
