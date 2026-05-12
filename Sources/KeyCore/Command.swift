import Foundation

public enum ConfigKey: String, Equatable, Sendable {
    case vaultDir = "vault-dir"
    case securityMode = "security-mode"
}

public enum SecurityMode: String, Codable, Equatable, Sendable, CaseIterable {
    case local
    case enclave
}

public enum VaultPathCommand: Equatable, Sendable {
    case get
    case set(String)
}

public enum VaultCommand: Equatable, Sendable {
    case status
    case path(VaultPathCommand)
    case share
    case join(manual: Bool)
    case approve(requestFile: String?)
    case sync
    case leave
    case unshare
}

public enum Command: Equatable {
    case help
    case version(json: Bool)
    case vault(VaultCommand)
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
