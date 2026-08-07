import Foundation

struct VaultReadValue: Equatable, Sendable {
    let type: SecretEntryType
    let plaintext: String
}

/// Supplies logical values from the storage format selected by the helper.
///
/// Implementations own the complete trust-to-read operation. Callers must not
/// authorize through this seam and then reopen storage independently.
protocol VaultReadServicing: Sendable {
    /// Opens and authenticates the selected vault without creating or
    /// repairing key material.
    func unlock() throws
    func read(name: String, allowStale: Bool) throws -> VaultReadValue
    func list(allowStale: Bool) throws -> [String]
}

/// Owns the lifecycle of the vault-key session selected by the helper.
///
/// Version 2 currently delegates this responsibility to `VaultKeyStoring`.
/// Permanent version 3 keeps its key only in a separate wrapper-backed memory
/// session, so the request handler needs this narrow format-neutral seam for
/// `key lock` and `key status`.
protocol VaultSessionServicing: KeySessionStatusReporting, Sendable {
    func lock()
}
