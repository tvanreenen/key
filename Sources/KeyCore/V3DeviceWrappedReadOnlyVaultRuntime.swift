import CryptoKit
import Foundation

/// Read-only product adapter for the first permanent device-wrapped profile.
///
/// KEY-509 deliberately exposes only the exact device-local checkpoint.
/// Forward-history discovery and key transitions arrive with ENR-510, so this
/// type cannot accidentally interpret permanent manifests with the released
/// alpha graph model.
struct V3DeviceWrappedReadOnlyVaultRuntime:
    VaultReadServicing,
    VaultUXServicing,
    Sendable
{
    private let source: any V3ImmutableObjectReading
    private let unlockRuntime: V3DeviceWrappedVaultUnlockRuntime
    private let planner = V3AuthenticatedReadPlanner()
    private let contentValidator: V3DeviceWrappedCheckpointContentValidator

    init(
        rootHandle: VaultRootDirectoryHandle,
        unlockRuntime: V3DeviceWrappedVaultUnlockRuntime
    ) {
        self.init(
            source: V3FilesystemImmutableObjectSource(
                rootHandle: rootHandle
            ),
            unlockRuntime: unlockRuntime
        )
    }

    init(
        source: any V3ImmutableObjectReading,
        unlockRuntime: V3DeviceWrappedVaultUnlockRuntime
    ) {
        self.source = source
        self.unlockRuntime = unlockRuntime
        contentValidator = V3DeviceWrappedCheckpointContentValidator(
            source: source
        )
    }

    func unlock() throws {
        _ = try unlockRuntime.unlock(
            reason: "Unlock the vault."
        )
    }

    func read(
        name: String,
        allowStale _: Bool
    ) throws -> VaultReadValue {
        let trusted = try authenticatedCheckpoint(
            reason: "Unlock the vault to read '\(name)'."
        )
        let plan = try planner.planCheckpointRead(
            named: name,
            entries: trusted.envelope.body.entries,
            checkpoint: trusted.checkpoint
        )
        let plaintext: String
        do {
            plaintext = try executor().execute(plan)
        } catch let error as V3AuthenticatedReadError {
            throw vaultUXError(for: error)
        } catch is V3EncryptedEntryError {
            throw VaultUXServiceError.recoveryRequired
        }
        return VaultReadValue(type: plan.entry.type, plaintext: plaintext)
    }

    func list(allowStale: Bool) throws -> [String] {
        let trusted = try authenticatedCheckpoint(
            reason: "Unlock the vault to list saved entries."
        )
        switch try contentValidator.validate(
            entries: trusted.envelope.body.entries,
            vaultID: trusted.checkpoint.vaultID
        ) {
        case .ready:
            break
        case .incomplete:
            guard allowStale else {
                throw VaultUXServiceError.vaultIncomplete
            }
        case .invalid, .resourceLimitExceeded:
            throw VaultUXServiceError.recoveryRequired
        }
        let plan = planner.planCheckpointList(
            entries: trusted.envelope.body.entries,
            checkpoint: trusted.checkpoint
        )
        try authorityValidator().validate(plan.authority)
        return plan.entries.map(\.name)
    }

    func status() throws -> VaultStatus {
        let trusted = try authenticatedCheckpoint(
            reason: "Unlock the vault to check its status."
        )
        let validation = try contentValidator.validate(
            entries: trusted.envelope.body.entries,
            vaultID: trusted.checkpoint.vaultID
        )
        try validateAuthority(trusted.checkpoint)
        let health: VaultHealth
        let entries: VaultEntrySummary
        let issues: [VaultIssue]
        switch validation {
        case .ready:
            health = .ready
            entries = .effective(trusted.envelope.body.entries.count)
            issues = []
        case .incomplete:
            health = .incomplete
            entries = .lastTrusted(trusted.envelope.body.entries.count)
            issues = [VaultIssue(
                code: .referencedObjectUnavailable,
                message: "A required encrypted entry file is unavailable."
            )]
        case .invalid:
            health = .recoveryRequired
            entries = .lastTrusted(trusted.envelope.body.entries.count)
            issues = [VaultIssue(
                code: .invalidReferencedObject,
                message: "A required encrypted entry failed verification. Keep the files intact for investigation."
            )]
        case .resourceLimitExceeded:
            health = .recoveryRequired
            entries = .lastTrusted(trusted.envelope.body.entries.count)
            issues = [VaultIssue(
                code: .resourceLimitExceeded,
                message: "Checking the last verified vault state exceeded Key's size or item-count limits."
            )]
        }
        return VaultStatus(
            format: .version3,
            health: health,
            entries: entries,
            trustedVersionID: String(
                v3LowercaseHex(trusted.checkpoint.envelopeDigest).prefix(16)
            ),
            issues: issues
        )
    }

    func authorizeRead(
        name: String,
        allowStale _: Bool
    ) throws {
        let trusted = try authenticatedCheckpoint(
            reason: "Unlock the vault to verify '\(name)'."
        )
        _ = try planner.planCheckpointRead(
            named: name,
            entries: trusted.envelope.body.entries,
            checkpoint: trusted.checkpoint
        )
    }

    func authorizeMutation() throws {
        throw readOnlyMutationError()
    }

    func conflicts() throws -> [VaultConflictSummary] {
        []
    }

    func conflict(id _: String) throws -> VaultConflictDetail {
        throw VaultUXServiceError.conflictNotFound
    }

    func conflictValue(
        id _: String,
        versionID _: String
    ) throws -> String {
        throw VaultUXServiceError.conflictNotFound
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw readOnlyMutationError()
    }

    private func authenticatedCheckpoint(
        reason: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        try unlockRuntime.authenticatedCheckpoint(reason: reason)
    }

    private func executor() -> V3AuthenticatedReadExecutor {
        V3AuthenticatedReadExecutor(
            source: source,
            vaultKeyProvider: { keyID in
                try unlockRuntime.loadVaultKey(keyID: keyID)
            },
            authorityValidator: authorityValidator()
        )
    }

    private func authorityValidator() -> V3ReadAuthorityValidator {
        V3ReadAuthorityValidator(
            currentStateProvider: { _ in
                throw V3AuthenticatedReadError.authorityChanged
            },
            checkpointProvider: { vaultID in
                do {
                    return try unlockRuntime.checkpointForRevalidation(
                        vaultID: vaultID
                    )
                } catch {
                    throw V3AuthenticatedReadError.authorityChanged
                }
            }
        )
    }

    private func validateAuthority(
        _ checkpoint: V3ManifestCheckpoint
    ) throws {
        do {
            try authorityValidator().validate(.lastTrusted(checkpoint))
        } catch {
            throw VaultUXServiceError.vaultIncomplete
        }
    }

    private func vaultUXError(
        for error: V3AuthenticatedReadError
    ) -> VaultUXServiceError {
        switch error {
        case .entryUnavailable, .authorityChanged:
            .vaultIncomplete
        case .invalidEntryObject, .entryObjectTooLarge:
            .recoveryRequired
        }
    }

    private func readOnlyMutationError() -> AppError {
        AppError.operationRefused(
            "Permanent version 3 vault writes are not enabled yet."
        )
    }
}

enum V3DeviceWrappedCheckpointContentValidation {
    case ready
    case incomplete
    case invalid
    case resourceLimitExceeded
}

/// Validates the bounded encrypted-object closure of one authenticated
/// permanent-profile checkpoint without opening plaintext.
struct V3DeviceWrappedCheckpointContentValidator: Sendable {
    private struct ReferenceKey: Hashable, Sendable {
        let entryID: String
        let digest: Data
    }

    private let source: any V3ImmutableObjectReading
    private let limits: V3ManifestRepositoryLimits
    private let entryCipher = V3EntryCipher()

    init(
        source: any V3ImmutableObjectReading,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.source = source
        self.limits = limits
    }

    func validate(
        entries: [V3ManifestEntry],
        vaultID: String
    ) throws -> V3DeviceWrappedCheckpointContentValidation {
        var references: [ReferenceKey: V3EntryAuthenticationContext] = [:]
        for entry in entries {
            guard let digest = Base64URL.decodeCanonical(
                entry.ciphertextDigest
            ), digest.count == 32,
                  let context = try? V3EntryAuthenticationContext(
                      vaultID: vaultID,
                      entry: entry
                  )
            else {
                return .invalid
            }
            let key = ReferenceKey(entryID: entry.entryID, digest: digest)
            if references[key] == nil,
               references.count >= limits.maximumReferencedEntryObjects {
                return .resourceLimitExceeded
            }
            guard references.updateValue(context, forKey: key) == nil else {
                return .invalid
            }
        }

        var hasUnavailableObject = false
        var totalEntryBytes = 0
        for reference in references.sorted(by: referencePrecedes) {
            let read: V3RepositoryObjectRead
            do {
                read = try source.readEntry(
                    entryID: reference.key.entryID,
                    digest: reference.key.digest,
                    maximumBytes: limits.maximumEntryBytes
                )
            } catch {
                return .invalid
            }
            switch read {
            case let .available(data):
                guard data.count <= limits.maximumEntryBytes,
                      data.count
                        <= limits.maximumTotalEntryBytes - totalEntryBytes
                else {
                    return .resourceLimitExceeded
                }
                totalEntryBytes += data.count
                guard Data(SHA256.hash(data: data)) == reference.key.digest,
                      let parsed = try? entryCipher.parse(data),
                      parsed.context == reference.value
                else {
                    return .invalid
                }
            case .unavailable:
                hasUnavailableObject = true
            case .invalid, .tooLarge:
                return .invalid
            }
        }
        return hasUnavailableObject ? .incomplete : .ready
    }

    private func referencePrecedes(
        _ lhs: (key: ReferenceKey, value: V3EntryAuthenticationContext),
        _ rhs: (key: ReferenceKey, value: V3EntryAuthenticationContext)
    ) -> Bool {
        if lhs.key.entryID != rhs.key.entryID {
            return Data(lhs.key.entryID.utf8).lexicographicallyPrecedes(
                Data(rhs.key.entryID.utf8)
            )
        }
        return lhs.key.digest.lexicographicallyPrecedes(rhs.key.digest)
    }
}
