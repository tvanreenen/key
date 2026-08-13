import Foundation

enum V3LocalMigrationError: Error, Equatable, LocalizedError {
    case invalidGeneratedIdentity
    case duplicateGeneratedIdentity
    case objectTooLarge
    case stagedObjectUnavailable
    case publishedObjectUnavailable
    case verifiedReopenMismatch
    case sourceChanged

    var errorDescription: String? {
        switch self {
        case .invalidGeneratedIdentity:
            "Migration generated an invalid version 3 identity."
        case .duplicateGeneratedIdentity:
            "Migration generated a duplicate version 3 identity."
        case .objectTooLarge:
            "The migrated version 3 vault would exceed a repository resource limit."
        case .stagedObjectUnavailable:
            "A staged version 3 migration object could not be reopened exactly."
        case .publishedObjectUnavailable:
            "A published version 3 migration object could not be reopened exactly."
        case .verifiedReopenMismatch:
            "The completed version 3 vault did not reproduce the exact version 2 source."
        case .sourceChanged:
            "The version 2 vault changed during migration. Version 2 remains selected; retry after file synchronization settles."
        }
    }
}

enum V3MigrationDestination: Equatable, Sendable {
    case releasedAlpha
    case deviceWrapped
}

struct V3LocalMigrationReport: Equatable, Sendable {
    let vaultID: String
    let entryCount: Int
    let secretCount: Int
    let totpCount: Int
    let destination: V3MigrationDestination

    init(
        vaultID: String,
        entryCount: Int,
        secretCount: Int,
        totpCount: Int,
        destination: V3MigrationDestination
    ) {
        self.vaultID = vaultID
        self.entryCount = entryCount
        self.secretCount = secretCount
        self.totpCount = totpCount
        self.destination = destination
    }

    var rendered: String {
        switch destination {
        case .releasedAlpha:
            releasedAlphaRendering
        case .deviceWrapped:
            deviceWrappedRendering
        }
    }

    private var releasedAlphaRendering: String {
        [
            "Migration completed.",
            "Entries migrated: \(entryCount) (\(secretCount) \(secretCount == 1 ? "secret" : "secrets"), \(totpCount) \(totpCount == 1 ? "TOTP entry" : "TOTP entries")).",
            "This Mac now uses authenticated version 3 vault '\(vaultID)'.",
            "The version 2 source files were retained unchanged. No cleanup was performed.",
            "After Key Agent restarts, ordinary entry commands publish guarded version 3 history.",
            "Other devices remain on version 2 and their later changes are not copied into this snapshot. To enroll a second Mac into this v3 vault, start with `key share invite --name <device-name>`."
        ].joined(separator: "\n") + "\n"
    }

    private var deviceWrappedRendering: String {
        [
            "Migration completed.",
            "Entries migrated: \(entryCount) (\(secretCount) \(secretCount == 1 ? "secret" : "secrets"), \(totpCount) \(totpCount == 1 ? "TOTP entry" : "TOTP entries")).",
            "This Mac now uses permanent version 3 vault '\(vaultID)'.",
            "Its new vault key is wrapped to this Mac's Secure Enclave identity and exists in plaintext only in Key Agent's unlocked memory session.",
            "The version 2 source files were retained unchanged. No cleanup was performed.",
            "Keep that version 2 copy while you validate the migration. It can help you return to version 2, but it cannot recover this version 3 vault.",
            "Other devices are not converted automatically. After they install a compatible release, enroll at least one other Mac before relying on version 3.",
            "If every enrolled Mac is lost, synchronized version 3 files cannot unlock or recover the vault."
        ].joined(separator: "\n") + "\n"
    }
}

enum V3LocalMigrationPhase: Equatable, Sendable {
    case candidateBuilt
    case entryStaged(index: Int)
    case manifestStaged
    case stagedCandidateVerified
    case entryPublished(index: Int)
    case publishedEntriesVerified
    case manifestPublished
    case publishedManifestVerified
    case checkpointInstalled
    case verifiedReopenCompleted
    case sourceRechecked
}

protocol V3LocalMigrationPhaseObserving: Sendable {
    func didReach(
        _ phase: V3LocalMigrationPhase,
        operationID: VaultTransactionOperationID
    ) throws
}

private struct V3NoopLocalMigrationPhaseObserver:
    V3LocalMigrationPhaseObserving
{
    func didReach(
        _: V3LocalMigrationPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

protocol V3LocalMigrationServicing {
    func migrate(
        operationID: VaultTransactionOperationID
    ) throws -> V3LocalMigrationReport
}

/// Defers stricter v3 root handling and migration-only dependencies until the
/// user explicitly applies migration. Ordinary v2 helper startup and reads do
/// not cross the v3 publication boundary.
struct DeferredV3LocalMigrationService: V3LocalMigrationServicing {
    typealias Factory = () throws -> any V3LocalMigrationServicing

    private let makeService: Factory

    init(makeService: @escaping Factory) {
        self.makeService = makeService
    }

    func migrate(
        operationID: VaultTransactionOperationID
    ) throws -> V3LocalMigrationReport {
        try makeService().migrate(operationID: operationID)
    }
}

/// Converts one helper-serialized v2 snapshot into a complete local-mode v3
/// genesis. Version 2 remains selected until every published object, the
/// device-local checkpoint, and an independent shipping-runtime reopen pass.
struct V3LocalMigrationService: V3LocalMigrationServicing {
    typealias VaultKeyProvider = @Sendable (
        _ reason: String,
        _ createIfMissing: Bool
    ) throws -> Data
    typealias VaultSelector = (_ vaultID: String) throws -> Void

    private let entryStore: EntryStore
    private let preflight: V2MigrationPreflight
    private let objectStore: any V3ImmutableObjectPublishing
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let loadVaultKey: VaultKeyProvider
    private let selectVault: VaultSelector
    private let makeUUID: @Sendable () -> String
    private let phaseObserver: any V3LocalMigrationPhaseObserving
    private let limits: V3ManifestRepositoryLimits
    private let builder = V3LocalGenesisBuilder()
    private let authenticator = V3ManifestAuthenticator()
    private let entryCipher = V3EntryCipher()

    init(
        entryStore: EntryStore,
        cipher: VaultCipher,
        objectStore: any V3ImmutableObjectPublishing,
        checkpointStore: any V3ManifestCheckpointStoring,
        loadVaultKey: @escaping VaultKeyProvider,
        selectVault: @escaping VaultSelector,
        makeUUID: @escaping @Sendable () -> String = {
            UUID().uuidString.lowercased()
        },
        phaseObserver: any V3LocalMigrationPhaseObserving =
            V3NoopLocalMigrationPhaseObserver(),
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.entryStore = entryStore
        preflight = V2MigrationPreflight(
            entryStore: entryStore,
            cipher: cipher
        )
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.loadVaultKey = loadVaultKey
        self.selectVault = selectVault
        self.makeUUID = makeUUID
        self.phaseObserver = phaseObserver
        self.limits = limits
    }

    func migrate(
        operationID: VaultTransactionOperationID
    ) throws -> V3LocalMigrationReport {
        let inspection = try preflight.inspectForMigration {
            try loadVaultKey(
                "Unlock key vault to verify version 2 migration readiness.",
                false
            )
        }
        guard inspection.report.isReady else {
            throw AppError.operationRefused(inspection.report.rendered)
        }

        let vaultKey: Data
        if let inspectedVaultKey = inspection.vaultKey {
            vaultKey = inspectedVaultKey
        } else {
            do {
                vaultKey = try loadVaultKey(
                    "Unlock the existing key for this empty version 2 vault.",
                    false
                )
            } catch AppError.entryNotFound {
                throw AppError.operationRefused(
                    "The version 2 vault is empty and has no existing vault key. There is nothing to migrate yet; wait for synchronization to finish or add an entry before retrying."
                )
            }
        }
        let sourceEntries = inspection.entries.sorted {
            Data($0.name.utf8).lexicographicallyPrecedes(Data($1.name.utf8))
        }
        let vaultID = makeUUID()
        let candidate = try builder.build(
            vaultID: vaultID,
            entryIDs: sourceEntries.map { _ in makeUUID() },
            sourceEntries: sourceEntries,
            vaultKey: vaultKey
        )
        try requireWithinLimits(candidate)
        try phaseObserver.didReach(
            .candidateBuilt,
            operationID: operationID
        )

        defer {
            removeStagingArtifacts(
                candidate,
                operationID: operationID
            )
        }

        for (index, entry) in candidate.entries.enumerated() {
            try objectStore.stageEntry(
                entry.encryptedEntry.canonicalBytes,
                entryID: entry.manifestEntry.entryID,
                digest: entry.digest,
                operationID: operationID
            )
            try phaseObserver.didReach(
                .entryStaged(index: index),
                operationID: operationID
            )
        }
        try objectStore.stageManifest(
            candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestStaged,
            operationID: operationID
        )

        try validateStagedCandidate(
            candidate,
            operationID: operationID,
            vaultKey: vaultKey
        )
        try phaseObserver.didReach(
            .stagedCandidateVerified,
            operationID: operationID
        )

        for (index, entry) in candidate.entries.enumerated() {
            try objectStore.publishStagedEntry(
                entry.encryptedEntry.canonicalBytes,
                entryID: entry.manifestEntry.entryID,
                digest: entry.digest,
                operationID: operationID
            )
            try phaseObserver.didReach(
                .entryPublished(index: index),
                operationID: operationID
            )
        }
        try validatePublishedEntries(candidate, vaultKey: vaultKey)
        try phaseObserver.didReach(
            .publishedEntriesVerified,
            operationID: operationID
        )

        try objectStore.publishStagedManifest(
            candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestPublished,
            operationID: operationID
        )
        let publishedManifest = try exactPublishedManifest(candidate)
        _ = try authenticator.verify(
            publishedManifest,
            vaultKey: vaultKey,
            trustAnchor: .localGenesis(vaultID: candidate.vaultID)
        )
        try phaseObserver.didReach(
            .publishedManifestVerified,
            operationID: operationID
        )

        let trusted = try V3ManifestReplayProtector(
            store: checkpointStore
        ).bootstrapLocalGenesis(
            publishedManifest,
            expectedVaultID: candidate.vaultID,
            vaultKey: vaultKey
        )
        guard trusted.verifiedManifest == candidate.verifiedManifest else {
            throw V3LocalMigrationError.publishedObjectUnavailable
        }
        try phaseObserver.didReach(
            .checkpointInstalled,
            operationID: operationID
        )

        try verifyShippingRuntime(candidate)
        try phaseObserver.didReach(
            .verifiedReopenCompleted,
            operationID: operationID
        )

        try requireUnchangedV2Source(sourceEntries)
        try phaseObserver.didReach(
            .sourceRechecked,
            operationID: operationID
        )

        try selectVault(candidate.vaultID)
        return V3LocalMigrationReport(
            vaultID: candidate.vaultID,
            entryCount: inspection.report.entryCount,
            secretCount: inspection.report.secretCount,
            totpCount: inspection.report.totpCount,
            destination: .releasedAlpha
        )
    }

    private func requireWithinLimits(
        _ candidate: V3LocalMigrationCandidate
    ) throws {
        guard candidate.entries.count
                <= limits.maximumReferencedEntryObjects,
              candidate.manifestData.count <= limits.maximumManifestBytes
        else {
            throw V3LocalMigrationError.objectTooLarge
        }
        var totalBytes = 0
        for entry in candidate.entries {
            let count = entry.encryptedEntry.canonicalBytes.count
            guard count <= limits.maximumEntryBytes,
                  totalBytes <= limits.maximumTotalEntryBytes - count
            else {
                throw V3LocalMigrationError.objectTooLarge
            }
            totalBytes += count
        }
    }

    private func validateStagedCandidate(
        _ candidate: V3LocalMigrationCandidate,
        operationID: VaultTransactionOperationID,
        vaultKey: Data
    ) throws {
        let manifest = try exactData(
            try objectStore.readStagedManifest(
                digest: candidate.verifiedManifest.envelopeDigest,
                operationID: operationID,
                maximumBytes: limits.maximumManifestBytes
            ),
            expected: candidate.manifestData,
            error: .stagedObjectUnavailable
        )
        let verified = try authenticator.verify(
            manifest,
            vaultKey: vaultKey,
            trustAnchor: .localGenesis(vaultID: candidate.vaultID)
        )
        try validateEntries(
            candidate,
            trustedManifest: V3TrustedManifest(
                verifiedManifest: verified,
                checkpoint: try V3ManifestCheckpoint(
                    verifiedManifest: verified
                )
            ),
            vaultKey: vaultKey,
            read: { entry in
                try objectStore.readStagedEntry(
                    entryID: entry.manifestEntry.entryID,
                    digest: entry.digest,
                    operationID: operationID,
                    maximumBytes: limits.maximumEntryBytes
                )
            },
            unavailableError: .stagedObjectUnavailable
        )
    }

    private func validatePublishedEntries(
        _ candidate: V3LocalMigrationCandidate,
        vaultKey: Data
    ) throws {
        let checkpoint = try V3ManifestCheckpoint(
            verifiedManifest: candidate.verifiedManifest
        )
        let trusted = V3TrustedManifest(
            verifiedManifest: candidate.verifiedManifest,
            checkpoint: checkpoint
        )
        try validateEntries(
            candidate,
            trustedManifest: trusted,
            vaultKey: vaultKey,
            read: { entry in
                try objectStore.readEntry(
                    entryID: entry.manifestEntry.entryID,
                    digest: entry.digest,
                    maximumBytes: limits.maximumEntryBytes
                )
            },
            unavailableError: .publishedObjectUnavailable
        )
    }

    private func validateEntries(
        _ candidate: V3LocalMigrationCandidate,
        trustedManifest: V3TrustedManifest,
        vaultKey: Data,
        read: (V3LocalMigrationCandidate.Entry) throws
            -> V3RepositoryObjectRead,
        unavailableError: V3LocalMigrationError
    ) throws {
        for entry in candidate.entries {
            let data = try exactData(
                try read(entry),
                expected: entry.encryptedEntry.canonicalBytes,
                error: unavailableError
            )
            let plaintext = try entryCipher.open(
                data,
                trustedManifest: trustedManifest,
                entryID: entry.manifestEntry.entryID,
                vaultKey: vaultKey
            )
            guard plaintext == entry.source.plaintext else {
                throw V3LocalMigrationError.verifiedReopenMismatch
            }
        }
    }

    private func exactPublishedManifest(
        _ candidate: V3LocalMigrationCandidate
    ) throws -> Data {
        try exactData(
            try objectStore.readManifest(
                digest: candidate.verifiedManifest.envelopeDigest,
                maximumBytes: limits.maximumManifestBytes
            ),
            expected: candidate.manifestData,
            error: .publishedObjectUnavailable
        )
    }

    private func exactData(
        _ result: V3RepositoryObjectRead,
        expected: Data,
        error: V3LocalMigrationError
    ) throws -> Data {
        guard case let .available(data) = result, data == expected else {
            throw error
        }
        return data
    }

    private func verifyShippingRuntime(
        _ candidate: V3LocalMigrationCandidate
    ) throws {
        let vaultKeyProvider = loadVaultKey
        let runtime = V3ReadOnlyVaultRuntime(
            source: objectStore,
            vaultID: candidate.vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: { reason in
                try vaultKeyProvider(reason, false)
            }
        )
        try runtime.unlock()
        let expectedNames = candidate.entries.map(\.source.name)
        guard try runtime.list(allowStale: false) == expectedNames else {
            throw V3LocalMigrationError.verifiedReopenMismatch
        }
        for entry in candidate.entries {
            let value = try runtime.read(
                name: entry.source.name,
                allowStale: false
            )
            guard value.type == entry.source.type,
                  value.plaintext == entry.source.plaintext
            else {
                throw V3LocalMigrationError.verifiedReopenMismatch
            }
        }
    }

    private func requireUnchangedV2Source(
        _ entries: [V2MigrationSourceEntry]
    ) throws {
        let expectedNames = Set(entries.map(\.name))
        let currentNames = try entryStore.listEntries()
        guard currentNames.count == expectedNames.count,
              Set(currentNames) == expectedNames
        else {
            throw V3LocalMigrationError.sourceChanged
        }
        for entry in entries {
            guard try entryStore.loadStoredSecret(entry.name).data
                    == entry.sourceData
            else {
                throw V3LocalMigrationError.sourceChanged
            }
        }
    }

    private func removeStagingArtifacts(
        _ candidate: V3LocalMigrationCandidate,
        operationID: VaultTransactionOperationID
    ) {
        for entry in candidate.entries {
            try? objectStore.removeStagedEntry(
                entry.encryptedEntry.canonicalBytes,
                entryID: entry.manifestEntry.entryID,
                digest: entry.digest,
                operationID: operationID
            )
        }
        try? objectStore.removeStagedManifest(
            candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest,
            operationID: operationID
        )
        try? objectStore.removeEmptyTransactionDirectories(
            operationID: operationID,
            entryIDs: candidate.entries.map(\.manifestEntry.entryID)
        )
    }

}
