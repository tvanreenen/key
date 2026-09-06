import CryptoKit
import Foundation

enum V3DeviceWrappedGenesisInstallError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidGeneratedKey
    case generatedIdentityMismatch
    case persistedIdentityUnavailable
    case localStateAlreadyExists
    case checkpointChanged
    case objectTooLarge
    case stagedObjectUnavailable
    case publishedObjectUnavailable
    case verifiedReopenMismatch
    case sourceChanged

    var errorDescription: String? {
        switch self {
        case .invalidGeneratedKey:
            "Permanent version 3 creation did not generate a 32-byte vault key."
        case .generatedIdentityMismatch:
            "The generated Secure Enclave identity does not belong to the new vault."
        case .persistedIdentityUnavailable:
            "The new Secure Enclave identity could not be reloaded from device-local storage. Version 2 remains selected."
        case .localStateAlreadyExists:
            "Permanent version 3 creation found existing local state for its generated vault identity."
        case .checkpointChanged:
            "The permanent version 3 checkpoint changed before vault selection. Version 2 remains selected."
        case .objectTooLarge:
            "The permanent version 3 vault would exceed a repository resource limit."
        case .stagedObjectUnavailable:
            "A staged permanent version 3 object could not be reopened exactly."
        case .publishedObjectUnavailable:
            "A published permanent version 3 object could not be reopened exactly."
        case .verifiedReopenMismatch:
            "The completed permanent version 3 vault did not reproduce the exact version 2 source."
        case .sourceChanged:
            "The version 2 vault changed during creation. Version 2 remains selected; retry after file synchronization settles."
        }
    }
}

struct V3DeviceWrappedGenesisInstallReport: Equatable, Sendable {
    let vaultID: String
    let deviceID: String
    let entryCount: Int
    let secretCount: Int
    let totpCount: Int
}

protocol V3DeviceWrappedGenesisInstalling {
    func install(
        operationID: VaultTransactionOperationID,
        deviceName: String
    ) throws -> V3DeviceWrappedGenesisInstallReport
}

enum V3DeviceWrappedGenesisInstallPhase: Equatable, Sendable {
    case identityCreated
    case candidateBuilt
    case entryStaged(index: Int)
    case manifestStaged
    case stagedCandidateVerified
    case deviceWrapperVerified
    case entryPublished(index: Int)
    case publishedEntriesVerified
    case manifestPublished
    case publishedManifestVerified
    case checkpointInstalled
    case manifestCached
    case sessionInstalled
    case verifiedReopenCompleted
    case sourceRechecked
    case localStateRechecked
}

protocol V3DeviceWrappedGenesisInstallPhaseObserving: Sendable {
    func didReach(
        _ phase: V3DeviceWrappedGenesisInstallPhase,
        operationID: VaultTransactionOperationID
    ) throws
}

private struct V3NoopDeviceWrappedGenesisInstallPhaseObserver:
    V3DeviceWrappedGenesisInstallPhaseObserving
{
    func didReach(
        _: V3DeviceWrappedGenesisInstallPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

protocol V3DeviceWrappedGenesisIdentityCreating: Sendable {
    func createDeviceWrappedIdentity(
        vaultID: String,
        displayName: String,
        reason: String
    ) throws -> any V3DeviceWrappedVaultKeyUnwrapping
}

/// The genesis transaction must prove that the identity it just created can be
/// reconstructed from device-local persistence before it publishes or selects
/// the new vault.
protocol V3DeviceWrappedGenesisIdentityManaging:
    V3DeviceWrappedGenesisIdentityCreating,
    V3DeviceWrappedIdentityLoading
{}

extension V3EnrollmentDeviceIdentityManager:
    V3DeviceWrappedGenesisIdentityManaging
{
    func createDeviceWrappedIdentity(
        vaultID: String,
        displayName: String,
        reason: String
    ) throws -> any V3DeviceWrappedVaultKeyUnwrapping {
        try createIdentity(
            vaultID: vaultID,
            displayName: displayName,
            reason: reason
        )
    }
}

/// Converts one exact v2 snapshot into a permanent device-wrapped genesis.
///
/// Version 2 stays selected until immutable entries, the authenticated
/// manifest, the device-local checkpoint and cache, and a read through the
/// permanent runtime have all succeeded. The newly generated vault key is
/// passed only through this call and the in-memory session store.
struct V3DeviceWrappedGenesisInstaller {
    typealias V2VaultKeyProvider = @Sendable (
        _ reason: String,
        _ createIfMissing: Bool
    ) throws -> Data
    typealias VaultSelector = (_ vaultID: String) throws -> Void
    typealias UUIDGenerator = @Sendable () -> String
    typealias VaultKeyGenerator = @Sendable () -> Data

    private let entryStore: EntryStore
    private let preflight: V2MigrationPreflight
    private let objectStore: any V3ImmutableObjectPublishing
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let cache: any V3CheckpointManifestCaching
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let identityManager: any V3DeviceWrappedGenesisIdentityManaging
    private let loadV2VaultKey: V2VaultKeyProvider
    private let selectVault: VaultSelector
    private let makeUUID: UUIDGenerator
    private let makeVaultKey: VaultKeyGenerator
    private let phaseObserver:
        any V3DeviceWrappedGenesisInstallPhaseObserving
    private let limits: V3ManifestRepositoryLimits
    private let builder = V3DeviceWrappedGenesisBuilder()
    private let envelopeCodec = V3DeviceWrappedManifestEnvelopeCodec()
    private let entryCipher = V3EntryCipher()
    private let checkpointUnlocker = V3DeviceWrappedCheckpointUnlocker()

    init(
        entryStore: EntryStore,
        cipher: VaultCipher,
        objectStore: any V3ImmutableObjectPublishing,
        checkpointStore: any V3ManifestCheckpointStoring,
        cache: any V3CheckpointManifestCaching,
        session: V3DeviceWrappedVaultKeySessionStore,
        identityManager: any V3DeviceWrappedGenesisIdentityManaging,
        loadV2VaultKey: @escaping V2VaultKeyProvider,
        selectVault: @escaping VaultSelector,
        makeUUID: @escaping UUIDGenerator = {
            UUID().uuidString.lowercased()
        },
        makeVaultKey: @escaping VaultKeyGenerator = {
            var generator = SystemRandomNumberGenerator()
            return Data((0..<32).map { _ in
                UInt8.random(
                    in: UInt8.min...UInt8.max,
                    using: &generator
                )
            })
        },
        phaseObserver:
            any V3DeviceWrappedGenesisInstallPhaseObserving =
                V3NoopDeviceWrappedGenesisInstallPhaseObserver(),
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.entryStore = entryStore
        preflight = V2MigrationPreflight(
            entryStore: entryStore,
            cipher: cipher
        )
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.cache = cache
        self.session = session
        self.identityManager = identityManager
        self.loadV2VaultKey = loadV2VaultKey
        self.selectVault = selectVault
        self.makeUUID = makeUUID
        self.makeVaultKey = makeVaultKey
        self.phaseObserver = phaseObserver
        self.limits = limits
    }

    func install(
        operationID: VaultTransactionOperationID,
        deviceName: String
    ) throws -> V3DeviceWrappedGenesisInstallReport {
        let inspection = try preflight.inspectForMigration {
            try loadV2VaultKey(
                "Unlock the version 2 vault to create its permanent version 3 replacement.",
                false
            )
        }
        guard inspection.report.isReady else {
            throw AppError.operationRefused(inspection.report.rendered)
        }

        let sourceEntries = inspection.entries.sorted {
            Data($0.name.utf8).lexicographicallyPrecedes(Data($1.name.utf8))
        }
        guard sourceEntries.count <= limits.maximumReferencedEntryObjects else {
            throw V3DeviceWrappedGenesisInstallError.objectTooLarge
        }
        if sourceEntries.isEmpty {
            do {
                _ = try loadV2VaultKey(
                    "Confirm the existing key for this empty version 2 vault before creating its permanent replacement.",
                    false
                )
            } catch AppError.entryNotFound {
                throw AppError.operationRefused(
                    "The version 2 vault is empty and has no existing vault key. There is nothing to convert yet; wait for synchronization to finish or add an entry before retrying."
                )
            }
            // A provider can deliver its first entry while Keychain access is
            // in progress. Stop before creating a new identity or vault key.
            try requireUnchangedV2Source([])
        }
        return try installGenesis(
            sourceEntries: sourceEntries,
            operationID: operationID,
            deviceName: deviceName,
            newDirectory: nil
        )
    }

    /// Creates an empty genesis only in an explicitly reserved new directory.
    /// This never loads or creates a legacy v2 key and is not a migration mode.
    func installNewVault(
        in directory: V3NewVaultDirectory,
        operationID: VaultTransactionOperationID,
        deviceName: String
    ) throws -> V3DeviceWrappedGenesisInstallReport {
        try directory.begin(for: entryStore.rootURL)
        return try installGenesis(
            sourceEntries: [],
            operationID: operationID,
            deviceName: deviceName,
            newDirectory: directory
        )
    }

    private func installGenesis(
        sourceEntries: [V2MigrationSourceEntry],
        operationID: VaultTransactionOperationID,
        deviceName: String,
        newDirectory: V3NewVaultDirectory?
    ) throws -> V3DeviceWrappedGenesisInstallReport {
        // Cover failures before candidate staging as well as publication.
        var selected = false
        defer { if !selected { session.invalidate() } }
        let vaultID = makeUUID()
        let authorityTransitionID = makeUUID()
        let entryIDs = sourceEntries.map { _ in makeUUID() }
        let vaultKey = makeVaultKey()
        guard vaultKey.count == 32 else {
            throw V3DeviceWrappedGenesisInstallError.invalidGeneratedKey
        }
        guard try checkpointStore.loadCheckpoint(vaultID: vaultID) == nil else {
            throw V3DeviceWrappedGenesisInstallError
                .localStateAlreadyExists
        }

        let identity = try identityManager.createDeviceWrappedIdentity(
            vaultID: vaultID,
            displayName: deviceName,
            reason: "Create this Mac's permanent version 3 vault identity."
        )
        guard identity.vaultID == vaultID else {
            throw V3DeviceWrappedGenesisInstallError
                .generatedIdentityMismatch
        }
        try phaseObserver.didReach(
            .identityCreated,
            operationID: operationID
        )
        guard let persistedIdentity = try identityManager.loadDeviceIdentity(
            vaultID: vaultID,
            reason: "Verify this Mac's permanent version 3 vault identity."
        ), persistedIdentity.vaultID == vaultID,
           persistedIdentity.publicIdentity == identity.publicIdentity
        else {
            throw V3DeviceWrappedGenesisInstallError
                .persistedIdentityUnavailable
        }
        let candidate = try builder.buildPublicationCandidate(
            vaultID: vaultID,
            authorityTransitionID: authorityTransitionID,
            entryIDs: entryIDs,
            sourceEntries: sourceEntries,
            vaultKey: vaultKey,
            ownerIdentity: identity.publicIdentity
        )
        try requireWithinLimits(candidate)
        try phaseObserver.didReach(
            .candidateBuilt,
            operationID: operationID
        )

        defer {
            removeStagingArtifacts(candidate, operationID: operationID)
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
            candidate.genesis.manifestData,
            digest: candidate.genesis.manifestDigest,
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
        try validateDeviceWrapper(
            candidate,
            identity: persistedIdentity,
            vaultKey: vaultKey
        )
        try phaseObserver.didReach(
            .deviceWrapperVerified,
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
            candidate.genesis.manifestData,
            digest: candidate.genesis.manifestDigest,
            operationID: operationID
        )
        try phaseObserver.didReach(
            .manifestPublished,
            operationID: operationID
        )
        let publishedManifest = try exactPublishedManifest(candidate)
        _ = try validateManifest(
            publishedManifest,
            candidate: candidate,
            vaultKey: vaultKey,
            unavailableError: .publishedObjectUnavailable
        )
        try phaseObserver.didReach(
            .publishedManifestVerified,
            operationID: operationID
        )

        let checkpoint = try V3ManifestCheckpoint(
            vaultID: vaultID,
            envelopeDigest: candidate.genesis.manifestDigest
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: nil,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .checkpointInstalled,
            operationID: operationID
        )
        try cache.store(publishedManifest, for: checkpoint)
        try phaseObserver.didReach(
            .manifestCached,
            operationID: operationID
        )
        try session.install(
            vaultKey,
            vaultID: vaultID,
            keyID: candidate.genesis.body.keyID
        )
        try phaseObserver.didReach(
            .sessionInstalled,
            operationID: operationID
        )

        try verifyPermanentRuntime(
            candidate,
            session: session
        )
        try phaseObserver.didReach(
            .verifiedReopenCompleted,
            operationID: operationID
        )
        if let newDirectory {
            removeStagingArtifacts(candidate, operationID: operationID)
            try newDirectory.requireInstalledGenesis(digest: candidate.genesis.manifestDigest)
        } else {
            try requireUnchangedV2Source(sourceEntries)
        }
        try phaseObserver.didReach(
            .sourceRechecked,
            operationID: operationID
        )
        try requireExactCheckpoint(checkpoint)
        try phaseObserver.didReach(
            .localStateRechecked,
            operationID: operationID
        )

        if let newDirectory {
            try newDirectory.requireInstalledGenesis(digest: candidate.genesis.manifestDigest)
            _ = try exactPublishedManifest(candidate)
        }

        try selectVault(vaultID)
        selected = true
        return V3DeviceWrappedGenesisInstallReport(
            vaultID: vaultID,
            deviceID: identity.publicIdentity.deviceID,
            entryCount: sourceEntries.count,
            secretCount: sourceEntries.filter { $0.type == .secret }.count,
            totpCount: sourceEntries.filter { $0.type == .totp }.count
        )
    }

    private func requireWithinLimits(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate
    ) throws {
        guard candidate.entries.count
                <= limits.maximumReferencedEntryObjects,
              candidate.genesis.manifestData.count
                <= limits.maximumManifestBytes
        else {
            throw V3DeviceWrappedGenesisInstallError.objectTooLarge
        }
        var totalBytes = 0
        for entry in candidate.entries {
            let count = entry.encryptedEntry.canonicalBytes.count
            guard count <= limits.maximumEntryBytes,
                  totalBytes <= limits.maximumTotalEntryBytes - count
            else {
                throw V3DeviceWrappedGenesisInstallError.objectTooLarge
            }
            totalBytes += count
        }
    }

    private func validateStagedCandidate(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate,
        operationID: VaultTransactionOperationID,
        vaultKey: Data
    ) throws {
        let manifestData = try exactData(
            try objectStore.readStagedManifest(
                digest: candidate.genesis.manifestDigest,
                operationID: operationID,
                maximumBytes: limits.maximumManifestBytes
            ),
            expected: candidate.genesis.manifestData,
            error: .stagedObjectUnavailable
        )
        _ = try validateManifest(
            manifestData,
            candidate: candidate,
            vaultKey: vaultKey,
            unavailableError: .stagedObjectUnavailable
        )
        try validateEntries(
            candidate,
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
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate,
        vaultKey: Data
    ) throws {
        try validateEntries(
            candidate,
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

    private func validateDeviceWrapper(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        vaultKey: Data
    ) throws {
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: candidate.genesis.body.vaultID,
            envelopeDigest: candidate.genesis.manifestDigest
        )
        let validationSession = V3DeviceWrappedVaultKeySessionStore()
        defer { validationSession.invalidate() }
        _ = try checkpointUnlocker.unlock(
            checkpoint: checkpoint,
            manifestData: candidate.genesis.manifestData,
            identity: identity,
            session: validationSession,
            reason: "Verify this Mac can reopen its permanent version 3 vault key."
        )
        guard try validationSession.load(
            vaultID: checkpoint.vaultID,
            keyID: candidate.genesis.body.keyID
        ) == vaultKey else {
            throw V3DeviceWrappedGenesisInstallError
                .verifiedReopenMismatch
        }
    }

    private func validateEntries(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate,
        vaultKey: Data,
        read: (V3DeviceWrappedGenesisPublicationCandidate.Entry) throws
            -> V3RepositoryObjectRead,
        unavailableError: V3DeviceWrappedGenesisInstallError
    ) throws {
        for entry in candidate.entries {
            let data = try exactData(
                try read(entry),
                expected: entry.encryptedEntry.canonicalBytes,
                error: unavailableError
            )
            let plaintext = try entryCipher.openTrusted(
                data,
                vaultID: candidate.genesis.body.vaultID,
                manifestEntry: entry.manifestEntry,
                vaultKey: vaultKey
            )
            guard plaintext == entry.source.plaintext else {
                throw V3DeviceWrappedGenesisInstallError
                    .verifiedReopenMismatch
            }
        }
    }

    private func validateManifest(
        _ data: Data,
        candidate: V3DeviceWrappedGenesisPublicationCandidate,
        vaultKey: Data,
        unavailableError: V3DeviceWrappedGenesisInstallError
    ) throws -> V3DeviceWrappedManifestEnvelope {
        let envelope: V3DeviceWrappedManifestEnvelope
        do {
            envelope = try envelopeCodec.parse(data)
        } catch {
            throw unavailableError
        }
        guard envelope.parents.isEmpty,
              envelope.authorizations.isEmpty,
              envelope.body == candidate.genesis.body,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  envelope.authenticationTag,
                  canonicalContent: envelope.canonicalContentBytes,
                  vaultID: envelope.body.vaultID,
                  vaultKey: vaultKey
              )) == true
        else {
            throw unavailableError
        }
        return envelope
    }

    private func exactPublishedManifest(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate
    ) throws -> Data {
        try exactData(
            try objectStore.readManifest(
                digest: candidate.genesis.manifestDigest,
                maximumBytes: limits.maximumManifestBytes
            ),
            expected: candidate.genesis.manifestData,
            error: .publishedObjectUnavailable
        )
    }

    private func exactData(
        _ result: V3RepositoryObjectRead,
        expected: Data,
        error: V3DeviceWrappedGenesisInstallError
    ) throws -> Data {
        guard case let .available(data) = result, data == expected else {
            throw error
        }
        return data
    }

    private func verifyPermanentRuntime(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate,
        session: V3DeviceWrappedVaultKeySessionStore
    ) throws {
        let unlockRuntime = V3DeviceWrappedVaultUnlockRuntime(
            vaultID: candidate.genesis.body.vaultID,
            checkpointStore: checkpointStore,
            source: objectStore,
            cache: cache,
            identityLoader: identityManager,
            session: session
        )
        let runtime = V3DeviceWrappedReadOnlyVaultRuntime(
            source: objectStore,
            unlockRuntime: unlockRuntime
        )
        let expectedNames = candidate.entries.map(\.source.name).sorted {
            Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8))
        }
        guard try runtime.list(allowStale: false) == expectedNames else {
            throw V3DeviceWrappedGenesisInstallError
                .verifiedReopenMismatch
        }
        for entry in candidate.entries {
            let value = try runtime.read(
                name: entry.source.name,
                allowStale: false
            )
            guard value.type == entry.source.type,
                  value.plaintext == entry.source.plaintext
            else {
                throw V3DeviceWrappedGenesisInstallError
                    .verifiedReopenMismatch
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
            throw V3DeviceWrappedGenesisInstallError.sourceChanged
        }
        for entry in entries {
            guard try entryStore.loadStoredSecret(entry.name).data
                    == entry.sourceData
            else {
                throw V3DeviceWrappedGenesisInstallError.sourceChanged
            }
        }
    }

    private func requireExactCheckpoint(
        _ expected: V3ManifestCheckpoint
    ) throws {
        guard try checkpointStore.loadCheckpoint(vaultID: expected.vaultID)
                == expected.canonicalBytes
        else {
            throw V3DeviceWrappedGenesisInstallError.checkpointChanged
        }
    }

    private func removeStagingArtifacts(
        _ candidate: V3DeviceWrappedGenesisPublicationCandidate,
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
            candidate.genesis.manifestData,
            digest: candidate.genesis.manifestDigest,
            operationID: operationID
        )
        try? objectStore.removeEmptyTransactionDirectories(
            operationID: operationID,
            entryIDs: candidate.entries.map(\.manifestEntry.entryID)
        )
    }
}

extension V3DeviceWrappedGenesisInstaller:
    V3DeviceWrappedGenesisInstalling
{}

/// Adapts permanent genesis installation to the stable migration command.
///
/// The installer retains all publication and selection authority. This layer
/// supplies only the local device label and renders the completed conversion
/// through the existing service protocol.
struct V3DeviceWrappedMigrationService: V3LocalMigrationServicing {
    private let installer: any V3DeviceWrappedGenesisInstalling
    private let deviceName: String

    init(
        installer: any V3DeviceWrappedGenesisInstalling,
        deviceName: String
    ) {
        precondition(isValidV3DeviceDisplayName(deviceName))
        self.installer = installer
        self.deviceName = deviceName
    }

    func migrate(
        operationID: VaultTransactionOperationID
    ) throws -> V3LocalMigrationReport {
        let report = try installer.install(
            operationID: operationID,
            deviceName: deviceName
        )
        return V3LocalMigrationReport(
            vaultID: report.vaultID,
            entryCount: report.entryCount,
            secretCount: report.secretCount,
            totpCount: report.totpCount,
            destination: .deviceWrapped
        )
    }
}
