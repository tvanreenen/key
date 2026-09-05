import Foundation
import Testing
@testable import KeyCore

@Suite
struct V3LocalMigrationTests {
    private static let vaultKey = Data((0..<32).map(UInt8.init))
    private static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44c0"
    )
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let entryA =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let entryB =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"

    @Test
    func migrationPublishesVerifiesAndSelectsV3Last() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let entryStore = EntryStore(rootURL: root)
        try saveV2(
            "correct horse battery staple",
            name: "mail/personal",
            type: .secret,
            in: entryStore
        )
        try saveV2(
            "JBSWY3DPEHPK3PXP",
            name: "totp/work",
            type: .totp,
            in: entryStore
        )
        let original = try sourceBytes(
            names: ["mail/personal", "totp/work"],
            store: entryStore
        )
        let checkpointStore = MigrationCheckpointStore()
        let keyProvider = MigrationKeyProvider(key: Self.vaultKey)
        let selector = MigrationSelector()
        let objectStore = try migrationObjectStore(root: root)
        let service = V3LocalMigrationService(
            entryStore: entryStore,
            cipher: VaultCipher(),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            loadVaultKey: keyProvider.load,
            selectVault: selector.select,
            makeUUID: MigrationUUIDSequence([
                Self.vaultID,
                Self.entryA,
                Self.entryB
            ]).next
        )

        let report = try service.migrate(operationID: Self.operationID)

        #expect(report.vaultID == Self.vaultID)
        #expect(report.entryCount == 2)
        #expect(report.secretCount == 1)
        #expect(report.totpCount == 1)
        #expect(selector.vaultID == Self.vaultID)
        #expect(checkpointStore.checkpoint(vaultID: Self.vaultID) != nil)
        #expect(try sourceBytes(
            names: ["mail/personal", "totp/work"],
            store: entryStore
        ) == original)
        #expect(!FileManager.default.fileExists(
            atPath: root.appendingPathComponent(".transactions").path
        ))
        #expect(!keyProvider.creationFlags.contains(true))

        let runtime = V3ReadOnlyVaultRuntime(
            source: objectStore,
            vaultID: Self.vaultID,
            checkpointStore: checkpointStore,
            vaultKeyProvider: { _ in Self.vaultKey }
        )
        #expect(try runtime.list(allowStale: false) == [
            "mail/personal",
            "totp/work"
        ])
        #expect(try runtime.read(
            name: "mail/personal",
            allowStale: false
        ).plaintext == "correct horse battery staple")
        #expect(try runtime.read(
            name: "totp/work",
            allowStale: false
        ).plaintext == "JBSWY3DPEHPK3PXP")
    }

    @Test
    func blockedPreflightPublishesAndSelectsNothing() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let entryStore = EntryStore(rootURL: root)
        try saveV2(
            "value",
            name: " leading-space",
            type: .secret,
            in: entryStore
        )
        let original = try sourceBytes(
            names: [" leading-space"],
            store: entryStore
        )
        let checkpointStore = MigrationCheckpointStore()
        let selector = MigrationSelector()
        let service = V3LocalMigrationService(
            entryStore: entryStore,
            cipher: VaultCipher(),
            objectStore: try migrationObjectStore(root: root),
            checkpointStore: checkpointStore,
            loadVaultKey: MigrationKeyProvider(
                key: Self.vaultKey
            ).load,
            selectVault: selector.select,
            makeUUID: MigrationUUIDSequence([
                Self.vaultID,
                Self.entryA
            ]).next
        )

        #expect(throws: AppError.self) {
            try service.migrate(operationID: Self.operationID)
        }
        #expect(selector.vaultID == nil)
        #expect(checkpointStore.checkpoint(vaultID: Self.vaultID) == nil)
        #expect(try sourceBytes(
            names: [" leading-space"],
            store: entryStore
        ) == original)
        #expect(!FileManager.default.fileExists(
            atPath: root.appendingPathComponent("manifests").path
        ))
    }

    @Test
    func everyPreselectionInterruptionLeavesV2SelectedAndUnchanged() throws {
        let phases: [V3LocalMigrationPhase] = [
            .candidateBuilt,
            .entryStaged(index: 0),
            .manifestStaged,
            .stagedCandidateVerified,
            .entryPublished(index: 0),
            .publishedEntriesVerified,
            .manifestPublished,
            .publishedManifestVerified,
            .checkpointInstalled,
            .verifiedReopenCompleted,
            .sourceRechecked
        ]

        for phase in phases {
            let root = try temporaryDirectory()
            let entryStore = EntryStore(rootURL: root)
            try saveV2(
                "value",
                name: "mail/personal",
                type: .secret,
                in: entryStore
            )
            let original = try sourceBytes(
                names: ["mail/personal"],
                store: entryStore
            )
            let checkpointStore = MigrationCheckpointStore()
            let selector = MigrationSelector()
            let observer = ThrowingMigrationPhaseObserver(phase: phase)
            let service = V3LocalMigrationService(
                entryStore: entryStore,
                cipher: VaultCipher(),
                objectStore: try migrationObjectStore(root: root),
                checkpointStore: checkpointStore,
                loadVaultKey: MigrationKeyProvider(
                    key: Self.vaultKey
                ).load,
                selectVault: selector.select,
                makeUUID: MigrationUUIDSequence([
                    Self.vaultID,
                    Self.entryA
                ]).next,
                phaseObserver: observer
            )

            #expect(throws: AppError.self) {
                try service.migrate(operationID: Self.operationID)
            }
            #expect(selector.vaultID == nil)
            #expect(try sourceBytes(
                names: ["mail/personal"],
                store: entryStore
            ) == original)
            try FileManager.default.removeItem(at: root)
        }
    }

    @Test
    func sourceChangeAfterVerifiedReopenPreventsSelection() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let entryStore = EntryStore(rootURL: root)
        try saveV2(
            "original",
            name: "mail/personal",
            type: .secret,
            in: entryStore
        )
        let replacement = try VaultCipher().encrypt(
            "changed by transport",
            keyData: Self.vaultKey
        )
        let replacementData = try JSONEncoder().encode(replacement)
        let sourceURL = try entryStore.url(for: "mail/personal")
        let selector = MigrationSelector()
        let observer = SourceChangingMigrationObserver(
            sourceURL: sourceURL,
            replacementData: replacementData
        )
        let service = V3LocalMigrationService(
            entryStore: entryStore,
            cipher: VaultCipher(),
            objectStore: try migrationObjectStore(root: root),
            checkpointStore: MigrationCheckpointStore(),
            loadVaultKey: MigrationKeyProvider(
                key: Self.vaultKey
            ).load,
            selectVault: selector.select,
            makeUUID: MigrationUUIDSequence([
                Self.vaultID,
                Self.entryA
            ]).next,
            phaseObserver: observer
        )

        #expect(throws: V3LocalMigrationError.sourceChanged) {
            try service.migrate(operationID: Self.operationID)
        }
        #expect(selector.vaultID == nil)
        #expect(try Data(contentsOf: sourceURL) == replacementData)
    }

    @Test
    func emptyMigrationUsesAnExistingKeyWithoutCreatingOne() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let keyProvider = MigrationKeyProvider(key: Self.vaultKey)
        let selector = MigrationSelector()
        let service = V3LocalMigrationService(
            entryStore: EntryStore(rootURL: root),
            cipher: VaultCipher(),
            objectStore: try migrationObjectStore(root: root),
            checkpointStore: MigrationCheckpointStore(),
            loadVaultKey: keyProvider.load,
            selectVault: selector.select,
            makeUUID: MigrationUUIDSequence([Self.vaultID]).next
        )

        let report = try service.migrate(operationID: Self.operationID)

        #expect(report.entryCount == 0)
        #expect(selector.vaultID == Self.vaultID)
        #expect(!keyProvider.creationFlags.isEmpty)
        #expect(!keyProvider.creationFlags.contains(true))
    }

    @Test
    func emptyMigrationDoesNotCreateAKeyWhenAnEntryArrives() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let entryStore = EntryStore(rootURL: root)
        let destination = try entryStore.url(for: "mail/arrived")
        let encrypted = try VaultCipher().encrypt(
            "delivered by the provider",
            keyData: Self.vaultKey
        )
        let provider = DeliveringMissingMigrationKeyProvider(
            destination: destination,
            data: try JSONEncoder().encode(encrypted)
        )
        let selector = MigrationSelector()
        let checkpointStore = MigrationCheckpointStore()
        let service = V3LocalMigrationService(
            entryStore: entryStore,
            cipher: VaultCipher(),
            objectStore: try migrationObjectStore(root: root),
            checkpointStore: checkpointStore,
            loadVaultKey: provider.load,
            selectVault: selector.select,
            makeUUID: MigrationUUIDSequence([Self.vaultID]).next
        )

        #expect(throws: AppError.operationRefused(
            "The version 2 vault is empty and has no existing vault key. There is nothing to migrate yet; wait for synchronization to finish or add an entry before retrying."
        )) {
            try service.migrate(operationID: Self.operationID)
        }
        #expect(provider.creationFlags == [false])
        #expect(selector.vaultID == nil)
        #expect(checkpointStore.checkpoint(vaultID: Self.vaultID) == nil)
        #expect(try entryStore.exists("mail/arrived"))
        #expect(!FileManager.default.fileExists(
            atPath: root.appendingPathComponent("manifests").path
        ))
    }

    @Test
    func configSelectionIsGuardedAndNotGenerallySettable() throws {
        let home = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let root = home.appendingPathComponent("Vault", isDirectory: true)
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        try writeLegacyTestConfiguration(home: home, root: root)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        let selected = try configStore.selectV3Vault(
            vaultID: Self.vaultID,
            expectedRootHandle: rootHandle,
            expectedKeychainMode: .local
        )

        #expect(selected.vaultID == Self.vaultID)
        #expect(try configStore.load().vaultID == Self.vaultID)
        #expect(throws: AppError.self) {
            try configStore.selectV3Vault(
                vaultID:
                    "018f4d38-7d5a-7b20-b0f1-97d6e96c44c9",
                expectedRootHandle: rootHandle,
                expectedKeychainMode: .local
            )
        }

        let otherHome = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: otherHome) }
        let otherRoot = otherHome.appendingPathComponent(
            "Vault",
            isDirectory: true
        )
        let changedStore = KeyConfigStore(homeDirectoryURL: otherHome)
        try writeLegacyTestConfiguration(home: otherHome, root: otherRoot)
        _ = try changedStore.setValue("icloud", for: .keychainMode)
        let changedRootHandle = try VaultRootDirectoryHandle(
            opening: otherRoot
        )

        #expect(throws: AppError.self) {
            try changedStore.selectV3Vault(
                vaultID: Self.vaultID,
                expectedRootHandle: changedRootHandle,
                expectedKeychainMode: .local
            )
        }
        #expect(try changedStore.load().vaultID == nil)

        let replacedHome = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: replacedHome) }
        let replacedRoot = replacedHome.appendingPathComponent(
            "Vault",
            isDirectory: true
        )
        let movedRoot = replacedHome.appendingPathComponent(
            "Original Vault",
            isDirectory: true
        )
        let replacedStore = KeyConfigStore(
            homeDirectoryURL: replacedHome
        )
        try writeLegacyTestConfiguration(home: replacedHome, root: replacedRoot)
        let originalRootHandle = try VaultRootDirectoryHandle(
            opening: replacedRoot
        )
        try FileManager.default.moveItem(
            at: replacedRoot,
            to: movedRoot
        )
        try FileManager.default.createDirectory(
            at: replacedRoot,
            withIntermediateDirectories: false
        )

        #expect(throws: VaultRootDirectoryHandleError.configuredRootChanged(
            path: replacedRoot.path(percentEncoded: false)
        )) {
            try replacedStore.selectV3Vault(
                vaultID: Self.vaultID,
                expectedRootHandle: originalRootHandle,
                expectedKeychainMode: .local
            )
        }
        #expect(try replacedStore.load().vaultID == nil)
    }

    @Test
    func helperSerializesMigrationAndRequiresRestartAfterSelection() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let migration = RecordingMigrationService()
        let owner = RecordingMigrationMutationOwner()
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: owner,
            migrationService: migration
        )

        let response = handler.handle(.migrationApply)

        #expect(response.exitCode == EXIT_SUCCESS)
        #expect(response.value?.contains("Migration completed.") == true)
        #expect(owner.kinds == [.migrateToV3])
        #expect(migration.operationIDs == [Self.operationID])
        #expect(handler.handle(.list).exitCode == EXIT_FAILURE)
    }

    private func saveV2(
        _ plaintext: String,
        name: String,
        type: SecretEntryType,
        in store: EntryStore
    ) throws {
        let encrypted = try VaultCipher().encrypt(
            plaintext,
            type: type,
            keyData: Self.vaultKey
        )
        let destination = try store.url(for: name)
        try FileManager.default.createDirectory(
            at: destination.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try JSONEncoder().encode(encrypted).write(
            to: destination,
            options: .atomic
        )
    }

    private func sourceBytes(
        names: [String],
        store: EntryStore
    ) throws -> [String: Data] {
        try Dictionary(uniqueKeysWithValues: names.map {
            ($0, try store.loadStoredSecret($0).data)
        })
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    private func migrationObjectStore(
        root: URL
    ) throws -> V3FilesystemTransactionArtifactStore {
        V3FilesystemTransactionArtifactStore(
            rootHandle: try VaultRootDirectoryHandle(opening: root)
        )
    }
}

private final class MigrationUUIDSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String]

    init(_ values: [String]) {
        self.values = values
    }

    func next() -> String {
        lock.withLock {
            precondition(!values.isEmpty)
            return values.removeFirst()
        }
    }
}

private final class MigrationKeyProvider: @unchecked Sendable {
    private let lock = NSLock()
    private let key: Data
    private var flags: [Bool] = []

    init(key: Data) {
        self.key = key
    }

    var creationFlags: [Bool] {
        lock.withLock { flags }
    }

    func load(
        reason _: String,
        createIfMissing: Bool
    ) throws -> Data {
        lock.withLock {
            flags.append(createIfMissing)
            return key
        }
    }
}

private final class DeliveringMissingMigrationKeyProvider:
    @unchecked Sendable
{
    private let lock = NSLock()
    private let destination: URL
    private let data: Data
    private var flags: [Bool] = []

    init(destination: URL, data: Data) {
        self.destination = destination
        self.data = data
    }

    var creationFlags: [Bool] {
        lock.withLock { flags }
    }

    func load(
        reason _: String,
        createIfMissing: Bool
    ) throws -> Data {
        try lock.withLock {
            flags.append(createIfMissing)
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: destination, options: .atomic)
            throw AppError.entryNotFound("Vault key does not exist yet.")
        }
    }
}

private final class MigrationSelector: @unchecked Sendable {
    private let lock = NSLock()
    private var selected: String?

    var vaultID: String? {
        lock.withLock { selected }
    }

    func select(_ vaultID: String) throws {
        try lock.withLock {
            guard selected == nil else {
                throw AppError.operationRefused(
                    "A vault was already selected."
                )
            }
            selected = vaultID
        }
    }
}

private final class MigrationCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var checkpoints: [String: Data] = [:]

    func loadCheckpoint(vaultID: String) throws -> Data? {
        lock.withLock { checkpoints[vaultID] }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {
        try lock.withLock {
            guard checkpoints[vaultID] == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            checkpoints[vaultID] = checkpoint
        }
    }

    func checkpoint(vaultID: String) -> Data? {
        lock.withLock { checkpoints[vaultID] }
    }
}

private final class ThrowingMigrationPhaseObserver:
    V3LocalMigrationPhaseObserving,
    @unchecked Sendable
{
    let phase: V3LocalMigrationPhase

    init(phase: V3LocalMigrationPhase) {
        self.phase = phase
    }

    func didReach(
        _ phase: V3LocalMigrationPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        guard phase == self.phase else {
            return
        }
        throw AppError.service("Simulated migration interruption.")
    }
}

private final class SourceChangingMigrationObserver:
    V3LocalMigrationPhaseObserving,
    @unchecked Sendable
{
    private let sourceURL: URL
    private let replacementData: Data

    init(sourceURL: URL, replacementData: Data) {
        self.sourceURL = sourceURL
        self.replacementData = replacementData
    }

    func didReach(
        _ phase: V3LocalMigrationPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        guard phase == .verifiedReopenCompleted else {
            return
        }
        try replacementData.write(to: sourceURL, options: .atomic)
    }
}

private final class RecordingMigrationService:
    V3LocalMigrationServicing,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var recorded: [VaultTransactionOperationID] = []

    var operationIDs: [VaultTransactionOperationID] {
        lock.withLock { recorded }
    }

    func migrate(
        operationID: VaultTransactionOperationID
    ) throws -> V3LocalMigrationReport {
        lock.withLock {
            recorded.append(operationID)
        }
        return V3LocalMigrationReport(
            vaultID:
                "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3",
            entryCount: 0,
            secretCount: 0,
            totpCount: 0,
            destination: .releasedAlpha
        )
    }
}

private final class RecordingMigrationMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var recordedKinds: [VaultTransactionMutationKind] = []

    var kinds: [VaultTransactionMutationKind] {
        lock.withLock { recordedKinds }
    }

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        lock.withLock {
            recordedKinds.append(kind)
        }
        return try mutation(VaultTransactionMutationContext(
            operationID: try VaultTransactionOperationID(
                validating:
                    "018f4d38-7d5a-7b20-b0f1-97d6e96c44c0"
            ),
            kind: kind
        ))
    }
}
