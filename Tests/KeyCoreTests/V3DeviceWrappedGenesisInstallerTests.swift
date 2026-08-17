import CryptoKit
import Foundation
import Testing
@testable import KeyCore

private let runLargeMigrationQualification =
    ProcessInfo.processInfo.environment["KEY_RUN_MIGRATION_QUALIFICATION"] == "1"

@Suite
struct V3DeviceWrappedGenesisInstallerTests {
    private static let v2Key = Data((0..<32).map(UInt8.init))
    private static let newVaultKey = Data((32..<64).map(UInt8.init))
    private static let operationID = try! VaultTransactionOperationID(
        validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c4500"
    )
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c4501"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c4502"
    private static let entryA =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c4503"
    private static let entryB =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c4504"

    @Test
    func installsExactPermanentGenesisAndSelectsItLast() throws {
        let fixture = try Fixture(entryCount: 2)
        defer { fixture.remove() }
        let sourceBefore = try fixture.sourceBytes()

        let report = try fixture.installer().install(
            operationID: Self.operationID,
            deviceName: "Test Mac"
        )

        #expect(report.vaultID == Self.vaultID)
        #expect(report.deviceID == fixture.identityCreator.deviceID)
        #expect(report.entryCount == 2)
        #expect(report.secretCount == 1)
        #expect(report.totpCount == 1)
        #expect(fixture.selector.vaultID == Self.vaultID)
        #expect(fixture.selector.checkpointWasInstalled)
        #expect(fixture.selector.cacheWasInstalled)
        #expect(fixture.selector.sessionWasInstalled)
        #expect(fixture.checkpointStore.checkpoint(Self.vaultID) != nil)
        #expect(fixture.cache.manifestData != nil)
        #expect(fixture.session.hasResidentKey)
        #expect(try fixture.sourceBytes() == sourceBefore)
        #expect(fixture.v2KeyProvider.creationFlags == [false])
        #expect(fixture.identityCreator.createdVaultIDs == [Self.vaultID])

        let checkpoint = try #require(
            fixture.checkpointStore.checkpoint(Self.vaultID)
        )
        let manifestData = try #require(fixture.cache.manifestData)
        #expect(Data(SHA256.hash(data: manifestData)) == checkpoint.envelopeDigest)
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            manifestData
        )
        #expect(envelope.parents.isEmpty)
        #expect(envelope.authorizations.isEmpty)
        #expect(envelope.body.devices.count == 1)
        #expect(envelope.body.devices[0].status == .active)
        #expect(envelope.body.wrappedKeys.count == 1)
        #expect(envelope.body.entries.map(\.name) == [
            "mail/personal", "totp/work",
        ])
        #expect(
            try fixture.session.load(
                vaultID: Self.vaultID,
                keyID: envelope.body.keyID
            ) == Self.newVaultKey
        )
        #expect(!FileManager.default.fileExists(
            atPath: fixture.root.appendingPathComponent(".transactions").path
        ))
    }

    @Test(.enabled(if: runLargeMigrationQualification))
    func migratesRealisticLargeMixedSnapshotWithoutChangingV2Source() throws {
        let sources = (0..<300).map { index in
            let group = String(format: "%02d", index / 25)
            let item = String(format: "%03d", index)
            if index.isMultiple(of: 5) {
                return Fixture.Source(
                    plaintext: "JBSWY3DPEHPK3PXP",
                    name: "totp/group-\(group)/service-\(item)",
                    type: .totp
                )
            }
            return Fixture.Source(
                plaintext: "credential-\(item)\nvalue-🔐-\(index * 17)",
                name: "accounts/group-\(group)/service-\(item)",
                type: .secret
            )
        }
        let fixture = try Fixture(sources: sources)
        defer { fixture.remove() }
        let sourceBefore = try fixture.sourceBytes()

        let report = try fixture.installer().install(
            operationID: Self.operationID,
            deviceName: "Qualification Mac"
        )

        #expect(report.entryCount == 300)
        #expect(report.secretCount == 240)
        #expect(report.totpCount == 60)
        #expect(fixture.selector.vaultID == Self.vaultID)
        #expect(try fixture.sourceBytes() == sourceBefore)
        #expect(fixture.v2KeyProvider.creationFlags == [false])
        #expect(!FileManager.default.fileExists(
            atPath: fixture.root.appendingPathComponent(".transactions").path
        ))

        let manifestData = try #require(fixture.cache.manifestData)
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            manifestData
        )
        #expect(envelope.body.entries.count == sources.count)
        #expect(
            Set(envelope.body.entries.map(\.name))
                == Set(sources.map(\.name))
        )
        #expect(
            envelope.body.entries.filter { $0.type == .secret }.count == 240
        )
        #expect(
            envelope.body.entries.filter { $0.type == .totp }.count == 60
        )
    }

    @Test
    func migrationAdapterUsesPermanentInstallerAndReportsTheNewProfile() throws {
        let installReport = V3DeviceWrappedGenesisInstallReport(
            vaultID: Self.vaultID,
            deviceID: "sha256:device",
            entryCount: 2,
            secretCount: 1,
            totpCount: 1
        )
        let installer = RecordingGenesisInstaller(report: installReport)
        let service = V3DeviceWrappedMigrationService(
            installer: installer,
            deviceName: "Tim's Mac"
        )

        let report = try service.migrate(operationID: Self.operationID)

        #expect(installer.operationIDs == [Self.operationID])
        #expect(installer.deviceNames == ["Tim's Mac"])
        #expect(report == V3LocalMigrationReport(
            vaultID: Self.vaultID,
            entryCount: 2,
            secretCount: 1,
            totpCount: 1,
            destination: .deviceWrapped
        ))
        #expect(report.rendered == """
            Migration completed.
            Entries migrated: 2 (1 secret, 1 TOTP entry).
            This Mac now uses permanent version 3 vault '\(Self.vaultID)'.
            Its new vault key is wrapped to this Mac's Secure Enclave identity and exists in plaintext only in Key Agent's unlocked memory session.
            The version 2 source files were retained unchanged. No cleanup was performed.
            Keep that version 2 copy while you validate the migration. It can help you return to version 2, but it cannot recover this version 3 vault.
            Other devices are not converted automatically. After they install a compatible release, enroll at least one other Mac before relying on version 3.
            If every enrolled Mac is lost, synchronized version 3 files cannot unlock or recover the vault.

            """)
    }

    @Test
    func everyPreselectionInterruptionRetainsV2AndNoSessionKey() throws {
        let phases: [V3DeviceWrappedGenesisInstallPhase] = [
            .identityCreated,
            .candidateBuilt,
            .entryStaged(index: 0),
            .manifestStaged,
            .stagedCandidateVerified,
            .deviceWrapperVerified,
            .entryPublished(index: 0),
            .publishedEntriesVerified,
            .manifestPublished,
            .publishedManifestVerified,
            .checkpointInstalled,
            .manifestCached,
            .sessionInstalled,
            .verifiedReopenCompleted,
            .sourceRechecked,
            .localStateRechecked,
        ]

        for phase in phases {
            let fixture = try Fixture(entryCount: 1)
            let sourceBefore = try fixture.sourceBytes()
            let observer = ThrowingInstallObserver(phase: phase)

            #expect(throws: TestInstallError.interrupted) {
                try fixture.installer(phaseObserver: observer).install(
                    operationID: Self.operationID,
                    deviceName: "Test Mac"
                )
            }
            #expect(fixture.selector.vaultID == nil)
            #expect(!fixture.session.hasResidentKey)
            #expect(try fixture.sourceBytes() == sourceBefore)
            fixture.remove()
        }
    }

    @Test
    func sourceChangeAfterVerifiedReopenPreventsSelection() throws {
        let fixture = try Fixture(entryCount: 1)
        defer { fixture.remove() }
        let observer = SourceChangingInstallObserver(
            sourceURL: try fixture.entryStore.url(for: "mail/personal"),
            replacement: try fixture.v2Data(
                plaintext: "changed during creation",
                type: .secret
            )
        )

        #expect(throws: V3DeviceWrappedGenesisInstallError.sourceChanged) {
            try fixture.installer(phaseObserver: observer).install(
                operationID: Self.operationID,
                deviceName: "Test Mac"
            )
        }
        #expect(fixture.selector.vaultID == nil)
        #expect(!fixture.session.hasResidentKey)
    }

    @Test
    func checkpointChangeBeforeSelectionKeepsV2Selected() throws {
        let fixture = try Fixture(entryCount: 1)
        defer { fixture.remove() }
        let replacement = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 0xa5, count: 32)
        )
        let observer = CheckpointChangingInstallObserver(
            store: fixture.checkpointStore,
            replacement: replacement
        )

        #expect(throws: V3DeviceWrappedGenesisInstallError.checkpointChanged) {
            try fixture.installer(phaseObserver: observer).install(
                operationID: Self.operationID,
                deviceName: "Test Mac"
            )
        }
        #expect(fixture.selector.vaultID == nil)
        #expect(!fixture.session.hasResidentKey)
    }

    @Test
    func emptyVaultRequiresExistingV2KeyBeforeCreatingGenesis() throws {
        let fixture = try Fixture(entryCount: 0)
        defer { fixture.remove() }

        let report = try fixture.installer().install(
            operationID: Self.operationID,
            deviceName: "Empty Mac"
        )

        #expect(report.entryCount == 0)
        #expect(fixture.v2KeyProvider.creationFlags == [false])
        #expect(fixture.selector.vaultID == Self.vaultID)
        let manifest = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            #require(fixture.cache.manifestData)
        )
        #expect(manifest.body.entries.isEmpty)
    }

    @Test
    func emptyVaultWithoutExistingKeyCreatesNoPermanentState() throws {
        let fixture = try Fixture(entryCount: 0)
        defer { fixture.remove() }
        fixture.v2KeyProvider.error = AppError.entryNotFound("missing")

        #expect(throws: AppError.operationRefused(
            "The version 2 vault is empty and has no existing vault key. There is nothing to convert yet; wait for synchronization to finish or add an entry before retrying."
        )) {
            try fixture.installer().install(
                operationID: Self.operationID,
                deviceName: "Empty Mac"
            )
        }
        #expect(fixture.v2KeyProvider.creationFlags == [false])
        #expect(fixture.identityCreator.createdVaultIDs.isEmpty)
        #expect(fixture.selector.vaultID == nil)
        #expect(fixture.checkpointStore.checkpoint(Self.vaultID) == nil)
    }

    @Test
    func firstEntryDeliveryDuringEmptyKeyCheckStopsBeforeCreation() throws {
        let fixture = try Fixture(entryCount: 0)
        defer { fixture.remove() }
        let destination = try fixture.entryStore.url(for: "mail/arrived")
        let provider = DeliveringInstallV2KeyProvider(
            destination: destination,
            data: try fixture.v2Data(
                plaintext: "delivered by provider",
                type: .secret
            ),
            key: Self.v2Key
        )

        #expect(throws: V3DeviceWrappedGenesisInstallError.sourceChanged) {
            try fixture.installer(loadV2VaultKey: provider.load).install(
                operationID: Self.operationID,
                deviceName: "Empty Mac"
            )
        }
        #expect(provider.creationFlags == [false])
        #expect(try fixture.entryStore.exists("mail/arrived"))
        #expect(fixture.identityCreator.createdVaultIDs.isEmpty)
        #expect(fixture.selector.vaultID == nil)
        #expect(fixture.checkpointStore.checkpoint(Self.vaultID) == nil)
    }

    @Test
    func invalidGeneratedKeyStopsBeforeIdentityOrPublication() throws {
        let fixture = try Fixture(entryCount: 1)
        defer { fixture.remove() }

        #expect(
            throws: V3DeviceWrappedGenesisInstallError.invalidGeneratedKey
        ) {
            try fixture.installer(vaultKey: Data(repeating: 0, count: 31))
                .install(
                    operationID: Self.operationID,
                    deviceName: "Test Mac"
                )
        }
        #expect(fixture.identityCreator.createdVaultIDs.isEmpty)
        #expect(fixture.selector.vaultID == nil)
        #expect(fixture.checkpointStore.checkpoint(Self.vaultID) == nil)
        #expect(!fixture.session.hasResidentKey)
    }

    @Test
    func identityMustReloadBeforeImmutablePublication() throws {
        let fixture = try Fixture(entryCount: 1)
        defer { fixture.remove() }
        let manager = UnreloadableInstallIdentityManager()

        #expect(
            throws: V3DeviceWrappedGenesisInstallError
                .persistedIdentityUnavailable
        ) {
            try fixture.installer(identityManager: manager).install(
                operationID: Self.operationID,
                deviceName: "Test Mac"
            )
        }
        #expect(fixture.selector.vaultID == nil)
        #expect(fixture.checkpointStore.checkpoint(Self.vaultID) == nil)
        #expect(!fixture.session.hasResidentKey)
        #expect(!FileManager.default.fileExists(
            atPath: fixture.root.appendingPathComponent("manifests").path
        ))
    }

    @Test
    func unusableDeviceWrapperStopsBeforeImmutablePublication() throws {
        let fixture = try Fixture(entryCount: 1)
        defer { fixture.remove() }
        let creator = FailingInstallIdentityCreator()

        #expect(throws: V3DeviceWrappedUnlockError.keyUnwrapFailed) {
            try fixture.installer(identityManager: creator).install(
                operationID: Self.operationID,
                deviceName: "Test Mac"
            )
        }
        #expect(fixture.selector.vaultID == nil)
        #expect(fixture.checkpointStore.checkpoint(Self.vaultID) == nil)
        #expect(!fixture.session.hasResidentKey)
        #expect(!FileManager.default.fileExists(
            atPath: fixture.root.appendingPathComponent("manifests").path
        ))
    }
}

private final class RecordingGenesisInstaller:
    V3DeviceWrappedGenesisInstalling
{
    private let lock = NSLock()
    private let report: V3DeviceWrappedGenesisInstallReport
    private var recordedOperationIDs: [VaultTransactionOperationID] = []
    private var recordedDeviceNames: [String] = []

    var operationIDs: [VaultTransactionOperationID] {
        lock.withLock { recordedOperationIDs }
    }

    var deviceNames: [String] {
        lock.withLock { recordedDeviceNames }
    }

    init(report: V3DeviceWrappedGenesisInstallReport) {
        self.report = report
    }

    func install(
        operationID: VaultTransactionOperationID,
        deviceName: String
    ) throws -> V3DeviceWrappedGenesisInstallReport {
        lock.withLock {
            recordedOperationIDs.append(operationID)
            recordedDeviceNames.append(deviceName)
        }
        return report
    }
}

private extension V3DeviceWrappedGenesisInstallerTests {
    final class Fixture {
        struct Source {
            let plaintext: String
            let name: String
            let type: SecretEntryType
        }

        private static let defaultSources = [
            Source(
                plaintext: "correct horse battery staple",
                name: "mail/personal",
                type: .secret
            ),
            Source(
                plaintext: "JBSWY3DPEHPK3PXP",
                name: "totp/work",
                type: .totp
            ),
        ]

        let root: URL
        let entryStore: EntryStore
        let objectStore: V3FilesystemTransactionArtifactStore
        let checkpointStore = InstallCheckpointStore()
        let cache = InstallManifestCache()
        let session = V3DeviceWrappedVaultKeySessionStore()
        let identityCreator = InstallIdentityCreator()
        let v2KeyProvider = InstallV2KeyProvider(key: v2Key)
        let selector: InstallSelector
        private let entryIDs: [String]

        convenience init(entryCount: Int) throws {
            precondition(entryCount <= Self.defaultSources.count)
            try self.init(
                sources: Array(Self.defaultSources.prefix(entryCount))
            )
        }

        init(sources: [Source]) throws {
            root = FileManager.default.temporaryDirectory.appendingPathComponent(
                UUID().uuidString,
                isDirectory: true
            )
            entryIDs = sources.indices.map(Self.entryID)
            try FileManager.default.createDirectory(
                at: root,
                withIntermediateDirectories: true
            )
            entryStore = EntryStore(rootURL: root)
            objectStore = V3FilesystemTransactionArtifactStore(
                rootHandle: try VaultRootDirectoryHandle(opening: root)
            )
            selector = InstallSelector(
                checkpointStore: checkpointStore,
                cache: cache,
                session: session
            )
            for source in sources {
                try saveV2(
                    source.plaintext,
                    name: source.name,
                    type: source.type
                )
            }
        }

        func installer(
            vaultKey: Data = newVaultKey,
            identityManager:
                (any V3DeviceWrappedGenesisIdentityManaging)? = nil,
            loadV2VaultKey:
                V3DeviceWrappedGenesisInstaller.V2VaultKeyProvider? = nil,
            phaseObserver: any V3DeviceWrappedGenesisInstallPhaseObserving =
                InstallNoopObserver()
        ) -> V3DeviceWrappedGenesisInstaller {
            V3DeviceWrappedGenesisInstaller(
                entryStore: entryStore,
                cipher: VaultCipher(),
                objectStore: objectStore,
                checkpointStore: checkpointStore,
                cache: cache,
                session: session,
                identityManager: identityManager ?? self.identityCreator,
                loadV2VaultKey: loadV2VaultKey ?? v2KeyProvider.load,
                selectVault: selector.select,
                makeUUID: InstallUUIDSequence([
                    vaultID, transitionID,
                ] + entryIDs).next,
                makeVaultKey: { vaultKey },
                phaseObserver: phaseObserver
            )
        }

        private static func entryID(_ index: Int) -> String {
            if index == 0 {
                return V3DeviceWrappedGenesisInstallerTests.entryA
            }
            if index == 1 {
                return V3DeviceWrappedGenesisInstallerTests.entryB
            }
            return String(
                format: "018f4d38-7d5a-7b20-b0f2-%012llx",
                UInt64(index)
            )
        }

        func sourceBytes() throws -> [String: Data] {
            var result: [String: Data] = [:]
            for name in try entryStore.listEntries() {
                result[name] = try entryStore.loadStoredSecret(name).data
            }
            return result
        }

        func v2Data(
            plaintext: String,
            type: SecretEntryType
        ) throws -> Data {
            try JSONEncoder().encode(VaultCipher().encrypt(
                plaintext,
                type: type,
                keyData: V3DeviceWrappedGenesisInstallerTests.v2Key
            ))
        }

        func remove() {
            try? FileManager.default.removeItem(at: root)
        }

        private func saveV2(
            _ plaintext: String,
            name: String,
            type: SecretEntryType
        ) throws {
            let destination = try entryStore.url(for: name)
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try v2Data(plaintext: plaintext, type: type).write(
                to: destination,
                options: .atomic
            )
        }
    }
}

private enum TestInstallError: Error {
    case interrupted
    case unexpectedCall
}

private struct InstallNoopObserver:
    V3DeviceWrappedGenesisInstallPhaseObserving
{
    func didReach(
        _: V3DeviceWrappedGenesisInstallPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

private final class ThrowingInstallObserver:
    V3DeviceWrappedGenesisInstallPhaseObserving,
    @unchecked Sendable
{
    let phase: V3DeviceWrappedGenesisInstallPhase

    init(phase: V3DeviceWrappedGenesisInstallPhase) {
        self.phase = phase
    }

    func didReach(
        _ phase: V3DeviceWrappedGenesisInstallPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        if phase == self.phase {
            throw TestInstallError.interrupted
        }
    }
}

private final class SourceChangingInstallObserver:
    V3DeviceWrappedGenesisInstallPhaseObserving,
    @unchecked Sendable
{
    let sourceURL: URL
    let replacement: Data

    init(sourceURL: URL, replacement: Data) {
        self.sourceURL = sourceURL
        self.replacement = replacement
    }

    func didReach(
        _ phase: V3DeviceWrappedGenesisInstallPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        if phase == .verifiedReopenCompleted {
            try replacement.write(to: sourceURL, options: .atomic)
        }
    }
}

private final class CheckpointChangingInstallObserver:
    V3DeviceWrappedGenesisInstallPhaseObserving,
    @unchecked Sendable
{
    let store: InstallCheckpointStore
    let replacement: V3ManifestCheckpoint

    init(
        store: InstallCheckpointStore,
        replacement: V3ManifestCheckpoint
    ) {
        self.store = store
        self.replacement = replacement
    }

    func didReach(
        _ phase: V3DeviceWrappedGenesisInstallPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        if phase == .sourceRechecked {
            store.force(replacement)
        }
    }
}

private final class InstallUUIDSequence: @unchecked Sendable {
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

private final class InstallV2KeyProvider: @unchecked Sendable {
    private let lock = NSLock()
    private let key: Data
    private var flags: [Bool] = []
    var error: Error?

    var creationFlags: [Bool] {
        lock.withLock { flags }
    }

    init(key: Data) {
        self.key = key
    }

    func load(reason _: String, createIfMissing: Bool) throws -> Data {
        try lock.withLock {
            flags.append(createIfMissing)
            if let error {
                throw error
            }
            return key
        }
    }
}

private final class DeliveringInstallV2KeyProvider: @unchecked Sendable {
    private let lock = NSLock()
    private let destination: URL
    private let data: Data
    private let key: Data
    private var flags: [Bool] = []

    var creationFlags: [Bool] { lock.withLock { flags } }

    init(destination: URL, data: Data, key: Data) {
        self.destination = destination
        self.data = data
        self.key = key
    }

    func load(reason _: String, createIfMissing: Bool) throws -> Data {
        try lock.withLock {
            flags.append(createIfMissing)
            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try data.write(to: destination, options: .atomic)
            return key
        }
    }
}

private final class InstallCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var values: [String: Data] = [:]

    func loadCheckpoint(vaultID: String) throws -> Data? {
        lock.withLock { values[vaultID] }
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws {
        try lock.withLock {
            guard values[vaultID] == expectedCheckpoint else {
                throw V3ManifestCheckpointStoreError.conflict
            }
            values[vaultID] = checkpoint
        }
    }

    func checkpoint(_ vaultID: String) -> V3ManifestCheckpoint? {
        lock.withLock {
            values[vaultID].flatMap {
                try? V3ManifestCheckpoint(canonicalBytes: $0)
            }
        }
    }

    func force(_ checkpoint: V3ManifestCheckpoint) {
        lock.withLock {
            values[checkpoint.vaultID] = checkpoint.canonicalBytes
        }
    }
}

private final class InstallManifestCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var data: Data?

    var manifestData: Data? {
        lock.withLock { data }
    }

    func load(
        for checkpoint: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        lock.withLock {
            if let data,
               Data(SHA256.hash(data: data)) == checkpoint.envelopeDigest
            {
                return .available(data)
            }
            return .missing
        }
    }

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws {
        guard Data(SHA256.hash(data: manifestData))
                == checkpoint.envelopeDigest
        else {
            throw V3CheckpointManifestCacheError.invalidManifest
        }
        lock.withLock { data = manifestData }
    }
}

private final class InstallSelector: @unchecked Sendable {
    private let lock = NSLock()
    private let checkpointStore: InstallCheckpointStore
    private let cache: InstallManifestCache
    private let session: V3DeviceWrappedVaultKeySessionStore
    private var selectedVaultID: String?
    private var observedCheckpoint = false
    private var observedCache = false
    private var observedSession = false

    var vaultID: String? { lock.withLock { selectedVaultID } }
    var checkpointWasInstalled: Bool { lock.withLock { observedCheckpoint } }
    var cacheWasInstalled: Bool { lock.withLock { observedCache } }
    var sessionWasInstalled: Bool { lock.withLock { observedSession } }

    init(
        checkpointStore: InstallCheckpointStore,
        cache: InstallManifestCache,
        session: V3DeviceWrappedVaultKeySessionStore
    ) {
        self.checkpointStore = checkpointStore
        self.cache = cache
        self.session = session
    }

    func select(_ vaultID: String) throws {
        let checkpoint = checkpointStore.checkpoint(vaultID)
        lock.withLock {
            selectedVaultID = vaultID
            observedCheckpoint = checkpoint != nil
            observedCache = cache.manifestData != nil
            observedSession = session.hasResidentKey
        }
    }
}

private final class InstallIdentityCreator:
    V3DeviceWrappedGenesisIdentityManaging,
    @unchecked Sendable
{
    private let lock = NSLock()
    private let signingKey = P256.Signing.PrivateKey()
    private let wrappingKey = P256.KeyAgreement.PrivateKey()
    private var vaultIDs: [String] = []
    private var identities: [String: InstallIdentity] = [:]

    var createdVaultIDs: [String] { lock.withLock { vaultIDs } }
    var deviceID: String {
        try! V3EnrollmentDeviceIdentity(
            displayName: "Test Mac",
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        ).deviceID
    }

    func createDeviceWrappedIdentity(
        vaultID: String,
        displayName: String,
        reason _: String
    ) throws -> any V3DeviceWrappedVaultKeyUnwrapping {
        let identity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
        let privateIdentity = InstallIdentity(
            vaultID: vaultID,
            publicIdentity: identity,
            privateKey: wrappingKey
        )
        lock.withLock {
            vaultIDs.append(vaultID)
            identities[vaultID] = privateIdentity
        }
        return privateIdentity
    }

    func loadDeviceIdentity(
        vaultID: String,
        reason _: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        lock.withLock { identities[vaultID] }
    }
}

private struct InstallIdentity: V3DeviceWrappedVaultKeyUnwrapping {
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let privateKey: P256.KeyAgreement.PrivateKey

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: privateKey,
            context: context
        )
    }
}

private final class FailingInstallIdentityCreator:
    V3DeviceWrappedGenesisIdentityManaging,
    @unchecked Sendable
{
    private let signingKey = P256.Signing.PrivateKey()
    private let wrappingKey = P256.KeyAgreement.PrivateKey()

    func createDeviceWrappedIdentity(
        vaultID: String,
        displayName: String,
        reason _: String
    ) throws -> any V3DeviceWrappedVaultKeyUnwrapping {
        FailingInstallIdentity(
            vaultID: vaultID,
            publicIdentity: try V3EnrollmentDeviceIdentity(
                displayName: displayName,
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey: wrappingKey.publicKey.x963Representation
            )
        )
    }

    func loadDeviceIdentity(
        vaultID: String,
        reason _: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        FailingInstallIdentity(
            vaultID: vaultID,
            publicIdentity: try V3EnrollmentDeviceIdentity(
                displayName: "Test Mac",
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey: wrappingKey.publicKey.x963Representation
            )
        )
    }
}

private final class UnreloadableInstallIdentityManager:
    V3DeviceWrappedGenesisIdentityManaging,
    @unchecked Sendable
{
    private let signingKey = P256.Signing.PrivateKey()
    private let wrappingKey = P256.KeyAgreement.PrivateKey()

    func createDeviceWrappedIdentity(
        vaultID: String,
        displayName: String,
        reason _: String
    ) throws -> any V3DeviceWrappedVaultKeyUnwrapping {
        InstallIdentity(
            vaultID: vaultID,
            publicIdentity: try V3EnrollmentDeviceIdentity(
                displayName: displayName,
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey: wrappingKey.publicKey.x963Representation
            ),
            privateKey: wrappingKey
        )
    }

    func loadDeviceIdentity(
        vaultID _: String,
        reason _: String
    ) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)? {
        nil
    }
}

private struct FailingInstallIdentity: V3DeviceWrappedVaultKeyUnwrapping {
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity

    func unwrapDeviceWrappedVaultKey(
        _: V3HPKEWrappedVaultKey,
        context _: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        throw TestInstallError.unexpectedCall
    }
}
