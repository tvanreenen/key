import Foundation
import Testing
@testable import KeyCore

@Suite
struct V3ReadOnlyServiceIntegrationTests {
    @Test
    func handlerRoutesLogicalReadsAndListsThroughSelectedV3Runtime() throws {
        let root = temporaryV3ServiceDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let reader = RecordingV3VaultReader()
        let handler = KeyServiceHandler(
            keyStore: RecordingV3VaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: VaultTransactionMutationOwner(),
            vaultUXService: ReadOnlyV3UXService(),
            vaultReader: reader,
            configuredVaultID:
                "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        )

        let read = handler.handle(.get(
            name: "mail/personal",
            allowStale: true
        ))
        #expect(read.value == "v3 value")
        #expect(reader.readRequests == [
            V3ReadRequest(name: "mail/personal", allowStale: true)
        ])

        let list = handler.handle(.list)
        #expect(list.value == "mail/personal\ntotp/work\n")
        #expect(reader.listRequests == [false])
    }

    @Test
    func selectedV3ICloudUnlockBypassesLegacyKeychainRepair() throws {
        let root = temporaryV3ServiceDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let keys = RecordingV3VaultKeyStore()
        let reader = RecordingV3VaultReader()
        let handler = KeyServiceHandler(
            keyStore: keys,
            entryStore: EntryStore(rootURL: root),
            keychainMode: .icloud,
            mutationOwner: VaultTransactionMutationOwner(),
            vaultUXService: ReadOnlyV3UXService(),
            vaultReader: reader,
            configuredVaultID:
                "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        )

        #expect(handler.handle(.unlock) == .success())
        #expect(reader.unlockCount == 1)
        #expect(keys.createIfMissingValues.isEmpty)
        #expect(keys.storeCount == 0)
    }

    @Test
    func shippingFactorySelectsReadOnlyV3WithoutTouchingKeyState() throws {
        let home = temporaryV3ServiceDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let root = home.appendingPathComponent(
            "Vault",
            isDirectory: true
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        let initial = try configStore.setValue(
            root.path(percentEncoded: false),
            for: .vaultDir
        )
        let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        try """
        # key configuration
        vault_dir = "\(root.path(percentEncoded: false))"
        keychain_mode = "local"
        vault_id = "\(vaultID)"
        """.write(
            to: initial.configFileURL,
            atomically: true,
            encoding: .utf8
        )
        let keys = RecordingV3VaultKeyStore()
        let handler = try KeyServiceHandler.live(
            keyStore: keys,
            keyConfiguration: configStore.load(),
            configStore: configStore,
            runtimeConfiguration: testV3RuntimeConfiguration()
        )

        let mutation = handler.handle(.addManual(
            name: "mail/new",
            secret: "value",
            type: .secret
        ))
        #expect(mutation.errorCode == .operationRefused)
        #expect(try EntryStore(rootURL: root).listEntries().isEmpty)
        #expect(keys.createIfMissingValues.isEmpty)
        #expect(keys.storeCount == 0)
    }

    @Test
    func shippingFactoryWithoutVaultIDRetainsV2UnlockBehavior() throws {
        let home = temporaryV3ServiceDirectory()
        defer { try? FileManager.default.removeItem(at: home) }
        let root = home.appendingPathComponent(
            "Vault",
            isDirectory: true
        )
        let configStore = KeyConfigStore(homeDirectoryURL: home)
        let configuration = try configStore.setValue(
            root.path(percentEncoded: false),
            for: .vaultDir
        )
        let keys = RecordingV3VaultKeyStore()
        let handler = try KeyServiceHandler.live(
            keyStore: keys,
            keyConfiguration: configuration,
            configStore: configStore,
            runtimeConfiguration: testV3RuntimeConfiguration()
        )

        let response = handler.handle(.unlock)
        #expect(response == .success())
        #expect(keys.createIfMissingValues == [true])
    }

    @Test
    func selectedV3BlocksLegacyMutationsMigrationAndKeyModeChanges() throws {
        let root = temporaryV3ServiceDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let handler = KeyServiceHandler(
            keyStore: RecordingV3VaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: VaultTransactionMutationOwner(),
            vaultUXService: ReadOnlyV3UXService(),
            vaultReader: RecordingV3VaultReader(),
            configuredVaultID:
                "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
        )

        let mutation = handler.handle(.addManual(
            name: "mail/new",
            secret: "value",
            type: .secret
        ))
        #expect(mutation.errorCode == .operationRefused)
        #expect(try EntryStore(rootURL: root).listEntries().isEmpty)

        #expect(
            handler.handle(.migrationPreflight).errorCode
                == .operationRefused
        )
        #expect(
            handler.handle(.setKeychainMode(.icloud)).errorCode
                == .operationRefused
        )
    }
}

private struct V3ReadRequest: Equatable, Sendable {
    let name: String
    let allowStale: Bool
}

private final class RecordingV3VaultReader:
    VaultReadServicing,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var unlocks = 0
    private var reads: [V3ReadRequest] = []
    private var lists: [Bool] = []

    var unlockCount: Int {
        lock.withLock { unlocks }
    }

    var readRequests: [V3ReadRequest] {
        lock.withLock { reads }
    }

    var listRequests: [Bool] {
        lock.withLock { lists }
    }

    func unlock() throws {
        lock.withLock {
            unlocks += 1
        }
    }

    func read(
        name: String,
        allowStale: Bool
    ) throws -> VaultReadValue {
        lock.withLock {
            reads.append(V3ReadRequest(
                name: name,
                allowStale: allowStale
            ))
        }
        return VaultReadValue(type: .secret, plaintext: "v3 value")
    }

    func list(allowStale: Bool) throws -> [String] {
        lock.withLock {
            lists.append(allowStale)
        }
        return ["mail/personal", "totp/work"]
    }
}

private final class RecordingV3VaultKeyStore:
    VaultKeyStoring,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var creationFlags: [Bool] = []
    private var stores = 0

    var createIfMissingValues: [Bool] {
        lock.withLock { creationFlags }
    }

    var storeCount: Int {
        lock.withLock { stores }
    }

    func loadKey(
        mode _: KeychainMode,
        reason _: String,
        createIfMissing: Bool
    ) throws -> Data {
        lock.withLock {
            creationFlags.append(createIfMissing)
        }
        return Data(repeating: 7, count: 32)
    }

    func keyExists(mode _: KeychainMode) throws -> Bool {
        true
    }

    func storeKey(
        _: Data,
        mode _: KeychainMode,
        overwriteExisting _: Bool
    ) throws {
        lock.withLock {
            stores += 1
        }
    }

    func invalidate() {}
}

private struct ReadOnlyV3UXService: VaultUXServicing {
    func status() throws -> VaultStatus {
        VaultStatus(
            format: .version3,
            health: .ready,
            entries: .effective(2)
        )
    }

    func authorizeRead(
        name _: String,
        allowStale _: Bool
    ) throws {}

    func authorizeMutation() throws {
        throw AppError.operationRefused(
            "Version 3 vault writes are not enabled."
        )
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
        throw VaultUXServiceError.conflictVersionNotFound
    }

    func resolve(_: [VaultConflictResolution]) throws {
        throw AppError.operationRefused(
            "Version 3 vault writes are not enabled."
        )
    }
}

private func temporaryV3ServiceDirectory() -> URL {
    let root = URL(
        fileURLWithPath: NSTemporaryDirectory(),
        isDirectory: true
    ).appendingPathComponent(UUID().uuidString, isDirectory: true)
    try? FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: true
    )
    return root
}

private func testV3RuntimeConfiguration() -> RuntimeConfiguration {
    RuntimeConfiguration(
        vaultService: "work.tvr.key.tests.v3",
        vaultAccount: "runtime",
        keychainAccessGroup: nil,
        helperMachServiceName: "work.tvr.key.tests.agent",
        helperBundleIdentifier: "work.tvr.key.tests.helper",
        launchAgentPlistName: "work.tvr.key.tests.agent.plist",
        useDataProtectionKeychain: false
    )
}
