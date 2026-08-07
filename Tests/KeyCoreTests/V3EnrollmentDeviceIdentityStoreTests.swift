import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3EnrollmentDeviceIdentityStoreTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"

    @Test
    func managerCreatesPersistsReloadsAndUsesOneExactIdentity() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )

        let created = try manager.createIdentity(
            vaultID: Self.vaultID,
            displayName: "Office Mac",
            reason: "Create device identity"
        )
        #expect(operations.generateCount == 1)
        let storedBytes = try #require(store.records[Self.vaultID])
        let record = try V3EnrollmentDeviceKeyRecord(
            canonicalBytes: storedBytes
        )
        #expect(record.canonicalBytes == storedBytes)
        #expect(record.identity == created.publicIdentity)
        #expect(
            record.signingKeyRepresentation
                != record.wrappingKeyRepresentation
        )

        let loadedIdentity = try manager.loadIdentity(
            vaultID: Self.vaultID,
            reason: "Load device identity"
        )
        let loaded = try #require(loadedIdentity)
        #expect(loaded.publicIdentity == created.publicIdentity)
        #expect(operations.publicKeyLoadCount == 1)

        let invitation = try V3EnrollmentInvitation(
            vaultID: Self.vaultID,
            parentManifestDigest: Data(repeating: 0x91, count: 32),
            invitingDevice: loaded.publicIdentity,
            invitedRole: .member,
            nonce: Data(repeating: 0xA1, count: 32),
            expiresAt: 1_900_000_000
        )
        let signed = try V3EnrollmentMessageAuthenticator().sign(
            invitation,
            using: loaded,
            reason: "Sign invitation"
        )
        #expect(
            try V3EnrollmentMessageAuthenticator().verify(signed)
                .invitation == invitation
        )
    }

    @Test
    func publicInventoryIdentityDoesNotInvokePrivateKeyOperations() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )
        let created = try manager.createIdentity(
            vaultID: Self.vaultID,
            displayName: "Office Mac",
            reason: "Create device identity"
        )
        operations.failPublicKeyLoad = true

        let recorded = try manager.loadRecordedPublicIdentity(
            vaultID: Self.vaultID
        )

        #expect(recorded == created.publicIdentity)
        #expect(operations.publicKeyLoadCount == 0)
    }

    @Test
    func existingIdentityIsNeverRegeneratedOrOverwritten() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )
        _ = try manager.createIdentity(
            vaultID: Self.vaultID,
            displayName: "Office Mac",
            reason: "Create device identity"
        )
        let original = store.records[Self.vaultID]

        #expect(
            throws:
                V3EnrollmentDeviceIdentityStoreError.identityAlreadyExists
        ) {
            try manager.createIdentity(
                vaultID: Self.vaultID,
                displayName: "Replacement Mac",
                reason: "Replace device identity"
            )
        }
        #expect(operations.generateCount == 1)
        #expect(store.records[Self.vaultID] == original)
    }

    @Test
    func corruptRecordFailsWithoutGeneratingAReplacement() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        store.records[Self.vaultID] = Data("{}".utf8)
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )

        #expect(
            throws: V3EnrollmentDeviceIdentityStoreError.invalidRecord
        ) {
            try manager.loadIdentity(
                vaultID: Self.vaultID,
                reason: "Load corrupt identity"
            )
        }
        #expect(operations.generateCount == 0)
        #expect(store.records[Self.vaultID] == Data("{}".utf8))
    }

    @Test
    func substitutedKeyRepresentationFailsWithoutChangingTheRecord() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let originalKeys = try operations.keys(
            signingScalar: 1,
            wrappingScalar: 2
        )
        let substitutedKeys = try operations.keys(
            signingScalar: 3,
            wrappingScalar: 4
        )
        let identity = try V3EnrollmentDeviceIdentity(
            displayName: "Office Mac",
            signingPublicKey: originalKeys.signingPublicKey,
            wrappingPublicKey: originalKeys.wrappingPublicKey
        )
        let substitutedRecord = try V3EnrollmentDeviceKeyRecord(
            vaultID: Self.vaultID,
            identity: identity,
            signingKeyRepresentation:
                substitutedKeys.signingKeyRepresentation,
            wrappingKeyRepresentation:
                substitutedKeys.wrappingKeyRepresentation
        ).canonicalBytes
        store.records[Self.vaultID] = substitutedRecord
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )

        #expect(
            throws: V3EnrollmentDeviceIdentityStoreError.identityMismatch
        ) {
            try manager.loadIdentity(
                vaultID: Self.vaultID,
                reason: "Load substituted identity"
            )
        }
        #expect(operations.generateCount == 0)
        #expect(store.records[Self.vaultID] == substitutedRecord)
    }

    @Test
    func inaccessibleKeysFailWithoutChangingOrReplacingState() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )
        _ = try manager.createIdentity(
            vaultID: Self.vaultID,
            displayName: "Office Mac",
            reason: "Create identity"
        )
        let original = store.records[Self.vaultID]
        operations.failPublicKeyLoad = true

        #expect(
            throws:
                V3EnrollmentDeviceIdentityStoreError.keyOperationFailed
        ) {
            try manager.loadIdentity(
                vaultID: Self.vaultID,
                reason: "Load inaccessible identity"
            )
        }
        #expect(operations.generateCount == 1)
        #expect(store.records[Self.vaultID] == original)
    }

    @Test
    func unavailableSecureEnclaveStopsBeforeGenerationOrPersistence() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        operations.isAvailable = false
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )

        #expect(
            throws:
                V3EnrollmentDeviceIdentityStoreError
                .secureEnclaveUnavailable
        ) {
            try manager.createIdentity(
                vaultID: Self.vaultID,
                displayName: "Office Mac",
                reason: "Create identity"
            )
        }
        #expect(operations.generateCount == 0)
        #expect(store.records.isEmpty)
    }

    @Test
    func invalidRequestStopsBeforeSecureEnclaveGeneration() throws {
        let store = MemoryEnrollmentDeviceKeyRecordStore()
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let manager = V3EnrollmentDeviceIdentityManager(
            recordStore: store,
            keyOperations: operations
        )

        #expect(
            throws:
                V3EnrollmentDeviceIdentityStoreError.invalidIdentityRequest
        ) {
            try manager.createIdentity(
                vaultID: Self.vaultID,
                displayName: "",
                reason: "Create identity"
            )
        }
        #expect(operations.generateCount == 0)
        #expect(store.records.isEmpty)
    }

    @Test
    func recordParserRejectsNoncanonicalExtendedAndOversizedState() throws {
        let operations = SoftwareEnrollmentDeviceKeyOperations()
        let keys = try operations.keys(
            signingScalar: 1,
            wrappingScalar: 2
        )
        let identity = try V3EnrollmentDeviceIdentity(
            displayName: "Office Mac",
            signingPublicKey: keys.signingPublicKey,
            wrappingPublicKey: keys.wrappingPublicKey
        )
        let record = try V3EnrollmentDeviceKeyRecord(
            vaultID: Self.vaultID,
            identity: identity,
            signingKeyRepresentation: keys.signingKeyRepresentation,
            wrappingKeyRepresentation: keys.wrappingKeyRepresentation
        )

        var spaced = Data("{ ".utf8)
        spaced.append(record.canonicalBytes.dropFirst())
        #expect(
            throws: V3EnrollmentDeviceIdentityStoreError.invalidRecord
        ) {
            try V3EnrollmentDeviceKeyRecord(canonicalBytes: spaced)
        }

        let extended = replacing(
            record.canonicalBytes,
            "\"version\":1",
            with: "\"unknown\":true,\"version\":1"
        )
        #expect(
            throws: V3EnrollmentDeviceIdentityStoreError.invalidRecord
        ) {
            try V3EnrollmentDeviceKeyRecord(canonicalBytes: extended)
        }

        #expect(
            throws: V3EnrollmentDeviceIdentityStoreError.invalidRecord
        ) {
            try V3EnrollmentDeviceKeyRecord(
                canonicalBytes: Data(
                    repeating: 0x41,
                    count: V3EnrollmentDeviceKeyRecord.maximumBytes + 1
                )
            )
        }
    }

    private func replacing(
        _ data: Data,
        _ original: String,
        with replacement: String
    ) -> Data {
        Data(
            String(decoding: data, as: UTF8.self)
                .replacingOccurrences(of: original, with: replacement)
                .utf8
        )
    }
}

private final class MemoryEnrollmentDeviceKeyRecordStore:
    V3EnrollmentDeviceKeyRecordStoring,
    @unchecked Sendable
{
    var records: [String: Data] = [:]

    func loadRecord(vaultID: String) throws -> Data? {
        records[vaultID]
    }

    func insertRecord(_ record: Data, vaultID: String) throws {
        guard records[vaultID] == nil else {
            throw V3EnrollmentDeviceIdentityStoreError
                .identityAlreadyExists
        }
        records[vaultID] = record
    }
}

private final class SoftwareEnrollmentDeviceKeyOperations:
    V3EnrollmentDeviceKeyOperating,
    @unchecked Sendable
{
    var isAvailable = true
    var failPublicKeyLoad = false
    private(set) var generateCount = 0
    private(set) var publicKeyLoadCount = 0

    func generateDeviceKeys(
        reason _: String
    ) throws -> V3EnrollmentGeneratedDeviceKeys {
        generateCount += 1
        return try keys(signingScalar: 1, wrappingScalar: 2)
    }

    func publicKeys(
        signingKeyRepresentation: Data,
        wrappingKeyRepresentation: Data,
        reason _: String
    ) throws -> (signing: Data, wrapping: Data) {
        publicKeyLoadCount += 1
        if failPublicKeyLoad {
            throw V3EnrollmentDeviceIdentityStoreError.keyOperationFailed
        }
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: signingKeyRepresentation
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: wrappingKeyRepresentation
        )
        return (
            signingKey.publicKey.x963Representation,
            wrappingKey.publicKey.x963Representation
        )
    }

    func signature(
        for input: Data,
        signingKeyRepresentation: Data,
        reason _: String
    ) throws -> Data {
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: signingKeyRepresentation
        )
        return try key.signature(for: input).rawRepresentation
    }

    func sharedSecret(
        with publicKey: P256.KeyAgreement.PublicKey,
        wrappingKeyRepresentation: Data,
        reason _: String
    ) throws -> SharedSecret {
        let key = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: wrappingKeyRepresentation
        )
        return try key.sharedSecretFromKeyAgreement(with: publicKey)
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        wrappingKeyRepresentation: Data,
        reason _: String
    ) throws -> Data {
        try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: P256.KeyAgreement.PrivateKey(
                rawRepresentation: wrappingKeyRepresentation
            ),
            context: context
        )
    }

    func keys(
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws -> V3EnrollmentGeneratedDeviceKeys {
        let signingRepresentation = privateKeyBytes(signingScalar)
        let wrappingRepresentation = privateKeyBytes(wrappingScalar)
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: signingRepresentation
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: wrappingRepresentation
        )
        return V3EnrollmentGeneratedDeviceKeys(
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation,
            signingKeyRepresentation: signingRepresentation,
            wrappingKeyRepresentation: wrappingRepresentation
        )
    }

    private func privateKeyBytes(_ scalar: UInt8) -> Data {
        var bytes = Data(repeating: 0, count: 32)
        bytes[31] = scalar
        return bytes
    }
}
