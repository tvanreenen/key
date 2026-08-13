import CryptoKit
import Foundation
import Testing
import JSONCanonicalization

@testable import KeyCore

struct V3DeviceWrappedCheckpointUnlockerTests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let vaultKey = Data((0..<32).map(UInt8.init))

    @Test
    func exactAuthenticatedCheckpointOpensIntoMemorySession() throws {
        let fixture = try Self.fixture()
        let session = V3DeviceWrappedVaultKeySessionStore()

        let envelope = try V3DeviceWrappedCheckpointUnlocker().unlock(
            checkpoint: fixture.checkpoint,
            manifestData: fixture.candidate.manifestData,
            identity: fixture.unwrapper,
            session: session,
            reason: "Unlock the vault"
        )

        #expect(envelope.body == fixture.candidate.body)
        #expect(fixture.unwrapper.unwrapCount == 1)
        #expect(
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            ) == Self.vaultKey
        )
    }

    @Test
    func checkpointMismatchFailsBeforePrivateKeyUse() throws {
        let fixture = try Self.fixture()
        let otherCheckpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(repeating: 9, count: 32)
        )
        let session = V3DeviceWrappedVaultKeySessionStore()

        #expect(throws: V3DeviceWrappedUnlockError.checkpointMismatch) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: otherCheckpoint,
                manifestData: fixture.candidate.manifestData,
                identity: fixture.unwrapper,
                session: session,
                reason: "Unlock the vault"
            )
        }
        #expect(fixture.unwrapper.unwrapCount == 0)
        #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    @Test
    func unrecognizedDeviceFailsBeforePrivateKeyUse() throws {
        let fixture = try Self.fixture()
        let other = try TestUnwrapper(
            vaultID: Self.vaultID,
            signingScalar: 3,
            wrappingScalar: 4
        )

        #expect(throws: V3DeviceWrappedUnlockError.deviceNotEnrolled) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: fixture.checkpoint,
                manifestData: fixture.candidate.manifestData,
                identity: other,
                session: V3DeviceWrappedVaultKeySessionStore(),
                reason: "Unlock the vault"
            )
        }
        #expect(other.unwrapCount == 0)
    }

    @Test
    func revokedDeviceReturnsExplicitOutcomeWithoutPrivateKeyUse() throws {
        let revoked = try TestUnwrapper(
            vaultID: Self.vaultID,
            signingScalar: 1,
            wrappingScalar: 2
        )
        let active = try TestUnwrapper(
            vaultID: Self.vaultID,
            signingScalar: 3,
            wrappingScalar: 4
        )
        let manifestData = try Self.manifest(
            devices: [
                V3DeviceWrappedManifestDevice(
                    identity: revoked.publicIdentity,
                    status: .revoked
                ),
                V3DeviceWrappedManifestDevice(
                    identity: active.publicIdentity,
                    status: .active
                ),
            ].sorted { $0.identity.deviceID < $1.identity.deviceID },
            activeRecipients: [active]
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: manifestData))
        )

        #expect(throws: V3DeviceWrappedUnlockError.deviceRevoked) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: checkpoint,
                manifestData: manifestData,
                identity: revoked,
                session: V3DeviceWrappedVaultKeySessionStore(),
                reason: "Unlock the vault"
            )
        }
        #expect(revoked.unwrapCount == 0)
    }

    @Test
    func badManifestAuthenticationNeverInstallsUnwrappedKey() throws {
        let fixture = try Self.fixture()
        let root = try #require(
            CanonicalJSON.parse(fixture.candidate.manifestData).objectValue
        )
        let changed = root.map { name, value in
            guard name == "authentication" else { return (name, value) }
            return (name, CanonicalJSONValue.object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(Data(repeating: 0, count: 32)))),
            ]))
        }
        let invalidData = CanonicalJSON.encode(.object(changed))
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: invalidData))
        )
        let session = V3DeviceWrappedVaultKeySessionStore()

        #expect(throws: V3DeviceWrappedUnlockError.authenticationFailed) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: checkpoint,
                manifestData: invalidData,
                identity: fixture.unwrapper,
                session: session,
                reason: "Unlock the vault"
            )
        }
        #expect(fixture.unwrapper.unwrapCount == 1)
        #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    @Test
    func wrongUnwrappedKeyIDNeverEntersTheSession() throws {
        let fixture = try Self.fixture()
        let invalidData = try Self.manifest(
            devices: [V3DeviceWrappedManifestDevice(
                identity: fixture.unwrapper.publicIdentity,
                status: .active
            )],
            activeRecipients: [fixture.unwrapper],
            wrappedVaultKey: Data(repeating: 7, count: 32)
        )
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: invalidData))
        )
        let session = V3DeviceWrappedVaultKeySessionStore()

        #expect(throws: V3DeviceWrappedUnlockError.authenticationFailed) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: checkpoint,
                manifestData: invalidData,
                identity: fixture.unwrapper,
                session: session,
                reason: "Unlock the vault"
            )
        }
        #expect(fixture.unwrapper.unwrapCount == 1)
        #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    @Test
    func futureProfileIsReportedAsUpgradeRequiredBeforePrivateKeyUse() throws {
        let fixture = try Self.fixture()
        let root = try #require(
            CanonicalJSON.parse(fixture.candidate.manifestData).objectValue
        )
        let content = try #require(
            root.first(where: { $0.0 == "content" })?.1.objectValue
        )
        let body = try #require(
            content.first(where: { $0.0 == "manifest" })?.1.objectValue
        )
        let futureBody = body.map { name, value in
            name == "profileVersion"
                ? (name, CanonicalJSONValue.integer(3))
                : (name, value)
        }
        let futureContent = content.map { name, value in
            name == "manifest"
                ? (name, CanonicalJSONValue.object(futureBody))
                : (name, value)
        }
        let futureRoot = root.map { name, value in
            name == "content"
                ? (name, CanonicalJSONValue.object(futureContent))
                : (name, value)
        }
        let futureData = CanonicalJSON.encode(.object(futureRoot))
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: futureData))
        )

        #expect(
            throws: V3DeviceWrappedUnlockError
                .unsupportedProfileVersion(3)
        ) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: checkpoint,
                manifestData: futureData,
                identity: fixture.unwrapper,
                session: V3DeviceWrappedVaultKeySessionStore(),
                reason: "Unlock the vault"
            )
        }
        #expect(fixture.unwrapper.unwrapCount == 0)
    }

    @Test
    func onlyCanonicalFutureEnvelopesAreReportedAsUpgradeRequired() throws {
        let fixture = try Self.fixture()
        let root = try #require(
            CanonicalJSON.parse(fixture.candidate.manifestData).objectValue
        )
        let futureRoot = root.map { name, value in
            name == "version"
                ? (name, CanonicalJSONValue.integer(4))
                : (name, value)
        }
        let futureData = CanonicalJSON.encode(.object(futureRoot))

        #expect(
            throws: V3DeviceWrappedUnlockError
                .unsupportedEnvelopeVersion(4)
        ) {
            try V3DeviceWrappedManifestEnvelopeCodec().parse(futureData)
        }

        var noncanonicalFutureData = Data([UInt8(ascii: " ")])
        noncanonicalFutureData.append(futureData)
        #expect(throws: V3DeviceWrappedUnlockError.invalidManifest) {
            try V3DeviceWrappedManifestEnvelopeCodec().parse(
                noncanonicalFutureData
            )
        }
    }

    @Test
    func malformedCheckpointManifestNeverInvokesPrivateKey() throws {
        let fixture = try Self.fixture()
        let malformed = Data("not canonical json".utf8)
        let checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: Data(SHA256.hash(data: malformed))
        )

        #expect(throws: V3DeviceWrappedUnlockError.invalidManifest) {
            try V3DeviceWrappedCheckpointUnlocker().unlock(
                checkpoint: checkpoint,
                manifestData: malformed,
                identity: fixture.unwrapper,
                session: V3DeviceWrappedVaultKeySessionStore(),
                reason: "Unlock the vault"
            )
        }
        #expect(fixture.unwrapper.unwrapCount == 0)
    }

    @Test
    func sessionExpiresAndExplicitLockInvalidatesIt() async throws {
        let fixture = try Self.fixture()
        let session = V3DeviceWrappedVaultKeySessionStore(
            inactivityTimeout: .milliseconds(25)
        )
        try session.install(
            Self.vaultKey,
            vaultID: Self.vaultID,
            keyID: fixture.candidate.body.keyID
        )

        #expect(
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            ) == Self.vaultKey
        )
        session.invalidate()
        #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            )
        }

        try session.install(
            Self.vaultKey,
            vaultID: Self.vaultID,
            keyID: fixture.candidate.body.keyID
        )
        for _ in 0..<100 where session.hasResidentKey {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(session.hasResidentKey == false)
        #expect(throws: V3DeviceWrappedVaultKeySessionError.unavailable) {
            try session.load(
                vaultID: Self.vaultID,
                keyID: fixture.candidate.body.keyID
            )
        }
    }

    private static func fixture() throws -> (
        unwrapper: TestUnwrapper,
        candidate: V3DeviceWrappedGenesisCandidate,
        checkpoint: V3ManifestCheckpoint
    ) {
        let unwrapper = try TestUnwrapper(
            vaultID: vaultID,
            signingScalar: 1,
            wrappingScalar: 2
        )
        let candidate = try V3DeviceWrappedGenesisBuilder().build(
            vaultID: vaultID,
            authorityTransitionID: transitionID,
            vaultKey: vaultKey,
            ownerIdentity: unwrapper.publicIdentity
        )
        return (
            unwrapper,
            candidate,
            try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: candidate.manifestDigest
            )
        )
    }

    private static func manifest(
        devices: [V3DeviceWrappedManifestDevice],
        activeRecipients: [TestUnwrapper],
        wrappedVaultKey: Data = vaultKey
    ) throws -> Data {
        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        var wrappedKeys: [V3DeviceWrappedManifestKey] = []
        for recipient in activeRecipients.sorted(by: {
            $0.publicIdentity.deviceID < $1.publicIdentity.deviceID
        }) {
            let context = try V3VaultKeyHPKEContext(
                vaultID: vaultID,
                keyID: keyID,
                authorityTransitionID: transitionID,
                recipientDeviceID: recipient.publicIdentity.deviceID
            )
            wrappedKeys.append(try V3DeviceWrappedManifestKey(
                recipientDeviceID: recipient.publicIdentity.deviceID,
                wrappedKey: V3VaultKeyHPKE().wrap(
                    vaultKey: wrappedVaultKey,
                    recipientPublicKey:
                        recipient.publicIdentity.wrappingPublicKey,
                    context: context
                )
            ))
        }
        let body = try V3DeviceWrappedManifestBody(
            vaultID: vaultID,
            keyID: keyID,
            authorityTransitionID: transitionID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: []
        )
        let content = CanonicalJSONValue.object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: CanonicalJSON.encode(content),
            vaultID: vaultID,
            vaultKey: vaultKey
        )
        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([])),
        ]))
    }
}

private final class TestUnwrapper:
    V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let wrappingPrivateKey: P256.KeyAgreement.PrivateKey
    private let lock = NSLock()
    private var count = 0

    var unwrapCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    init(
        vaultID: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        let signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: Self.scalar(signingScalar)
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: Self.scalar(wrappingScalar)
        )
        wrappingPrivateKey = wrappingKey
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: "Test Mac \(signingScalar)",
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data {
        lock.lock()
        count += 1
        lock.unlock()
        return try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: wrappingPrivateKey,
            context: context
        )
    }

    private static func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}
