import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3EnrollmentAdoptionTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    fileprivate static let vaultKey = Data((0..<32).map(UInt8.init))
    fileprivate static let activeTime: UInt64 = 1_900_000_000

    @Test
    func adoptionAuthenticatesBeforeInstallingAndSelectsLast() throws {
        let fixture = try Fixture()
        let phases = AdoptionPhases()
        let selection = AdoptionSelection()
        let service = fixture.service(
            phases: phases,
            selection: selection
        )

        let report = try service.adopt(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            approvedTranscriptDigest: fixture.transcript.digest,
            at: Self.activeTime,
            operationID: try VaultTransactionOperationID(
                validating: "018f4d38-7d5a-7b20-b0f1-97d6e96c44c1"
            )
        )

        #expect(report.vaultID == Self.vaultID)
        #expect(report.deviceName == "Joining Mac")
        #expect(fixture.keyStore.localKeyData == Self.vaultKey)
        #expect(
            try V3ManifestCheckpoint(
                canonicalBytes: #require(fixture.checkpointStore.checkpoint)
            ).envelopeDigest == fixture.candidate.verifiedManifest.envelopeDigest
        )
        #expect(selection.selectedVaultID == Self.vaultID)
        #expect(
            phases.values == [
                .approvalVerified, .ceremonyConsumed,
                .vaultKeyInstalled, .checkpointInstalled,
                .runtimeVerified,
            ]
        )
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: fixture.stateStore.state
            ).phase == .consumed
        )
    }

    @Test
    func unavailableApprovalChangesNoLocalAuthority() throws {
        let fixture = try Fixture(includeCandidate: false)
        let selection = AdoptionSelection()

        #expect(throws: V3EnrollmentAdoptionError.approvalUnavailable) {
            try fixture.service(selection: selection).adopt(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                approvedTranscriptDigest: fixture.transcript.digest,
                at: Self.activeTime,
                operationID: VaultTransactionOperationID()
            )
        }
        #expect(fixture.keyStore.localKeyData == nil)
        #expect(fixture.checkpointStore.checkpoint == nil)
        #expect(selection.selectedVaultID == nil)
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: fixture.stateStore.state
            ).phase == .awaitingComparison
        )
    }

    @Test
    func conflictingExistingKeyIsNeverReplaced() throws {
        let fixture = try Fixture()
        let conflicting = Data(repeating: 0xEE, count: 32)
        fixture.keyStore.localKeyData = conflicting

        #expect(throws: V3EnrollmentAdoptionError.conflictingVaultKey) {
            try fixture.service().adopt(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                approvedTranscriptDigest: fixture.transcript.digest,
                at: Self.activeTime,
                operationID: VaultTransactionOperationID()
            )
        }
        #expect(fixture.keyStore.localKeyData == conflicting)
        #expect(fixture.keyStore.storeCount == 0)
        #expect(fixture.checkpointStore.checkpoint == nil)
    }

    @Test
    func aggregateManifestLimitStopsBeforeInstallingTrust() throws {
        let fixture = try Fixture()
        let largestManifest = try #require(
            fixture.source.manifests.values.map(\.count).max()
        )
        let limits = V3ManifestRepositoryLimits(
            maximumManifestObjects: fixture.source.manifests.count,
            maximumHistoryDepth: 10,
            maximumManifestBytes: largestManifest,
            maximumTotalManifestBytes: largestManifest
        )
        let selection = AdoptionSelection()

        #expect(throws: V3EnrollmentAdoptionError.invalidApproval) {
            try fixture.service(
                selection: selection,
                limits: limits
            ).adopt(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                approvedTranscriptDigest: fixture.transcript.digest,
                at: Self.activeTime,
                operationID: VaultTransactionOperationID()
            )
        }
        #expect(fixture.keyStore.localKeyData == nil)
        #expect(fixture.checkpointStore.checkpoint == nil)
        #expect(selection.selectedVaultID == nil)
    }

    @Test
    func interruptedSelectionRetriesExactConsumedCeremonyAfterExpiry() throws {
        let fixture = try Fixture()
        let selection = AdoptionSelection(fail: true)
        let service = fixture.service(selection: selection)

        #expect(throws: V3EnrollmentAdoptionError.selectionFailed) {
            try service.adopt(
                vaultID: Self.vaultID,
                invitationDigest: fixture.invitation.digest,
                approvedTranscriptDigest: fixture.transcript.digest,
                at: Self.activeTime,
                operationID: VaultTransactionOperationID()
            )
        }
        #expect(fixture.keyStore.localKeyData == Self.vaultKey)
        #expect(fixture.checkpointStore.checkpoint != nil)
        #expect(
            try V3EnrollmentCeremonyState(
                canonicalBytes: fixture.stateStore.state
            ).phase == .consumed
        )

        selection.fail = false
        _ = try service.adopt(
            vaultID: Self.vaultID,
            invitationDigest: fixture.invitation.digest,
            approvedTranscriptDigest: fixture.transcript.digest,
            at: fixture.invitation.expiresAt + 1,
            operationID: VaultTransactionOperationID()
        )

        #expect(selection.selectedVaultID == Self.vaultID)
        #expect(fixture.keyStore.storeCount == 1)
    }
}

private struct Fixture {
    let invitation: V3EnrollmentInvitation
    let transcript: V3EnrollmentTranscript
    let candidate: V3EnrollmentOwnerTransitionCandidate
    let source: AdoptionSource
    let stateStore: AdoptionStateStore
    let checkpointStore = AdoptionCheckpointStore()
    let keyStore = MemoryVaultKeyStore()
    let identityManager: V3EnrollmentDeviceIdentityManager

    init(includeCandidate: Bool = true) throws {
        let parent = try V3LocalGenesisBuilder().build(
            vaultID: V3EnrollmentAdoptionTests.vaultID,
            entryIDs: [],
            sourceEntries: [],
            vaultKey: V3EnrollmentAdoptionTests.vaultKey
        ).verifiedManifest
        let inviter = try AdoptionSigner(
            vaultID: V3EnrollmentAdoptionTests.vaultID,
            displayName: "Existing Mac",
            signingScalar: 0x21,
            wrappingScalar: 0x22
        )
        let recordStore = AdoptionIdentityRecordStore()
        identityManager = V3EnrollmentDeviceIdentityManager(
            recordStore: recordStore,
            keyOperations: AdoptionDeviceKeyOperations()
        )
        let joiner = try identityManager.createIdentity(
            vaultID: V3EnrollmentAdoptionTests.vaultID,
            displayName: "Joining Mac",
            reason: "Create joining identity."
        )
        invitation = try V3EnrollmentInvitation(
            vaultID: V3EnrollmentAdoptionTests.vaultID,
            parentManifestDigest: parent.envelopeDigest,
            invitingDevice: inviter.publicIdentity,
            invitedRole: .member,
            nonce: Data(repeating: 0x41, count: 32),
            expiresAt: V3EnrollmentAdoptionTests.activeTime + 300
        )
        let authenticator = V3EnrollmentMessageAuthenticator()
        let signedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Sign invitation."
        )
        let verifiedInvitation = try authenticator.verify(signedInvitation)
        let joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0x42, count: 32)
        )
        let signedJoinRequest = try authenticator.sign(
            joinRequest,
            answering: verifiedInvitation,
            using: joiner,
            reason: "Sign join request."
        )
        transcript = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: joinRequest
        )
        let inviterState = try V3EnrollmentCeremonyState(
            vaultID: V3EnrollmentAdoptionTests.vaultID,
            invitationDigest: invitation.digest,
            role: .inviter,
            phase: .awaitingComparison,
            signedInvitation: signedInvitation,
            signedJoinRequest: signedJoinRequest
        )
        candidate = try V3EnrollmentOwnerTransitionBuilder().build(
            state: inviterState,
            parent: parent,
            vaultKey: V3EnrollmentAdoptionTests.vaultKey,
            inviterIdentity: inviter,
            authorizationReason: "Approve joining Mac."
        )
        var manifests = [
            parent.envelopeDigest: parent.envelope.canonicalBytes
        ]
        if includeCandidate {
            manifests[candidate.verifiedManifest.envelopeDigest] =
                candidate.manifestData
        }
        source = AdoptionSource(manifests: manifests)
        let joinerState = try V3EnrollmentCeremonyState(
            vaultID: V3EnrollmentAdoptionTests.vaultID,
            invitationDigest: invitation.digest,
            role: .joiner,
            phase: .awaitingComparison,
            signedInvitation: signedInvitation,
            signedJoinRequest: signedJoinRequest
        )
        stateStore = AdoptionStateStore(state: joinerState)
    }

    func service(
        phases: AdoptionPhases = AdoptionPhases(),
        selection: AdoptionSelection = AdoptionSelection(),
        limits: V3ManifestRepositoryLimits = .standard
    ) -> V3EnrollmentAdoptionService {
        V3EnrollmentAdoptionService(
            source: source,
            checkpointStore: checkpointStore,
            exchange: V3EnrollmentExchangeCoordinator(
                mailbox: AdoptionEmptyMailbox(),
                stateStore: stateStore
            ),
            identityManager: identityManager,
            vaultKeyStore: keyStore,
            keychainMode: .local,
            selectVault: { vaultID in
                try selection.select(vaultID)
            },
            verifyRuntime: { vaultID in
                #expect(vaultID == V3EnrollmentAdoptionTests.vaultID)
                #expect(
                    keyStore.localKeyData
                        == V3EnrollmentAdoptionTests.vaultKey
                )
            },
            limits: limits,
            phaseObserver: phases
        )
    }
}

private final class AdoptionSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    let manifests: [Data: Data]

    init(manifests: [Data: Data]) {
        self.manifests = manifests
    }

    func manifestDigests(
        maximumCount _: Int
    ) throws -> V3RepositoryDirectoryListing {
        .available(
            digests: Array(manifests.keys),
            objectCount: manifests.count
        )
    }

    func readManifest(
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        manifests[digest].map(V3RepositoryObjectRead.available)
            ?? .unavailable
    }

    func readEntry(
        entryID _: String,
        digest _: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        .unavailable
    }
}

private final class AdoptionStateStore:
    V3EnrollmentCeremonyStateStoring,
    @unchecked Sendable
{
    var state: Data

    init(state: V3EnrollmentCeremonyState) {
        self.state = state.canonicalBytes
    }

    func loadState(
        vaultID _: String,
        invitationDigest _: Data
    ) throws -> Data? {
        state
    }

    func replaceState(
        _ state: Data,
        expectedState: Data?,
        vaultID _: String,
        invitationDigest _: Data
    ) throws {
        guard self.state == expectedState else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        self.state = state
    }
}

private final class AdoptionCheckpointStore:
    V3ManifestCheckpointStoring,
    @unchecked Sendable
{
    var checkpoint: Data?

    func loadCheckpoint(vaultID _: String) throws -> Data? {
        checkpoint
    }

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID _: String
    ) throws {
        guard self.checkpoint == expectedCheckpoint else {
            throw V3ManifestCheckpointStoreError.conflict
        }
        self.checkpoint = checkpoint
    }
}

private final class AdoptionIdentityRecordStore:
    V3EnrollmentDeviceKeyRecordStoring,
    @unchecked Sendable
{
    var records: [String: Data] = [:]

    func loadRecord(vaultID: String) throws -> Data? {
        records[vaultID]
    }

    func insertRecord(_ record: Data, vaultID: String) throws {
        guard records[vaultID] == nil else {
            throw V3EnrollmentDeviceIdentityStoreError.identityAlreadyExists
        }
        records[vaultID] = record
    }
}

private struct AdoptionDeviceKeyOperations:
    V3EnrollmentDeviceKeyOperating,
    Sendable
{
    var isAvailable: Bool { true }

    func generateDeviceKeys(
        reason _: String
    ) throws -> V3EnrollmentGeneratedDeviceKeys {
        let signing = try P256.Signing.PrivateKey(
            rawRepresentation: privateBytes(0x31)
        )
        let wrapping = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: privateBytes(0x32)
        )
        return V3EnrollmentGeneratedDeviceKeys(
            signingPublicKey: signing.publicKey.x963Representation,
            wrappingPublicKey: wrapping.publicKey.x963Representation,
            signingKeyRepresentation: signing.rawRepresentation,
            wrappingKeyRepresentation: wrapping.rawRepresentation
        )
    }

    func publicKeys(
        signingKeyRepresentation: Data,
        wrappingKeyRepresentation: Data,
        reason _: String
    ) throws -> (signing: Data, wrapping: Data) {
        (
            try P256.Signing.PrivateKey(
                rawRepresentation: signingKeyRepresentation
            ).publicKey.x963Representation,
            try P256.KeyAgreement.PrivateKey(
                rawRepresentation: wrappingKeyRepresentation
            ).publicKey.x963Representation
        )
    }

    func signature(
        for input: Data,
        signingKeyRepresentation: Data,
        reason _: String
    ) throws -> Data {
        try P256.Signing.PrivateKey(
            rawRepresentation: signingKeyRepresentation
        ).signature(for: input).rawRepresentation
    }

    func sharedSecret(
        with publicKey: P256.KeyAgreement.PublicKey,
        wrappingKeyRepresentation: Data,
        reason _: String
    ) throws -> SharedSecret {
        try P256.KeyAgreement.PrivateKey(
            rawRepresentation: wrappingKeyRepresentation
        ).sharedSecretFromKeyAgreement(with: publicKey)
    }
}

private struct AdoptionSigner: V3EnrollmentMessageSigning, Sendable {
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    private let signingKey: P256.Signing.PrivateKey

    init(
        vaultID: String,
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        signingKey = try P256.Signing.PrivateKey(
            rawRepresentation: privateBytes(signingScalar)
        )
        let wrapping = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: privateBytes(wrappingScalar)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: signingKey.publicKey.x963Representation,
            wrappingPublicKey: wrapping.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingKey.signature(for: input).rawRepresentation
    }
}

private final class AdoptionSelection: @unchecked Sendable {
    var fail: Bool
    var selectedVaultID: String?

    init(fail: Bool = false) {
        self.fail = fail
    }

    func select(_ vaultID: String) throws {
        if fail {
            throw AppError.operationRefused("Injected selection failure.")
        }
        selectedVaultID = vaultID
    }
}

private final class AdoptionPhases:
    V3EnrollmentAdoptionPhaseObserving,
    @unchecked Sendable
{
    var values: [V3EnrollmentAdoptionPhase] = []

    func didReach(
        _ phase: V3EnrollmentAdoptionPhase,
        operationID _: VaultTransactionOperationID
    ) throws {
        values.append(phase)
    }
}

private struct AdoptionEmptyMailbox: V3EnrollmentMailboxStoring {
    func invitationDigests(
        maximumCount _: Int
    ) throws -> V3EnrollmentMailboxListing { .available(digests: [], objectCount: 0) }
    func readInvitation(digest _: Data) throws -> V3RepositoryObjectRead { .unavailable }
    func publishInvitation(_: Data) throws {}
    func joinRequestDigests(
        invitationDigest _: Data,
        maximumCount _: Int
    ) throws -> V3EnrollmentMailboxListing { .available(digests: [], objectCount: 0) }
    func readJoinRequest(
        invitationDigest _: Data,
        joinRequestDigest _: Data
    ) throws -> V3RepositoryObjectRead { .unavailable }
    func publishJoinRequest(
        _: Data,
        invitationDigest _: Data
    ) throws {}
}

private func privateBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}
