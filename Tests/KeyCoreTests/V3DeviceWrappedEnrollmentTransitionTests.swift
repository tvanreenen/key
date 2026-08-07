import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3DeviceWrappedEnrollmentTransitionTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    fileprivate static let genesisTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let firstEnrollmentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
    private static let secondEnrollmentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
    fileprivate static let entryID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b7"
    fileprivate static let currentKey = Data(0..<32)
    private static let nextKey = Data(repeating: 0x41, count: 32)
    private static let laterKey = Data(repeating: 0x51, count: 32)
    private static let approvalTime: UInt64 = 4_102_444_800

    @Test
    func firstEnrollmentRotatesKeyAndResealsTheCompleteSnapshot() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x61
        )

        let candidate = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
            from: fixture.base,
            currentEntries: fixture.currentEntries,
            state: ceremony.state,
            currentVaultKey: Self.currentKey,
            nextVaultKey: Self.nextKey,
            authorityTransitionID: Self.firstEnrollmentTransitionID,
            owner: fixture.owner,
            at: Self.approvalTime,
            authorizationReason: "Approve the compared Mac."
        )

        #expect(candidate.expectedCheckpoint == fixture.base.checkpoint)
        #expect(candidate.transcriptDigest == ceremony.transcript.digest)
        #expect(candidate.body.devices.count == 2)
        #expect(candidate.body.wrappedKeys.count == 2)
        #expect(candidate.body.entries.count == 1)
        #expect(candidate.stagedEntries.count == 1)
        #expect(candidate.body.keyID != fixture.base.envelope.body.keyID)
        #expect(
            candidate.body.authorityTransitionID
                == Self.firstEnrollmentTransitionID
        )
        #expect(candidate.manifestDigest == Data(SHA256.hash(
            data: candidate.manifestData
        )))

        let oldEntry = try #require(fixture.base.envelope.body.entries.first)
        let newEntry = try #require(candidate.body.entries.first)
        #expect(newEntry.entryID == oldEntry.entryID)
        #expect(newEntry.name == oldEntry.name)
        #expect(newEntry.type == oldEntry.type)
        #expect(newEntry.revision == oldEntry.revision)
        #expect(newEntry.keyID == candidate.body.keyID)
        #expect(newEntry.ciphertextDigest != oldEntry.ciphertextDigest)
        #expect(
            try V3EntryCipher().openTrusted(
                candidate.stagedEntries[0].canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: newEntry,
                vaultKey: Self.nextKey
            ) == "correct horse battery staple"
        )
        #expect(throws: V3EncryptedEntryError.self) {
            try V3EntryCipher().openTrusted(
                candidate.stagedEntries[0].canonicalBytes,
                vaultID: Self.vaultID,
                manifestEntry: newEntry,
                vaultKey: Self.currentKey
            )
        }

        try Self.requireWrapperOpens(
            candidate,
            recipient: fixture.owner,
            expectedKey: Self.nextKey
        )
        try Self.requireWrapperOpens(
            candidate,
            recipient: fixture.firstJoiner,
            expectedKey: Self.nextKey
        )
    }

    @Test
    func laterEnrollmentUsesTheSameKeyRotatingTransition() throws {
        let fixture = try Fixture()
        let firstCeremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x62
        )
        let first = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
            from: fixture.base,
            currentEntries: fixture.currentEntries,
            state: firstCeremony.state,
            currentVaultKey: Self.currentKey,
            nextVaultKey: Self.nextKey,
            authorityTransitionID: Self.firstEnrollmentTransitionID,
            owner: fixture.owner,
            at: Self.approvalTime,
            authorizationReason: "Approve the first compared Mac."
        )
        let laterBase = try Self.trustedCheckpoint(for: first)
        let laterEntries = Self.entryMap(first.stagedEntries)
        let laterCeremony = try fixture.ceremony(
            parentDigest: laterBase.checkpoint.envelopeDigest,
            joiner: fixture.secondJoiner,
            role: .owner,
            nonce: 0x63
        )

        let later = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
            from: laterBase,
            currentEntries: laterEntries,
            state: laterCeremony.state,
            currentVaultKey: Self.nextKey,
            nextVaultKey: Self.laterKey,
            authorityTransitionID: Self.secondEnrollmentTransitionID,
            owner: fixture.owner,
            at: Self.approvalTime,
            authorizationReason: "Approve the next compared Mac."
        )

        #expect(later.body.devices.count == 3)
        #expect(later.body.wrappedKeys.count == 3)
        #expect(later.body.devices.filter({ $0.role == .owner }).count == 2)
        #expect(later.body.entries.map(\.revision) == [1])
        #expect(later.body.entries.allSatisfy({ $0.keyID == later.body.keyID }))
        try Self.requireWrapperOpens(
            later,
            recipient: fixture.owner,
            expectedKey: Self.laterKey
        )
        try Self.requireWrapperOpens(
            later,
            recipient: fixture.firstJoiner,
            expectedKey: Self.laterKey
        )
        try Self.requireWrapperOpens(
            later,
            recipient: fixture.secondJoiner,
            expectedKey: Self.laterKey
        )
    }

    @Test
    func refusesRotationWithoutEveryCurrentEntry() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x64
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentTransitionError
                .incompleteEntrySnapshot
        ) {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: fixture.base,
                currentEntries: [:],
                state: ceremony.state,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.firstEnrollmentTransitionID,
                owner: fixture.owner,
                at: Self.approvalTime,
                authorizationReason: "Approve the compared Mac."
            )
        }
    }

    @Test
    func refusesToReuseTheCurrentVaultKey() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x65
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentTransitionError
                .invalidNextVaultKey
        ) {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                state: ceremony.state,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.currentKey,
                authorityTransitionID: Self.firstEnrollmentTransitionID,
                owner: fixture.owner,
                at: Self.approvalTime,
                authorizationReason: "Approve the compared Mac."
            )
        }
    }

    @Test
    func refusesToCreateANewApprovalAfterInvitationExpiry() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x66
        )

        #expect(throws: V3EnrollmentProtocolError.expired) {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: fixture.base,
                currentEntries: fixture.currentEntries,
                state: ceremony.state,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.firstEnrollmentTransitionID,
                owner: fixture.owner,
                at: Self.approvalTime + 1,
                authorizationReason: "Approve the compared Mac."
            )
        }
    }

    @Test
    func refusesAnActiveMemberAsEnrollmentAuthorizer() throws {
        let fixture = try Fixture()
        let firstCeremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x67
        )
        let first = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
            from: fixture.base,
            currentEntries: fixture.currentEntries,
            state: firstCeremony.state,
            currentVaultKey: Self.currentKey,
            nextVaultKey: Self.nextKey,
            authorityTransitionID: Self.firstEnrollmentTransitionID,
            owner: fixture.owner,
            at: Self.approvalTime,
            authorizationReason: "Approve the compared Mac."
        )
        let laterBase = try Self.trustedCheckpoint(for: first)
        let memberCeremony = try fixture.ceremony(
            parentDigest: laterBase.checkpoint.envelopeDigest,
            inviter: fixture.firstJoiner,
            joiner: fixture.secondJoiner,
            role: .member,
            nonce: 0x68
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentTransitionError.invalidOwner
        ) {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: laterBase,
                currentEntries: Self.entryMap(first.stagedEntries),
                state: memberCeremony.state,
                currentVaultKey: Self.nextKey,
                nextVaultKey: Self.laterKey,
                authorityTransitionID: Self.secondEnrollmentTransitionID,
                owner: fixture.firstJoiner,
                at: Self.approvalTime,
                authorizationReason: "Attempt enrollment as a member."
            )
        }
    }

    @Test
    func refusesSubstitutedCurrentEntryBytes() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x69
        )
        let object = try #require(fixture.currentEntries.first)
        let substituted = try V3EntryCipher().seal(
            "substituted plaintext",
            context: object.value.context,
            vaultKey: Self.currentKey
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentTransitionError.invalidEntry
        ) {
            try V3DeviceWrappedEnrollmentTransitionBuilder().build(
                from: fixture.base,
                currentEntries: [object.key: substituted],
                state: ceremony.state,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                authorityTransitionID: Self.firstEnrollmentTransitionID,
                owner: fixture.owner,
                at: Self.approvalTime,
                authorizationReason: "Approve the compared Mac."
            )
        }
    }

    private static func trustedCheckpoint(
        for candidate: V3DeviceWrappedEnrollmentTransitionCandidate
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: candidate.body.vaultID,
                envelopeDigest: candidate.manifestDigest
            ),
            envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                candidate.manifestData
            )
        )
    }

    private static func entryMap(
        _ entries: [V3EncryptedEntry]
    ) -> [V3EntryObjectKey: V3EncryptedEntry] {
        Dictionary(uniqueKeysWithValues: entries.map { entry in
            (
                V3EntryObjectKey(
                    entryID: entry.context.entryID,
                    digest: Data(SHA256.hash(data: entry.canonicalBytes))
                ),
                entry
            )
        })
    }

    private static func requireWrapperOpens(
        _ candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        recipient: SoftwareDevice,
        expectedKey: Data
    ) throws {
        let wrapped = try #require(candidate.body.wrappedKeys.first(where: {
            $0.recipientDeviceID == recipient.publicIdentity.deviceID
        }))
        let context = try V3VaultKeyHPKEContext(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            recipientDeviceID: recipient.publicIdentity.deviceID
        )
        #expect(
            try V3VaultKeyHPKE().unwrap(
                wrapped.wrappedKey,
                recipientPrivateKey: recipient.wrappingPrivateKey,
                context: context
            ) == expectedKey
        )
    }
}

private struct Fixture {
    let owner: SoftwareDevice
    let firstJoiner: SoftwareDevice
    let secondJoiner: SoftwareDevice
    let base: V3DeviceWrappedTrustedCheckpoint
    let currentEntries: [V3EntryObjectKey: V3EncryptedEntry]

    init() throws {
        owner = try SoftwareDevice(
            displayName: "Owner Mac",
            signingScalar: 0x11,
            wrappingScalar: 0x12
        )
        firstJoiner = try SoftwareDevice(
            displayName: "Member Mac",
            signingScalar: 0x21,
            wrappingScalar: 0x22
        )
        secondJoiner = try SoftwareDevice(
            displayName: "Later Owner Mac",
            signingScalar: 0x31,
            wrappingScalar: 0x32
        )
        let publication = try V3DeviceWrappedGenesisBuilder()
            .buildPublicationCandidate(
                vaultID: V3DeviceWrappedEnrollmentTransitionTests.vaultID,
                authorityTransitionID:
                    V3DeviceWrappedEnrollmentTransitionTests
                        .genesisTransitionID,
                entryIDs: [
                    V3DeviceWrappedEnrollmentTransitionTests.entryID
                ],
                sourceEntries: [V2MigrationSourceEntry(
                    name: "account/password",
                    type: .secret,
                    plaintext: "correct horse battery staple",
                    sourceData: Data("retained v2 source".utf8)
                )],
                vaultKey:
                    V3DeviceWrappedEnrollmentTransitionTests.currentKey,
                ownerIdentity: owner.publicIdentity
            )
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(
            publication.genesis.manifestData
        )
        base = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: envelope.body.vaultID,
                envelopeDigest: publication.genesis.manifestDigest
            ),
            envelope: envelope
        )
        currentEntries = Dictionary(uniqueKeysWithValues:
            publication.entries.map { entry in
                (
                    V3EntryObjectKey(
                        entryID: entry.manifestEntry.entryID,
                        digest: entry.digest
                    ),
                    entry.encryptedEntry
                )
            }
        )
    }

    func ceremony(
        parentDigest: Data,
        inviter: SoftwareDevice? = nil,
        joiner: SoftwareDevice,
        role: V3DeviceRole,
        nonce: UInt8
    ) throws -> (
        state: V3EnrollmentCeremonyState,
        transcript: V3EnrollmentTranscript
    ) {
        let inviter = inviter ?? owner
        let invitation = try V3EnrollmentInvitation(
            vaultID: V3DeviceWrappedEnrollmentTransitionTests.vaultID,
            parentManifestDigest: parentDigest,
            invitingDevice: inviter.publicIdentity,
            invitedRole: role,
            nonce: Data(repeating: nonce, count: 32),
            expiresAt: 4_102_444_800
        )
        let authenticator = V3EnrollmentMessageAuthenticator()
        let signedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Create invitation."
        )
        let verifiedInvitation = try authenticator.verify(signedInvitation)
        let request = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: nonce &+ 1, count: 32)
        )
        let signedRequest = try authenticator.sign(
            request,
            answering: verifiedInvitation,
            using: joiner,
            reason: "Join vault."
        )
        let transcript = try V3EnrollmentTranscript(
            invitation: invitation,
            joinRequest: request
        )
        return (
            try V3EnrollmentCeremonyState(
                vaultID: invitation.vaultID,
                invitationDigest: invitation.digest,
                role: .inviter,
                phase: .awaitingComparison,
                signedInvitation: signedInvitation,
                signedJoinRequest: signedRequest
            ),
            transcript
        )
    }
}

private struct SoftwareDevice: V3EnrollmentMessageSigning {
    let vaultID = V3DeviceWrappedEnrollmentTransitionTests.vaultID
    let publicIdentity: V3EnrollmentDeviceIdentity
    let signingPrivateKey: P256.Signing.PrivateKey
    let wrappingPrivateKey: P256.KeyAgreement.PrivateKey

    init(
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        signingPrivateKey = try P256.Signing.PrivateKey(
            rawRepresentation: privateKeyBytes(signingScalar)
        )
        wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: privateKeyBytes(wrappingScalar)
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingPrivateKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try signingPrivateKey.signature(for: input).rawRepresentation
    }
}

private func privateKeyBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}
