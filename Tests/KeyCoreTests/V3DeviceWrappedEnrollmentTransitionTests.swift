import CryptoKit
import Foundation
import JSONCanonicalization
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
        let validated = try V3DeviceWrappedEnrollmentTransitionValidator()
            .validate(
                later,
                parent: laterBase,
                currentEntries: laterEntries,
                currentVaultKey: Self.nextKey,
                nextVaultKey: Self.laterKey,
                state: laterCeremony.state,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the inviting Mac's new wrapper."
            )

        #expect(later.body.devices.count == 3)
        #expect(later.body.wrappedKeys.count == 3)
        #expect(later.body.devices.filter({ $0.role == .owner }).count == 2)
        #expect(later.body.entries.map(\.revision) == [1])
        #expect(later.body.entries.allSatisfy({ $0.keyID == later.body.keyID }))
        #expect(validated.candidate.body == later.body)
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

    @Test
    func validatorAcceptsTheExactCompleteTransition() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x70
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

        let validated = try V3DeviceWrappedEnrollmentTransitionValidator()
            .validate(
                candidate,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: ceremony.state,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the inviting Mac's new wrapper."
            )

        #expect(validated.parent == fixture.base.envelope)
        #expect(validated.candidate.body == candidate.body)
        #expect(validated.manifestDigest == candidate.manifestDigest)
        #expect(validated.stagedEntries.count == 1)
    }

    @Test
    func preflightAcceptsOnlyTheOwnerAuthorizedParentBinding() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x76
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

        let authorized = try V3DeviceWrappedEnrollmentTransitionValidator()
            .preflightOwnerAuthorizedCandidate(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                parent: fixture.base,
                currentVaultKey: Self.currentKey
            )

        #expect(authorized.candidate.body == candidate.body)
        #expect(authorized.manifestDigest == candidate.manifestDigest)
        #expect(authorized.authorizingOwner == fixture.owner.publicIdentity)

        let otherParentCandidate = try V3DeviceWrappedManifestCandidateBuilder()
            .edit(
                in: fixture.base,
                name: "account/password",
                type: .secret,
                plaintext: "newer parent value",
                vaultKey: Self.currentKey
            )
        let otherParent = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: otherParentCandidate.manifestDigest
            ),
            envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                otherParentCandidate.manifestData
            )
        )
        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidTransition
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator()
                .preflightOwnerAuthorizedCandidate(
                    manifestData: candidate.manifestData,
                    manifestDigest: candidate.manifestDigest,
                    parent: otherParent,
                    currentVaultKey: Self.currentKey
                )
        }
    }

    @Test
    func preflightPreservesFutureProfileUpgradeRequirement() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x77
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
        let root = try #require(
            CanonicalJSON.parse(candidate.manifestData).objectValue
        )
        let content = try #require(
            root.first(where: { $0.0 == "content" })?.1.objectValue
        )
        let body = try #require(
            content.first(where: { $0.0 == "manifest" })?.1.objectValue
        )
        let futureBody = body.map { name, value in
            name == "profileVersion"
                ? (name, CanonicalJSONValue.integer(2))
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

        #expect(
            throws: V3DeviceWrappedUnlockError
                .unsupportedProfileVersion(2)
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator()
                .preflightOwnerAuthorizedCandidate(
                    manifestData: futureData,
                    manifestDigest: Data(SHA256.hash(data: futureData)),
                    parent: fixture.base,
                    currentVaultKey: Self.currentKey
                )
        }
    }

    @Test
    func validatorRejectsAResealWithDifferentPlaintext() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x71
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
        let staged = try #require(candidate.stagedEntries.first)
        let substituted = try V3EntryCipher().seal(
            "different plaintext",
            context: staged.context,
            vaultKey: Self.nextKey
        )
        let originalEntry = try #require(candidate.body.entries.first)
        let substitutedEntry = V3ManifestEntry(
            entryID: originalEntry.entryID,
            name: originalEntry.name,
            type: originalEntry.type,
            revision: originalEntry.revision,
            keyID: originalEntry.keyID,
            ciphertextDigest: substituted.ciphertextDigest
        )
        let alteredBody = try V3DeviceWrappedManifestBody(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            devices: candidate.body.devices,
            wrappedKeys: candidate.body.wrappedKeys,
            entries: [substitutedEntry]
        )
        let altered = try Self.authorizedCandidate(
            basedOn: candidate,
            body: alteredBody,
            stagedEntries: [substituted],
            vaultKey: Self.nextKey,
            signer: fixture.owner
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidStagedEntry
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator().validate(
                altered,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: ceremony.state,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the inviting Mac's new wrapper."
            )
        }
    }

    @Test
    func validatorRejectsAuthorizationFromANonOwner() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x72
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
        let altered = try Self.authorizedCandidate(
            basedOn: candidate,
            body: candidate.body,
            stagedEntries: candidate.stagedEntries,
            vaultKey: Self.nextKey,
            signer: fixture.firstJoiner
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidOwnerAuthorization
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator()
                .preflightOwnerAuthorizedCandidate(
                    manifestData: altered.manifestData,
                    manifestDigest: altered.manifestDigest,
                    parent: fixture.base,
                    currentVaultKey: Self.currentKey
                )
        }
        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidOwnerAuthorization
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator().validate(
                altered,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: ceremony.state,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the inviting Mac's new wrapper."
            )
        }
    }

    @Test
    func validatorRejectsADeviceOtherThanTheComparedJoiner() throws {
        let fixture = try Fixture()
        let firstCeremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x73
        )
        let candidate = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
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
        let otherCeremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.secondJoiner,
            role: .owner,
            nonce: 0x74
        )
        let relabeled = V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: candidate.expectedCheckpoint,
            body: candidate.body,
            manifestData: candidate.manifestData,
            manifestDigest: candidate.manifestDigest,
            stagedEntries: candidate.stagedEntries,
            transcriptDigest: otherCeremony.transcript.digest
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidTransition
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator().validate(
                relabeled,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: otherCeremony.state,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the inviting Mac's new wrapper."
            )
        }
    }

    @Test
    func validatorRejectsAnOwnerWrapperForTheWrongKey() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            role: .member,
            nonce: 0x75
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
        let ownerID = fixture.owner.publicIdentity.deviceID
        let context = try V3VaultKeyHPKEContext(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            recipientDeviceID: ownerID
        )
        let wrongWrapper = try V3DeviceWrappedManifestKey(
            recipientDeviceID: ownerID,
            wrappedKey: V3VaultKeyHPKE().wrap(
                vaultKey: Data(repeating: 0xEE, count: 32),
                recipientPublicKey:
                    fixture.owner.publicIdentity.wrappingPublicKey,
                context: context
            )
        )
        let wrappers = candidate.body.wrappedKeys.map {
            $0.recipientDeviceID == ownerID ? wrongWrapper : $0
        }
        let alteredBody = try V3DeviceWrappedManifestBody(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            devices: candidate.body.devices,
            wrappedKeys: wrappers,
            entries: candidate.body.entries
        )
        let altered = try Self.authorizedCandidate(
            basedOn: candidate,
            body: alteredBody,
            stagedEntries: candidate.stagedEntries,
            vaultKey: Self.nextKey,
            signer: fixture.owner
        )

        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .localWrapperInvalid
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator().validate(
                altered,
                parent: fixture.base,
                currentEntries: fixture.currentEntries,
                currentVaultKey: Self.currentKey,
                nextVaultKey: Self.nextKey,
                state: ceremony.state,
                localIdentity: fixture.owner,
                at: Self.approvalTime,
                unwrapReason: "Verify the inviting Mac's new wrapper."
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

    private static func authorizedCandidate(
        basedOn candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        body: V3DeviceWrappedManifestBody,
        stagedEntries: [V3EncryptedEntry],
        vaultKey: Data,
        signer: SoftwareDevice
    ) throws -> V3DeviceWrappedEnrollmentTransitionCandidate {
        let content = CanonicalJSONValue.object([
            (
                "parents",
                .array([.string(Base64URL.encode(
                    candidate.expectedCheckpoint.envelopeDigest
                ))])
            ),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: body.vaultID,
            vaultKey: vaultKey
        )
        let signature = try V3P256Signature.canonicalize(
            signer.signature(
                for: V3ManifestAuthenticator.authenticationInput(
                    for: canonicalContent
                ),
                reason: "Create a validator test candidate."
            )
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([.object([
                ("algorithm", .string("P-256-ECDSA-SHA256")),
                (
                    "signerDeviceID",
                    .string(signer.publicIdentity.deviceID)
                ),
                ("signature", .string(Base64URL.encode(signature))),
            ])])),
        ]))
        return V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: candidate.expectedCheckpoint,
            body: body,
            manifestData: manifestData,
            manifestDigest: Data(SHA256.hash(data: manifestData)),
            stagedEntries: stagedEntries,
            transcriptDigest: candidate.transcriptDigest
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

private struct SoftwareDevice:
    V3EnrollmentMessageSigning,
    V3DeviceWrappedVaultKeyUnwrapping
{
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

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason _: String
    ) throws -> Data {
        try V3VaultKeyHPKE().unwrap(
            wrappedKey,
            recipientPrivateKey: wrappingPrivateKey,
            context: context
        )
    }
}

private func privateKeyBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}
