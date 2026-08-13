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
        #expect(later.body.devices.allSatisfy({ $0.status == .active }))
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
    func anyActiveDeviceCanAuthorizeEnrollment() throws {
        let fixture = try Fixture()
        let firstCeremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
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
            nonce: 0x68
        )

        let later = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
            from: laterBase,
            currentEntries: Self.entryMap(first.stagedEntries),
            state: memberCeremony.state,
            currentVaultKey: Self.nextKey,
            nextVaultKey: Self.laterKey,
            authorityTransitionID: Self.secondEnrollmentTransitionID,
            owner: fixture.firstJoiner,
            at: Self.approvalTime,
            authorizationReason: "Approve enrollment from an active device."
        )

        #expect(later.body.devices.contains(where: {
            $0.identity == fixture.secondJoiner.publicIdentity
                && $0.status == .active
        }))
    }

    @Test
    func refusesSubstitutedCurrentEntryBytes() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
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
            .preflightOwnerAuthorizedKeyTransition(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                parent: fixture.base,
                currentVaultKey: Self.currentKey
            )

        #expect(authorized.candidate.body == candidate.body)
        #expect(authorized.manifestDigest == candidate.manifestDigest)
        #expect(authorized.authorizingDevice == fixture.owner.publicIdentity)

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
                .preflightOwnerAuthorizedKeyTransition(
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

        #expect(
            throws: V3DeviceWrappedUnlockError
                .unsupportedProfileVersion(3)
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator()
                .preflightOwnerAuthorizedKeyTransition(
                    manifestData: futureData,
                    manifestDigest: Data(SHA256.hash(data: futureData)),
                    parent: fixture.base,
                    currentVaultKey: Self.currentKey
                )
        }
    }

    @Test
    func catchUpDiscoverySelectsOneOwnerAuthorizedDirectChild() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x7E)
        let unrelated = Data("unrelated provider object".utf8)
        let unrelatedDigest = Data(SHA256.hash(data: unrelated))
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [
                fixture.base.checkpoint.envelopeDigest: .available(
                    fixture.base.envelope.canonicalBytes
                ),
                candidate.manifestDigest: .available(
                    candidate.manifestData
                ),
                unrelatedDigest: .available(unrelated),
            ]
        )

        let outcome = try V3DeviceWrappedKeyTransitionDiscovery(
            source: source
        ).discover(
            from: fixture.base,
            currentVaultKey: Self.currentKey
        )

        #expect(outcome == .candidate(
            manifestData: candidate.manifestData,
            manifestDigest: candidate.manifestDigest
        ))
    }

    @Test
    func catchUpDiscoveryPreservesCompetingOwnerAuthorizedChildren() throws {
        let fixture = try Fixture()
        let first = try Self.catchUpCandidate(fixture, nonce: 0x7F)
        let second = try Self.catchUpCandidate(fixture, nonce: 0x80)
        let expected = [
            first.manifestDigest,
            second.manifestDigest,
        ].sorted(by: { $0.lexicographicallyPrecedes($1) })
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [
                first.manifestDigest: .available(first.manifestData),
                second.manifestDigest: .available(second.manifestData),
            ]
        )

        let outcome = try V3DeviceWrappedKeyTransitionDiscovery(
            source: source
        ).discover(
            from: fixture.base,
            currentVaultKey: Self.currentKey
        )

        #expect(outcome == .competingCandidates(expected))
    }

    @Test
    func catchUpDiscoveryIgnoresUnauthenticatedProviderChildren() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x81)
        var alteredData = candidate.manifestData
        alteredData[alteredData.index(before: alteredData.endIndex)] ^= 1
        let alteredDigest = Data(SHA256.hash(data: alteredData))
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [alteredDigest: .available(alteredData)]
        )

        let outcome = try V3DeviceWrappedKeyTransitionDiscovery(
            source: source
        ).discover(
            from: fixture.base,
            currentVaultKey: Self.currentKey
        )

        #expect(outcome == .none)
    }

    @Test
    func ownerAuthorizedFutureProfileChildRequiresAnUpgrade() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x83)
        let futureData = try Self.signedFutureProfileManifest(
            basedOn: candidate,
            signer: fixture.owner
        )
        let futureDigest = Data(SHA256.hash(data: futureData))
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [futureDigest: .available(futureData)]
        )

        #expect(throws: V3DeviceWrappedCatchUpError.upgradeRequired) {
            _ = try V3DeviceWrappedKeyTransitionDiscovery(
                source: source
            ).discover(
                from: fixture.base,
                currentVaultKey: Self.currentKey
            )
        }
    }

    @Test
    func unauthenticatedFutureProfileObjectCannotForceAnUpgrade() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x84)
        let futureData = try Self.signedFutureProfileManifest(
            basedOn: candidate,
            signer: fixture.firstJoiner
        )
        let futureDigest = Data(SHA256.hash(data: futureData))
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [futureDigest: .available(futureData)]
        )

        let outcome = try V3DeviceWrappedKeyTransitionDiscovery(
            source: source
        ).discover(
            from: fixture.base,
            currentVaultKey: Self.currentKey
        )

        #expect(outcome == .none)
    }

    @Test
    func catchUpDiscoveryWaitsForEveryListedManifest() throws {
        let fixture = try Fixture()
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [
                Data(repeating: 0xEE, count: 32): .unavailable,
            ]
        )

        #expect(throws: V3DeviceWrappedCatchUpError.temporaryUnavailable) {
            _ = try V3DeviceWrappedKeyTransitionDiscovery(
                source: source
            ).discover(
                from: fixture.base,
                currentVaultKey: Self.currentKey
            )
        }
    }

    @Test
    func unavailableManifestPreventsSelectingOneOfCompetingChildren() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x82)
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [
                candidate.manifestDigest: .available(
                    candidate.manifestData
                ),
                Data(repeating: 0xEF, count: 32): .unavailable,
            ]
        )

        #expect(throws: V3DeviceWrappedCatchUpError.temporaryUnavailable) {
            _ = try V3DeviceWrappedKeyTransitionDiscovery(
                source: source
            ).discover(
                from: fixture.base,
                currentVaultKey: Self.currentKey
            )
        }
    }

    @Test
    func catchUpDiscoveryRejectsAnUntrustedParentKey() throws {
        let fixture = try Fixture()
        let source = CatchUpTransitionObjectSource(entries: [:])

        #expect(throws: V3DeviceWrappedCatchUpError.recoveryRequired) {
            _ = try V3DeviceWrappedKeyTransitionDiscovery(
                source: source
            ).discover(
                from: fixture.base,
                currentVaultKey: Self.nextKey
            )
        }
    }

    @Test
    func catchUpDiscoveryEnforcesAggregateManifestBytesWhileScanning() throws {
        let first = Data(repeating: 0x11, count: 40)
        let second = Data(repeating: 0x22, count: 40)
        let source = CatchUpTransitionObjectSource(
            entries: [:],
            manifests: [
                Data(SHA256.hash(data: first)): .available(first),
                Data(SHA256.hash(data: second)): .available(second),
            ]
        )
        let limits = V3ManifestRepositoryLimits(
            maximumManifestObjects: 2,
            maximumHistoryDepth: 1,
            maximumManifestBytes: 64,
            maximumTotalManifestBytes: 64
        )
        let fixture = try Fixture()

        #expect(throws: V3DeviceWrappedCatchUpError.recoveryRequired) {
            _ = try V3DeviceWrappedKeyTransitionDiscovery(
                source: source,
                limits: limits
            ).discover(
                from: fixture.base,
                currentVaultKey: Self.currentKey
            )
        }
    }

    @Test
    func catchUpOpenerAuthenticatesTheAddressedKeyAndCompleteReseal() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x78)
        let source = Self.catchUpSource(
            fixture: fixture,
            candidate: candidate
        )
        let identity = CatchUpTransitionUnwrapper(device: fixture.owner)

        let opened = try V3DeviceWrappedCatchUpTransitionOpener(
            source: source
        ).open(
            manifestData: candidate.manifestData,
            manifestDigest: candidate.manifestDigest,
            parent: fixture.base,
            currentVaultKey: Self.currentKey,
            identity: identity,
            reason: "Open the next authenticated vault-key epoch."
        )

        let expected = try Self.trustedCheckpoint(for: candidate)
        #expect(opened.vaultKey == Self.nextKey)
        #expect(opened.trustedCheckpoint == expected)
        #expect(opened.authorizingDevice == fixture.owner.publicIdentity)
        #expect(identity.unwrapCount == 1)
        #expect(source.entryReadCount == 2)
    }

    @Test
    func catchUpOpenerAllowsAnActiveMemberToOpenALaterEpoch() throws {
        let fixture = try Fixture()
        let first = try Self.catchUpCandidate(fixture, nonce: 0x7D)
        let firstBase = try Self.trustedCheckpoint(for: first)
        let firstEntries = Self.entryMap(first.stagedEntries)
        let ceremony = try fixture.ceremony(
            parentDigest: first.manifestDigest,
            joiner: fixture.secondJoiner,
            nonce: 0x7E
        )
        let later = try V3DeviceWrappedEnrollmentTransitionBuilder().build(
            from: firstBase,
            currentEntries: firstEntries,
            state: ceremony.state,
            currentVaultKey: Self.nextKey,
            nextVaultKey: Self.laterKey,
            authorityTransitionID: Self.secondEnrollmentTransitionID,
            owner: fixture.owner,
            at: Self.approvalTime,
            authorizationReason: "Approve another compared Mac."
        )
        let source = Self.catchUpSource(
            currentEntries: firstEntries,
            candidate: later
        )

        let opened = try V3DeviceWrappedCatchUpTransitionOpener(
            source: source
        ).open(
            manifestData: later.manifestData,
            manifestDigest: later.manifestDigest,
            parent: firstBase,
            currentVaultKey: Self.nextKey,
            identity: fixture.firstJoiner,
            reason: "Open a later authenticated vault-key epoch."
        )

        let expected = try Self.trustedCheckpoint(for: later)
        #expect(opened.vaultKey == Self.laterKey)
        #expect(opened.trustedCheckpoint == expected)
    }

    @Test
    func catchUpOpenerNeverUnwrapsBeforeOwnerPreflight() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x79)
        let unauthorized = try Self.authorizedCandidate(
            basedOn: candidate,
            body: candidate.body,
            stagedEntries: candidate.stagedEntries,
            vaultKey: Self.nextKey,
            signer: fixture.firstJoiner
        )
        let source = Self.catchUpSource(
            fixture: fixture,
            candidate: unauthorized
        )
        let identity = CatchUpTransitionUnwrapper(device: fixture.owner)

        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidDeviceAuthorization
        ) {
            try V3DeviceWrappedCatchUpTransitionOpener(source: source).open(
                manifestData: unauthorized.manifestData,
                manifestDigest: unauthorized.manifestDigest,
                parent: fixture.base,
                currentVaultKey: Self.currentKey,
                identity: identity,
                reason: "Do not open an unauthorized transition."
            )
        }
        #expect(identity.unwrapCount == 0)
        #expect(source.entryReadCount == 0)
    }

    @Test
    func catchUpOpenerPreservesCancellationBeforeEntryReads() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x7A)
        let source = Self.catchUpSource(
            fixture: fixture,
            candidate: candidate
        )
        let identity = CatchUpTransitionUnwrapper(
            device: fixture.owner,
            error: .authenticationCancelled
        )

        #expect(
            throws: V3DeviceWrappedCatchUpTransitionOpeningError
                .authenticationCancelled
        ) {
            try V3DeviceWrappedCatchUpTransitionOpener(source: source).open(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                parent: fixture.base,
                currentVaultKey: Self.currentKey,
                identity: identity,
                reason: "Open the next authenticated vault-key epoch."
            )
        }
        #expect(identity.unwrapCount == 1)
        #expect(source.entryReadCount == 0)
    }

    @Test
    func catchUpOpenerDoesNotTrustAnUnavailableResealedEntry() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x7B)
        let missingKey = try entryObjectKey(
            #require(candidate.body.entries.first)
        )
        let source = Self.catchUpSource(
            fixture: fixture,
            candidate: candidate,
            replacing: [missingKey: .unavailable]
        )

        #expect(
            throws: V3DeviceWrappedCatchUpTransitionOpeningError
                .temporaryUnavailable
        ) {
            try V3DeviceWrappedCatchUpTransitionOpener(source: source).open(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                parent: fixture.base,
                currentVaultKey: Self.currentKey,
                identity: fixture.owner,
                reason: "Open the next authenticated vault-key epoch."
            )
        }
    }

    @Test
    func catchUpOpenerRejectsSubstitutedEntryBytes() throws {
        let fixture = try Fixture()
        let candidate = try Self.catchUpCandidate(fixture, nonce: 0x7C)
        let substitutedKey = try entryObjectKey(
            #require(candidate.body.entries.first)
        )
        let source = Self.catchUpSource(
            fixture: fixture,
            candidate: candidate,
            replacing: [
                substitutedKey: .available(Data("substituted".utf8))
            ]
        )

        #expect(
            throws: V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        ) {
            try V3DeviceWrappedCatchUpTransitionOpener(source: source).open(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest,
                parent: fixture.base,
                currentVaultKey: Self.currentKey,
                identity: fixture.owner,
                reason: "Open the next authenticated vault-key epoch."
            )
        }
    }

    @Test
    func validatorRejectsAResealWithDifferentPlaintext() throws {
        let fixture = try Fixture()
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
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
                .invalidDeviceAuthorization
        ) {
            try V3DeviceWrappedEnrollmentTransitionValidator()
                .preflightOwnerAuthorizedKeyTransition(
                    manifestData: altered.manifestData,
                    manifestDigest: altered.manifestDigest,
                    parent: fixture.base,
                    currentVaultKey: Self.currentKey
                )
        }
        #expect(
            throws: V3DeviceWrappedEnrollmentValidationError
                .invalidDeviceAuthorization
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

    private static func catchUpCandidate(
        _ fixture: Fixture,
        nonce: UInt8
    ) throws -> V3DeviceWrappedEnrollmentTransitionCandidate {
        let ceremony = try fixture.ceremony(
            parentDigest: fixture.base.checkpoint.envelopeDigest,
            joiner: fixture.firstJoiner,
            nonce: nonce
        )
        return try V3DeviceWrappedEnrollmentTransitionBuilder().build(
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
    }

    private static func signedFutureProfileManifest(
        basedOn candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        signer: SoftwareDevice
    ) throws -> Data {
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
                ? (name, CanonicalJSONValue.integer(3))
                : (name, value)
        }
        let futureContent = CanonicalJSONValue.object(content.map {
            name, value in
            name == "manifest"
                ? (name, CanonicalJSONValue.object(futureBody))
                : (name, value)
        })
        let canonicalContent = CanonicalJSON.encode(futureContent)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: candidate.body.vaultID,
            vaultKey: Self.nextKey
        )
        let signature = try V3P256Signature.canonicalize(
            signer.signature(
                for: V3ManifestAuthenticator.authenticationInput(
                    for: canonicalContent
                ),
                reason: "Create a future-profile discovery candidate."
            )
        )
        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", futureContent),
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
    }

    private static func catchUpSource(
        fixture: Fixture,
        candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        replacing replacements: [V3EntryObjectKey: V3RepositoryObjectRead]
            = [:]
    ) -> CatchUpTransitionObjectSource {
        catchUpSource(
            currentEntries: fixture.currentEntries,
            candidate: candidate,
            replacing: replacements
        )
    }

    private static func catchUpSource(
        currentEntries: [V3EntryObjectKey: V3EncryptedEntry],
        candidate: V3DeviceWrappedEnrollmentTransitionCandidate,
        replacing replacements: [V3EntryObjectKey: V3RepositoryObjectRead]
            = [:]
    ) -> CatchUpTransitionObjectSource {
        var entries = Dictionary(uniqueKeysWithValues:
            currentEntries.map { key, value in
                (key, V3RepositoryObjectRead.available(value.canonicalBytes))
            }
        )
        for entry in candidate.stagedEntries {
            let key = V3EntryObjectKey(
                entryID: entry.context.entryID,
                digest: Data(SHA256.hash(data: entry.canonicalBytes))
            )
            entries[key] = .available(entry.canonicalBytes)
        }
        entries.merge(replacements) { _, replacement in replacement }
        return CatchUpTransitionObjectSource(entries: entries)
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

private final class CatchUpTransitionUnwrapper:
    V3DeviceWrappedVaultKeyUnwrapping,
    @unchecked Sendable
{
    private let device: SoftwareDevice
    private let error: V3EnrollmentDeviceIdentityStoreError?
    private let lock = NSLock()
    private var count = 0

    init(
        device: SoftwareDevice,
        error: V3EnrollmentDeviceIdentityStoreError? = nil
    ) {
        self.device = device
        self.error = error
    }

    var vaultID: String {
        device.vaultID
    }

    var publicIdentity: V3EnrollmentDeviceIdentity {
        device.publicIdentity
    }

    var unwrapCount: Int {
        lock.withLock { count }
    }

    func unwrapDeviceWrappedVaultKey(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        context: V3VaultKeyHPKEContext,
        reason: String
    ) throws -> Data {
        try lock.withLock {
            count += 1
            if let error {
                throw error
            }
            return try device.unwrapDeviceWrappedVaultKey(
                wrappedKey,
                context: context,
                reason: reason
            )
        }
    }
}

private final class CatchUpTransitionObjectSource:
    V3ImmutableObjectReading,
    @unchecked Sendable
{
    private let entries: [V3EntryObjectKey: V3RepositoryObjectRead]
    private let manifests: [Data: V3RepositoryObjectRead]
    private let lock = NSLock()
    private var reads = 0

    init(
        entries: [V3EntryObjectKey: V3RepositoryObjectRead],
        manifests: [Data: V3RepositoryObjectRead] = [:]
    ) {
        self.entries = entries
        self.manifests = manifests
    }

    var entryReadCount: Int {
        lock.withLock { reads }
    }

    func manifestDigests(
        maximumCount: Int
    ) throws -> V3RepositoryDirectoryListing {
        guard manifests.count <= maximumCount else {
            return .limitExceeded
        }
        return .available(
            digests: manifests.keys.sorted(by: {
                $0.lexicographicallyPrecedes($1)
            }),
            objectCount: manifests.count
        )
    }

    func readManifest(
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        manifests[digest] ?? .unavailable
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes _: Int
    ) throws -> V3RepositoryObjectRead {
        lock.withLock {
            reads += 1
        }
        return entries[V3EntryObjectKey(
            entryID: entryID,
            digest: digest
        )] ?? .unavailable
    }
}

private func privateKeyBytes(_ scalar: UInt8) -> Data {
    // Full-width deterministic fixture keys avoid a CryptoKit edge case seen
    // with artificially tiny private scalars while remaining valid P-256 keys.
    Data(repeating: scalar, count: 32)
}
