import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3ReplacementDeviceIdentityClassifierTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b3"
    private static let parentTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b4"
    private static let revocationTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c94b5"
    private static let currentVaultKey = Data(0..<32)
    private static let nextVaultKey = Data(32..<64)

    @Test
    func noLocalIdentityNeedsNoReplacement() throws {
        let fixture = try Fixture()

        let result = try V3ReplacementDeviceIdentityClassifier().classify(
            nil,
            at: fixture.base
        )

        #expect(result == .noLocalIdentity)
    }

    @Test
    func exactTrustedRosterClassifiesActiveAndRevokedIdentities() throws {
        let fixture = try Fixture()
        let activeTarget = try Self.deletionTarget(
            fixture.member.identity
        )
        let active = try V3ReplacementDeviceIdentityClassifier().classify(
            activeTarget,
            at: fixture.base
        )
        let expectedActive: V3ReplacementDeviceIdentityClassification =
            .active(
                activeTarget,
                authority: V3ReplacementDeviceIdentityAuthority
                    .trustedCheckpoint(
                        fixture.base.checkpoint
                    )
            )
        #expect(active == expectedActive)

        let revokedCheckpoint = try Self.checkpoint(
            devices: [
                Self.device(fixture.owner.identity, status: .active),
                Self.device(fixture.member.identity, status: .revoked),
            ],
            vaultKey: Self.currentVaultKey,
            transitionID: Self.revocationTransitionID
        )
        let revoked = try V3ReplacementDeviceIdentityClassifier().classify(
            activeTarget,
            at: revokedCheckpoint
        )
        let expectedRevoked: V3ReplacementDeviceIdentityClassification =
            .revoked(
                activeTarget,
                authority: V3ReplacementDeviceIdentityAuthority
                    .trustedCheckpoint(
                        revokedCheckpoint.checkpoint
                    )
            )
        #expect(revoked == expectedRevoked)
    }

    @Test
    func unknownIdentityFailsClosedAsUnrecognized() throws {
        let fixture = try Fixture()
        let stranger = try TestDevice(
            name: "Unknown Mac",
            signing: 0x31,
            wrapping: 0x32
        )
        let target = try Self.deletionTarget(stranger.identity)

        let result = try V3ReplacementDeviceIdentityClassifier().classify(
            target,
            at: fixture.base
        )

        let expected: V3ReplacementDeviceIdentityClassification =
            .unrecognized(
                target,
                authority: V3ReplacementDeviceIdentityAuthority
                    .trustedCheckpoint(
                        fixture.base.checkpoint
                    )
            )
        #expect(result == expected)
    }

    @Test
    func sameDeviceIDDifferentIdentityIsASecurityMismatch() throws {
        let fixture = try Fixture()
        let renamed = try V3EnrollmentDeviceIdentity(
            displayName: "Substituted Mac",
            signingPublicKey:
                fixture.member.identity.signingPublicKey,
            wrappingPublicKey:
                fixture.member.identity.wrappingPublicKey
        )
        let target = try Self.deletionTarget(renamed)

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .identityMismatch
        ) {
            _ = try V3ReplacementDeviceIdentityClassifier().classify(
                target,
                at: fixture.base
            )
        }
    }

    @Test
    func ownerAuthorizedDirectRevocationProvesReplacementEligibility()
        throws
    {
        let fixture = try Fixture()
        let target = try Self.deletionTarget(fixture.member.identity)
        let candidate = try fixture.revocationCandidate()

        let result = try V3ReplacementDeviceIdentityClassifier().classify(
            target,
            from: fixture.base,
            content: .upToDate,
            keyTransition: .candidate(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest
            ),
            currentVaultKey: Self.currentVaultKey
        )

        let expected: V3ReplacementDeviceIdentityClassification =
            .revoked(
                target,
                authority: V3ReplacementDeviceIdentityAuthority
                    .ownerAuthorizedRevocation(
                        parentCheckpoint: fixture.base.checkpoint,
                        manifestDigest: candidate.manifestDigest,
                        authorizingDevice: fixture.owner.identity
                    )
            )
        #expect(result == expected)
    }

    @Test
    func substitutedRevocationBytesDoNotAuthorizeReplacement() throws {
        let fixture = try Fixture()
        let target = try Self.deletionTarget(fixture.member.identity)
        let candidate = try fixture.revocationCandidate()
        var substituted = candidate.manifestData
        substituted[substituted.startIndex] ^= 0x01

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        ) {
            _ = try V3ReplacementDeviceIdentityClassifier().classify(
                target,
                from: fixture.base,
                content: .upToDate,
                keyTransition: .candidate(
                    manifestData: substituted,
                    manifestDigest: candidate.manifestDigest
                ),
                currentVaultKey: Self.currentVaultKey
            )
        }
    }

    @Test
    func competingTransitionsDoNotAuthorizeReplacement() throws {
        let fixture = try Fixture()
        let target = try Self.deletionTarget(fixture.member.identity)
        let candidate = try fixture.revocationCandidate()
        let competingDigest = Data(SHA256.hash(
            data: Data("competing transition".utf8)
        ))
        let digests = [candidate.manifestDigest, competingDigest].sorted {
            $0.lexicographicallyPrecedes($1)
        }

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .conflictingAuthority
        ) {
            _ = try V3ReplacementDeviceIdentityClassifier().classify(
                target,
                from: fixture.base,
                content: .upToDate,
                keyTransition: .competingCandidates(digests),
                currentVaultKey: Self.currentVaultKey
            )
        }
    }

    @Test
    func ownerAuthorizedFutureProfileRequiresUpgrade() throws {
        let fixture = try Fixture()
        let target = try Self.deletionTarget(fixture.member.identity)
        let candidate = try fixture.revocationCandidate()
        let futureData = try Self.signedFutureProfileManifest(
            basedOn: candidate,
            signer: fixture.owner
        )

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .upgradeRequired
        ) {
            _ = try V3ReplacementDeviceIdentityClassifier().classify(
                target,
                from: fixture.base,
                content: .upToDate,
                keyTransition: .candidate(
                    manifestData: futureData,
                    manifestDigest: Data(SHA256.hash(data: futureData))
                ),
                currentVaultKey: Self.currentVaultKey
            )
        }
    }

    @Test
    func wrongVaultAndUnboundCheckpointDoNotClassifyLocalState() throws {
        let fixture = try Fixture()
        let target = try Self.deletionTarget(fixture.member.identity)
        let unbound = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: Data(repeating: 0xFF, count: 32)
            ),
            envelope: fixture.base.envelope
        )

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        ) {
            _ = try V3ReplacementDeviceIdentityClassifier().classify(
                target,
                at: unbound
            )
        }

        let otherVault = try V3EnrollmentDeviceKeyRecord(
            vaultID: "028f4d38-7d5a-7b20-b0f1-97d6e96c94b3",
            identity: fixture.member.identity,
            signingKeyRepresentation: Data([0x01]),
            wrappingKeyRepresentation: Data([0x02])
        )
        let otherTarget = try V3EnrollmentDeviceIdentityDeletionTarget(
            recordData: otherVault.canonicalBytes
        )
        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        ) {
            _ = try V3ReplacementDeviceIdentityClassifier().classify(
                otherTarget,
                at: fixture.base
            )
        }
    }

    private static func deletionTarget(
        _ identity: V3EnrollmentDeviceIdentity
    ) throws -> V3EnrollmentDeviceIdentityDeletionTarget {
        let record = try V3EnrollmentDeviceKeyRecord(
            vaultID: vaultID,
            identity: identity,
            signingKeyRepresentation: Data([0x01]),
            wrappingKeyRepresentation: Data([0x02])
        )
        return try V3EnrollmentDeviceIdentityDeletionTarget(
            recordData: record.canonicalBytes
        )
    }

    private static func device(
        _ identity: V3EnrollmentDeviceIdentity,
        status: V3DeviceStatus
    ) -> V3DeviceWrappedManifestDevice {
        V3DeviceWrappedManifestDevice(
            identity: identity,
            status: status
        )
    }

    private static func checkpoint(
        devices unsortedDevices: [V3DeviceWrappedManifestDevice],
        vaultKey: Data,
        transitionID: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        let devices = unsortedDevices.sorted {
            Data($0.identity.deviceID.utf8).lexicographicallyPrecedes(
                Data($1.identity.deviceID.utf8)
            )
        }
        let keyID = try V3VaultKeyID.derive(
            vaultKey: vaultKey,
            vaultID: vaultID
        )
        let wrappedKeys = try devices.compactMap {
            rosterDevice -> V3DeviceWrappedManifestKey? in
            guard rosterDevice.status == .active else { return nil }
            let context = try V3VaultKeyHPKEContext(
                vaultID: vaultID,
                keyID: keyID,
                authorityTransitionID: transitionID,
                recipientDeviceID: rosterDevice.identity.deviceID
            )
            return try V3DeviceWrappedManifestKey(
                recipientDeviceID: rosterDevice.identity.deviceID,
                wrappedKey: V3VaultKeyHPKE().wrap(
                    vaultKey: vaultKey,
                    recipientPublicKey:
                        rosterDevice.identity.wrappingPublicKey,
                    context: context
                )
            )
        }
        let body = try V3DeviceWrappedManifestBody(
            vaultID: vaultID,
            keyID: keyID,
            authorityTransitionID: transitionID,
            devices: devices,
            wrappedKeys: wrappedKeys,
            entries: []
        )
        let content: CanonicalJSONValue = .object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: vaultID,
            vaultKey: vaultKey
        )
        let manifestData = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(tag))),
            ])),
            ("authorizations", .array([])),
        ]))
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: vaultID,
                envelopeDigest: Data(SHA256.hash(data: manifestData))
            ),
            envelope: try V3DeviceWrappedManifestEnvelopeCodec().parse(
                manifestData
            )
        )
    }

    private static func signedFutureProfileManifest(
        basedOn candidate: V3DeviceWrappedRevocationTransitionCandidate,
        signer: TestDevice
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
                ? (
                    name,
                    CanonicalJSONValue.integer(
                        V3DeviceWrappedManifestBody.profileVersion + 1
                    )
                )
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
            vaultKey: nextVaultKey
        )
        let signature = try V3P256Signature.canonicalize(
            signer.signature(
                for: V3ManifestAuthenticator.authenticationInput(
                    for: canonicalContent
                ),
                reason: "Authorize future-profile replacement test."
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
                ("signerDeviceID", .string(signer.identity.deviceID)),
                ("signature", .string(Base64URL.encode(signature))),
            ])])),
        ]))
    }

    private struct Fixture {
        let owner: TestDevice
        let member: TestDevice
        let base: V3DeviceWrappedTrustedCheckpoint
        let plan: V3DeviceWrappedRevocationPlan

        init() throws {
            owner = try TestDevice(
                name: "Owner Mac",
                signing: 0x11,
                wrapping: 0x12
            )
            member = try TestDevice(
                name: "Member Mac",
                signing: 0x21,
                wrapping: 0x22
            )
            base = try checkpoint(
                devices: [
                    device(owner.identity, status: .active),
                    device(member.identity, status: .active),
                ],
                vaultKey: currentVaultKey,
                transitionID: parentTransitionID
            )
            plan = try V3DeviceWrappedRevocationPlanner().plan(
                from: base,
                authorizingDeviceID: owner.identity.deviceID,
                revoking: member.identity.deviceID
            )
        }

        func revocationCandidate() throws
            -> V3DeviceWrappedRevocationTransitionCandidate
        {
            try V3DeviceWrappedRevocationTransitionBuilder().build(
                from: base,
                currentEntries: [:],
                plan: plan,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                authorityTransitionID: revocationTransitionID,
                owner: owner,
                authorizationReason: "Authorize replacement test."
            )
        }
    }

    private struct TestDevice: V3EnrollmentMessageSigning {
        let vaultID = V3ReplacementDeviceIdentityClassifierTests.vaultID
        let identity: V3EnrollmentDeviceIdentity
        let signingPrivateKey: P256.Signing.PrivateKey

        var publicIdentity: V3EnrollmentDeviceIdentity { identity }

        init(name: String, signing: UInt8, wrapping: UInt8) throws {
            signingPrivateKey = try P256.Signing.PrivateKey(
                rawRepresentation: Self.scalar(signing)
            )
            let wrappingPrivateKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: Self.scalar(wrapping)
            )
            identity = try V3EnrollmentDeviceIdentity(
                displayName: name,
                signingPublicKey:
                    signingPrivateKey.publicKey.x963Representation,
                wrappingPublicKey:
                    wrappingPrivateKey.publicKey.x963Representation
            )
        }

        func signature(for input: Data, reason _: String) throws -> Data {
            try signingPrivateKey.signature(for: input).rawRepresentation
        }

        private static func scalar(_ value: UInt8) -> Data {
            Data(SHA256.hash(data: Data([value])))
        }
    }
}
