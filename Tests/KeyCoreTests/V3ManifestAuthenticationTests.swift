import CryptoKit
import Foundation
import JSONCanonicalization
import Testing
@testable import KeyCore

struct V3ManifestAuthenticationTests {
    @Test
    func manifestAuthenticationMatchesIndependentHKDFAndHMACVector() throws {
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: Data("{}".utf8),
            vaultID: Fixture.vaultID,
            vaultKey: Fixture.vaultKey
        )

        #expect(tag.hex == "c6723b1c5ac2944e59c3179df901b9f316947dcee71beb9ad40581c1df3e0f14")
    }

    @Test
    func localGenesisAuthenticatesWithExplicitVaultTrustAnchor() throws {
        let fixture = Fixture()
        let envelope = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )

        let verified = try V3ManifestAuthenticator().verify(
            envelope,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
        )

        #expect(verified.envelope.content.manifest.vaultID == Fixture.vaultID)
        #expect(verified.envelope.content.manifest.entries.first?.name == "email/personal")
        #expect(verified.envelopeDigest == Data(SHA256.hash(data: envelope)))
    }

    @Test
    func localGenesisRejectsWrongKeyAndUntrustedVaultIdentity() throws {
        let fixture = Fixture()
        let envelope = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )

        #expect(throws: V3ManifestError.authenticationFailed) {
            try V3ManifestAuthenticator().verify(
                envelope,
                vaultKey: Data(repeating: 0xAA, count: 32),
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }
        #expect(throws: V3ManifestError.parentMismatch) {
            try V3ManifestAuthenticator().verify(
                envelope,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4")
            )
        }
    }

    @Test
    func parserRejectsNonCanonicalUnknownAndFutureJSON() throws {
        let fixture = Fixture()
        let canonical = try fixture.envelope(
            content: fixture.content()
        )
        var spaced = Data("{ ".utf8)
        spaced.append(canonical.dropFirst())

        #expect(throws: V3ManifestError.nonCanonicalJSON) {
            _ = try V3ManifestAuthenticator().parse(spaced)
        }
        #expect(throws: V3ManifestError.invalidStructure("$")) {
            try V3ManifestAuthenticator().parse(
                Data("{\"bogus\":true,\"format\":\"key-vault-manifest-envelope\",\"version\":3}".utf8)
            )
        }
        #expect(throws: V3ManifestError.unsupportedVersion(4)) {
            try V3ManifestAuthenticator().parse(
                Data("{\"format\":\"key-vault-manifest-envelope\",\"version\":4}".utf8)
            )
        }
    }

    @Test
    func unreleasedPrototypeMetadataIsNotAVersion3Manifest() {
        let prototypeMetadata = Data(
            #"{"devices":[],"epoch":1,"securityMode":"enclave","vaultID":"prototype-vault","version":1,"wrappedKeys":[]}"#.utf8
        )

        #expect(throws: V3ManifestError.invalidStructure("$.format")) {
            _ = try V3ManifestAuthenticator().parse(prototypeMetadata)
        }
    }

    @Test
    func removedGenerationFieldsAreRejectedAsUnknown() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )
        let bodyWithGeneration = replacing(
            parent,
            "\"format\":\"key-vault-manifest\",\"keyID\"",
            with: "\"format\":\"key-vault-manifest\",\"generation\":1,\"keyID\""
        )
        #expect(throws: V3ManifestError.invalidStructure("$.content.manifest")) {
            _ = try V3ManifestAuthenticator().parse(bodyWithGeneration)
        }

        let child = try fixture.envelope(
            content: fixture.content(parents: fixture.parentReferences(to: [parent]))
        )
        let singularParent = replacing(
            child,
            "\"parents\":[",
            with: "\"parent\":["
        )
        #expect(throws: V3ManifestError.invalidStructure("$.content")) {
            _ = try V3ManifestAuthenticator().parse(singularParent)
        }
    }

    @Test
    func removedKeyEpochFieldsAreRejectedAsUnknown() throws {
        let fixture = Fixture()
        let local = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )
        let replacements = [
            (
                "\"keyID\":\"\(Fixture.keyID.rawValue)\",\"mode\"",
                "\"keyEpoch\":1,\"mode\"",
                "$.content.manifest"
            ),
            (
                "\"keyID\":\"\(Fixture.keyID.rawValue)\",\"name\"",
                "\"keyEpoch\":1,\"name\"",
                "$.content.manifest.entries[0]"
            ),
            (
                "\"tag\"",
                "\"keyEpoch\":1,\"tag\"",
                "$.authentication"
            )
        ]
        for (original, replacement, path) in replacements {
            #expect(throws: V3ManifestError.invalidStructure(path)) {
                _ = try V3ManifestAuthenticator().parse(
                    replacing(local, original, with: replacement)
                )
            }
        }

        let shared = try fixture.envelope(
            content: fixture.content()
        )
        #expect(throws: V3ManifestError.invalidStructure(
            "$.content.manifest.wrappedKeys[0]"
        )) {
            _ = try V3ManifestAuthenticator().parse(replacing(
                shared,
                "\"ciphertext\":\"AQID\",\"deviceID\":\"\(fixture.deviceID)\"}",
                with: "\"ciphertext\":\"AQID\",\"deviceID\":\"\(fixture.deviceID)\",\"keyEpoch\":1}"
            ))
        }
    }

    @Test
    func redundantActiveKeyIDFieldsAreRejectedAsUnknown() throws {
        let fixture = Fixture()
        let local = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )
        #expect(throws: V3ManifestError.invalidStructure("$.authentication")) {
            _ = try V3ManifestAuthenticator().parse(replacing(
                local,
                "\"tag\"",
                with: "\"keyID\":\"\(Fixture.keyID.rawValue)\",\"tag\""
            ))
        }

        let shared = try fixture.envelope(
            content: fixture.content()
        )
        #expect(throws: V3ManifestError.invalidStructure(
            "$.content.manifest.wrappedKeys[0]"
        )) {
            _ = try V3ManifestAuthenticator().parse(replacing(
                shared,
                "\"ciphertext\":\"AQID\",\"deviceID\":\"\(fixture.deviceID)\"}",
                with: "\"ciphertext\":\"AQID\",\"deviceID\":\"\(fixture.deviceID)\",\"keyID\":\"\(Fixture.keyID.rawValue)\"}"
            ))
        }
    }

    @Test
    func canonicalJSONFailuresMapToManifestErrors() {
        #expect(throws: V3ManifestError.duplicateProperty) {
            _ = try V3ManifestAuthenticator().parse(Data(#"{"a":1,"\u0061":2}"#.utf8))
        }
        #expect(throws: V3ManifestError.invalidEncoding) {
            _ = try V3ManifestAuthenticator().parse(Data([0xEF, 0xBB, 0xBF, 0x7B, 0x7D]))
        }

        let count = 33
        let deeplyNested = String(repeating: "[", count: count)
            + "0"
            + String(repeating: "]", count: count)
        #expect(throws: V3ManifestError.invalidJSON) {
            _ = try V3ManifestAuthenticator().parse(Data(deeplyNested.utf8))
        }
    }

    @Test
    func changingAnyManifestBodyFieldWithoutRetaggingIsRejected() throws {
        let fixture = Fixture()
        let localEnvelope = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )

        #expect(throws: V3ManifestError.invalidStructure("$.content.manifest.format")) {
            let mutated = replacing(
                localEnvelope,
                "\"format\":\"key-vault-manifest\"",
                with: "\"format\":\"key-vault-other\""
            )
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }
        #expect(throws: V3ManifestError.invalidStructure("$.content.manifest.version")) {
            let mutated = replacing(
                localEnvelope,
                "\"version\":3,\"wrappedKeys\"",
                with: "\"version\":4,\"wrappedKeys\""
            )
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }

        let localReplacements = [
            ("entryID", Fixture.entryID, "018f4d39-930c-735d-8d6f-588e9b0a3a49"),
            ("entryName", "\"name\":\"email/personal\"", "\"name\":\"email/work\""),
            ("entryType", "\"type\":\"secret\"", "\"type\":\"totp\""),
            ("entryRevision", "\"revision\":4", "\"revision\":5"),
            (
                "entryKeyID",
                "\"keyID\":\"\(Fixture.keyID.rawValue)\",\"name\"",
                "\"keyID\":\"\(Fixture.alternateKeyID.rawValue)\",\"name\""
            ),
            ("ciphertextDigest", Fixture.digest, String(repeating: "E", count: 43))
        ]

        for (_, original, replacement) in localReplacements {
            let mutated = replacing(localEnvelope, original, with: replacement)
            #expect(throws: V3ManifestError.authenticationFailed) {
                _ = try V3ManifestAuthenticator().verify(
                    mutated,
                    vaultKey: Fixture.vaultKey,
                    trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
                )
            }
        }

        let alternateVaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
        #expect(throws: V3ManifestError.authenticationFailed) {
            let mutated = replacing(localEnvelope, Fixture.vaultID, with: alternateVaultID)
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: alternateVaultID)
            )
        }

        #expect(throws: V3ManifestError.authenticationFailed) {
            let mutated = replacing(
                localEnvelope,
                "\"keyID\":\"\(Fixture.keyID.rawValue)\",\"mode\"",
                with: "\"keyID\":\"\(Fixture.alternateKeyID.rawValue)\",\"mode\""
            )
            _ = try V3ManifestAuthenticator().verify(
                mutated,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }

        let parent = try fixture.envelope(
            content: fixture.content()
        )
        let child = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [parent]),
                entryRevision: 5
            )
        )

        let sharedReplacements = [
            ("mode", "\"mode\":\"shared\"", "\"mode\":\"local\""),
            ("deviceID", fixture.deviceID, String(repeating: "A", count: 43)),
            ("displayName", "\"displayName\":\"Laptop\"", "\"displayName\":\"Desktop\""),
            ("role", "\"role\":\"owner\"", "\"role\":\"member\""),
            ("status", "\"status\":\"active\"", "\"status\":\"revoked\""),
            ("signingPublicKey", fixture.signingPublicKeyValue, fixture.alternateSigningPublicKeyValue),
            ("wrappingPublicKey", fixture.wrappingPublicKeyValue, fixture.alternateWrappingPublicKeyValue),
            ("wrappedKeyCiphertext", "\"ciphertext\":\"AQID\",\"deviceID\"", "\"ciphertext\":\"BAUG\",\"deviceID\"")
        ]

        for (_, original, replacement) in sharedReplacements {
            let mutated = replacing(child, original, with: replacement)
            #expect(throws: V3ManifestError.authenticationFailed) {
                _ = try V3ManifestAuthenticator().verify(
                    mutated,
                    vaultKey: Fixture.vaultKey,
                    trustAnchor: try Fixture.trustAnchor(for: parent)
                )
            }
        }
    }

    @Test
    func entryOnlyChildAuthenticatesWithoutOwnerPresence() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                entryRevision: 4
            )
        )
        let child = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [parent]),
                entryRevision: 5
            )
        )

        let verified = try V3ManifestAuthenticator().verify(
            child,
            vaultKey: Fixture.vaultKey,
            trustAnchor: try Fixture.trustAnchor(for: parent)
        )

        #expect(verified.envelope.content.manifest.entries.first?.revision == 5)
        #expect(verified.envelope.authorizations.isEmpty)
    }

    @Test
    func childMustExtendTheExactTrustedParent() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content()
        )
        let otherParent = replacing(parent, Fixture.digest, with: String(repeating: "C", count: 43))
        let child = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [otherParent])
            )
        )

        #expect(throws: V3ManifestError.parentMismatch) {
            try V3ManifestAuthenticator().verify(
                child,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }
    }

    @Test
    func authorityChangeRequiresActiveParentOwnerSignature() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content()
        )
        let candidateContent = fixture.content(
            parents: fixture.parentReferences(to: [parent]),
            keyID: Fixture.alternateKeyID
        )
        let unsigned = try fixture.envelope(
            content: candidateContent,
            vaultKey: Fixture.alternateVaultKey
        )

        #expect(throws: V3ManifestError.authorizationRequired) {
            try V3ManifestAuthenticator().verify(
                unsigned,
                vaultKey: Fixture.alternateVaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let signed = try fixture.envelope(
            content: candidateContent,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)],
            vaultKey: Fixture.alternateVaultKey
        )
        let verified = try V3ManifestAuthenticator().verify(
            signed,
            vaultKey: Fixture.alternateVaultKey,
            trustAnchor: try Fixture.trustAnchor(for: parent)
        )
        #expect(verified.envelope.content.manifest.keyID == Fixture.alternateKeyID)
        #expect(verified.envelope.authorizations.map(\.signerDeviceID) == [fixture.deviceID])
    }

    @Test
    func invalidMemberCandidateAndHighSSignaturesFailClosed() throws {
        let ownerFixture = Fixture()
        let memberParent = try ownerFixture.envelope(
            content: ownerFixture.content(
                parents: .array([]),
                additionalDeviceRole: .member
            )
        )
        let memberCandidateContent = ownerFixture.content(
            parents: ownerFixture.parentReferences(to: [memberParent]),
            keyID: Fixture.alternateKeyID,
            additionalDeviceRole: .member
        )
        let memberSigned = try ownerFixture.envelope(
            content: memberCandidateContent,
            signers: [(ownerFixture.alternateDeviceID, ownerFixture.alternateSigningPrivateKey)],
            vaultKey: Fixture.alternateVaultKey
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                memberSigned,
                vaultKey: Fixture.alternateVaultKey,
                trustAnchor: try Fixture.trustAnchor(for: memberParent)
            )
        }

        let ownerOnlyParent = try ownerFixture.envelope(
            content: ownerFixture.content(
                parents: .array([])
            )
        )
        let introducedContent = ownerFixture.content(
            parents: ownerFixture.parentReferences(to: [ownerOnlyParent]),
            additionalDeviceRole: .member
        )
        let introducedSigned = try ownerFixture.envelope(
            content: introducedContent,
            signers: [(ownerFixture.alternateDeviceID, ownerFixture.alternateSigningPrivateKey)]
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                introducedSigned,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: ownerOnlyParent)
            )
        }

        let ownerParent = try ownerFixture.envelope(
            content: ownerFixture.content()
        )
        let ownerCandidateContent = ownerFixture.content(
            parents: ownerFixture.parentReferences(to: [ownerParent]),
            keyID: Fixture.alternateKeyID
        )
        let highSSigned = try ownerFixture.envelope(
            content: ownerCandidateContent,
            signers: [(ownerFixture.deviceID, ownerFixture.signingPrivateKey)],
            forceHighS: true,
            vaultKey: Fixture.alternateVaultKey
        )
        #expect(throws: V3ManifestError.authorizationFailed) {
            try V3ManifestAuthenticator().verify(
                highSSigned,
                vaultKey: Fixture.alternateVaultKey,
                trustAnchor: try Fixture.trustAnchor(for: ownerParent)
            )
        }
    }

    @Test
    func entryOnlyTransitionRejectsInjectedAuthorization() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content()
        )
        let content = fixture.content(
            parents: fixture.parentReferences(to: [parent]),
            entryRevision: 5
        )
        let signed = try fixture.envelope(
            content: content,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)]
        )

        #expect(throws: V3ManifestError.unexpectedAuthorization) {
            try V3ManifestAuthenticator().verify(
                signed,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }
    }

    @Test
    func modeSpecificMembershipAndWrappedKeyStateFailClosed() throws {
        let fixture = Fixture()
        let parent = try fixture.envelope(
            content: fixture.content()
        )
        let parentReferences = fixture.parentReferences(to: [parent])

        func signedCandidate(_ content: CanonicalJSONValue) throws -> Data {
            try fixture.envelope(
                content: content,
                signers: [(fixture.deviceID, fixture.signingPrivateKey)]
            )
        }

        let localWithDevice = try signedCandidate(fixture.content(
            parents: parentReferences,
            mode: .local
        ))
        #expect(throws: V3ManifestError.semanticViolation("devices.localMode")) {
            try V3ManifestAuthenticator().verify(
                localWithDevice,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let localWithWrapper = try signedCandidate(fixture.content(
            parents: parentReferences,
            mode: .local,
            includeDevice: false,
            includeWrapper: true
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.localMode")) {
            try V3ManifestAuthenticator().verify(
                localWithWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let ownerless = try signedCandidate(fixture.content(
            parents: parentReferences,
            role: .member
        ))
        #expect(throws: V3ManifestError.semanticViolation("devices.activeOwner")) {
            try V3ManifestAuthenticator().verify(
                ownerless,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let missingWrapper = try signedCandidate(fixture.content(
            parents: parentReferences,
            includeWrapper: false
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.coverage")) {
            try V3ManifestAuthenticator().verify(
                missingWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let unknownRecipient = try signedCandidate(fixture.content(
            parents: parentReferences,
            wrapperDeviceID: fixture.alternateDeviceID
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.deviceID")) {
            try V3ManifestAuthenticator().verify(
                unknownRecipient,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let revokedWithWrapper = try signedCandidate(fixture.content(
            parents: parentReferences,
            role: .member,
            status: .revoked,
            additionalDeviceRole: .owner
        ))
        #expect(throws: V3ManifestError.semanticViolation("wrappedKeys.deviceID")) {
            try V3ManifestAuthenticator().verify(
                revokedWithWrapper,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }

        let validRevokedMembership = try signedCandidate(fixture.content(
            parents: parentReferences,
            role: .member,
            status: .revoked,
            includeWrapper: false,
            additionalDeviceRole: .owner
        ))
        let verified = try V3ManifestAuthenticator().verify(
            validRevokedMembership,
            vaultKey: Fixture.vaultKey,
            trustAnchor: try Fixture.trustAnchor(for: parent)
        )
        #expect(verified.envelope.content.manifest.devices.count == 2)
        #expect(verified.envelope.content.manifest.wrappedKeys.count == 1)
    }

    @Test
    func authenticatedSemanticViolationsRemainUntrusted() throws {
        let fixture = Fixture()
        let badName = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false,
                entryName: "../escape"
            )
        )
        #expect(throws: V3ManifestError.semanticViolation("entries.name")) {
            try V3ManifestAuthenticator().verify(
                badName,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
            )
        }

        let parent = try fixture.envelope(
            content: fixture.content()
        )
        let wrongDeviceIDContent = fixture.content(
            parents: fixture.parentReferences(to: [parent]),
            deviceID: String(repeating: "A", count: 43)
        )
        let wrongDeviceID = try fixture.envelope(
            content: wrongDeviceIDContent,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)]
        )
        #expect(throws: V3ManifestError.semanticViolation("devices.deviceID")) {
            try V3ManifestAuthenticator().verify(
                wrongDeviceID,
                vaultKey: Fixture.vaultKey,
                trustAnchor: try Fixture.trustAnchor(for: parent)
            )
        }
    }

    @Test
    func mergeAuthenticatesEveryCanonicalParentAndPreservesBothBranches() throws {
        let fixture = Fixture()
        let authenticator = V3ManifestAuthenticator()
        let genesis = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )
        let verifiedGenesis = try authenticator.verify(
            genesis,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
        )
        let left = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [genesis]),
                mode: .local,
                includeDevice: false,
                entryName: "email/left"
            )
        )
        let right = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [genesis]),
                mode: .local,
                includeDevice: false,
                entryName: "email/right"
            )
        )
        let verifiedLeft = try authenticator.verify(
            left,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .verifiedParents([verifiedGenesis])
        )
        let verifiedRight = try authenticator.verify(
            right,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .verifiedParents([verifiedGenesis])
        )
        let merge = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [left, right]),
                mode: .local,
                includeDevice: false,
                entryName: "email/merged"
            )
        )

        let verifiedMerge = try authenticator.verify(
            merge,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .verifiedParents([verifiedRight, verifiedLeft])
        )

        #expect(verifiedMerge.envelope.content.parents == fixture.parentDigestStrings(
            for: [left, right]
        ))
    }

    @Test
    func malformedOrIncompleteMergeParentSetsFailClosed() throws {
        let fixture = Fixture()
        let authenticator = V3ManifestAuthenticator()
        let genesis = try fixture.envelope(
            content: fixture.content(
                parents: .array([]),
                mode: .local,
                includeDevice: false
            )
        )
        let verifiedGenesis = try authenticator.verify(
            genesis,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .localGenesis(vaultID: Fixture.vaultID)
        )
        let left = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [genesis]),
                mode: .local,
                includeDevice: false,
                entryName: "email/left"
            )
        )
        let right = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [genesis]),
                mode: .local,
                includeDevice: false,
                entryName: "email/right"
            )
        )
        let verifiedLeft = try authenticator.verify(
            left,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .verifiedParents([verifiedGenesis])
        )
        let verifiedRight = try authenticator.verify(
            right,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .verifiedParents([verifiedGenesis])
        )
        let sortedParents = fixture.parentDigestStrings(for: [left, right])
        let merge = try fixture.envelope(
            content: fixture.content(
                parents: .array(sortedParents.map(CanonicalJSONValue.string)),
                mode: .local,
                includeDevice: false
            )
        )

        #expect(throws: V3ManifestError.parentMismatch) {
            _ = try authenticator.verify(
                merge,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .verifiedParents([verifiedLeft])
            )
        }

        let duplicate = try fixture.envelope(
            content: fixture.content(
                parents: .array([
                    .string(sortedParents[0]),
                    .string(sortedParents[0])
                ]),
                mode: .local,
                includeDevice: false
            )
        )
        #expect(throws: V3ManifestError.invalidStructure("$.content.parents")) {
            _ = try authenticator.parse(duplicate)
        }

        let unsorted = try fixture.envelope(
            content: fixture.content(
                parents: .array(sortedParents.reversed().map(CanonicalJSONValue.string)),
                mode: .local,
                includeDevice: false
            )
        )
        #expect(throws: V3ManifestError.invalidStructure("$.content.parents")) {
            _ = try authenticator.parse(unsorted)
        }

        let authorityChangingMerge = try fixture.envelope(
            content: fixture.content(
                parents: .array(sortedParents.map(CanonicalJSONValue.string))
            )
        )
        #expect(throws: V3ManifestError.parentAuthorityConflict) {
            _ = try authenticator.verify(
                authorityChangingMerge,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .verifiedParents([verifiedLeft, verifiedRight])
            )
        }
    }

    @Test
    func mergeRejectsParentsWithDifferentActiveKeyAuthority() throws {
        let fixture = Fixture()
        let authenticator = V3ManifestAuthenticator()
        let sharedBase = try fixture.envelope(
            content: fixture.content(
                parents: .array([])
            )
        )
        let verifiedBase = try Fixture.preverified(sharedBase)
        let left = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [sharedBase]),
                entryName: "email/left"
            )
        )
        let verifiedLeft = try authenticator.verify(
            left,
            vaultKey: Fixture.vaultKey,
            trustAnchor: .verifiedParents([verifiedBase])
        )
        let rightContent = fixture.content(
            parents: fixture.parentReferences(to: [sharedBase]),
            keyID: Fixture.alternateKeyID,
            entryName: "email/right"
        )
        let right = try fixture.envelope(
            content: rightContent,
            signers: [(fixture.deviceID, fixture.signingPrivateKey)],
            vaultKey: Fixture.alternateVaultKey
        )
        let verifiedRight = try authenticator.verify(
            right,
            vaultKey: Fixture.alternateVaultKey,
            trustAnchor: .verifiedParents([verifiedBase])
        )
        let merge = try fixture.envelope(
            content: fixture.content(
                parents: fixture.parentReferences(to: [left, right]),
                entryName: "email/merged"
            )
        )

        #expect(throws: V3ManifestError.parentAuthorityConflict) {
            _ = try authenticator.verify(
                merge,
                vaultKey: Fixture.vaultKey,
                trustAnchor: .verifiedParents([verifiedLeft, verifiedRight])
            )
        }
    }
}

private struct Fixture {
    static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    static let entryID = "018f4d39-930c-735d-8d6f-588e9b0a3a48"
    static let digest = String(repeating: "A", count: 43)
    static let vaultKey = Data((0..<32).map(UInt8.init))
    static let alternateVaultKey = Data(repeating: 0xFF, count: 32)
    static let keyID = try! V3VaultKeyID.derive(
        vaultKey: vaultKey,
        vaultID: vaultID
    )
    static let alternateKeyID = try! V3VaultKeyID.derive(
        vaultKey: alternateVaultKey,
        vaultID: vaultID
    )

    let signingPrivateKey = P256.Signing.PrivateKey()
    let wrappingPrivateKey = P256.KeyAgreement.PrivateKey()
    let alternateSigningPrivateKey = P256.Signing.PrivateKey()
    let alternateWrappingPrivateKey = P256.KeyAgreement.PrivateKey()

    var signingPublicKeyValue: String {
        encodeBase64URL(signingPrivateKey.publicKey.x963Representation)
    }

    var wrappingPublicKeyValue: String {
        encodeBase64URL(wrappingPrivateKey.publicKey.x963Representation)
    }

    var alternateSigningPublicKeyValue: String {
        encodeBase64URL(alternateSigningPrivateKey.publicKey.x963Representation)
    }

    var alternateWrappingPublicKeyValue: String {
        encodeBase64URL(alternateWrappingPrivateKey.publicKey.x963Representation)
    }

    var deviceID: String {
        V3ManifestAuthenticator.deviceID(
            signingPublicKey: signingPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingPrivateKey.publicKey.x963Representation
        )
    }

    var alternateDeviceID: String {
        V3ManifestAuthenticator.deviceID(
            signingPublicKey: alternateSigningPrivateKey.publicKey.x963Representation,
            wrappingPublicKey: alternateWrappingPrivateKey.publicKey.x963Representation
        )
    }

    func content(
        parents: CanonicalJSONValue = .array([]),
        mode: V3VaultMode = .shared,
        keyID: V3VaultKeyID = Fixture.keyID,
        role: V3DeviceRole = .owner,
        status: V3DeviceStatus = .active,
        includeDevice: Bool = true,
        includeWrapper: Bool? = nil,
        wrapperDeviceID: String? = nil,
        additionalDeviceRole: V3DeviceRole? = nil,
        deviceID overriddenDeviceID: String? = nil,
        entryName: String = "email/personal",
        entryRevision: UInt64 = 4,
        entryKeyID: V3VaultKeyID = Fixture.keyID
    ) -> CanonicalJSONValue {
        .object([
            ("parents", parents),
            ("manifest", manifest(
                mode: mode,
                keyID: keyID,
                role: role,
                status: status,
                includeDevice: includeDevice,
                includeWrapper: includeWrapper,
                wrapperDeviceID: wrapperDeviceID,
                additionalDeviceRole: additionalDeviceRole,
                deviceID: overriddenDeviceID,
                entryName: entryName,
                entryRevision: entryRevision,
                entryKeyID: entryKeyID
            ))
        ])
    }

    func manifest(
        mode: V3VaultMode,
        keyID: V3VaultKeyID,
        role: V3DeviceRole,
        status: V3DeviceStatus,
        includeDevice: Bool,
        includeWrapper: Bool?,
        wrapperDeviceID: String?,
        additionalDeviceRole: V3DeviceRole?,
        deviceID overriddenDeviceID: String?,
        entryName: String,
        entryRevision: UInt64,
        entryKeyID: V3VaultKeyID
    ) -> CanonicalJSONValue {
        let actualDeviceID = overriddenDeviceID ?? deviceID
        var deviceRecords: [(String, CanonicalJSONValue)] = []
        if includeDevice {
            let members: [(String, CanonicalJSONValue)] = [
                ("deviceID", .string(actualDeviceID)),
                ("displayName", .string("Laptop")),
                ("role", .string(role.rawValue)),
                ("status", .string(status.rawValue)),
                ("signingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDSA")),
                    ("encoding", .string("x963")),
                    ("value", .string(signingPublicKeyValue))
                ])),
                ("wrappingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDH")),
                    ("encoding", .string("x963")),
                    ("value", .string(wrappingPublicKeyValue))
                ]))
            ]
            deviceRecords.append((actualDeviceID, .object(members)))
        }
        if let additionalDeviceRole {
            deviceRecords.append((alternateDeviceID, .object([
                ("deviceID", .string(alternateDeviceID)),
                ("displayName", .string("Phone")),
                ("role", .string(additionalDeviceRole.rawValue)),
                ("status", .string(V3DeviceStatus.active.rawValue)),
                ("signingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDSA")),
                    ("encoding", .string("x963")),
                    ("value", .string(alternateSigningPublicKeyValue))
                ])),
                ("wrappingPublicKey", .object([
                    ("algorithm", .string("P-256-ECDH")),
                    ("encoding", .string("x963")),
                    ("value", .string(alternateWrappingPublicKeyValue))
                ]))
            ])))
        }
        let devices = deviceRecords
            .sorted { Data($0.0.utf8).lexicographicallyPrecedes(Data($1.0.utf8)) }
            .map(\.1)

        var wrapperRecords: [(String, CanonicalJSONValue)] = []
        if includeWrapper ?? includeDevice {
            let actualWrapperDeviceID = wrapperDeviceID ?? actualDeviceID
            wrapperRecords.append((actualWrapperDeviceID, .object([
                ("deviceID", .string(actualWrapperDeviceID)),
                ("algorithm", .string("p256-ecies-x963-sha256-aes-gcm")),
                ("ciphertext", .string("AQID"))
            ])))
        }
        if additionalDeviceRole != nil {
            wrapperRecords.append((alternateDeviceID, .object([
                ("deviceID", .string(alternateDeviceID)),
                ("algorithm", .string("p256-ecies-x963-sha256-aes-gcm")),
                ("ciphertext", .string("BAUG"))
            ])))
        }
        let wrappedKeys = wrapperRecords
            .sorted { Data($0.0.utf8).lexicographicallyPrecedes(Data($1.0.utf8)) }
            .map(\.1)

        return .object([
            ("format", .string("key-vault-manifest")),
            ("version", .integer(3)),
            ("vaultID", .string(Self.vaultID)),
            ("mode", .string(mode.rawValue)),
            ("keyID", .string(keyID.rawValue)),
            ("devices", .array(devices)),
            ("wrappedKeys", .array(wrappedKeys)),
            ("entries", .array([
                .object([
                    ("entryID", .string(Self.entryID)),
                    ("name", .string(entryName)),
                    ("type", .string("secret")),
                    ("revision", .integer(entryRevision)),
                    ("keyID", .string(entryKeyID.rawValue)),
                    ("ciphertextDigest", .string(Self.digest))
                ])
            ]))
        ])
    }

    func parentReferences(to envelopes: [Data]) -> CanonicalJSONValue {
        .array(parentDigestStrings(for: envelopes).map(CanonicalJSONValue.string))
    }

    func parentDigestStrings(for envelopes: [Data]) -> [String] {
        envelopes
            .map { Data(SHA256.hash(data: $0)) }
            .sorted(by: { $0.lexicographicallyPrecedes($1) })
            .map(encodeBase64URL)
    }

    static func preverified(_ data: Data) throws -> V3VerifiedManifest {
        V3VerifiedManifest(
            envelope: try V3ManifestAuthenticator().parse(data),
            envelopeDigest: Data(SHA256.hash(data: data))
        )
    }

    /// Builds a test-only trust anchor for shared state whose enrollment
    /// ceremony is deliberately outside this test suite.
    static func trustAnchor(for data: Data) throws -> V3ManifestTrustAnchor {
        .verifiedParents([try preverified(data)])
    }

    func envelope(
        content: CanonicalJSONValue,
        signers: [(String, P256.Signing.PrivateKey)] = [],
        forceHighS: Bool = false,
        vaultKey: Data = Fixture.vaultKey
    ) throws -> Data {
        let canonicalContent = CanonicalJSON.encode(content)
        let tag = try V3ManifestAuthenticator.authenticationTag(
            canonicalContent: canonicalContent,
            vaultID: Self.vaultID,
            vaultKey: vaultKey
        )
        let input = V3ManifestAuthenticator.authenticationInput(for: canonicalContent)
        let digest = SHA256.hash(data: input)
        let authorizations = try signers.map { signerID, privateKey -> CanonicalJSONValue in
            let signature = try privateKey.signature(for: digest)
            let lowS = try V3ManifestAuthenticator.canonicalizeP256Signature(signature.rawRepresentation)
            let storedSignature = forceHighS ? highSSignature(fromLowS: lowS) : lowS
            return .object([
                ("algorithm", .string("P-256-ECDSA-SHA256")),
                ("signerDeviceID", .string(signerID)),
                ("signature", .string(encodeBase64URL(storedSignature)))
            ])
        }

        return CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(encodeBase64URL(tag)))
            ])),
            ("authorizations", .array(authorizations))
        ]))
    }
}

private func encodeBase64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func replacing(_ data: Data, _ original: String, with replacement: String) -> Data {
    let source = String(decoding: data, as: UTF8.self)
    precondition(source.contains(original), "Fixture does not contain \(original)")
    return Data(source.replacingOccurrences(of: original, with: replacement).utf8)
}

private func highSSignature(fromLowS signature: Data) -> Data {
    let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ]
    let bytes = Array(signature)
    let s = Array(bytes[32..<64])
    var highS = [UInt8](repeating: 0, count: 32)
    var borrow = 0
    for index in stride(from: 31, through: 0, by: -1) {
        let difference = Int(order[index]) - Int(s[index]) - borrow
        if difference < 0 {
            highS[index] = UInt8(difference + 256)
            borrow = 1
        } else {
            highS[index] = UInt8(difference)
            borrow = 0
        }
    }
    return Data(bytes[0..<32] + highS)
}

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
