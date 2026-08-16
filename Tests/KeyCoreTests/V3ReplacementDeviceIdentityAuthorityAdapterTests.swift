import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3ReplacementDeviceIdentityAuthorityAdapterTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96cb4b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96cb4b4"
    private static let vaultKey = Data(0..<32)

    @Test
    func activeIdentityUsesTheCompleteConflictAwareObservation() throws {
        let fixture = try Fixture(targetStatus: .active)

        let result = try fixture.adapter.classifyCurrentAuthority(
            for: fixture.target
        )

        #expect(result == .active(
            fixture.target,
            authority: .trustedCheckpoint(fixture.trusted.checkpoint)
        ))
        #expect(fixture.state.sessionCount == 1)
        #expect(fixture.state.checkpointCount == 1)
        #expect(fixture.state.keyLoadCount == 1)
        #expect(fixture.content.inspectionCount == 1)
        #expect(fixture.discovery.discoveryCount == 1)
    }

    @Test
    func revokedCheckpointNeedsNoVaultKeyOrRepositoryObservation() throws {
        let fixture = try Fixture(targetStatus: .revoked)

        let result = try fixture.adapter.classifyCurrentAuthority(
            for: fixture.target
        )

        #expect(result == .revoked(
            fixture.target,
            authority: .trustedCheckpoint(fixture.trusted.checkpoint)
        ))
        #expect(fixture.state.sessionCount == 1)
        #expect(fixture.state.checkpointCount == 1)
        #expect(fixture.state.keyLoadCount == 0)
        #expect(fixture.content.inspectionCount == 0)
        #expect(fixture.discovery.discoveryCount == 0)
    }

    @Test
    func competingTransitionsRefuseReplacementAuthority() throws {
        let fixture = try Fixture(targetStatus: .active)
        fixture.discovery.outcome = .competingCandidates([
            Data(repeating: 0x11, count: 32),
            Data(repeating: 0x22, count: 32),
        ])

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .conflictingAuthority
        ) {
            _ = try fixture.adapter.classifyCurrentAuthority(
                for: fixture.target
            )
        }
        #expect(fixture.state.keyLoadCount == 1)
        #expect(fixture.content.inspectionCount == 1)
        #expect(fixture.discovery.discoveryCount == 1)
    }

    @Test
    func targetFromAnotherVaultIsRejectedBeforeOpeningASession() throws {
        let fixture = try Fixture(targetStatus: .active)
        let otherRecord = try V3EnrollmentDeviceKeyRecord(
            vaultID: "028f4d38-7d5a-7b20-b0f1-97d6e96cb4b3",
            identity: fixture.target.identity,
            signingKeyRepresentation: Data([0x01]),
            wrappingKeyRepresentation: Data([0x02])
        )
        let otherTarget = try V3EnrollmentDeviceIdentityDeletionTarget(
            recordData: otherRecord.canonicalBytes
        )

        #expect(
            throws: V3ReplacementDeviceIdentityClassificationError
                .invalidAuthority
        ) {
            _ = try fixture.adapter.classifyCurrentAuthority(
                for: otherTarget
            )
        }
        #expect(fixture.state.sessionCount == 0)
    }

    private final class Fixture {
        let target: V3EnrollmentDeviceIdentityDeletionTarget
        let trusted: V3DeviceWrappedTrustedCheckpoint
        let state: State
        let content = ContentSteps()
        let discovery = TransitionDiscovery()

        var adapter: V3ReplacementDeviceIdentityAuthorityAdapter {
            V3ReplacementDeviceIdentityAuthorityAdapter(
                vaultID: vaultID,
                stateManager: state,
                contentSteps: content,
                keyTransitionDiscovery: discovery
            )
        }

        init(targetStatus: V3DeviceStatus) throws {
            let owner = try TestDevice(
                name: "Owner Mac",
                signing: 0x11,
                wrapping: 0x12
            )
            let member = try TestDevice(
                name: "Replacement Mac",
                signing: 0x21,
                wrapping: 0x22
            )
            let record = try V3EnrollmentDeviceKeyRecord(
                vaultID: vaultID,
                identity: member.identity,
                signingKeyRepresentation: Data([0x01]),
                wrappingKeyRepresentation: Data([0x02])
            )
            target = try V3EnrollmentDeviceIdentityDeletionTarget(
                recordData: record.canonicalBytes
            )
            trusted = try Self.makeCheckpoint(devices: [
                V3DeviceWrappedManifestDevice(
                    identity: owner.identity,
                    status: .active
                ),
                V3DeviceWrappedManifestDevice(
                    identity: member.identity,
                    status: targetStatus
                ),
            ])
            state = State(trusted: trusted, vaultKey: vaultKey)
        }

        private static func makeCheckpoint(
            devices unsortedDevices: [V3DeviceWrappedManifestDevice]
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
                device -> V3DeviceWrappedManifestKey? in
                guard device.status == .active else { return nil }
                let context = try V3VaultKeyHPKEContext(
                    vaultID: vaultID,
                    keyID: keyID,
                    authorityTransitionID: transitionID,
                    recipientDeviceID: device.identity.deviceID
                )
                return try V3DeviceWrappedManifestKey(
                    recipientDeviceID: device.identity.deviceID,
                    wrappedKey: V3VaultKeyHPKE().wrap(
                        vaultKey: vaultKey,
                        recipientPublicKey:
                            device.identity.wrappingPublicKey,
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
    }

    private final class State:
        V3DeviceWrappedCatchUpStateManaging,
        @unchecked Sendable
    {
        let trusted: V3DeviceWrappedTrustedCheckpoint
        let vaultKey: Data
        private(set) var sessionCount = 0
        private(set) var checkpointCount = 0
        private(set) var keyLoadCount = 0

        init(trusted: V3DeviceWrappedTrustedCheckpoint, vaultKey: Data) {
            self.trusted = trusted
            self.vaultKey = vaultKey
        }

        func authenticatedCheckpoint(
            reason _: String
        ) throws -> V3DeviceWrappedTrustedCheckpoint {
            checkpointCount += 1
            return trusted
        }

        func loadVaultKey(keyID: V3VaultKeyID) throws -> Data {
            #expect(keyID == trusted.envelope.body.keyID)
            keyLoadCount += 1
            return vaultKey
        }

        func withCatchUpSession<Result>(
            _ operation: () throws -> Result
        ) rethrows -> Result {
            sessionCount += 1
            return try operation()
        }
    }

    private final class ContentSteps:
        V3DeviceWrappedSameEpochCatchUpStepServicing,
        @unchecked Sendable
    {
        private(set) var inspectionCount = 0

        func inspect(
            trusted _: V3DeviceWrappedTrustedCheckpoint,
            vaultKey _: Data
        ) throws -> V3DeviceWrappedCatchUpPlan {
            inspectionCount += 1
            return .upToDate
        }

        func advance(
            trusted _: V3DeviceWrappedTrustedCheckpoint,
            vaultKey _: Data,
            expectedCheckpoint _: V3ManifestCheckpoint,
            manifestDigest _: Data
        ) throws -> V3DeviceWrappedTrustedCheckpoint {
            throw TestError.unexpectedAdvance
        }
    }

    private final class TransitionDiscovery:
        V3DeviceWrappedKeyTransitionDiscovering,
        @unchecked Sendable
    {
        var outcome: V3DeviceWrappedKeyTransitionDiscoveryOutcome = .none
        private(set) var discoveryCount = 0

        func discover(
            from _: V3DeviceWrappedTrustedCheckpoint,
            currentVaultKey _: Data
        ) throws -> V3DeviceWrappedKeyTransitionDiscoveryOutcome {
            discoveryCount += 1
            return outcome
        }
    }

    private struct TestDevice {
        let identity: V3EnrollmentDeviceIdentity

        init(name: String, signing: UInt8, wrapping: UInt8) throws {
            let signingKey = try P256.Signing.PrivateKey(
                rawRepresentation: Self.scalar(signing)
            )
            let wrappingKey = try P256.KeyAgreement.PrivateKey(
                rawRepresentation: Self.scalar(wrapping)
            )
            identity = try V3EnrollmentDeviceIdentity(
                displayName: name,
                signingPublicKey: signingKey.publicKey.x963Representation,
                wrappingPublicKey: wrappingKey.publicKey.x963Representation
            )
        }

        private static func scalar(_ value: UInt8) -> Data {
            Data(SHA256.hash(data: Data([value])))
        }
    }

    private enum TestError: Error {
        case unexpectedAdvance
    }
}
