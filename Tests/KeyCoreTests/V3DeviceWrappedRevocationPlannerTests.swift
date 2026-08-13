import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3DeviceWrappedRevocationPlannerTests {
    private static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c84b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c84b4"
    private static let vaultKey = Data(0..<32)

    @Test
    func activeOwnerCanRevokeAnActiveMember() throws {
        let owner = try identity("Owner Mac", signing: 1, wrapping: 2)
        let member = try identity("Member Mac", signing: 3, wrapping: 4)
        let earlier = try identity("Old Mac", signing: 5, wrapping: 6)
        let base = try checkpoint([
            device(owner, role: .owner, status: .active),
            device(member, role: .member, status: .active),
            device(earlier, role: .member, status: .revoked),
        ])

        let plan = try V3DeviceWrappedRevocationPlanner().plan(
            from: base,
            authorizingDeviceID: owner.deviceID,
            revoking: member.deviceID
        )

        #expect(plan.expectedCheckpoint == base.checkpoint)
        #expect(plan.authorizingOwner.identity == owner)
        #expect(plan.revokedDevice.identity == member)
        #expect(plan.revokedDevice.status == .active)
        #expect(plan.resultingDevices.count == 3)
        #expect(plan.remainingActiveDevices.map(\.identity.deviceID) == [
            owner.deviceID,
        ])
        #expect(plan.resultingDevices.first(where: {
            $0.identity.deviceID == member.deviceID
        })?.status == .revoked)
        #expect(plan.resultingDevices.first(where: {
            $0.identity.deviceID == earlier.deviceID
        })?.status == .revoked)
    }

    @Test
    func activeOwnerCanRevokeAnotherOwnerWhenOneOwnerRemains() throws {
        let first = try identity("First Owner", signing: 7, wrapping: 8)
        let second = try identity("Second Owner", signing: 9, wrapping: 10)
        let base = try checkpoint([
            device(first, role: .owner, status: .active),
            device(second, role: .owner, status: .active),
        ])

        let plan = try V3DeviceWrappedRevocationPlanner().plan(
            from: base,
            authorizingDeviceID: first.deviceID,
            revoking: second.deviceID
        )

        #expect(plan.remainingActiveDevices.map(\.identity.deviceID) == [
            first.deviceID,
        ])
        #expect(plan.resultingDevices.first(where: {
            $0.identity.deviceID == second.deviceID
        })?.role == .owner)
    }

    @Test
    func refusesToRemoveTheLastActiveOwner() throws {
        let owner = try identity("Owner Mac", signing: 11, wrapping: 12)
        let member = try identity("Member Mac", signing: 13, wrapping: 14)
        let base = try checkpoint([
            device(owner, role: .owner, status: .active),
            device(member, role: .member, status: .active),
        ])

        #expect(
            throws: V3DeviceWrappedRevocationPlanningError.lastActiveOwner
        ) {
            _ = try V3DeviceWrappedRevocationPlanner().plan(
                from: base,
                authorizingDeviceID: owner.deviceID,
                revoking: owner.deviceID
            )
        }
    }

    @Test
    func requiresAnActiveOwnerToAuthorizeRevocation() throws {
        let owner = try identity("Owner Mac", signing: 15, wrapping: 16)
        let member = try identity("Member Mac", signing: 17, wrapping: 18)
        let base = try checkpoint([
            device(owner, role: .owner, status: .active),
            device(member, role: .member, status: .active),
        ])

        #expect(
            throws: V3DeviceWrappedRevocationPlanningError
                .invalidAuthorizingOwner
        ) {
            _ = try V3DeviceWrappedRevocationPlanner().plan(
                from: base,
                authorizingDeviceID: member.deviceID,
                revoking: owner.deviceID
            )
        }
    }

    @Test
    func refusesUnknownAlreadyRevokedAndAuthorizingDevices() throws {
        let owner = try identity("Owner Mac", signing: 19, wrapping: 20)
        let active = try identity("Active Mac", signing: 21, wrapping: 22)
        let revoked = try identity("Revoked Mac", signing: 23, wrapping: 24)
        let unknown = try identity("Unknown Mac", signing: 25, wrapping: 26)
        let base = try checkpoint([
            device(owner, role: .owner, status: .active),
            device(active, role: .owner, status: .active),
            device(revoked, role: .member, status: .revoked),
        ])

        #expect(
            throws: V3DeviceWrappedRevocationPlanningError.deviceNotFound
        ) {
            _ = try V3DeviceWrappedRevocationPlanner().plan(
                from: base,
                authorizingDeviceID: owner.deviceID,
                revoking: unknown.deviceID
            )
        }
        #expect(
            throws: V3DeviceWrappedRevocationPlanningError
                .deviceAlreadyRevoked
        ) {
            _ = try V3DeviceWrappedRevocationPlanner().plan(
                from: base,
                authorizingDeviceID: owner.deviceID,
                revoking: revoked.deviceID
            )
        }
        #expect(
            throws: V3DeviceWrappedRevocationPlanningError
                .cannotRevokeAuthorizingDevice
        ) {
            _ = try V3DeviceWrappedRevocationPlanner().plan(
                from: base,
                authorizingDeviceID: owner.deviceID,
                revoking: owner.deviceID
            )
        }
    }

    @Test
    func rejectsACheckpointThatDoesNotBindTheEnvelope() throws {
        let owner = try identity("Owner Mac", signing: 27, wrapping: 28)
        let member = try identity("Member Mac", signing: 29, wrapping: 30)
        let base = try checkpoint([
            device(owner, role: .owner, status: .active),
            device(member, role: .member, status: .active),
        ])
        let altered = V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: Data(repeating: 0xFF, count: 32)
            ),
            envelope: base.envelope
        )

        #expect(
            throws: V3DeviceWrappedRevocationPlanningError
                .invalidTrustedCheckpoint
        ) {
            _ = try V3DeviceWrappedRevocationPlanner().plan(
                from: altered,
                authorizingDeviceID: owner.deviceID,
                revoking: member.deviceID
            )
        }
    }

    private func checkpoint(
        _ unsortedDevices: [V3DeviceWrappedManifestDevice]
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        let devices = unsortedDevices.sorted {
            Data($0.identity.deviceID.utf8).lexicographicallyPrecedes(
                Data($1.identity.deviceID.utf8)
            )
        }
        let keyID = try V3VaultKeyID.derive(
            vaultKey: Self.vaultKey,
            vaultID: Self.vaultID
        )
        let body = try V3DeviceWrappedManifestBody(
            vaultID: Self.vaultID,
            keyID: keyID,
            authorityTransitionID: Self.transitionID,
            devices: devices,
            wrappedKeys: try devices.compactMap { device in
                guard device.status == .active else { return nil }
                return try wrapper(for: device.identity)
            },
            entries: []
        )
        let content: CanonicalJSONValue = .object([
            ("parents", .array([])),
            ("manifest", body.canonicalValue),
        ])
        let data = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-envelope")),
            ("version", .integer(3)),
            ("content", content),
            ("authentication", .object([
                ("algorithm", .string("HKDF-SHA256+HMAC-SHA256")),
                ("tag", .string(Base64URL.encode(
                    Data(repeating: 0xA5, count: 32)
                ))),
            ])),
            ("authorizations", .array([])),
        ]))
        let envelope = try V3DeviceWrappedManifestEnvelopeCodec().parse(data)
        return V3DeviceWrappedTrustedCheckpoint(
            checkpoint: try V3ManifestCheckpoint(
                vaultID: Self.vaultID,
                envelopeDigest: Data(SHA256.hash(data: data))
            ),
            envelope: envelope
        )
    }

    private func device(
        _ identity: V3EnrollmentDeviceIdentity,
        role: V3DeviceRole,
        status: V3DeviceStatus
    ) -> V3DeviceWrappedManifestDevice {
        V3DeviceWrappedManifestDevice(
            identity: identity,
            role: role,
            status: status
        )
    }

    private func identity(
        _ name: String,
        signing: UInt8,
        wrapping: UInt8
    ) throws -> V3EnrollmentDeviceIdentity {
        try V3EnrollmentDeviceIdentity(
            displayName: name,
            signingPublicKey: try P256.Signing.PrivateKey(
                rawRepresentation: scalar(signing)
            ).publicKey.x963Representation,
            wrappingPublicKey: try P256.KeyAgreement.PrivateKey(
                rawRepresentation: scalar(wrapping)
            ).publicKey.x963Representation
        )
    }

    private func wrapper(
        for identity: V3EnrollmentDeviceIdentity
    ) throws -> V3DeviceWrappedManifestKey {
        try V3DeviceWrappedManifestKey(
            recipientDeviceID: identity.deviceID,
            wrappedKey: V3HPKEWrappedVaultKey(
                encapsulatedKey: identity.wrappingPublicKey,
                ciphertext: Data(repeating: 0x5A, count: 48)
            )
        )
    }

    private func scalar(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}
