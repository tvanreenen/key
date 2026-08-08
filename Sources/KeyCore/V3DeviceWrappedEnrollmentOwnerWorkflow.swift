import Foundation

/// CLI-facing owner workflow for the permanent device-wrapped profile.
/// Joining-side adoption remains a separate increment; this adapter exposes
/// invitation, comparison, inventory, and durable owner approval on a Mac
/// that already owns the selected vault.
struct V3DeviceWrappedEnrollmentOwnerWorkflow:
    V3EnrollmentWorkflowServicing,
    Sendable
{
    typealias Identity =
        any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
    typealias IdentityLoader = @Sendable (
        _ vaultID: String,
        _ reason: String
    ) throws -> Identity?
    typealias PublicIdentityLoader = @Sendable (
        _ vaultID: String
    ) throws -> V3EnrollmentDeviceIdentity?

    private static let invitationLifetime: UInt64 = 10 * 60
    private static let maximumMailboxObjects = 4_096

    private let vaultID: String
    private let stateLoader: any V3DeviceWrappedMutationStateLoading
    private let exchange: V3EnrollmentExchangeCoordinator
    private let loadIdentity: IdentityLoader
    private let loadPublicIdentity: PublicIdentityLoader
    private let approvalService:
        any V3DeviceWrappedEnrollmentOwnerApproving

    init(
        vaultID: String,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        exchange: V3EnrollmentExchangeCoordinator,
        loadIdentity: @escaping IdentityLoader,
        loadPublicIdentity: @escaping PublicIdentityLoader,
        approvalService: any V3DeviceWrappedEnrollmentOwnerApproving
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.stateLoader = stateLoader
        self.exchange = exchange
        self.loadIdentity = loadIdentity
        self.loadPublicIdentity = loadPublicIdentity
        self.approvalService = approvalService
    }

    func deviceInventory() throws -> V3VaultDeviceInventory {
        let trusted = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to inspect authenticated devices."
        )
        let localIdentity = try loadPublicIdentity(vaultID)
        return V3VaultDeviceInventory(
            vaultID: vaultID,
            mode: .shared,
            currentDeviceID: localIdentity?.deviceID,
            devices: trusted.envelope.body.devices.map {
                V3VaultDeviceSummary(
                    deviceID: $0.identity.deviceID,
                    displayName: $0.identity.displayName,
                    role: $0.role,
                    status: $0.status
                )
            }
        )
    }

    func listInvitations() throws -> String {
        let digests = try exchange.availableInvitationDigests(
            maximumCount: Self.maximumMailboxObjects
        ).sorted(by: { $0.lexicographicallyPrecedes($1) })
        guard !digests.isEmpty else {
            return "No enrollment invitations are available yet.\n"
        }
        return digests.map(v3LowercaseHex).joined(separator: "\n") + "\n"
    }

    func createInvitation(
        deviceName: String,
        role: V3DeviceRole,
        at unixTime: UInt64
    ) throws -> String {
        let trusted = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to create an enrollment invitation."
        )
        guard trusted.checkpoint.vaultID == vaultID,
              let identity = try loadIdentity(
                  vaultID,
                  "Load this Mac's permanent enrollment identity."
              ), identity.publicIdentity.displayName == deviceName,
              let owner = trusted.envelope.body.devices.first(where: {
                  $0.identity.deviceID == identity.publicIdentity.deviceID
              }), owner.identity == identity.publicIdentity,
              owner.role == .owner,
              owner.status == .active
        else {
            throw AppError.operationRefused(
                "Only an active owner recorded by this vault can invite another Mac. Use this Mac's existing device name."
            )
        }
        guard unixTime <= UInt64.max - Self.invitationLifetime else {
            throw V3EnrollmentProtocolError.invalidFormat
        }
        let invitation = try V3EnrollmentInvitation(
            vaultID: vaultID,
            parentManifestDigest: trusted.checkpoint.envelopeDigest,
            invitingDevice: identity.publicIdentity,
            invitedRole: role,
            nonce: randomNonce(),
            expiresAt: unixTime + Self.invitationLifetime
        )
        let signed = try V3EnrollmentMessageAuthenticator().sign(
            invitation,
            using: identity,
            reason: "Publish a short-lived invitation for the joining Mac."
        )
        _ = try exchange.beginInviting(signed, at: unixTime)
        return [
            "Enrollment invitation created.",
            "Vault: \(vaultID)",
            "Invitation: \(v3LowercaseHex(invitation.digest))",
            "Role offered: \(role.rawValue)",
            "Expires in 10 minutes.",
            "On the other Mac, run `key share join \(v3LowercaseHex(invitation.digest)) --name <device-name>`."
        ].joined(separator: "\n") + "\n"
    }

    func join(
        invitationDigest _: Data,
        deviceName _: String,
        at _: UInt64
    ) throws -> String {
        throw AppError.operationRefused(
            "This Mac already selects a version 3 vault and cannot join another one."
        )
    }

    func listJoinRequests(
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> String {
        let digests = try exchange.availableJoinRequestDigests(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime,
            maximumCount: Self.maximumMailboxObjects
        ).sorted(by: { $0.lexicographicallyPrecedes($1) })
        guard !digests.isEmpty else {
            return "No join requests are available for that invitation yet.\n"
        }
        return digests.map(v3LowercaseHex).joined(separator: "\n") + "\n"
    }

    func compare(
        vaultID requestedVaultID: String,
        invitationDigest: Data,
        joinRequestDigest: Data?,
        at unixTime: UInt64
    ) throws -> String {
        guard requestedVaultID == vaultID else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        let state: V3EnrollmentCeremonyState
        if let joinRequestDigest {
            state = try exchange.receiveJoinRequest(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                joinRequestDigest: joinRequestDigest,
                at: unixTime
            )
        } else {
            state = try exchange.resume(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                at: unixTime
            )
        }
        let transcript = try requiredTranscript(state)
        return comparisonText(
            transcript,
            heading: "Enrollment comparison ready.",
            next: "If both Macs show this exact code and device pair, run `key share approve \(vaultID) \(v3LowercaseHex(invitationDigest)) \(transcript.comparisonCode)`."
        )
    }

    func approve(
        vaultID requestedVaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String {
        guard requestedVaultID == vaultID else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        let state = try exchange.resumeDeviceWrappedOwnerApproval(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        let transcript = try requiredTranscript(
            state,
            comparisonCode: comparisonCode
        )
        _ = try approvalService.approve(
            invitationDigest: invitationDigest,
            approvedTranscriptDigest: transcript.digest,
            at: unixTime,
            operationID: operationID
        )
        return "Enrollment approved. The other Mac can now run `key share accept \(vaultID) \(v3LowercaseHex(invitationDigest)) \(comparisonCode)`.\n"
    }

    func accept(
        vaultID _: String,
        invitationDigest _: Data,
        comparisonCode _: String,
        at _: UInt64,
        operationID _: VaultTransactionOperationID
    ) throws -> String {
        throw AppError.operationRefused(
            "Permanent version 3 acceptance is not enabled in this helper runtime yet."
        )
    }

    private func requiredTranscript(
        _ state: V3EnrollmentCeremonyState,
        comparisonCode: String? = nil
    ) throws -> V3EnrollmentTranscript {
        guard let transcript = state.transcript,
              comparisonCode.map({ $0 == transcript.comparisonCode }) ?? true
        else {
            throw V3EnrollmentAdoptionError.invalidCeremony
        }
        return transcript
    }

    private func comparisonText(
        _ transcript: V3EnrollmentTranscript,
        heading: String,
        next: String
    ) -> String {
        [
            heading,
            "Vault: \(transcript.invitation.vaultID)",
            "Existing Mac: \(transcript.invitation.invitingDevice.displayName)",
            "Joining Mac: \(transcript.joinRequest.joiningDevice.displayName)",
            "Role: \(transcript.invitation.invitedRole.rawValue)",
            "Comparison code: \(transcript.comparisonCode)",
            next
        ].joined(separator: "\n") + "\n"
    }

    private func randomNonce() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<32).map { _ in
            UInt8.random(
                in: UInt8.min...UInt8.max,
                using: &generator
            )
        })
    }
}
