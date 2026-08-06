import CryptoKit
import Foundation

func makeLiveV3EnrollmentWorkflowService(
    rootHandle: VaultRootDirectoryHandle,
    selectedVaultID: String?,
    keyStore: any VaultKeyStoring,
    keyConfiguration: KeyConfiguration,
    configStore: KeyConfigStore,
    runtimeConfiguration: RuntimeConfiguration
) -> V3EnrollmentWorkflowService {
    let objectStore = V3FilesystemTransactionArtifactStore(
        rootHandle: rootHandle
    )
    let checkpointStore = V3ManifestCheckpointKeychainStore(
        configuration: runtimeConfiguration
    )
    let exchange = V3EnrollmentExchangeCoordinator(
        mailbox: V3FilesystemEnrollmentMailbox(rootHandle: rootHandle),
        stateStore: V3EnrollmentCeremonyStateKeychainStore(
            configuration: runtimeConfiguration
        )
    )
    let identityManager = V3EnrollmentDeviceIdentityManager(
        recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(
            configuration: runtimeConfiguration
        ),
        keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations()
    )
    return V3EnrollmentWorkflowService(
        selectedVaultID: selectedVaultID,
        source: objectStore,
        objectStore: objectStore,
        checkpointStore: checkpointStore,
        exchange: exchange,
        identityManager: identityManager,
        vaultKeyStore: keyStore,
        keychainMode: keyConfiguration.keychainMode,
        selectVault: { vaultID in
            _ = try configStore.selectV3Vault(
                vaultID: vaultID,
                expectedRootHandle: rootHandle,
                expectedKeychainMode: keyConfiguration.keychainMode
            )
        },
        verifyRuntime: { vaultID in
            try V3ReadOnlyVaultRuntime(
                source: objectStore,
                vaultID: vaultID,
                checkpointStore: checkpointStore,
                vaultKeyProvider: { reason in
                    try keyStore.loadKey(
                        mode: keyConfiguration.keychainMode,
                        reason: reason,
                        createIfMissing: false
                    )
                }
            ).unlock()
        }
    )
}

protocol V3EnrollmentWorkflowServicing {
    func deviceInventory() throws -> V3VaultDeviceInventory
    func listInvitations() throws -> String
    func createInvitation(
        deviceName: String,
        role: V3DeviceRole,
        at unixTime: UInt64
    ) throws -> String
    func join(
        invitationDigest: Data,
        deviceName: String,
        at unixTime: UInt64
    ) throws -> String
    func listJoinRequests(
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> String
    func compare(
        vaultID: String,
        invitationDigest: Data,
        joinRequestDigest: Data?,
        at unixTime: UInt64
    ) throws -> String
    func approve(
        vaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String
    func accept(
        vaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String
}

struct DeferredV3EnrollmentWorkflowService:
    V3EnrollmentWorkflowServicing
{
    typealias Factory = () throws -> any V3EnrollmentWorkflowServicing
    private let makeService: Factory

    init(makeService: @escaping Factory) {
        self.makeService = makeService
    }

    func deviceInventory() throws -> V3VaultDeviceInventory {
        try makeService().deviceInventory()
    }

    func listInvitations() throws -> String {
        try makeService().listInvitations()
    }

    func createInvitation(
        deviceName: String,
        role: V3DeviceRole,
        at unixTime: UInt64
    ) throws -> String {
        try makeService().createInvitation(
            deviceName: deviceName,
            role: role,
            at: unixTime
        )
    }

    func join(
        invitationDigest: Data,
        deviceName: String,
        at unixTime: UInt64
    ) throws -> String {
        try makeService().join(
            invitationDigest: invitationDigest,
            deviceName: deviceName,
            at: unixTime
        )
    }

    func listJoinRequests(
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> String {
        try makeService().listJoinRequests(
            invitationDigest: invitationDigest,
            at: unixTime
        )
    }

    func compare(
        vaultID: String,
        invitationDigest: Data,
        joinRequestDigest: Data?,
        at unixTime: UInt64
    ) throws -> String {
        try makeService().compare(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            joinRequestDigest: joinRequestDigest,
            at: unixTime
        )
    }

    func approve(
        vaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String {
        try makeService().approve(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            comparisonCode: comparisonCode,
            at: unixTime,
            operationID: operationID
        )
    }

    func accept(
        vaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String {
        try makeService().accept(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            comparisonCode: comparisonCode,
            at: unixTime,
            operationID: operationID
        )
    }
}

/// High-level device-sharing use cases shared by the XPC handler and CLI.
///
/// The CLI passes explicit immutable message IDs. This layer translates those
/// choices into the narrow protocol coordinators; it never treats a directory
/// listing, provider timestamp, or "latest" file as user approval.
struct V3EnrollmentWorkflowService: V3EnrollmentWorkflowServicing {
    private static let invitationLifetime: UInt64 = 10 * 60
    private static let maximumMailboxObjects = 4_096

    private let selectedVaultID: String?
    private let source: any V3ImmutableObjectReading
    private let objectStore: any V3ImmutableObjectPublishing
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let exchange: V3EnrollmentExchangeCoordinator
    private let identityManager: V3EnrollmentDeviceIdentityManager
    private let vaultKeyStore: any VaultKeyStoring
    private let keychainMode: KeychainMode
    private let selectVault: V3EnrollmentAdoptionService.VaultSelector
    private let verifyRuntime: V3EnrollmentAdoptionService.RuntimeVerifier

    init(
        selectedVaultID: String?,
        source: any V3ImmutableObjectReading,
        objectStore: any V3ImmutableObjectPublishing,
        checkpointStore: any V3ManifestCheckpointStoring,
        exchange: V3EnrollmentExchangeCoordinator,
        identityManager: V3EnrollmentDeviceIdentityManager,
        vaultKeyStore: any VaultKeyStoring,
        keychainMode: KeychainMode,
        selectVault: @escaping V3EnrollmentAdoptionService.VaultSelector,
        verifyRuntime: @escaping V3EnrollmentAdoptionService.RuntimeVerifier
    ) {
        self.selectedVaultID = selectedVaultID
        self.source = source
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.exchange = exchange
        self.identityManager = identityManager
        self.vaultKeyStore = vaultKeyStore
        self.keychainMode = keychainMode
        self.selectVault = selectVault
        self.verifyRuntime = verifyRuntime
    }

    func deviceInventory() throws -> V3VaultDeviceInventory {
        guard let vaultID = selectedVaultID else {
            throw AppError.operationRefused(
                "Device inspection requires a selected version 3 vault."
            )
        }
        let authority = try currentAuthenticatedDeviceAuthority(
            vaultID: vaultID,
            reason: "Unlock version 3 vault to inspect authenticated devices."
        )
        let localIdentity = try identityManager.loadRecordedPublicIdentity(
            vaultID: vaultID
        )
        return V3VaultDeviceInventory(
            vaultID: vaultID,
            mode: authority.mode,
            currentDeviceID: localIdentity?.deviceID,
            devices: authority.devices.map {
                V3VaultDeviceSummary(
                    deviceID: $0.deviceID,
                    displayName: $0.displayName,
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
        guard let vaultID = selectedVaultID else {
            throw AppError.operationRefused(
                "Create an enrollment invitation on a Mac that already uses the version 3 vault."
            )
        }
        let current = try currentTrustedState(
            vaultID: vaultID,
            reason: "Unlock version 3 vault to create an enrollment invitation."
        )
        let parentBody = current.effective.envelope.content.manifest
        let identity: any V3EnrollmentMessageSigning
        switch parentBody.mode {
        case .local:
            identity = try loadOrCreateIdentity(
                vaultID: vaultID,
                deviceName: deviceName,
                reason: "Create this Mac's enrollment identity."
            )
        case .shared:
            guard let existing = try identityManager.loadIdentity(
                vaultID: vaultID,
                reason: "Load this Mac's enrollment identity."
            ), existing.publicIdentity.displayName == deviceName,
               let inviter = parentBody.devices.first(where: {
                   $0.deviceID == existing.publicIdentity.deviceID
               }),
               inviter.role == .owner,
               inviter.status == .active,
               existing.publicIdentity.matchesManifestDevice(inviter)
            else {
                throw AppError.operationRefused(
                    "Only an active owner recorded by the current vault can invite another Mac. Use this Mac's existing device name."
                )
            }
            identity = existing
        }
        guard unixTime <= UInt64.max - Self.invitationLifetime else {
            throw V3EnrollmentProtocolError.invalidFormat
        }
        let invitation = try V3EnrollmentInvitation(
            vaultID: vaultID,
            parentManifestDigest:
                current.effective.envelopeDigest,
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
        invitationDigest: Data,
        deviceName: String,
        at unixTime: UInt64
    ) throws -> String {
        guard selectedVaultID == nil else {
            throw AppError.operationRefused(
                "This Mac already selects a version 3 vault and cannot join another one."
            )
        }
        let invitation = try exchange.receiveInvitation(
            digest: invitationDigest,
            at: unixTime
        )
        let vaultID = invitation.invitation.vaultID
        if let state = try exchange.resumeJoining(
            answering: invitation,
            at: unixTime
        ) {
            guard let transcript = state.transcript else {
                throw V3EnrollmentAdoptionError.invalidCeremony
            }
            guard transcript.joinRequest.joiningDevice.displayName
                    == deviceName
            else {
                throw AppError.operationRefused(
                    "This enrollment request already uses the device name '\(transcript.joinRequest.joiningDevice.displayName)'. Reuse that exact name."
                )
            }
            return comparisonText(
                transcript,
                heading: "Join request republished.",
                next: "Compare this code on both Macs. The existing Mac can run `key share requests \(v3LowercaseHex(invitationDigest))`, then `key share compare \(vaultID) \(v3LowercaseHex(invitationDigest)) <request-id>`."
            )
        }
        let identity = try loadOrCreateIdentity(
            vaultID: vaultID,
            deviceName: deviceName,
            reason: "Create this Mac's enrollment identity."
        )
        let request = try V3EnrollmentJoinRequest(
            invitationDigest: invitationDigest,
            joiningDevice: identity.publicIdentity,
            nonce: randomNonce()
        )
        let signed = try V3EnrollmentMessageAuthenticator().sign(
            request,
            answering: invitation,
            using: identity,
            reason: "Answer the selected vault invitation."
        )
        let state = try exchange.beginJoining(
            signed,
            answering: invitation,
            at: unixTime
        )
        guard let transcript = state.transcript else {
            throw V3EnrollmentAdoptionError.invalidCeremony
        }
        return comparisonText(
            transcript,
            heading: "Join request published.",
            next: "Compare this code on both Macs. The existing Mac can run `key share requests \(v3LowercaseHex(invitationDigest))`, then `key share compare \(vaultID) \(v3LowercaseHex(invitationDigest)) <request-id>`."
        )
    }

    func listJoinRequests(
        invitationDigest: Data,
        at unixTime: UInt64
    ) throws -> String {
        guard let vaultID = selectedVaultID else {
            throw AppError.operationRefused(
                "List join requests on the Mac that created the invitation."
            )
        }
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
        vaultID: String,
        invitationDigest: Data,
        joinRequestDigest: Data?,
        at unixTime: UInt64
    ) throws -> String {
        let state: V3EnrollmentCeremonyState
        if let joinRequestDigest {
            guard selectedVaultID == vaultID else {
                throw V3EnrollmentCeremonyStateError.wrongRole
            }
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
        guard let transcript = state.transcript else {
            throw V3EnrollmentAdoptionError.invalidCeremony
        }
        let action = state.role == .inviter ? "approve" : "accept"
        return comparisonText(
            transcript,
            heading: "Enrollment comparison ready.",
            next: "If both Macs show this exact code and device pair, run `key share \(action) \(vaultID) \(v3LowercaseHex(invitationDigest)) \(transcript.comparisonCode)`."
        )
    }

    func approve(
        vaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String {
        guard selectedVaultID == vaultID else {
            throw V3EnrollmentCeremonyStateError.wrongRole
        }
        let state = try exchange.resumeOwnerApproval(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        let transcript = try requireComparison(
            state: state,
            comparisonCode: comparisonCode
        )
        guard let identity = try identityManager.loadIdentity(
            vaultID: vaultID,
            reason: "Load this Mac's enrollment identity."
        ) else {
            throw V3EnrollmentAdoptionError.identityUnavailable
        }
        let current = try currentTrustedState(
            vaultID: vaultID,
            reason: "Unlock version 3 vault to approve the compared Mac."
        )
        let observer = V3LiveManifestAncestryObserver(
            source: source,
            checkpointStore: checkpointStore,
            vaultID: vaultID,
            vaultKey: current.vaultKey
        )
        _ = try V3EnrollmentOwnerApprovalCoordinator(
            mutationOwner: DirectVaultTransactionMutationOwner(
                operationID: operationID
            ),
            ancestryObserver: observer,
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            exchange: exchange
        ).approve(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            approvedTranscriptDigest: transcript.digest,
            vaultKey: current.vaultKey,
            inviterIdentity: identity,
            at: unixTime,
            authorizationReason: "Approve the compared Mac for this vault.",
            operationID: operationID
        )
        return "Enrollment approved. The other Mac can now run `key share accept \(vaultID) \(v3LowercaseHex(invitationDigest)) \(comparisonCode)`.\n"
    }

    func accept(
        vaultID: String,
        invitationDigest: Data,
        comparisonCode: String,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> String {
        guard selectedVaultID == nil else {
            throw AppError.operationRefused(
                "This Mac already selects a version 3 vault."
            )
        }
        let state = try exchange.resumeJoinerAdoption(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        let transcript = try requireComparison(
            state: state,
            comparisonCode: comparisonCode
        )
        return try V3EnrollmentAdoptionService(
            source: source,
            checkpointStore: checkpointStore,
            exchange: exchange,
            identityManager: identityManager,
            vaultKeyStore: vaultKeyStore,
            keychainMode: keychainMode,
            selectVault: selectVault,
            verifyRuntime: verifyRuntime
        ).adopt(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            approvedTranscriptDigest: transcript.digest,
            at: unixTime,
            operationID: operationID
        ).rendered
    }

    private func currentTrustedState(
        vaultID: String,
        reason: String
    ) throws -> CurrentTrustedState {
        let current = try currentObservedState(
            vaultID: vaultID,
            reason: reason
        )
        switch current.observed.classification.status {
        case .incomplete:
            throw VaultUXServiceError.vaultIncomplete
        case .contentConflicted:
            throw VaultUXServiceError.contentConflict
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        case .ready:
            break
        }
        guard current.observed.resourceUsage != nil,
              let proof = current.observed.classification.ancestryProof,
              proof.heads.count == 1,
              let effective = proof.heads.first
        else {
            throw VaultUXServiceError.recoveryRequired
        }
        return CurrentTrustedState(
            trusted: current.trusted,
            effective: effective,
            vaultKey: current.vaultKey
        )
    }

    /// Returns only authority fields that agree across every authenticated
    /// head. Content-only forks can therefore be inspected without weakening
    /// the single-head requirement used by enrollment mutations.
    private func currentAuthenticatedDeviceAuthority(
        vaultID: String,
        reason: String
    ) throws -> AuthenticatedDeviceAuthority {
        let current = try currentObservedState(
            vaultID: vaultID,
            reason: reason
        )
        switch current.observed.classification.status {
        case .incomplete:
            throw VaultUXServiceError.vaultIncomplete
        case .securityConflicted:
            throw VaultUXServiceError.securityConflict
        case .recoveryRequired:
            throw VaultUXServiceError.recoveryRequired
        case .ready, .contentConflicted:
            break
        }
        guard current.observed.resourceUsage != nil,
              let proof = current.observed.classification.ancestryProof,
              let first = proof.heads.first,
              proof.heads.dropFirst().allSatisfy({
                  hasSameV3ManifestAuthority(
                      first.envelope.content.manifest,
                      $0.envelope.content.manifest
                  )
              })
        else {
            throw VaultUXServiceError.recoveryRequired
        }
        let manifest = first.envelope.content.manifest
        return AuthenticatedDeviceAuthority(
            mode: manifest.mode,
            devices: manifest.devices
        )
    }

    private func currentObservedState(
        vaultID: String,
        reason: String
    ) throws -> CurrentObservedState {
        guard let checkpointData = try checkpointStore.loadCheckpoint(
            vaultID: vaultID
        ) else {
            throw VaultUXServiceError.recoveryRequired
        }
        let checkpoint: V3ManifestCheckpoint
        do {
            checkpoint = try V3ManifestCheckpoint(
                canonicalBytes: checkpointData
            )
        } catch {
            throw VaultUXServiceError.recoveryRequired
        }
        let manifestData: Data
        switch try source.readManifest(
            digest: checkpoint.envelopeDigest,
            maximumBytes: V3ManifestRepositoryLimits.standard
                .maximumManifestBytes
        ) {
        case .available(let data)
            where Data(SHA256.hash(data: data))
                == checkpoint.envelopeDigest:
            manifestData = data
        case .unavailable:
            throw VaultUXServiceError.vaultIncomplete
        case .available, .invalid, .tooLarge:
            throw VaultUXServiceError.recoveryRequired
        }
        let vaultKey = try vaultKeyStore.loadKey(
            mode: keychainMode,
            reason: reason,
            createIfMissing: false
        )
        let trusted: V3TrustedManifest
        do {
            trusted = try V3ManifestReplayProtector(
                store: checkpointStore
            ).trustCurrent(
                manifestData,
                expectedVaultID: vaultID,
                vaultKey: vaultKey
            )
        } catch is V3ManifestError {
            throw VaultUXServiceError.recoveryRequired
        } catch is V3ManifestReplayError {
            throw VaultUXServiceError.recoveryRequired
        }
        let observed = try V3ImmutableObjectRepository(
            source: source
        ).observeForPublication(
            trustedCurrent: trusted,
            vaultKeys: [vaultKey]
        )
        return CurrentObservedState(
            trusted: trusted,
            observed: observed,
            vaultKey: vaultKey
        )
    }

    private func loadOrCreateIdentity(
        vaultID: String,
        deviceName: String,
        reason: String
    ) throws -> V3EnrollmentDevicePrivateIdentity {
        if let existing = try identityManager.loadIdentity(
            vaultID: vaultID,
            reason: reason
        ) {
            guard existing.publicIdentity.displayName == deviceName else {
                throw AppError.operationRefused(
                    "This Mac already has the enrollment name '\(existing.publicIdentity.displayName)' for this vault. Reuse that exact name."
                )
            }
            return existing
        }
        return try identityManager.createIdentity(
            vaultID: vaultID,
            displayName: deviceName,
            reason: reason
        )
    }

    private func requireComparison(
        state: V3EnrollmentCeremonyState,
        comparisonCode: String
    ) throws -> V3EnrollmentTranscript {
        guard let transcript = state.transcript,
            transcript.comparisonCode == comparisonCode
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
            UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
        })
    }

    private struct CurrentTrustedState {
        let trusted: V3TrustedManifest
        let effective: V3VerifiedManifest
        let vaultKey: Data
    }

    private struct CurrentObservedState {
        let trusted: V3TrustedManifest
        let observed: V3VaultRepositoryObservation
        let vaultKey: Data
    }

    private struct AuthenticatedDeviceAuthority {
        let mode: V3VaultMode
        let devices: [V3ManifestDevice]
    }
}
