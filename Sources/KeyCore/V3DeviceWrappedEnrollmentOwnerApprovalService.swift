import Foundation

protocol V3DeviceWrappedEnrollmentOwnerApproving: Sendable {
    func approve(
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint
}

/// Orchestrates one permanent-profile owner approval from the exact compared
/// ceremony through a durable key-rotating checkpoint transition.
///
/// The service owns workflow ordering, not cryptographic details: the builder
/// creates the candidate, the validator/publisher proves and commits it, and
/// the repository observer prevents publication from stale synchronized state.
struct V3DeviceWrappedEnrollmentOwnerApprovalService:
    V3DeviceWrappedEnrollmentOwnerApproving,
    Sendable
{
    typealias VaultKeyGenerator = @Sendable () -> Data
    typealias Identity =
        any V3EnrollmentMessageSigning & V3DeviceWrappedVaultKeyUnwrapping
    typealias IdentityLoader = @Sendable (
        _ vaultID: String,
        _ reason: String
    ) throws -> Identity?

    private let vaultID: String
    private let stateLoader: any V3DeviceWrappedMutationStateLoading
    private let source: any V3ImmutableObjectReading
    private let objectStore: any V3TransactionArtifactStore
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let recoveryAnchorStore:
        any V3ImmutableTransactionRecoveryAnchorStoring
    private let cache: any V3CheckpointManifestCaching
    private let exchange: V3EnrollmentExchangeCoordinator
    private let loadIdentity: IdentityLoader
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let limits: V3ManifestRepositoryLimits
    private let makeVaultKey: VaultKeyGenerator
    private let builder = V3DeviceWrappedEnrollmentTransitionBuilder()

    init(
        vaultID: String,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        source: any V3ImmutableObjectReading,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        exchange: V3EnrollmentExchangeCoordinator,
        loadIdentity: @escaping IdentityLoader,
        session: V3DeviceWrappedVaultKeySessionStore,
        limits: V3ManifestRepositoryLimits = .standard,
        makeVaultKey: @escaping VaultKeyGenerator = {
            var generator = SystemRandomNumberGenerator()
            return Data((0..<32).map { _ in
                UInt8.random(
                    in: UInt8.min...UInt8.max,
                    using: &generator
                )
            })
        }
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.stateLoader = stateLoader
        self.source = source
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.recoveryAnchorStore = recoveryAnchorStore
        self.cache = cache
        self.exchange = exchange
        self.loadIdentity = loadIdentity
        self.session = session
        self.limits = limits
        self.makeVaultKey = makeVaultKey
    }

    func approve(
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard invitationDigest.count == 32,
              approvedTranscriptDigest.count == 32
        else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        let state = try exchange.resumeDeviceWrappedOwnerApproval(
            vaultID: vaultID,
            invitationDigest: invitationDigest
        )
        guard state.transcript?.digest == approvedTranscriptDigest else {
            throw V3EnrollmentCeremonyStateError.conflict
        }
        guard let identity = try loadIdentity(
            vaultID,
            "Use this Mac's vault access credentials."
        ) else {
            throw V3EnrollmentAdoptionError.identityUnavailable
        }

        let publisher = makePublisher(operationID: operationID)
        let commit = commitHandler(
            invitationDigest: invitationDigest,
            transcriptDigest: approvedTranscriptDigest,
            at: unixTime
        )
        let recovery = try publisher.recoverInterruptedTransaction(
            vaultID: vaultID,
            expectedTranscriptDigest: approvedTranscriptDigest,
            localIdentity: identity,
            unwrapReason: "Recover this Mac's interrupted permanent enrollment.",
            afterCheckpointAdvance: commit
        )
        switch recovery.outcome {
        case .completed, .alreadyCompleted:
            guard let trusted = recovery.trustedCheckpoint,
                  recovery.vaultKey != nil
            else {
                throw V3ImmutableTransactionError.invalidAncestryProof
            }
            return trusted
        case .nothingToRecover, .abandoned:
            break
        }

        guard state.phase != .consumed else {
            throw V3EnrollmentCeremonyStateError.replayed
        }
        try state.signedInvitation.invitation.requireUnexpired(at: unixTime)
        let parent = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock the vault to approve the Mac whose code you compared."
        )
        guard parent.checkpoint.envelopeDigest
                == state.signedInvitation.invitation.parentManifestDigest
        else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
        let currentVaultKey = try stateLoader.loadVaultKey(
            keyID: parent.envelope.body.keyID
        )
        let currentEntries = try V3DeviceWrappedEntrySnapshotLoader(
            source: source,
            limits: limits
        ).load(parent)
        let nextVaultKey = try freshVaultKey(excluding: currentVaultKey)
        let authorityTransitionID = try v3EnrollmentAuthorityTransitionID(
            transcriptDigest: approvedTranscriptDigest
        )
        guard isValidV3UUID(authorityTransitionID),
              authorityTransitionID
                != parent.envelope.body.authorityTransitionID
        else {
            throw V3DeviceWrappedEnrollmentTransitionError.invalidCandidate
        }
        let candidate = try builder.build(
            from: parent,
            currentEntries: currentEntries,
            state: state,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            authorityTransitionID: authorityTransitionID,
            owner: identity,
            at: unixTime,
            authorizationReason: "Give the Mac whose code you compared access to this vault and change its encryption key."
        )
        return try publisher.publish(
            candidate,
            parent: parent,
            currentEntries: currentEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            state: state,
            localIdentity: identity,
            at: unixTime,
            unwrapReason: "Verify this Mac can open the rotated vault key.",
            afterCheckpointAdvance: commit
        )
    }

    private func makePublisher(
        operationID: VaultTransactionOperationID
    ) -> V3DeviceWrappedEnrollmentTransitionPublisher {
        V3DeviceWrappedEnrollmentTransitionPublisher(
            mutationOwner: DirectVaultTransactionMutationOwner(
                operationID: operationID
            ),
            repositoryObserver: V3LiveDeviceWrappedRepositoryObserver(
                source: source,
                checkpointStore: checkpointStore,
                cache: cache,
                limits: limits
            ),
            objectStore: objectStore,
            checkpointStore: checkpointStore,
            recoveryAnchorStore: recoveryAnchorStore,
            cache: cache,
            limits: limits
        )
    }

    private func commitHandler(
        invitationDigest: Data,
        transcriptDigest: Data,
        at unixTime: UInt64
    ) -> V3DeviceWrappedEnrollmentCommitHandler {
        { trusted, vaultKey in
            try session.install(
                vaultKey,
                vaultID: vaultID,
                keyID: trusted.envelope.body.keyID
            )
            _ = try exchange.markDeviceWrappedOwnerApprovalConsumed(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                transcriptDigest: transcriptDigest,
                at: unixTime
            )
        }
    }

    private func freshVaultKey(excluding current: Data) throws -> Data {
        for _ in 0..<16 {
            let candidate = makeVaultKey()
            guard candidate.count == 32 else {
                throw V3DeviceWrappedEnrollmentTransitionError
                    .invalidNextVaultKey
            }
            if candidate != current {
                return candidate
            }
        }
        throw V3DeviceWrappedEnrollmentTransitionError.invalidNextVaultKey
    }

}
