import Foundation

protocol V3DeviceWrappedRevocationServicing: Sendable {
    func prepare(
        revoking deviceID: String
    ) throws -> V3DeviceWrappedRevocationPlan

    func revoke(
        _ plan: V3DeviceWrappedRevocationPlan,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint
}

/// Orchestrates one explicitly reviewed permanent-profile device revocation.
///
/// Preparation binds the selected device and authorizing owner to one exact
/// authenticated checkpoint. Execution recovers an earlier durable attempt
/// first, then refuses any changed plan before generating a key, resealing the
/// complete snapshot, or publishing immutable authority.
struct V3DeviceWrappedRevocationService:
    V3DeviceWrappedRevocationServicing,
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
    typealias PublisherFactory = @Sendable (
        _ operationID: VaultTransactionOperationID
    ) -> any V3DeviceWrappedRevocationPublishing
    typealias VaultKeyGenerator = @Sendable () -> Data
    typealias TransitionIDGenerator = @Sendable () -> String

    private let vaultID: String
    private let stateLoader: any V3DeviceWrappedMutationStateLoading
    private let source: any V3ImmutableObjectReading
    private let loadIdentity: IdentityLoader
    private let loadPublicIdentity: PublicIdentityLoader
    private let session: V3DeviceWrappedVaultKeySessionStore
    private let makePublisher: PublisherFactory
    private let makeVaultKey: VaultKeyGenerator
    private let makeTransitionID: TransitionIDGenerator
    private let limits: V3ManifestRepositoryLimits
    private let planner = V3DeviceWrappedRevocationPlanner()
    private let builder = V3DeviceWrappedRevocationTransitionBuilder()

    init(
        vaultID: String,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        source: any V3ImmutableObjectReading,
        loadIdentity: @escaping IdentityLoader,
        loadPublicIdentity: @escaping PublicIdentityLoader,
        session: V3DeviceWrappedVaultKeySessionStore,
        makePublisher: @escaping PublisherFactory,
        limits: V3ManifestRepositoryLimits = .standard,
        makeVaultKey: @escaping VaultKeyGenerator = {
            var generator = SystemRandomNumberGenerator()
            return Data((0..<32).map { _ in
                UInt8.random(
                    in: UInt8.min...UInt8.max,
                    using: &generator
                )
            })
        },
        makeTransitionID: @escaping TransitionIDGenerator = {
            UUID().uuidString.lowercased()
        }
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.stateLoader = stateLoader
        self.source = source
        self.loadIdentity = loadIdentity
        self.loadPublicIdentity = loadPublicIdentity
        self.session = session
        self.makePublisher = makePublisher
        self.limits = limits
        self.makeVaultKey = makeVaultKey
        self.makeTransitionID = makeTransitionID
    }

    init(
        vaultID: String,
        stateLoader: any V3DeviceWrappedMutationStateLoading,
        source: any V3ImmutableObjectReading,
        objectStore: any V3TransactionArtifactStore,
        checkpointStore: any V3ManifestCheckpointStoring,
        recoveryAnchorStore:
            any V3ImmutableTransactionRecoveryAnchorStoring,
        cache: any V3CheckpointManifestCaching,
        loadIdentity: @escaping IdentityLoader,
        loadPublicIdentity: @escaping PublicIdentityLoader,
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
        },
        makeTransitionID: @escaping TransitionIDGenerator = {
            UUID().uuidString.lowercased()
        }
    ) {
        self.init(
            vaultID: vaultID,
            stateLoader: stateLoader,
            source: source,
            loadIdentity: loadIdentity,
            loadPublicIdentity: loadPublicIdentity,
            session: session,
            makePublisher: { operationID in
                V3DeviceWrappedRevocationTransitionPublisher(
                    mutationOwner: DirectVaultTransactionMutationOwner(
                        operationID: operationID
                    ),
                    repositoryObserver:
                        V3LiveDeviceWrappedRepositoryObserver(
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
            },
            limits: limits,
            makeVaultKey: makeVaultKey,
            makeTransitionID: makeTransitionID
        )
    }

    func prepare(
        revoking deviceID: String
    ) throws -> V3DeviceWrappedRevocationPlan {
        guard let localIdentity = try loadPublicIdentity(vaultID) else {
            throw V3DeviceWrappedRevocationPlanningError
                .invalidAuthorizingOwner
        }
        let trusted = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to review device revocation."
        )
        let plan = try planner.plan(
            from: trusted,
            authorizingDeviceID: localIdentity.deviceID,
            revoking: deviceID
        )
        guard plan.authorizingOwner.identity == localIdentity else {
            throw V3DeviceWrappedRevocationPlanningError
                .invalidAuthorizingOwner
        }
        return plan
    }

    func revoke(
        _ plan: V3DeviceWrappedRevocationPlan,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard plan.expectedCheckpoint.vaultID == vaultID,
              let identity = try loadIdentity(
                vaultID,
                "Load this Mac's permanent owner identity."
              ),
              identity.publicIdentity == plan.authorizingOwner.identity
        else {
            throw V3DeviceWrappedRevocationTransitionError.invalidPlan
        }

        let publisher = makePublisher(operationID)
        let commit: V3DeviceWrappedRevocationCommitHandler = {
            trusted,
            vaultKey in
            try session.install(
                vaultKey,
                vaultID: vaultID,
                keyID: trusted.envelope.body.keyID
            )
        }
        let recovery = try publisher.recoverInterruptedTransaction(
            vaultID: vaultID,
            localIdentity: identity,
            unwrapReason: "Recover this Mac's interrupted device revocation.",
            afterCheckpointAdvance: commit
        )
        switch recovery.outcome {
        case .completed, .alreadyCompleted:
            return try requireRecovered(recovery, matches: plan)
        case .nothingToRecover, .abandoned:
            break
        }

        let parent = try stateLoader.authenticatedCheckpoint(
            reason: "Unlock version 3 vault to revoke the reviewed device."
        )
        guard parent.checkpoint == plan.expectedCheckpoint else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
        let reviewedPlan = try planner.plan(
            from: parent,
            authorizingDeviceID: identity.publicIdentity.deviceID,
            revoking: plan.revokedDevice.identity.deviceID
        )
        guard reviewedPlan == plan else {
            throw V3DeviceWrappedRevocationTransitionError.invalidPlan
        }

        let currentVaultKey = try stateLoader.loadVaultKey(
            keyID: parent.envelope.body.keyID
        )
        let currentEntries = try V3DeviceWrappedEntrySnapshotLoader(
            source: source,
            limits: limits
        ).load(parent)
        let nextVaultKey = try freshVaultKey(excluding: currentVaultKey)
        let transitionID = try freshTransitionID(
            excluding: parent.envelope.body.authorityTransitionID
        )
        let candidate = try builder.build(
            from: parent,
            currentEntries: currentEntries,
            plan: reviewedPlan,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            authorityTransitionID: transitionID,
            owner: identity,
            authorizationReason: "Revoke the reviewed device and rotate this vault's key."
        )
        return try publisher.publish(
            candidate,
            parent: parent,
            currentEntries: currentEntries,
            currentVaultKey: currentVaultKey,
            nextVaultKey: nextVaultKey,
            localIdentity: identity,
            unwrapReason: "Verify this Mac can open the rotated vault key.",
            afterCheckpointAdvance: commit
        )
    }

    private func requireRecovered(
        _ recovery: V3DeviceWrappedRevocationRecoveryResult,
        matches plan: V3DeviceWrappedRevocationPlan
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard let trusted = recovery.trustedCheckpoint,
              recovery.vaultKey != nil,
              trusted.envelope.parents
                == [plan.expectedCheckpoint.envelopeDigest],
              trusted.envelope.body.devices == plan.resultingDevices,
              trusted.envelope.authorizations.count == 1,
              trusted.envelope.authorizations[0].signerDeviceID
                == plan.authorizingOwner.identity.deviceID
        else {
            throw V3ImmutableTransactionError.expectedHeadsChanged
        }
        return trusted
    }

    private func freshVaultKey(excluding current: Data) throws -> Data {
        for _ in 0..<16 {
            let candidate = makeVaultKey()
            guard candidate.count == 32 else {
                throw V3DeviceWrappedRevocationTransitionError
                    .invalidNextVaultKey
            }
            if candidate != current {
                return candidate
            }
        }
        throw V3DeviceWrappedRevocationTransitionError.invalidNextVaultKey
    }

    private func freshTransitionID(excluding current: String) throws -> String {
        for _ in 0..<16 {
            let candidate = makeTransitionID()
            guard isValidV3UUID(candidate) else {
                throw V3DeviceWrappedRevocationTransitionError.invalidCandidate
            }
            if candidate != current {
                return candidate
            }
        }
        throw V3DeviceWrappedRevocationTransitionError.invalidCandidate
    }
}
