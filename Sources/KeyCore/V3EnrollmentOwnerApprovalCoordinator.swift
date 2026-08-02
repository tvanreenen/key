import CryptoKit
import Foundation

enum V3EnrollmentOwnerApprovalError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidRepositoryState
    case objectTooLarge
    case stagedManifestUnavailable
    case publishedManifestUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidRepositoryState:
            "Owner approval requires the exact complete local vault head named by the invitation."
        case .objectTooLarge:
            "The owner-authorized enrollment manifest exceeds a repository resource limit."
        case .stagedManifestUnavailable:
            "The staged owner-authorized enrollment manifest could not be reopened exactly."
        case .publishedManifestUnavailable:
            "The published owner-authorized enrollment manifest could not be reopened exactly."
        }
    }
}

enum V3EnrollmentOwnerApprovalPhase: Equatable, Sendable {
    case approvalPrepared
    case manifestStaged
    case repositoryStateRechecked
    case manifestPublished
    case checkpointAdvanced
    case ceremonyConsumed
}

protocol V3EnrollmentOwnerApprovalPhaseObserving: Sendable {
    func didReach(
        _ phase: V3EnrollmentOwnerApprovalPhase,
        operationID: VaultTransactionOperationID
    ) throws
}

private struct V3NoopEnrollmentOwnerApprovalPhaseObserver:
    V3EnrollmentOwnerApprovalPhaseObserving
{
    func didReach(
        _: V3EnrollmentOwnerApprovalPhase,
        operationID _: VaultTransactionOperationID
    ) throws {}
}

/// Publishes the exact owner-approved local-to-shared transition.
///
/// Only one immutable manifest is added, so an interruption always leaves the
/// old checkpoint or the complete new checkpoint. The device-local approval
/// record retains the randomized wrappers and signature, allowing an exact
/// retry without granting synchronized staging files any authority.
struct V3EnrollmentOwnerApprovalCoordinator: Sendable {
    private let mutationOwner: any VaultTransactionMutationOwning
    private let ancestryObserver: any V3ManifestAncestryObserving
    private let objectStore: any V3ImmutableObjectPublishing
    private let checkpointStore: any V3ManifestCheckpointStoring
    private let exchange: V3EnrollmentExchangeCoordinator
    private let builder: V3EnrollmentOwnerTransitionBuilder
    private let limits: V3ManifestRepositoryLimits
    private let phaseObserver: any V3EnrollmentOwnerApprovalPhaseObserving

    init(
        mutationOwner: any VaultTransactionMutationOwning,
        ancestryObserver: any V3ManifestAncestryObserving,
        objectStore: any V3ImmutableObjectPublishing,
        checkpointStore: any V3ManifestCheckpointStoring,
        exchange: V3EnrollmentExchangeCoordinator,
        builder: V3EnrollmentOwnerTransitionBuilder =
            V3EnrollmentOwnerTransitionBuilder(),
        limits: V3ManifestRepositoryLimits = .standard,
        phaseObserver: any V3EnrollmentOwnerApprovalPhaseObserving =
            V3NoopEnrollmentOwnerApprovalPhaseObserver()
    ) {
        self.mutationOwner = mutationOwner
        self.ancestryObserver = ancestryObserver
        self.objectStore = objectStore
        self.checkpointStore = checkpointStore
        self.exchange = exchange
        self.builder = builder
        self.limits = limits
        self.phaseObserver = phaseObserver
    }

    func approve(
        vaultID: String,
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        vaultKey: Data,
        inviterIdentity: any V3EnrollmentMessageSigning,
        at unixTime: UInt64,
        authorizationReason: String
    ) throws -> V3TrustedManifest {
        try mutationOwner.perform(.enrollDevice) { context in
            try approve(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                approvedTranscriptDigest: approvedTranscriptDigest,
                vaultKey: vaultKey,
                inviterIdentity: inviterIdentity,
                at: unixTime,
                authorizationReason: authorizationReason,
                operationID: context.operationID
            )
        }
    }

    private func approve(
        vaultID: String,
        invitationDigest: Data,
        approvedTranscriptDigest: Data,
        vaultKey: Data,
        inviterIdentity: any V3EnrollmentMessageSigning,
        at unixTime: UInt64,
        authorizationReason: String,
        operationID: VaultTransactionOperationID
    ) throws -> V3TrustedManifest {
        guard approvedTranscriptDigest.count == 32 else {
            throw V3EnrollmentOwnerTransitionError.invalidCeremony
        }
        var state = try exchange.resumeOwnerApproval(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            at: unixTime
        )
        guard state.transcript?.digest == approvedTranscriptDigest else {
            throw V3EnrollmentCeremonyStateError.conflict
        }

        let initialObservation = try ancestryObserver.observeAncestry()
        let parentDigest = state.signedInvitation.invitation
            .parentManifestDigest
        guard
            let parent = initialObservation.proof.manifests.first(
                where: { $0.envelopeDigest == parentDigest }
            )
        else {
            throw V3EnrollmentOwnerApprovalError.invalidRepositoryState
        }

        let candidate: V3EnrollmentOwnerTransitionCandidate
        let resumedPreparedApproval = state.ownerApproval != nil
        var candidateAlreadyPublished = false
        if let approval = state.ownerApproval {
            candidate = try builder.rebuild(
                state: state,
                parent: parent,
                vaultKey: vaultKey,
                approval: approval
            )
            if checkpointDescends(
                from: candidate.verifiedManifest.envelopeDigest,
                in: initialObservation.proof
            ) {
                return try finishAlreadyPublished(
                    candidate,
                    proof: initialObservation.proof,
                    state: state,
                    at: unixTime,
                    operationID: operationID
                )
            }
            candidateAlreadyPublished = try isCandidateAlreadyPublished(
                candidate
            )
        } else {
            try requireExactParentState(
                initialObservation.proof,
                parentDigest: parentDigest
            )
            candidate = try builder.build(
                state: state,
                parent: parent,
                vaultKey: vaultKey,
                inviterIdentity: inviterIdentity,
                authorizationReason: authorizationReason
            )
            state = try exchange.prepareOwnerApproval(
                vaultID: vaultID,
                invitationDigest: invitationDigest,
                approval: candidate.approval,
                at: unixTime
            )
            try phaseObserver.didReach(
                .approvalPrepared,
                operationID: operationID
            )
        }

        try requireExactParentState(
            initialObservation.proof,
            parentDigest: parentDigest
        )
        try requireWithinLimits(
            candidate,
            observation: initialObservation,
            candidateAlreadyPublished: candidateAlreadyPublished
        )
        defer {
            try? objectStore.removeStagedManifest(
                candidate.manifestData,
                digest: candidate.verifiedManifest.envelopeDigest,
                operationID: operationID
            )
            try? objectStore.removeEmptyTransactionDirectories(
                operationID: operationID,
                entryIDs: []
            )
        }

        try objectStore.stageManifest(
            candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest,
            operationID: operationID
        )
        guard
            case .available(let stagedData) =
                try objectStore
                .readStagedManifest(
                    digest: candidate.verifiedManifest.envelopeDigest,
                    operationID: operationID,
                    maximumBytes: limits.maximumManifestBytes
                ), stagedData == candidate.manifestData
        else {
            throw V3EnrollmentOwnerApprovalError
                .stagedManifestUnavailable
        }
        try phaseObserver.didReach(
            .manifestStaged,
            operationID: operationID
        )

        let recheckedObservation = try ancestryObserver.observeAncestry()
        guard
            try V3ExpectedRepositoryState(
                proof: recheckedObservation.proof
            ) == V3ExpectedRepositoryState(proof: initialObservation.proof)
        else {
            throw V3EnrollmentOwnerApprovalError.invalidRepositoryState
        }
        try requireExactParentState(
            recheckedObservation.proof,
            parentDigest: parentDigest
        )
        if resumedPreparedApproval, !candidateAlreadyPublished {
            candidateAlreadyPublished = try isCandidateAlreadyPublished(
                candidate
            )
        }
        try requireWithinLimits(
            candidate,
            observation: recheckedObservation,
            candidateAlreadyPublished: candidateAlreadyPublished
        )
        try phaseObserver.didReach(
            .repositoryStateRechecked,
            operationID: operationID
        )

        try objectStore.publishStagedManifest(
            candidate.manifestData,
            digest: candidate.verifiedManifest.envelopeDigest,
            operationID: operationID
        )
        guard
            case .available(let publishedData) = try objectStore.readManifest(
                digest: candidate.verifiedManifest.envelopeDigest,
                maximumBytes: limits.maximumManifestBytes
            ), publishedData == candidate.manifestData
        else {
            throw V3EnrollmentOwnerApprovalError
                .publishedManifestUnavailable
        }
        try phaseObserver.didReach(
            .manifestPublished,
            operationID: operationID
        )

        let checkpoint = try V3ManifestCheckpoint(
            verifiedManifest: candidate.verifiedManifest
        )
        try checkpointStore.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint:
                initialObservation.proof.checkpoint.canonicalBytes,
            vaultID: vaultID
        )
        try phaseObserver.didReach(
            .checkpointAdvanced,
            operationID: operationID
        )
        _ = try exchange.markConsumed(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            transcriptDigest: approvedTranscriptDigest,
            at: unixTime
        )
        try phaseObserver.didReach(
            .ceremonyConsumed,
            operationID: operationID
        )
        return V3TrustedManifest(
            verifiedManifest: candidate.verifiedManifest,
            checkpoint: checkpoint
        )
    }

    private func finishAlreadyPublished(
        _ candidate: V3EnrollmentOwnerTransitionCandidate,
        proof: V3ManifestAncestryProof,
        state: V3EnrollmentCeremonyState,
        at unixTime: UInt64,
        operationID: VaultTransactionOperationID
    ) throws -> V3TrustedManifest {
        guard
            checkpointDescends(
                from: candidate.verifiedManifest.envelopeDigest,
                in: proof
            ),
            let checkpointManifest = proof.manifests.first(where: {
                $0.envelopeDigest == proof.checkpoint.envelopeDigest
            }),
            proof.checkpoint.vaultID == state.vaultID
        else {
            throw V3EnrollmentOwnerApprovalError.invalidRepositoryState
        }
        _ = try exchange.markConsumed(
            vaultID: state.vaultID,
            invitationDigest: state.invitationDigest,
            transcriptDigest: candidate.transcriptDigest,
            at: unixTime
        )
        try phaseObserver.didReach(
            .ceremonyConsumed,
            operationID: operationID
        )
        return V3TrustedManifest(
            verifiedManifest: checkpointManifest,
            checkpoint: proof.checkpoint
        )
    }

    private func checkpointDescends(
        from candidateDigest: Data,
        in proof: V3ManifestAncestryProof
    ) -> Bool {
        var manifestsByDigest: [Data: V3VerifiedManifest] = [:]
        for manifest in proof.manifests {
            guard
                manifestsByDigest.updateValue(
                    manifest,
                    forKey: manifest.envelopeDigest
                ) == nil
            else {
                return false
            }
        }
        var pending = [proof.checkpoint.envelopeDigest]
        var visited: Set<Data> = []
        while let digest = pending.popLast() {
            if digest == candidateDigest {
                return true
            }
            guard visited.insert(digest).inserted,
                let manifest = manifestsByDigest[digest]
            else {
                continue
            }
            for encodedParent in manifest.envelope.content.parents {
                guard let parent = Base64URL.decodeCanonical(encodedParent),
                    parent.count == 32
                else {
                    return false
                }
                pending.append(parent)
            }
        }
        return false
    }

    private func isCandidateAlreadyPublished(
        _ candidate: V3EnrollmentOwnerTransitionCandidate
    ) throws -> Bool {
        switch try objectStore.readManifest(
            digest: candidate.verifiedManifest.envelopeDigest,
            maximumBytes: limits.maximumManifestBytes
        ) {
        case .available(let data):
            guard data == candidate.manifestData else {
                throw V3EnrollmentOwnerApprovalError
                    .publishedManifestUnavailable
            }
            return true
        case .unavailable:
            return false
        case .invalid, .tooLarge:
            throw V3EnrollmentOwnerApprovalError
                .publishedManifestUnavailable
        }
    }

    private func requireExactParentState(
        _ proof: V3ManifestAncestryProof,
        parentDigest: Data
    ) throws {
        guard proof.checkpoint.envelopeDigest == parentDigest,
            proof.heads.count == 1,
            proof.heads[0].envelopeDigest == parentDigest,
            proof.heads[0].envelope.content.manifest.mode == .local
        else {
            throw V3EnrollmentOwnerApprovalError.invalidRepositoryState
        }
    }

    private func requireWithinLimits(
        _ candidate: V3EnrollmentOwnerTransitionCandidate,
        observation: V3ManifestAncestryObservation,
        candidateAlreadyPublished: Bool
    ) throws {
        let usage = observation.resourceUsage
        let additionalManifestObjects = candidateAlreadyPublished ? 0 : 1
        let additionalManifestBytes =
            candidateAlreadyPublished
            ? 0
            : candidate.manifestData.count
        guard candidate.manifestData.count <= limits.maximumManifestBytes,
            usage.manifestObjectCount >= 0,
            usage.manifestObjectCount
                <= limits.maximumManifestObjects
                - additionalManifestObjects,
            usage.maximumHistoryDepth < limits.maximumHistoryDepth,
            usage.totalManifestBytes >= 0,
            usage.totalManifestBytes
                <= limits.maximumTotalManifestBytes
                - additionalManifestBytes,
            usage.referencedEntryObjectCount
                <= limits.maximumReferencedEntryObjects,
            usage.totalEntryBytes <= limits.maximumTotalEntryBytes
        else {
            throw V3EnrollmentOwnerApprovalError.objectTooLarge
        }
    }
}
