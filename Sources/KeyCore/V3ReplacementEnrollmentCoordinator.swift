import Foundation

enum V3ReplacementEnrollmentCoordinatorError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidRequest
    case invalidConfirmation
    case reviewedStateChanged
    case replacementAlreadyInProgress
    case noReplacementInProgress

    var errorDescription: String? {
        switch self {
        case .invalidRequest:
            "The replacement-device request is invalid."
        case .invalidConfirmation:
            "Replacement requires the complete reviewed confirmation token."
        case .reviewedStateChanged:
            "The device or vault authority changed after replacement was reviewed. Review the current state and try again."
        case .replacementAlreadyInProgress:
            "A different replacement-device operation is already in progress."
        case .noReplacementInProgress:
            "No replacement-device operation is available to resume."
        }
    }
}

/// Re-observes current authenticated authority for one exact residual
/// identity. Implementations must use conflict-aware repository discovery;
/// provider ordering or one independently selected child is not authority.
protocol V3ReplacementDeviceIdentityAuthorityClassifying: Sendable {
    func classifyCurrentAuthority(
        for target: V3EnrollmentDeviceIdentityDeletionTarget
    ) throws -> V3ReplacementDeviceIdentityClassification
}

/// Performs the destructive half of confirmed replacement enrollment.
///
/// Review and execution remain separate. `begin` accepts only the digest of
/// the exact review the user confirmed, then re-observes that same authority
/// inside the helper's enrollment mutation boundary. Only after that check
/// does it persist a prepared intent and remove the old private identity.
///
/// Each completed deletion is followed by an exact compare-and-swap phase
/// update. If the process stops between those operations, the deletion
/// primitives are idempotent and `resume` safely repeats the incomplete step.
/// The completed intent remains durable until later enrollment adoption
/// consumes it after installing the replacement identity and checkpoint.
struct V3ReplacementEnrollmentCoordinator: Sendable {
    private let vaultID: String
    private let mutationOwner: any VaultTransactionMutationOwning
    private let authorityClassifier:
        any V3ReplacementDeviceIdentityAuthorityClassifying
    private let identityDeleter: V3EnrollmentDeviceIdentityDeleter
    private let checkpointStore: any V3ManifestCheckpointDeleting
    private let intentStore: any V3ReplacementEnrollmentIntentStoring

    init(
        vaultID: String,
        mutationOwner: any VaultTransactionMutationOwning,
        authorityClassifier:
            any V3ReplacementDeviceIdentityAuthorityClassifying,
        identityDeleter: V3EnrollmentDeviceIdentityDeleter,
        checkpointStore: any V3ManifestCheckpointDeleting,
        intentStore: any V3ReplacementEnrollmentIntentStoring
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.mutationOwner = mutationOwner
        self.authorityClassifier = authorityClassifier
        self.identityDeleter = identityDeleter
        self.checkpointStore = checkpointStore
        self.intentStore = intentStore
    }

    func begin(
        review: V3ReplacementEnrollmentReview,
        confirmedReviewDigest: Data
    ) throws -> V3ReplacementEnrollmentIntent {
        guard review.vaultID == vaultID else {
            throw V3ReplacementEnrollmentCoordinatorError.invalidRequest
        }
        guard confirmedReviewDigest.count == 32,
              confirmedReviewDigest == review.digest
        else {
            throw V3ReplacementEnrollmentCoordinatorError
                .invalidConfirmation
        }

        return try mutationOwner.perform(.enrollDevice) { _ in
            if let currentData = try intentStore.loadReplacementIntent(
                vaultID: vaultID
            ) {
                let current = try V3ReplacementEnrollmentIntent(
                    canonicalBytes: currentData
                )
                if current.review != review {
                    return try replaceUntouchedPreparedIntent(
                        current,
                        currentData: currentData,
                        with: review
                    )
                }
                return try advance(
                    current,
                    currentData: currentData,
                    preparedAuthorityAlreadyValidated: false
                )
            }

            try requireCurrentAuthority(for: review)
            let prepared = V3ReplacementEnrollmentIntent(review: review)
            let preparedData = prepared.canonicalBytes
            try intentStore.replaceReplacementIntent(
                preparedData,
                expectedIntent: nil,
                vaultID: vaultID
            )
            return try advance(
                prepared,
                currentData: preparedData,
                preparedAuthorityAlreadyValidated: true
            )
        }
    }

    func resume() throws -> V3ReplacementEnrollmentIntent {
        try mutationOwner.perform(.enrollDevice) { _ in
            guard let currentData = try intentStore
                .loadReplacementIntent(vaultID: vaultID)
            else {
                throw V3ReplacementEnrollmentCoordinatorError
                    .noReplacementInProgress
            }
            let current = try V3ReplacementEnrollmentIntent(
                canonicalBytes: currentData
            )
            guard current.vaultID == vaultID else {
                throw V3ReplacementEnrollmentCoordinatorError.invalidRequest
            }
            return try advance(
                current,
                currentData: currentData,
                preparedAuthorityAlreadyValidated: false
            )
        }
    }

    private func advance(
        _ initial: V3ReplacementEnrollmentIntent,
        currentData initialData: Data,
        preparedAuthorityAlreadyValidated: Bool
    ) throws -> V3ReplacementEnrollmentIntent {
        var intent = initial
        var currentData = initialData

        if intent.phase == .prepared {
            if !preparedAuthorityAlreadyValidated {
                try requireCurrentAuthority(for: intent.review)
            }
            let advanced = try intent.advanced(
                to: .identityDeletionStarted
            )
            let advancedData = advanced.canonicalBytes
            try intentStore.replaceReplacementIntent(
                advancedData,
                expectedIntent: currentData,
                vaultID: vaultID
            )
            intent = advanced
            currentData = advancedData
        }

        if intent.phase == .identityDeletionStarted {
            try identityDeleter.deleteIdentity(intent.review.target)
            let advanced = try intent.advanced(to: .identityDeleted)
            let advancedData = advanced.canonicalBytes
            try intentStore.replaceReplacementIntent(
                advancedData,
                expectedIntent: currentData,
                vaultID: vaultID
            )
            intent = advanced
            currentData = advancedData
        }

        if intent.phase == .identityDeleted {
            try checkpointStore.deleteCheckpoint(
                expectedCheckpoint:
                    intent.review.expectedCheckpoint.canonicalBytes,
                vaultID: vaultID
            )
            let advanced = try intent.advanced(to: .checkpointDeleted)
            try intentStore.replaceReplacementIntent(
                advanced.canonicalBytes,
                expectedIntent: currentData,
                vaultID: vaultID
            )
            intent = advanced
        }

        guard intent.phase == .checkpointDeleted else {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        return intent
    }

    /// A prepared intent may outlive the exact authority snapshot reviewed by
    /// the user—for example, its owner-authorized revocation child may become
    /// the local trusted checkpoint before a retry. A newly confirmed review
    /// may replace that stale intent only while the exact old private identity
    /// still exists. Identity deletion is the first destructive step, so this
    /// proves cleanup never began; missing or different state remains blocked.
    private func replaceUntouchedPreparedIntent(
        _ current: V3ReplacementEnrollmentIntent,
        currentData: Data,
        with review: V3ReplacementEnrollmentReview
    ) throws -> V3ReplacementEnrollmentIntent {
        guard current.phase == .prepared,
              let localTarget = try identityDeleter.deletionTarget(
                  vaultID: vaultID
              ),
              localTarget == current.review.target,
              review.target == localTarget
        else {
            throw V3ReplacementEnrollmentCoordinatorError
                .replacementAlreadyInProgress
        }

        try requireCurrentAuthority(for: review)
        let replacement = V3ReplacementEnrollmentIntent(review: review)
        let replacementData = replacement.canonicalBytes
        try intentStore.replaceReplacementIntent(
            replacementData,
            expectedIntent: currentData,
            vaultID: vaultID
        )
        return try advance(
            replacement,
            currentData: replacementData,
            preparedAuthorityAlreadyValidated: true
        )
    }

    private func requireCurrentAuthority(
        for review: V3ReplacementEnrollmentReview
    ) throws {
        let classification = try authorityClassifier
            .classifyCurrentAuthority(for: review.target)
        guard case .revoked = classification,
              let currentReview = try? V3ReplacementEnrollmentReview(
                  classification: classification
              ),
              currentReview == review
        else {
            throw V3ReplacementEnrollmentCoordinatorError
                .reviewedStateChanged
        }
    }
}
