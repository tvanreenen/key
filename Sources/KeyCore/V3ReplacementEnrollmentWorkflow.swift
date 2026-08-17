import CryptoKit
import Foundation

public enum V3VaultDeviceReplacementAuthorityKind:
    String,
    Codable,
    Equatable,
    Sendable
{
    case trustedCheckpoint
    case survivingDevice
}

/// CLI-safe projection of one exact revoked-device replacement decision.
/// Private key representations and internal canonical records never cross
/// the helper boundary.
public struct V3VaultDeviceReplacementReview:
    Codable,
    Equatable,
    Sendable
{
    public let vaultID: String
    public let checkpointID: String
    public let confirmationToken: String
    public let replacedDevice: V3VaultDeviceSummary
    public let authorityKind: V3VaultDeviceReplacementAuthorityKind
    public let authorizingDevice: V3VaultDeviceSummary?
    public let revocationManifestID: String?

    public init(
        vaultID: String,
        checkpointID: String,
        confirmationToken: String,
        replacedDevice: V3VaultDeviceSummary,
        authorityKind: V3VaultDeviceReplacementAuthorityKind,
        authorizingDevice: V3VaultDeviceSummary?,
        revocationManifestID: String?
    ) {
        self.vaultID = vaultID
        self.checkpointID = checkpointID
        self.confirmationToken = confirmationToken
        self.replacedDevice = replacedDevice
        self.authorityKind = authorityKind
        self.authorizingDevice = authorizingDevice
        self.revocationManifestID = revocationManifestID
    }

    init(
        review: V3ReplacementEnrollmentReview,
        invitationDigest: Data? = nil
    ) {
        let authorityKind: V3VaultDeviceReplacementAuthorityKind
        let authorizingDevice: V3VaultDeviceSummary?
        let revocationManifestID: String?
        switch review.authority {
        case .trustedCheckpoint:
            authorityKind = .trustedCheckpoint
            authorizingDevice = nil
            revocationManifestID = nil
        case let .ownerAuthorizedRevocation(
            _,
            manifestDigest,
            authorizer
        ):
            authorityKind = .survivingDevice
            authorizingDevice = V3VaultDeviceSummary(
                deviceID: authorizer.deviceID,
                displayName: authorizer.displayName,
                status: .active
            )
            revocationManifestID = v3LowercaseHex(manifestDigest)
        }
        vaultID = review.vaultID
        checkpointID = v3LowercaseHex(
            review.expectedCheckpoint.envelopeDigest
        )
        confirmationToken = v3LowercaseHex(
            invitationDigest.map {
                v3ReplacementEnrollmentConfirmationDigest(
                    reviewDigest: review.digest,
                    invitationDigest: $0
                )
            } ?? review.digest
        )
        replacedDevice = V3VaultDeviceSummary(
            deviceID: review.target.identity.deviceID,
            displayName: review.target.identity.displayName,
            status: .revoked
        )
        self.authorityKind = authorityKind
        self.authorizingDevice = authorizingDevice
        self.revocationManifestID = revocationManifestID
    }
}

func v3ReplacementEnrollmentConfirmationDigest(
    reviewDigest: Data,
    invitationDigest: Data
) -> Data {
    precondition(reviewDigest.count == 32)
    precondition(invitationDigest.count == 32)
    var transcript = Data(
        "key-vault-replacement-enrollment-confirmation-v1".utf8
    )
    transcript.append(0)
    transcript.append(reviewDigest)
    transcript.append(invitationDigest)
    return Data(SHA256.hash(data: transcript))
}

enum V3ReplacementEnrollmentAdmissionState: Equatable, Sendable {
    case inactive
    case cleanupPrepared
    case cleanupPending
    case enrollmentPending
}

/// Classifies durable replacement progress for helper composition, then
/// consumes the completed authorization only after the new identity and
/// checkpoint are usable.
struct V3ReplacementEnrollmentAdmission: Sendable {
    private let intentStore: any V3ReplacementEnrollmentIntentStoring

    init(intentStore: any V3ReplacementEnrollmentIntentStoring) {
        self.intentStore = intentStore
    }

    func state(
        vaultID: String
    ) throws -> V3ReplacementEnrollmentAdmissionState {
        guard let data = try intentStore.loadReplacementIntent(
            vaultID: vaultID
        ) else {
            return .inactive
        }
        let intent = try V3ReplacementEnrollmentIntent(
            canonicalBytes: data
        )
        guard intent.vaultID == vaultID else {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        switch intent.phase {
        case .prepared:
            return .cleanupPrepared
        case .identityDeletionStarted, .identityDeleted:
            return .cleanupPending
        case .checkpointDeleted:
            return .enrollmentPending
        }
    }

    func consumeCompletedIntent(vaultID: String) throws {
        guard let data = try intentStore.loadReplacementIntent(
            vaultID: vaultID
        ) else {
            return
        }
        let intent = try V3ReplacementEnrollmentIntent(
            canonicalBytes: data
        )
        guard intent.vaultID == vaultID,
              intent.phase == .checkpointDeleted
        else {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        try intentStore.replaceReplacementIntent(
            nil,
            expectedIntent: data,
            vaultID: vaultID
        )
    }
}

enum V3ReplacementEnrollmentWorkflowError:
    Error,
    Equatable,
    LocalizedError
{
    case noLocalIdentity
    case deviceStillActive
    case identityUnrecognized
    case invalidConfirmation

    var errorDescription: String? {
        switch self {
        case .noLocalIdentity:
            "This Mac has no prior enrollment identity to replace."
        case .deviceStillActive:
            "This Mac is still active in the authenticated vault. Revoke it from a surviving Mac before rejoining."
        case .identityUnrecognized:
            "This Mac's local enrollment identity is not recognized by the authenticated vault."
        case .invalidConfirmation:
            "Replacement requires the complete confirmation token from the current review."
        }
    }
}

protocol V3ReplacementEnrollmentCoordinating: Sendable {
    func begin(
        review: V3ReplacementEnrollmentReview,
        confirmedReviewDigest: Data
    ) throws -> V3ReplacementEnrollmentIntent

    func resume() throws -> V3ReplacementEnrollmentIntent
}

extension V3ReplacementEnrollmentCoordinator:
    V3ReplacementEnrollmentCoordinating
{}

protocol V3ReplacementEnrollmentWorkflowServicing: Sendable {
    func review() throws -> V3ReplacementEnrollmentReview

    func replace(
        confirmedReviewDigest: Data
    ) throws -> V3ReplacementEnrollmentIntent
}

/// Turns one authenticated revoked-device decision into a retry-safe local
/// handoff for ordinary enrollment.
///
/// Review is read-only. Execution accepts only the digest of the exact review
/// the user confirmed. Once destructive cleanup has durably started, retries
/// use the stored review instead of requiring the deleted Secure Enclave key.
/// A prepared intent is still re-reviewed so newly arrived authority cannot be
/// hidden behind stale local workflow state.
struct V3ReplacementEnrollmentWorkflow:
    V3ReplacementEnrollmentWorkflowServicing,
    Sendable
{
    typealias TargetLoader = @Sendable (
        _ vaultID: String
    ) throws -> V3EnrollmentDeviceIdentityDeletionTarget?

    private let vaultID: String
    private let loadTarget: TargetLoader
    private let authorityClassifier:
        any V3ReplacementDeviceIdentityAuthorityClassifying
    private let intentStore: any V3ReplacementEnrollmentIntentStoring
    private let coordinator: any V3ReplacementEnrollmentCoordinating

    init(
        vaultID: String,
        loadTarget: @escaping TargetLoader,
        authorityClassifier:
            any V3ReplacementDeviceIdentityAuthorityClassifying,
        intentStore: any V3ReplacementEnrollmentIntentStoring,
        coordinator: any V3ReplacementEnrollmentCoordinating
    ) {
        precondition(isValidV3UUID(vaultID))
        self.vaultID = vaultID
        self.loadTarget = loadTarget
        self.authorityClassifier = authorityClassifier
        self.intentStore = intentStore
        self.coordinator = coordinator
    }

    func review() throws -> V3ReplacementEnrollmentReview {
        if let stored = try storedIntent(), stored.phase != .prepared {
            return stored.review
        }
        guard let target = try loadTarget(vaultID) else {
            throw V3ReplacementEnrollmentWorkflowError.noLocalIdentity
        }
        return try currentReview(for: target)
    }

    func replace(
        confirmedReviewDigest: Data
    ) throws -> V3ReplacementEnrollmentIntent {
        guard confirmedReviewDigest.count == 32 else {
            throw V3ReplacementEnrollmentWorkflowError
                .invalidConfirmation
        }

        let stored = try storedIntent()
        if let stored, stored.phase != .prepared {
            guard stored.review.digest == confirmedReviewDigest else {
                throw V3ReplacementEnrollmentWorkflowError
                    .invalidConfirmation
            }
            return try coordinator.resume()
        }

        if let target = try loadTarget(vaultID) {
            let current = try currentReview(for: target)
            return try coordinator.begin(
                review: current,
                confirmedReviewDigest: confirmedReviewDigest
            )
        }

        guard let stored,
              stored.review.digest == confirmedReviewDigest
        else {
            throw V3ReplacementEnrollmentWorkflowError.noLocalIdentity
        }
        return try coordinator.begin(
            review: stored.review,
            confirmedReviewDigest: confirmedReviewDigest
        )
    }

    private func currentReview(
        for target: V3EnrollmentDeviceIdentityDeletionTarget
    ) throws -> V3ReplacementEnrollmentReview {
        let classification = try authorityClassifier
            .classifyCurrentAuthority(for: target)
        switch classification {
        case .noLocalIdentity:
            throw V3ReplacementEnrollmentWorkflowError.noLocalIdentity
        case .active:
            throw V3ReplacementEnrollmentWorkflowError.deviceStillActive
        case .unrecognized:
            throw V3ReplacementEnrollmentWorkflowError
                .identityUnrecognized
        case .revoked:
            return try V3ReplacementEnrollmentReview(
                classification: classification
            )
        }
    }

    private func storedIntent() throws -> V3ReplacementEnrollmentIntent? {
        guard let data = try intentStore.loadReplacementIntent(
            vaultID: vaultID
        ) else {
            return nil
        }
        let intent = try V3ReplacementEnrollmentIntent(
            canonicalBytes: data
        )
        guard intent.vaultID == vaultID else {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        return intent
    }
}
