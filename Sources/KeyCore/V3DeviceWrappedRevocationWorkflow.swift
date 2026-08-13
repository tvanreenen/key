import CryptoKit
import Foundation
internal import JSONCanonicalization

/// CLI-safe description of one exact device-revocation decision.
///
/// A domain-separated token binds the full checkpoint digest and selected
/// device ID. It lets the helper prove that execution still matches the exact
/// decision the user saw; display names and abbreviated versions are never
/// treated as authority.
public struct V3VaultDeviceRevocationReview:
    Codable,
    Equatable,
    Sendable
{
    public let vaultID: String
    public let checkpointID: String
    public let confirmationToken: String
    public let authorizingDevice: V3VaultDeviceSummary
    public let revokedDevice: V3VaultDeviceSummary
    public let remainingActiveDevices: [V3VaultDeviceSummary]

    public init(
        vaultID: String,
        checkpointID: String,
        confirmationToken: String,
        authorizingDevice: V3VaultDeviceSummary,
        revokedDevice: V3VaultDeviceSummary,
        remainingActiveDevices: [V3VaultDeviceSummary]
    ) {
        self.vaultID = vaultID
        self.checkpointID = checkpointID
        self.confirmationToken = confirmationToken
        self.authorizingDevice = authorizingDevice
        self.revokedDevice = revokedDevice
        self.remainingActiveDevices = remainingActiveDevices
    }

    private enum CodingKeys: String, CodingKey {
        case vaultID
        case checkpointID
        case confirmationToken
        case authorizingDevice
        case revokedDevice
        case remainingActiveDevices
    }
}

enum V3DeviceWrappedRevocationWorkflowError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidConfirmationToken
    case reviewedStateChanged

    var errorDescription: String? {
        switch self {
        case .invalidConfirmationToken:
            "Device revocation requires the complete reviewed confirmation token."
        case .reviewedStateChanged:
            "The vault changed after device revocation was reviewed. Review the current device list and try again."
        }
    }
}

protocol V3DeviceWrappedRevocationWorkflowServicing: Sendable {
    func review(
        revoking deviceID: String,
        operationID: VaultTransactionOperationID
    ) throws -> V3VaultDeviceRevocationReview

    func revoke(
        deviceID: String,
        confirmationToken: String,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint
}

/// Keeps human confirmation separate from cryptographic publication.
///
/// Review first recovers any locally interrupted revocation, then catches the
/// device up before projecting an authenticated internal plan into CLI-safe
/// metadata. Execution performs the same recovery preflight and returns an
/// exact completed retry idempotently. Otherwise it catches up and prepares the
/// plan again, then accepts it only when the checkpoint and selected device
/// still produce the user's confirmation token. The revocation service
/// independently revalidates that same plan at commit time.
struct V3DeviceWrappedRevocationWorkflow:
    V3DeviceWrappedRevocationWorkflowServicing,
    Sendable
{
    typealias CatchUp = @Sendable (
        VaultTransactionOperationID
    ) throws -> V3DeviceWrappedCatchUpCoordinatorOutcome

    private static let confirmationDomain =
        "work.tvr.key/v3/device-revocation-confirmation"

    private let service: any V3DeviceWrappedRevocationServicing
    private let catchUp: CatchUp?
    private let catchUpGate = V3DeviceWrappedCatchUpAccessGate()

    init(
        service: any V3DeviceWrappedRevocationServicing,
        catchUp: CatchUp? = nil
    ) {
        self.service = service
        self.catchUp = catchUp
    }

    func review(
        revoking deviceID: String,
        operationID: VaultTransactionOperationID
    ) throws -> V3VaultDeviceRevocationReview {
        _ = try service.recoverInterruptedRevocation(
            operationID: operationID
        )
        try requireCaughtUp(operationID: operationID)
        return review(for: try service.prepare(revoking: deviceID))
    }

    func revoke(
        deviceID: String,
        confirmationToken: String,
        operationID: VaultTransactionOperationID
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard isCanonicalConfirmationToken(confirmationToken) else {
            throw V3DeviceWrappedRevocationWorkflowError
                .invalidConfirmationToken
        }
        let recovery = try service.recoverInterruptedRevocation(
            operationID: operationID
        )
        switch recovery.outcome {
        case .completed, .alreadyCompleted:
            return try requireRecovered(
                recovery,
                deviceID: deviceID,
                confirmationToken: confirmationToken
            )
        case .nothingToRecover, .abandoned:
            break
        }
        try requireCaughtUp(operationID: operationID)
        let plan = try service.prepare(revoking: deviceID)
        guard plan.revokedDevice.identity.deviceID == deviceID,
              self.confirmationToken(
                  checkpoint: plan.expectedCheckpoint,
                  deviceID: deviceID
              ) == confirmationToken
        else {
            throw V3DeviceWrappedRevocationWorkflowError
                .reviewedStateChanged
        }
        return try service.revoke(plan, operationID: operationID)
    }

    private func requireRecovered(
        _ recovery: V3DeviceWrappedRevocationRecoveryResult,
        deviceID: String,
        confirmationToken: String
    ) throws -> V3DeviceWrappedTrustedCheckpoint {
        guard let plan = recovery.plan,
              let trusted = recovery.trustedCheckpoint,
              recovery.vaultKey != nil,
              plan.revokedDevice.identity.deviceID == deviceID,
              self.confirmationToken(
                  checkpoint: plan.expectedCheckpoint,
                  deviceID: deviceID
              ) == confirmationToken
        else {
            throw V3DeviceWrappedRevocationWorkflowError
                .reviewedStateChanged
        }
        return trusted
    }

    private func requireCaughtUp(
        operationID: VaultTransactionOperationID
    ) throws {
        guard let catchUp else {
            return
        }
        try catchUpGate.requireCurrent {
            try catchUp(operationID)
        }
    }

    private func review(
        for plan: V3DeviceWrappedRevocationPlan
    ) -> V3VaultDeviceRevocationReview {
        V3VaultDeviceRevocationReview(
            vaultID: plan.expectedCheckpoint.vaultID,
            checkpointID: v3LowercaseHex(
                plan.expectedCheckpoint.envelopeDigest
            ),
            confirmationToken: confirmationToken(
                checkpoint: plan.expectedCheckpoint,
                deviceID: plan.revokedDevice.identity.deviceID
            ),
            authorizingDevice: summary(plan.authorizingDevice),
            revokedDevice: summary(plan.revokedDevice),
            remainingActiveDevices: plan.remainingActiveDevices.map(summary)
        )
    }

    private func summary(
        _ device: V3DeviceWrappedManifestDevice
    ) -> V3VaultDeviceSummary {
        V3VaultDeviceSummary(
            deviceID: device.identity.deviceID,
            displayName: device.identity.displayName,
            status: device.status
        )
    }

    private func isCanonicalConfirmationToken(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private func confirmationToken(
        checkpoint: V3ManifestCheckpoint,
        deviceID: String
    ) -> String {
        let decision = CanonicalJSON.encode(.object([
            ("format", .string("key-vault-device-revocation")),
            ("version", .integer(1)),
            ("vaultID", .string(checkpoint.vaultID)),
            ("checkpointID", .string(v3LowercaseHex(
                checkpoint.envelopeDigest
            ))),
            ("deviceID", .string(deviceID))
        ]))
        var input = Data(Self.confirmationDomain.utf8)
        input.append(0)
        input.append(decision)
        return v3LowercaseHex(Data(SHA256.hash(data: input)))
    }
}
