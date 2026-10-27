import CryptoKit
import Foundation
internal import JSONCanonicalization

/// Public selectors and the exact reviewed decision only. No hardware credential
/// is needed or accepted to remove its future coverage from this vault.
public enum KeyRecoveryRecipientRemovalRequest: Codable, Equatable, Sendable {
  case review(recipientID: String)
  case remove(
    recipientID: String, confirmationToken: String, pendingOperationID: String?,
    acknowledgesProtectionLoss: Bool)

  var recipientID: String {
    switch self {
    case .review(let id), .remove(let id, _, _, _): id
    }
  }
  func validate() throws {
    guard (try? V3RecoveryRecipientID(rawValue: recipientID)) != nil else {
      throw AppError.operationRefused("Provide the complete recovery key recipient ID.")
    }
    if case .remove(_, let token, let operation, _) = self {
      guard isRecoveryRemovalDigest(token),
        operation.map { (try? VaultTransactionOperationID(validating: $0)) != nil } ?? true
      else {
        throw AppError.operationRefused(
          "Removal requires the complete reviewed confirmation and original saved operation ID, when present."
        )
      }
    }
  }
}

public struct KeyRecoveryRecipientRemovalReview: Codable, Equatable, Sendable {
  public let vaultID: String
  public let checkpointID: String
  public let recipientID: String
  public let remainingRecipientIDs: [String]
  public let confirmationToken: String
  public let pendingOperationID: String?
  public var removesLastRecoveryKey: Bool { remainingRecipientIDs.isEmpty }

  func validate(for requested: String) throws {
    guard isValidV3UUID(vaultID), isRecoveryRemovalDigest(checkpointID),
      recipientID == requested, (try? V3RecoveryRecipientID(rawValue: recipientID)) != nil,
      isRecoveryRemovalDigest(confirmationToken), remainingRecipientIDs.count <= 64,
      Set(remainingRecipientIDs).count == remainingRecipientIDs.count,
      !remainingRecipientIDs.contains(recipientID),
      remainingRecipientIDs.allSatisfy({ (try? V3RecoveryRecipientID(rawValue: $0)) != nil }),
      pendingOperationID.map { (try? VaultTransactionOperationID(validating: $0)) != nil } ?? true
    else {
      throw AppError.service("Invalid recovery key removal review.")
    }
  }
}

public enum KeyRecoveryRecipientRemovalResult: Codable, Equatable, Sendable {
  case review(KeyRecoveryRecipientRemovalReview)
  case completed(
    vaultID: String, recipientID: String, manifestDigest: String,
    cleanupPending: Bool, alreadyRemoved: Bool)
}

struct V3RecoveryRecipientRemovalReviewBinding {
  func review(_ plan: V3RecoveryRecipientRemovalPlan, operationID: String? = nil)
    -> KeyRecoveryRecipientRemovalReview
  {
    .init(
      vaultID: plan.expectedCheckpoint.vaultID,
      checkpointID: v3LowercaseHex(plan.expectedCheckpoint.envelopeDigest),
      recipientID: plan.removedRecipient.recipientID.rawValue,
      remainingRecipientIDs: plan.resultingRecipients.filter { $0.status == .active }.map {
        $0.recipientID.rawValue
      },
      confirmationToken: token(plan), pendingOperationID: operationID)
  }
  func token(_ plan: V3RecoveryRecipientRemovalPlan) -> String {
    let decision = CanonicalJSON.encode(
      .object([
        ("format", .string("key-vault-recovery-recipient-removal")), ("version", .integer(1)),
        ("checkpoint", .string(Base64URL.encode(plan.expectedCheckpoint.canonicalBytes))),
        ("authorizingDevice", plan.authorizingDevice.identity.canonicalValue),
        ("authorizingStatus", .string(plan.authorizingDevice.status.rawValue)),
        ("removedRecipient", plan.removedRecipient.canonicalValue),
        ("resultingRecipients", .array(plan.resultingRecipients.map(\.canonicalValue))),
      ]))
    var input = Data("work.tvr.key/v3/recovery-recipient-removal-confirmation".utf8)
    input.append(0)
    input.append(decision)
    return v3LowercaseHex(Data(SHA256.hash(data: input)))
  }
}

func isRecoveryRemovalDigest(_ value: String) -> Bool {
  value.utf8.count == 64
    && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
