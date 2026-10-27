import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Access-change scenario data with real publication and separate revocation/removal plans.
enum V3RecoveryAuthorityChangeTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Publication = V3RecoveryPublicationTestSupport
  typealias Revocation = V3RecoveryRevocationTestSupport
  enum Action: CaseIterable, Sendable { case revoke, remove, removeLast }
  enum Review {
    case device(V3DeviceWrappedRevocationPlan)
    case recipient(V3RecoveryRecipientRemovalPlan)
  }
  struct Commit {
    let checkpoint: V3ManifestCheckpoint
    let envelope: V3RecoveryManifestEnvelope
  }
  struct Fixture: Sendable {
    let action: Action
    let disk: V3RecoveryPublicationTestSupport.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let key: Data
    let deviceID: String?
    let signatures: Int
    let unwraps: Int
    var owner: V3RecoveryRegistrationTestSupport.Owner { disk.core.owner }
    init(_ action: Action, empty: Bool = false) throws {
      self.action = action
      if action == .revoke {
        let f = try Revocation.Fixture(empty: empty)
        disk = f.enrollment.disk
        parent = f.parent
        checkpoint = f.checkpoint
        entries = f.entries
        key = f.currentKey
        deviceID = f.enrollment.joiner.publicIdentity.deviceID
      } else {
        disk = try Publication.Fixture(empty: empty, backup: action != .removeLast)
        parent = disk.parent
        checkpoint = disk.checkpoint
        entries = disk.entries
        key = Core.nextKey
        deviceID = nil
      }
      signatures = disk.core.owner.signatures
      unwraps = disk.core.owner.unwraps
    }
    func prepare(_ service: V3RecoveryAuthorityChangeService) throws -> Review {
      if let deviceID { return .device(try service.prepareRevocation(revoking: deviceID)) }
      return .recipient(try service.prepareRemoval(removing: disk.anchor.recipientID))
    }
    func execute(
      _ service: V3RecoveryAuthorityChangeService, review: Review,
      operationID: VaultTransactionOperationID? = nil
    ) throws -> Commit {
      switch review {
      case .device(let p):
        let c = try service.revoke(p, operationID: operationID ?? disk.operationID)
        return .init(checkpoint: c.checkpoint, envelope: c.envelope)
      case .recipient(let p):
        let c = try service.remove(
          p, operationID: operationID ?? disk.operationID,
          protectionLossAcknowledgement: p.removesLastActiveRecipient ? .init(plan: p) : nil)
        return .init(checkpoint: c.checkpoint, envelope: c.envelope)
      }
    }
    func addBranch() throws {
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "different branch"),
        checkpoint: checkpoint, parent: parent, currentEntries: entries, vaultKey: key)
      try disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
  }
}
