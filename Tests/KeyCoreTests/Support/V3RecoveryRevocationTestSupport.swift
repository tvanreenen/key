import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Published enrolled history and reviewed device-revocation candidates.
enum V3RecoveryRevocationTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Publication = V3RecoveryPublicationTestSupport
  typealias Enrollment = V3RecoveryEnrollmentTestSupport
  static let currentKey = Data(repeating: 0x33, count: 32)
  static let nextKey = Data(repeating: 0x44, count: 32)
  struct Fixture: Sendable {
    let enrollment: V3RecoveryEnrollmentTestSupport.Fixture
    let parent: V3RecoveryManifestEnvelope
    let checkpoint: V3ManifestCheckpoint
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    let signatures: Int
    let unwraps: Int
    var owner: V3RecoveryRegistrationTestSupport.Owner { enrollment.disk.core.owner }
    var currentKey: Data { SelfKey.current }
    init(empty: Bool = false) throws {
      enrollment = try Enrollment.Fixture(empty: empty)
      let disk = enrollment.disk
      let joined = try V3RecoveryDeviceEnrollmentBuilder().build(
        checkpoint: disk.checkpoint, parent: disk.parent, currentEntries: disk.entries,
        state: enrollment.state, currentVaultKey: Core.nextKey, nextVaultKey: SelfKey.current,
        owner: disk.core.owner, at: 4_102_444_800, reason: "Owned enrollment fixture")
      let commit = try V3RecoveryDeviceEnrollmentPublisher(
        mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
        checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
        registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
        ceremonyStore: enrollment.local, cache: disk.cache
      ).publish(
        joined, state: enrollment.state, approvedTranscriptDigest: joined.transcriptDigest,
        currentVaultKey: Core.nextKey, nextVaultKey: SelfKey.current, identity: disk.core.owner,
        at: 4_102_444_800, reason: "Owned enrollment wrapper fixture")
      parent = commit.envelope
      checkpoint = commit.checkpoint
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(joined.stagedEntries)
      signatures = disk.core.owner.signatures
      unwraps = disk.core.owner.unwraps
    }
    func plan() throws -> V3DeviceWrappedRevocationPlan {
      try V3RecoveryDeviceRevocationPlanner().plan(
        checkpoint: checkpoint, parent: parent,
        currentVaultKey: SelfKey.current, authorizingDeviceID: owner.publicIdentity.deviceID,
        revoking: enrollment.joiner.publicIdentity.deviceID)
    }
    func build() throws -> V3RecoveryDeviceRevocationCandidate {
      try V3RecoveryDeviceRevocationBuilder().build(
        parent: parent, currentEntries: entries,
        plan: plan(), currentVaultKey: SelfKey.current, nextVaultKey: SelfKey.next,
        owner: owner, reason: "Owned revocation fixture")
    }
    func addBranch() throws {
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "other branch"),
        checkpoint: checkpoint, parent: parent, currentEntries: entries, vaultKey: SelfKey.current)
      try enrollment.disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
  }
  private enum SelfKey {
    static let current = V3RecoveryRevocationTestSupport.currentKey
    static let next = V3RecoveryRevocationTestSupport.nextKey
  }
}
