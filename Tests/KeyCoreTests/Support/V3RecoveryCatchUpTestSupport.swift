import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Independent local checkpoints and software Mac identities over real published lifecycle history.
enum V3RecoveryCatchUpTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Publication = V3RecoveryPublicationTestSupport
  private typealias Stop = Publication.Stop
  enum Action: CaseIterable, Sendable {
    case rotation, enrollment, revocation, removal, lastRemoval, addition
  }

  final class Fixture: @unchecked Sendable {
    let disk: Publication.Fixture
    let receiver: Core.Owner
    let target: Core.Owner
    let local: Publication.Checkpoints
    let pending = [Publication.Ownership(), Publication.Ownership(), Publication.Ownership()]
    let session = V3DeviceWrappedVaultKeySessionStore()
    let localCache: V3CheckpointManifestFilesystemCache
    let floor: V3RecoveryContentCommit
    let initialEntries: [V3EntryObjectKey: V3EncryptedEntry]
    let initialKey: Data
    var parent: V3RecoveryManifestEnvelope
    var entries: [V3EntryObjectKey: V3EncryptedEntry]
    var key: Data
    var owner: Core.Owner { disk.core.owner }
    init(root: URL? = nil, empty: Bool = false, last: Bool = false) throws {
      disk = try Publication.Fixture(root: root, empty: empty, backup: !last)
      receiver = try Core.Owner()
      target = try Core.Owner()
      var current = disk.parent
      var currentEntries = disk.entries
      var currentKey = Core.nextKey
      for joining in [receiver, target] {
        let state = try V3RecoveryEnrollmentTestSupport.ceremony(
          parentDigest: current.digest, owner: disk.core.owner, joiner: joining)
        let next = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        let candidate = try V3RecoveryDeviceEnrollmentBuilder().build(
          checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: current.digest),
          parent: current, currentEntries: currentEntries, state: state,
          currentVaultKey: currentKey, nextVaultKey: next, owner: disk.core.owner,
          at: 4_102_444_800, reason: "Owned two-Mac fixture enrollment")
        let commit = try V3RecoveryDeviceEnrollmentPublisher(
          mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          ceremonyStore: V3RecoveryEnrollmentTestSupport.StateStore(state.canonicalBytes),
          cache: disk.cache
        ).publish(
          candidate, state: state, approvedTranscriptDigest: candidate.transcriptDigest,
          currentVaultKey: currentKey, nextVaultKey: next, identity: disk.core.owner,
          at: 4_102_444_800, reason: "Owned two-Mac fixture opening")
        current = commit.envelope
        currentEntries = try V3EntrySnapshotValidator(limits: .standard).entryMap(
          candidate.stagedEntries)
        currentKey = next
      }
      parent = current
      entries = currentEntries
      key = currentKey
      floor = .init(
        checkpoint: try .init(vaultID: Core.vaultID, envelopeDigest: current.digest),
        envelope: current)
      initialEntries = currentEntries
      initialKey = currentKey
      local = Publication.Checkpoints(floor.checkpoint.canonicalBytes)
      let cacheRoot = disk.root.appendingPathComponent("other-mac-cache")
      try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: true)
      localCache = .init(rootHandle: try VaultRootDirectoryHandle(opening: cacheRoot))
      try localCache.store(current.canonicalBytes, for: floor.checkpoint)
      try unlock()
    }
    func unlock() throws {
      try session.install(
        initialKey, vaultID: Core.vaultID, keyID: floor.envelope.body.fields.keyID)
    }
    func ownerSession() throws -> V3DeviceWrappedVaultKeySessionStore {
      let result = V3DeviceWrappedVaultKeySessionStore()
      try result.install(key, vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      return result
    }
    func publish(_ action: Action) throws -> V3RecoveryManifestEnvelope {
      let before = parent
      let next = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
      switch action {
      case .rotation:
        let session = try ownerSession()
        parent = try V3RecoveryKeyRotationService(
          vaultID: Core.vaultID, identity: owner, session: session, objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          cache: disk.cache
        ).rotate(expectedCheckpoint: cp(), operationID: .init()).envelope
        key = try session.load(vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      case .revocation: return try revoke(target)
      case .removal, .lastRemoval:
        let session = try ownerSession()
        let service = V3RecoveryAuthorityChangeService(
          vaultID: Core.vaultID, identity: owner, session: session, objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          cache: disk.cache)
        let plan = try service.prepareRemoval(removing: disk.anchor.recipientID)
        parent = try service.remove(
          plan, operationID: .init(),
          protectionLossAcknowledgement: plan.removesLastActiveRecipient ? .init(plan: plan) : nil
        ).envelope
        key = try session.load(vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      case .enrollment:
        let state = try V3RecoveryEnrollmentTestSupport.ceremony(
          parentDigest: parent.digest, owner: owner, joiner: Core.Owner())
        let candidate = try V3RecoveryDeviceEnrollmentBuilder().build(
          checkpoint: cp(), parent: parent, currentEntries: entries, state: state,
          currentVaultKey: key, nextVaultKey: next, owner: owner, at: 4_102_444_800,
          reason: "Owned additional Mac fixture")
        parent = try V3RecoveryDeviceEnrollmentPublisher(
          mutationOwner: VaultTransactionMutationOwner(), objectStore: disk.store,
          checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
          registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
          ceremonyStore: V3RecoveryEnrollmentTestSupport.StateStore(state.canonicalBytes),
          cache: disk.cache
        ).publish(
          candidate, state: state, approvedTranscriptDigest: candidate.transcriptDigest,
          currentVaultKey: key, nextVaultKey: next, identity: owner, at: 4_102_444_800,
          reason: "Owned additional Mac opening"
        ).envelope
        key = next
      case .addition:
        // Recipient addition bytes are constructed by the real domain builder;
        // materialization here is not another possession/registration ceremony.
        let candidate = try V3RecoveryRegistrationBuilder().prepare(
          checkpoint: cp(), parent: parent, currentEntries: entries,
          currentVaultKey: key, nextVaultKey: next,
          credential: Core.Fixture().credential, occupancy: .absent, owner: owner,
          reason: "Owned recipient addition fixture", operationID: .init())
        try disk.seed(candidate.candidate, entries: candidate.stagedEntries)
        parent = candidate.candidate
        disk.checkpoints.value = try cp().canonicalBytes
        key = next
      }
      #expect(parent.parents == [before.digest])
      entries = try loadEntries(parent)
      return parent
    }
    func revoke(_ removed: Core.Owner) throws -> V3RecoveryManifestEnvelope {
      let session = try ownerSession()
      let service = V3RecoveryAuthorityChangeService(
        vaultID: Core.vaultID, identity: owner, session: session, objectStore: disk.store,
        checkpointStore: disk.checkpoints, recoveryAnchorStore: disk.ownership,
        registrationAnchorStore: disk.registration, adoptionAnchorStore: disk.adoption,
        cache: disk.cache)
      parent = try service.revoke(
        service.prepareRevocation(revoking: removed.publicIdentity.deviceID),
        operationID: .init()
      ).envelope
      key = try session.load(vaultID: Core.vaultID, keyID: parent.body.fields.keyID)
      entries = try loadEntries(parent)
      return parent
    }
    func edit(_ value: String) throws {
      let candidate = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: value),
        checkpoint: cp(), parent: parent, currentEntries: entries, vaultKey: key)
      parent = try disk.publisher().publish(candidate, vaultKey: key).envelope
      entries = try loadEntries(parent)
    }
    func branchFromFloor() throws {
      let branch = try V3RecoveryContentMutationBuilder().build(
        .edit(name: "fixture/secret", type: .secret, plaintext: "late old-epoch branch"),
        checkpoint: floor.checkpoint, parent: floor.envelope, currentEntries: initialEntries,
        vaultKey: initialKey)
      try disk.seed(branch.envelope, entries: branch.stagedEntries)
    }
    func cp() throws -> V3ManifestCheckpoint {
      try .init(vaultID: Core.vaultID, envelopeDigest: parent.digest)
    }
    func loadEntries(_ envelope: V3RecoveryManifestEnvelope) throws -> [V3EntryObjectKey:
      V3EncryptedEntry]
    {
      var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
      for record in envelope.body.fields.entries {
        let address = try V3RecoveryMergeMutationValidator.address(record)
        guard
          case .available(let data) = try disk.store.readEntry(
            entryID: address.entryID, digest: address.digest, maximumBytes: 1_048_576)
        else { throw Stop.interrupted }
        result[address] = try V3EntryCipher().parse(data)
      }
      return result
    }
  }
}
