import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryPublicationBudgetTests {
  private typealias Core = V3RecoveryRegistrationTestSupport

  @Test(arguments: [false, true], [false, true])
  func projectionPreservesCumulativeRecoveryLimits(references: Bool, published: Bool) throws {
    let core = try Core.Fixture()
    let registration = try core.prepare()
    let floor = try Frame(registration)
    let first = try edit(floor, key: Core.nextKey)
    let second = try edit(first, key: Core.nextKey)
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 32, maximumHistoryDepth: references ? 10 : 1,
      maximumReferencedEntryObjects: references ? 3 : 32)
    // The exact boundary remains usable; an unpublished projection must not
    // double-count its candidate or require historical entry ciphertext.
    try project(floor, next: first, history: [core.parent, floor.envelope], limits: limits)
    let history =
      [core.parent, floor.envelope, first.envelope]
      + (published ? [second.envelope] : [])
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try project(first, next: second, history: history, limits: limits)
    }
  }

  @Test func theOldestContinuingRecipientStillOwnsItsHistoryBudget() throws {
    let core = try Core.Fixture(backup: true)
    let registration = try core.prepare()
    let floor = try Frame(registration)
    let next = try edit(floor, key: Core.nextKey)
    // The new token's floor is only one step away. The continuing backup's
    // earlier floor must also remain recoverable, at two steps away.
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try project(
        floor, next: next, history: [core.parent, floor.envelope],
        limits: .init(maximumManifestObjects: 32, maximumHistoryDepth: 1))
    }
  }

  @Test func firstRegistrationDoesNotChargePreRegistrationHistory() throws {
    let core = try Core.Fixture()
    let initial = Frame(envelope: core.parent, entries: core.entries)
    let first = try edit(initial, key: Core.oldKey)
    let second = try edit(first, key: Core.oldKey)
    let registration = try V3RecoveryRegistrationBuilder().prepare(
      checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: second.envelope.digest),
      parent: second.envelope, currentEntries: second.entries,
      currentVaultKey: Core.oldKey, nextVaultKey: Core.nextKey,
      credential: core.credential, occupancy: .absent, owner: core.owner,
      reason: "Software registration budget fixture")
    try project(
      second, next: Frame(registration),
      history: [initial.envelope, first.envelope, second.envelope],
      limits: .init(maximumManifestObjects: 32, maximumHistoryDepth: 1))
  }

  private struct Frame {
    let envelope: V3RecoveryManifestEnvelope
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    init(envelope: V3RecoveryManifestEnvelope, entries: [V3EntryObjectKey: V3EncryptedEntry]) {
      self.envelope = envelope
      self.entries = entries
    }
    init(_ registration: V3RecoveryRegistrationPreparation) throws {
      envelope = registration.candidate
      entries = try V3EntrySnapshotValidator(limits: .standard).entryMap(registration.stagedEntries)
    }
  }

  private func edit(_ frame: Frame, key: Data) throws -> Frame {
    let old = frame.envelope.body
    let record = try #require(old.fields.entries.first { $0.name == "fixture/secret" })
    let entry = try V3EntryCipher().seal(
      "Software revision \(record.revision + 1)",
      context: .init(
        vaultID: Core.vaultID, entryID: record.entryID, name: record.name, type: record.type,
        keyID: record.keyID, revision: record.revision + 1), vaultKey: key)
    let fields = old.fields
    let body = try V3RecoveryManifestBody(
      fields: .init(
        vaultID: fields.vaultID, keyID: fields.keyID,
        authorityTransitionID: fields.authorityTransitionID, devices: fields.devices,
        wrappedKeys: fields.wrappedKeys,
        entries: fields.entries.map {
          $0.entryID == record.entryID ? V3ResealedEntry(encryptedEntry: entry).manifestEntry : $0
        }),
      epochSigningKey: old.epochSigningKey, transitionProof: old.transitionProof,
      recovery: old.recovery)
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: [frame.envelope.digest], vaultKey: key, authorizations: [])
    let entries = frame.entries.values.filter { $0.context.entryID != record.entryID } + [entry]
    return try Frame(
      envelope: envelope, entries: V3EntrySnapshotValidator(limits: .standard).entryMap(entries))
  }

  private func project(
    _ current: Frame, next: Frame, history: [V3RecoveryManifestEnvelope],
    limits: V3ManifestRepositoryLimits
  ) throws {
    var entries = current.entries
    entries.merge(next.entries) { _, new in new }
    let source = Source(
      manifests: Dictionary(uniqueKeysWithValues: history.map { ($0.digest, $0.canonicalBytes) }),
      entries: entries)
    let repository = V3ExactTransitionRepository(source: source, limits: limits)
    let state = try repository.observe(
      checkpoint: .init(vaultID: Core.vaultID, envelopeDigest: current.envelope.digest),
      expectedBase: current.envelope.canonicalBytes,
      candidate: next.envelope, stagedEntries: Array(next.entries.values))
    try repository.requireProjectedUsage(
      state, candidate: next.envelope, stagedEntries: Array(next.entries.values))
  }

  private struct Source: V3ImmutableObjectReading {
    let manifests: [Data: Data]
    let entries: [V3EntryObjectKey: V3EncryptedEntry]
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      manifests.count > maximumCount
        ? .limitExceeded : .available(digests: Array(manifests.keys), objectCount: manifests.count)
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      guard let bytes = manifests[digest] else { return .unavailable }
      return bytes.count > maximumBytes ? .tooLarge : .available(bytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      guard let bytes = entries[.init(entryID: entryID, digest: digest)]?.canonicalBytes else {
        return .unavailable
      }
      return bytes.count > maximumBytes ? .tooLarge : .available(bytes)
    }
  }
}
