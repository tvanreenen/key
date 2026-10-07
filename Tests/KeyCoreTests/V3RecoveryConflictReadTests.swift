import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Complete real software publications feed the production observer and sealed
/// read planner. Executor callbacks exercise the final authority boundary.
struct V3RecoveryConflictReadTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private let branches = V3RecoveryManifestReconciliationTests()

  @Test(arguments: 0..<4)
  func actualConflictVersionsReadExactBytesAndBindCheckpointAndHeads(kind: Int) throws {
    let f = try Publication.Fixture()
    defer { f.remove() }
    try publishConflict(f, kind: kind)
    let observed = try observe(f)
    let snapshot = try #require(try V3ConflictObservationBuilder().build(observed))
    let detail = try #require(snapshot.conflicts.first)
    var values = Set<String>()
    for version in detail.versions {
      let plan = try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
        conflictID: detail.summary.id, versionID: version.id, observed: observed)
      #expect(
        plan.authority == .current(.init(checkpoint: f.checkpoint, heads: snapshot.expectedHeads)))
      #expect(plan.entry.keyID == f.parent.body.fields.keyID && plan.vaultID == Core.vaultID)
      values.insert(try execute(plan, source: f.store, observed: observed))
    }
    let expected: Set<String> =
      kind == 2
      ? ["JBSWY3DPEHPK3PXP", "MZXW6YTBOI"]
      : [kind == 3 ? "Software fixture secret e\u{301}\r\n" : "first e\u{301}\r\n", "second"]
    #expect(values == expected)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.core.owner.unwraps == 0)
    #expect(f.ownership.value == nil && f.registration.value == nil && f.adoption.value == nil)
  }

  @Test func deletionIsNotMissingVersionOrEmptyPlaintext() throws {
    let f = try Publication.Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/secret")])
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "kept")])
    let observed = try observe(f)
    let detail = try #require(try V3ConflictObservationBuilder().build(observed)?.conflicts.first)
    let deletion = try #require(detail.versions.first { $0.entryName == nil })
    #expect(
      throws: AppError.operationRefused(
        "That authenticated version deleted the entry and has no secret value to read.")
    ) {
      try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
        conflictID: detail.summary.id,
        versionID: deletion.id, observed: observed)
    }
    let kept = try #require(detail.versions.first { $0.entryName != nil })
    let plan = try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
      conflictID: detail.summary.id,
      versionID: kept.id, observed: observed)
    #expect(try execute(plan, source: f.store, observed: observed) == "kept")
  }

  @Test func selectorsAreExactMembershipNotPathsOrDigestPrefixes() throws {
    let f = try Publication.Fixture()
    defer { f.remove() }
    try publishConflict(f)
    let observed = try observe(f)
    let detail = try #require(try V3ConflictObservationBuilder().build(observed)?.conflicts.first)
    let valid = try #require(detail.versions.first)
    for id in ["", "../entries", detail.summary.id + "x"] {
      #expect(throws: VaultUXServiceError.conflictNotFound) {
        try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
          conflictID: id, versionID: valid.id, observed: observed)
      }
    }
    for version in ["", "../entries", String(valid.id.dropLast()), valid.id + "x"] {
      #expect(throws: VaultUXServiceError.conflictVersionNotFound) {
        try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
          conflictID: detail.summary.id, versionID: version, observed: observed)
      }
    }
  }

  @Test func changedHeadSetMakesPreviouslyDisplayedIDsUnusable() throws {
    let f = try Publication.Fixture()
    defer { f.remove() }
    try publishConflict(f)
    let initial = try #require(
      try V3ConflictObservationBuilder().build(observe(f))?.conflicts.first)
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "third")])
    #expect(throws: VaultUXServiceError.conflictNotFound) {
      try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
        conflictID: initial.summary.id,
        versionID: initial.versions[0].id, observed: observe(f))
    }
  }

  @Test(arguments: [false, true])
  func linearOrAutomaticallyMergeableHistoryDoesNotInventAConflict(automatic: Bool) throws {
    let f = try Publication.Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "edit")])
    if automatic {
      _ = try branches.publishBranch(
        f, requests: [.edit(name: "fixture/totp", type: .totp, plaintext: "MZXW6YTBOI")])
    }
    #expect(throws: VaultUXServiceError.conflictNotFound) {
      try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
        conflictID: "unknown", versionID: "unknown", observed: observe(f))
    }
  }

  @Test(arguments: 0..<3)
  func executorRefusesLateAuthorityChangeEvenAfterOpeningCorrectCiphertext(change: Int) throws {
    let f = try Publication.Fixture()
    defer { f.remove() }
    try publishConflict(f)
    let observed = try observe(f)
    let detail = try #require(try V3ConflictObservationBuilder().build(observed)?.conflicts.first)
    let plan = try V3AuthenticatedReadPlanner().planRecoveryConflictRead(
      conflictID: detail.summary.id,
      versionID: detail.versions[0].id, observed: observed)
    let expected = V3ExpectedRepositoryState(
      checkpoint: observed.checkpoint,
      heads: try observed.heads.map {
        try V3VaultHead(vaultID: Core.vaultID, envelopeDigest: $0)
      })
    #expect(throws: V3AuthenticatedReadError.authorityChanged) {
      try V3AuthenticatedReadExecutor(
        source: f.store,
        vaultKeyProvider: { _ in Core.nextKey },
        authorityValidator: .init(
          currentStateProvider: { _ in
            if change == 0 { throw V3AuthenticatedReadError.authorityChanged }
            if change == 1 {
              return .init(checkpoint: expected.checkpoint, heads: Array(expected.heads.dropLast()))
            }
            return .init(
              checkpoint: try V3ManifestCheckpoint(
                vaultID: Core.vaultID,
                envelopeDigest: Data(repeating: 0, count: 32)), heads: expected.heads)
          }, checkpointProvider: { _ in throw V3AuthenticatedReadError.authorityChanged })
      ).execute(plan)
    }
  }

  private func publishConflict(_ f: Publication.Fixture, kind: Int = 0) throws {
    for (index, value) in ["first e\u{301}\r\n", "second"].enumerated() {
      let request: V3EntryMutationRequest
      switch kind {
      case 1:
        request = .add(
          entryID: UUID().uuidString.lowercased(), name: "same/name", type: .secret,
          plaintext: value)
      case 2:
        request = .edit(
          name: "fixture/totp", type: .totp,
          plaintext: index == 0 ? "JBSWY3DPEHPK3PXP" : "MZXW6YTBOI")
      case 3:
        let original = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
        request =
          index == 0
          ? .move(
            sourceName: "fixture/secret", sourceData: original.canonicalBytes,
            destinationName: "renamed/entry", overwrite: false)
          : .edit(name: "fixture/secret", type: .secret, plaintext: value)
      default: request = .edit(name: "fixture/secret", type: .secret, plaintext: value)
      }
      _ = try branches.publishBranch(f, requests: [request])
    }
  }

  private func observe(_ f: Publication.Fixture) throws -> V3RecoverySameEpochObservation {
    try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: .init(checkpoint: f.checkpoint, envelope: f.parent), vaultKey: Core.nextKey)
  }
  private func execute(
    _ plan: V3AuthenticatedReadPlan, source: any V3ImmutableObjectReading,
    observed: V3RecoverySameEpochObservation
  ) throws -> String {
    try V3AuthenticatedReadExecutor(
      source: source, vaultKeyProvider: { _ in Core.nextKey },
      authorityValidator: .init(
        currentStateProvider: { _ in
          .init(
            checkpoint: observed.checkpoint,
            heads: try observed.heads.map {
              try V3VaultHead(vaultID: Core.vaultID, envelopeDigest: $0)
            })
        }, checkpointProvider: { _ in throw V3AuthenticatedReadError.authorityChanged })
    ).execute(plan)
  }
}
