import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3RecoveryMergeMutationTests {
  private typealias Publication = V3RecoveryContentMutationPublisherTests
  private typealias Fixture = Publication.Fixture
  private typealias Core = V3RecoveryRegistrationTests
  private let branches = V3RecoveryManifestReconciliationTests()
  private static let addedID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c1"
  private static let otherID = "018f4d38-7d5a-7b20-b0f1-97d6e96c84c2"

  @Test func automaticMergeIncludesEveryExactParentAndPreservesCoverageWithoutResealing() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "updated")
      ])
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildAutomatic(
      from: observed, vaultKey: Core.nextKey)
    let complete = try validate(candidate, observed: observed)
    #expect(candidate.kind == .mergeHeads && candidate.resolutions.isEmpty)
    #expect(
      candidate.expectedHeads == observed.heads && candidate.envelope.parents == observed.heads)
    #expect(candidate.stagedEntries.isEmpty && candidate.envelope.authorizations.isEmpty)
    #expect(candidate.envelope.body.fields.entries.map(\.name) == ["fixture/secret"])
    #expect(complete.allSatisfy { observed.entryObjects[$0.key] == $0.value })
    #expect(
      try V3RecoveryMergeMutationBuilder().buildAutomatic(
        from: observed, vaultKey: Core.nextKey) == candidate)
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test func anUnpublishedAutomaticMergeCandidateIsRestorableThroughTheRecoverySelector() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "restorable")
      ])
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildAutomatic(
      from: observed, vaultKey: Core.nextKey)
    _ = try validate(candidate, observed: observed)
    // Fixture delivery only: this does not test a production merge publisher.
    try f.seed(candidate.envelope, entries: [])
    let selected = try V3RecoveryHistorySelector(source: f.store).select(
      anchor: f.anchor, credentialPublicKey: f.core.token.publicKey.x963Representation)
    let agreements = Core.Counter()
    let receiver = try PIVHPKEReceiver(publicBytes: f.core.token.publicKey.x963Representation) {
      peer in
      agreements.increment()
      let secret = try f.core.token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer))
      return secret.withUnsafeBytes { Data($0) }
    }
    let snapshot = try V3RecoverySnapshotVerifier(source: f.store).open(
      selected, boundAnchor: f.anchor, receiver: receiver)
    #expect(selected.head.digest == candidate.envelope.digest && agreements.value == 1)
    #expect(snapshot.entries.map(\.plaintext) == ["restorable"])
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test func selectingAnOlderConflictedVersionResealsItsValueAboveEveryParentRevision() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "selected older value")
      ])
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "other first"),
        .edit(name: "fixture/secret", type: .secret, plaintext: "other later"),
      ])
    let observed = try observation(f)
    let choices = try choose(observed, head: a.envelope.digest)
    let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
      choices, from: observed, vaultKey: Core.nextKey)
    let complete = try validate(candidate, observed: observed)
    let staged = try #require(candidate.stagedEntries.first)
    #expect(candidate.kind == .resolveConflict && candidate.stagedEntries.count == 1)
    let original = try #require(f.parent.body.fields.entries.first { $0.name == "fixture/secret" })
    #expect(
      staged.context.revision == original.revision + 3 && staged.context.name == "fixture/secret")
    let values = try V3EntrySnapshotValidator(limits: .standard).plaintexts(
      fields: candidate.envelope.body.fields, entries: complete, vaultKey: Core.nextKey)
    #expect(values[staged.context.entryID] == Data("selected older value".utf8))
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test func choosingDeletionKeepsTheEntryAbsentWithoutStagingNewCiphertext() throws {
    let f = try Fixture()
    defer { f.remove() }
    let deleted = try branches.publishBranch(f, requests: [.remove(name: "fixture/secret")])
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "other")
      ])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
      choose(observed, head: deleted.envelope.digest), from: observed, vaultKey: Core.nextKey)
    _ = try validate(candidate, observed: observed)
    #expect(candidate.stagedEntries.isEmpty)
    #expect(candidate.envelope.body.fields.entries.map(\.name) == ["fixture/totp"])
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test func selectingRenamePreservesItsExactNameTypeIdentityAndValue() throws {
    let f = try Fixture()
    defer { f.remove() }
    let entry = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    let moved = try branches.publishBranch(
      f,
      requests: [
        .move(
          sourceName: "fixture/secret", sourceData: entry.canonicalBytes,
          destinationName: "renamed/account", overwrite: false)
      ])
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "other")
      ])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
      choose(observed, head: moved.envelope.digest), from: observed, vaultKey: Core.nextKey)
    _ = try validate(candidate, observed: observed)
    let staged = try #require(candidate.stagedEntries.first)
    #expect(
      staged.context.entryID == entry.context.entryID
        && staged.context.revision == entry.context.revision + 2)
    #expect(staged.context.name == "renamed/account" && staged.context.type == entry.context.type)
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test func destinationChoiceRetainsOnlyTheChosenIdentityWithoutResealingIt() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f,
      requests: [
        .add(entryID: Self.addedID, name: "same/account", type: .secret, plaintext: "first")
      ])
    _ = try branches.publishBranch(
      f,
      requests: [
        .add(entryID: Self.otherID, name: "same/account", type: .secret, plaintext: "second")
      ])
    let observed = try observation(f)
    let snapshot = try conflictSnapshot(observed)
    let detail = try #require(snapshot.conflicts.first)
    let choice = try #require(detail.versions.first)
    let selected = try #require(snapshot.selections[detail.summary.id]?.versions[choice.id] ?? nil)
    let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
      [.init(conflictID: detail.summary.id, versionID: choice.id)], from: observed,
      vaultKey: Core.nextKey)
    _ = try validate(candidate, observed: observed)
    #expect(candidate.stagedEntries.isEmpty)
    #expect(candidate.envelope.body.fields.entries.first { $0.name == "same/account" } == selected)
    #expect(candidate.envelope.body.fields.entries.count == 3)
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test(arguments: 0..<5)
  func incompleteDuplicateUnknownAndStaleChoicesRefuseConstruction(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "first")
      ])
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "second")
      ])
    let observed = try observation(f)
    let choices = try choose(observed, head: a.envelope.digest)
    let choice = try #require(choices.first)
    let input: [VaultConflictResolution]
    switch variant {
    case 0: input = []
    case 1: input = choices + choices
    case 2: input = [.init(conflictID: "not a current conflict", versionID: choice.versionID)]
    case 3: input = [.init(conflictID: choice.conflictID, versionID: "not a current version")]
    default:
      _ = try branches.publishBranch(
        f,
        requests: [
          .edit(name: "fixture/secret", type: .secret, plaintext: "third")
        ])
      input = choices
    }
    #expect(throws: (any Error).self) {
      try V3RecoveryMergeMutationBuilder().buildResolution(
        input, from: variant == 4 ? observation(f) : observed, vaultKey: Core.nextKey)
    }
    #expect(throws: V3RecoveryMergeMutationError.invalidCandidate) {
      try V3RecoveryMergeMutationBuilder().buildAutomatic(from: observed, vaultKey: Core.nextKey)
    }
  }

  @Test func choicesCreatingANewDestinationCollisionCannotSilentlyDeleteAnotherSelection() throws {
    let f = try Fixture()
    defer { f.remove() }
    let secret = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    let otp = try #require(f.entries.values.first { $0.context.name == "fixture/totp" })
    let a = try branches.publishBranch(
      f,
      requests: [
        .move(
          sourceName: "fixture/secret", sourceData: secret.canonicalBytes,
          destinationName: "new/shared", overwrite: false),
        .edit(name: "fixture/totp", type: .totp, plaintext: "JBSWY3DPEHPK3PXP"),
      ])
    let b = try branches.publishBranch(
      f,
      requests: [
        .move(
          sourceName: "fixture/totp", sourceData: otp.canonicalBytes,
          destinationName: "new/shared", overwrite: false),
        .edit(name: "fixture/secret", type: .secret, plaintext: "other"),
      ])
    let observed = try observation(f)
    let snapshot = try conflictSnapshot(observed)
    let choices = try snapshot.conflicts.map { detail in
      let digest =
        detail.summary.entryName == "fixture/secret" ? a.envelope.digest : b.envelope.digest
      let version = try #require(detail.versions.first { v3LowercaseHex(digest).hasPrefix($0.id) })
      return VaultConflictResolution(conflictID: detail.summary.id, versionID: version.id)
    }
    #expect(choices.count == 2)
    #expect(throws: V3RecoveryMergeMutationError.destinationStillConflicted) {
      try V3RecoveryMergeMutationBuilder().buildResolution(
        choices, from: observed, vaultKey: Core.nextKey)
    }
  }

  @Test(arguments: 0..<6)
  func exactHeadsCheckpointKindMetadataAndStagingAreIndependentlyChecked(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f,
      requests: [
        .edit(name: "fixture/secret", type: .secret, plaintext: "updated")
      ])
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildAutomatic(
      from: observed, vaultKey: Core.nextKey)
    var envelope = candidate.envelope
    if variant == 3 {
      envelope = try V3RecoveryEpochBoundary().encode(
        body: envelope.body, parents: [observed.heads[0]], vaultKey: Core.nextKey,
        authorizations: [])
    }
    if variant == 4 {
      let body = envelope.body
      envelope = try V3RecoveryEpochBoundary().encode(
        body: V3RecoveryManifestBody(
          fields: body.fields, epochSigningKey: body.epochSigningKey,
          transitionProof: nil, recovery: body.recovery),
        parents: observed.heads, vaultKey: Core.nextKey, authorizations: [])
    }
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID,
      envelopeDigest: variant == 0 ? observed.heads[0] : candidate.expectedCheckpoint.envelopeDigest
    )
    let input = V3RecoveryMergeMutationCandidate(
      kind: variant == 2 ? .editEntry : candidate.kind,
      expectedCheckpoint: checkpoint,
      expectedHeads: variant == 1 ? observed.heads.reversed() : candidate.expectedHeads,
      resolutions: [], envelope: envelope,
      stagedEntries: variant == 5 ? Array(f.entries.values) : [])
    #expect(throws: (any Error).self) { try validate(input, observed: observed) }
  }

  @Test func selectedValueCannotChangeEvenWithAValidReplacementCiphertextAndManifestMAC() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "first")])
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "second")])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
      choose(observed, head: a.envelope.digest), from: observed, vaultKey: Core.nextKey)
    let staged = try #require(candidate.stagedEntries.first)
    let changed = try V3EntryCipher().seal(
      "different fixture value", context: staged.context, vaultKey: Core.nextKey)
    let fields = candidate.envelope.body.fields
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: fields.vaultID, keyID: fields.keyID,
        authorityTransitionID: fields.authorityTransitionID, devices: fields.devices,
        wrappedKeys: fields.wrappedKeys,
        entries: fields.entries.map {
          $0.entryID == changed.context.entryID
            ? V3ResealedEntry(encryptedEntry: changed).manifestEntry : $0
        }),
      epochSigningKey: candidate.envelope.body.epochSigningKey,
      transitionProof: candidate.envelope.body.transitionProof,
      recovery: candidate.envelope.body.recovery)
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: observed.heads, vaultKey: Core.nextKey, authorizations: [])
    let input = V3RecoveryMergeMutationCandidate(
      kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
      expectedHeads: candidate.expectedHeads, resolutions: candidate.resolutions,
      envelope: envelope, stagedEntries: [changed])
    #expect(throws: V3RecoveryMergeMutationError.invalidCandidate) {
      try validate(input, observed: observed)
    }
  }

  @Test(arguments: [false, true])
  func resolutionStagingMustBeCompleteAndContainNoUnselectedObjects(extra: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "first")])
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "second")])
    let observed = try observation(f)
    let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
      choose(observed, head: a.envelope.digest), from: observed, vaultKey: Core.nextKey)
    let input = V3RecoveryMergeMutationCandidate(
      kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
      expectedHeads: candidate.expectedHeads, resolutions: candidate.resolutions,
      envelope: candidate.envelope,
      stagedEntries: extra ? candidate.stagedEntries + Array(f.entries.values) : [])
    #expect(throws: V3RecoveryMergeMutationError.invalidCandidate) {
      try validate(input, observed: observed)
    }
  }

  @Test func wrongSessionKeyAndTighterResourceLimitsRefuseTheMerge() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "updated")])
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let observed = try observation(f)
    #expect(throws: (any Error).self) {
      try V3RecoveryMergeMutationBuilder().buildAutomatic(from: observed, vaultKey: Core.oldKey)
    }
    let manifestSizes = observed.envelopes.values.map { $0.canonicalBytes.count }
    let entrySizes = observed.entryObjects.values.map { $0.canonicalBytes.count }
    let maximumManifest = try #require(manifestSizes.max())
    let maximumEntry = try #require(entrySizes.max())
    for limits in [
      V3ManifestRepositoryLimits(maximumManifestObjects: 1, maximumHistoryDepth: 10),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumManifestBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumEntryBytes: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumReferencedEntryObjects: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumManifestBytes: maximumManifest,
        maximumTotalManifestBytes: manifestSizes.reduce(0, +) - 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: 10, maximumHistoryDepth: 10, maximumEntryBytes: maximumEntry,
        maximumTotalEntryBytes: entrySizes.reduce(0, +) - 1),
    ] {
      #expect(throws: (any Error).self) {
        try V3RecoveryMergeMutationBuilder(limits: limits).buildAutomatic(
          from: observed, vaultKey: Core.nextKey)
      }
    }
  }

  @Test func ordinarySingleParentPublicationStillRefusesAnAllParentCandidateBeforeCreatingIntent()
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "updated")])
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let candidate = try V3RecoveryMergeMutationBuilder().buildAutomatic(
      from: observation(f), vaultKey: Core.nextKey)
    #expect(throws: V3RecoveryContentMutationError.invalidCandidate) {
      try f.publisher().publish(
        V3RecoveryContentMutationCandidate(
          kind: candidate.kind, expectedCheckpoint: candidate.expectedCheckpoint,
          envelope: candidate.envelope, stagedEntries: candidate.stagedEntries),
        vaultKey: Core.nextKey)
    }
    try requirePreservedAuthority(candidate, f: f)
  }

  @Test func depthAndObjectLimitsIncludeTheNewMergeManifest() throws {
    let f = try Fixture()
    defer { f.remove() }
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "updated")])
    _ = try branches.publishBranch(f, requests: [.remove(name: "fixture/totp")])
    let observed = try observation(f)
    for limits in [
      V3ManifestRepositoryLimits(maximumManifestObjects: 10, maximumHistoryDepth: 1),
      V3ManifestRepositoryLimits(
        maximumManifestObjects: observed.listedObjectCount, maximumHistoryDepth: 10),
    ] {
      #expect(throws: V3RecoveryMergeMutationError.resourceLimit) {
        try V3RecoveryMergeMutationBuilder(limits: limits).buildAutomatic(
          from: observed, vaultKey: Core.nextKey)
      }
    }
    let exact = V3ManifestRepositoryLimits(
      maximumManifestObjects: observed.listedObjectCount + 1, maximumHistoryDepth: 2)
    _ = try V3RecoveryMergeMutationBuilder(limits: exact).buildAutomatic(
      from: observed, vaultKey: Core.nextKey)
  }

  @Test func aggregateEntryBudgetIncludesTheNewResolutionCiphertext() throws {
    let f = try Fixture()
    defer { f.remove() }
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "first")])
    _ = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "second")])
    let observed = try observation(f)
    let choices = try choose(observed, head: a.envelope.digest)
    let limits = V3ManifestRepositoryLimits(
      maximumManifestObjects: 10, maximumHistoryDepth: 10,
      maximumReferencedEntryObjects: observed.entryObjects.count)
    #expect(throws: V3RecoveryMergeMutationError.resourceLimit) {
      try V3RecoveryMergeMutationBuilder(limits: limits).buildResolution(
        choices, from: observed, vaultKey: Core.nextKey)
    }
  }

  @Test(arguments: [false, true])
  func theMaximumRevisionRefusesResealingButStillPermitsAnExplicitDeletion(delete: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    // A test-only already-trusted floor near the counter bound. No history
    // advancement or production checkpoint mutation is claimed by this seed.
    let secret = try #require(f.entries.values.first { $0.context.name == "fixture/secret" })
    let fields = f.parent.body.fields
    let high = try V3EntryCipher().seal(
      "near maximum",
      context: V3EntryAuthenticationContext(
        vaultID: fields.vaultID, entryID: secret.context.entryID,
        name: secret.context.name, type: .secret, keyID: fields.keyID,
        revision: v3MaximumSafeInteger - 1),
      vaultKey: Core.nextKey)
    let body = try V3RecoveryManifestBody(
      fields: V3DeviceWrappedManifestFields(
        vaultID: fields.vaultID, keyID: fields.keyID,
        authorityTransitionID: fields.authorityTransitionID, devices: fields.devices,
        wrappedKeys: fields.wrappedKeys,
        entries: fields.entries.map {
          $0.entryID == secret.context.entryID
            ? V3ResealedEntry(encryptedEntry: high).manifestEntry : $0
        }),
      epochSigningKey: f.parent.body.epochSigningKey,
      transitionProof: f.parent.body.transitionProof,
      recovery: f.parent.body.recovery)
    let envelope = try V3RecoveryEpochBoundary().encode(
      body: body, parents: [f.parent.digest], vaultKey: Core.nextKey, authorizations: [])
    try f.seed(envelope, entries: [high])
    let floor = V3RecoveryContentCommit(
      checkpoint: try V3ManifestCheckpoint(vaultID: Core.vaultID, envelopeDigest: envelope.digest),
      envelope: envelope)
    var entries = f.entries.filter { $0.key.entryID != secret.context.entryID }
    entries[
      try V3RecoveryMergeMutationValidator.address(
        V3ResealedEntry(encryptedEntry: high).manifestEntry)] = high
    let a = try branches.publishBranch(
      f, requests: [.edit(name: "fixture/secret", type: .secret, plaintext: "maximum")],
      from: floor, entries: entries)
    let b = try branches.publishBranch(
      f, requests: [.remove(name: "fixture/secret")], from: floor, entries: entries)
    let observed = try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: floor, vaultKey: Core.nextKey)
    let choices = try choose(observed, head: delete ? b.envelope.digest : a.envelope.digest)
    if delete {
      let candidate = try V3RecoveryMergeMutationBuilder().buildResolution(
        choices, from: observed, vaultKey: Core.nextKey)
      _ = try validate(candidate, observed: observed)
      #expect(
        candidate.stagedEntries.isEmpty
          && candidate.envelope.body.fields.entries.map(\.name) == ["fixture/totp"])
    } else {
      #expect(throws: V3EntryResealingError.revisionOverflow) {
        try V3RecoveryMergeMutationBuilder().buildResolution(
          choices, from: observed, vaultKey: Core.nextKey)
      }
    }
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes && f.ownership.value == nil)
  }

  private func observation(_ f: Fixture) throws -> V3RecoverySameEpochObservation {
    try V3RecoverySameEpochRepositoryObserver(source: f.store).observe(
      from: .init(checkpoint: f.checkpoint, envelope: f.parent), vaultKey: Core.nextKey)
  }
  private func validate(
    _ candidate: V3RecoveryMergeMutationCandidate, observed: V3RecoverySameEpochObservation
  ) throws
    -> [V3EntryObjectKey: V3EncryptedEntry]
  {
    try V3RecoveryMergeMutationValidator().validate(
      candidate, observed: observed, vaultKey: Core.nextKey)
  }
  private func conflictSnapshot(_ observed: V3RecoverySameEpochObservation) throws
    -> V3VaultUXSnapshot
  {
    guard
      case .contentConflict(let report) = try V3RecoveryManifestReconciler().reconcile(observed),
      let floor = observed.envelopes[observed.checkpoint.envelopeDigest]
    else { throw Publication.Stop.interrupted }
    return V3ConflictObservationBuilder().build(
      report, entries: .lastTrusted(floor.body.fields.entries.count),
      trustedVersionID: nil, trustedHeadDigest: observed.checkpoint.envelopeDigest,
      trustedEntries: Set(floor.body.fields.entries))
  }
  private func choose(_ observed: V3RecoverySameEpochObservation, head: Data) throws
    -> [VaultConflictResolution]
  {
    let snapshot = try conflictSnapshot(observed)
    return try snapshot.conflicts.map { detail in
      let version = try #require(detail.versions.first { v3LowercaseHex(head).hasPrefix($0.id) })
      return VaultConflictResolution(conflictID: detail.summary.id, versionID: version.id)
    }
  }
  private func requirePreservedAuthority(_ candidate: V3RecoveryMergeMutationCandidate, f: Fixture)
    throws
  {
    let a = candidate.envelope.body
    let b = f.parent.body
    #expect(
      a.fields.keyID == b.fields.keyID
        && a.fields.authorityTransitionID == b.fields.authorityTransitionID)
    #expect(a.fields.devices == b.fields.devices && a.fields.wrappedKeys == b.fields.wrappedKeys)
    #expect(
      a.epochSigningKey == b.epochSigningKey && a.transitionProof == b.transitionProof
        && a.recovery == b.recovery)
    #expect(f.checkpoints.value == f.checkpoint.canonicalBytes)
    #expect(f.ownership.value == nil && f.registration.value == nil && f.adoption.value == nil)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0)
  }
}
