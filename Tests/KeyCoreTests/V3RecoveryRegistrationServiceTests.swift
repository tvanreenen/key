import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Real contained filesystem, codecs, mutation owner, reader, agreement adapter
/// and publication. Only device-local storage and native card/provider calls are
/// scripted; no hardware, user vault or installed helper is used.
struct V3RecoveryRegistrationServiceTests {
  private typealias Core = V3RecoveryRegistrationTests

  @Test func statusAuthenticatesAnUnregisteredCheckpointWithoutTokenOrPrivateOperations() throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(try f.status() == .unregistered(checkpoint: f.core.checkpoint))
    #expect(f.card.publicSessions == 0 && f.provider.requests == 0)
    #expect(f.core.owner.signatures == 0 && f.core.owner.unwraps == 0)
    #expect(f.ownership.value == nil && f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func statusPreservesPendingPreparationBeforeAndAfterExternalWrite() throws {
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let bytes = try Data(contentsOf: f.bundleURL(export.operationID))
    let ownership = f.ownership.value
    let sessions = f.card.publicSessions
    let expected = V3RecoveryRegistrationStatus.pending(
      checkpoint: f.core.checkpoint, activationCommitted: false)
    #expect(try f.status() == expected)
    f.card.anchor = export.anchor
    #expect(try f.status() == expected)
    #expect(f.card.publicSessions == sessions && f.provider.requests == 0)
    #expect(f.core.owner.unwraps == 0 && f.core.owner.signatures == 1)
    #expect(f.ownership.value == ownership)
    #expect(try Data(contentsOf: f.bundleURL(export.operationID)) == bytes)
  }

  @Test(arguments: [
    V3RecoveryRegistrationServicePhase.manifestPublished, .checkpointAdvanced, .ownershipCleared,
  ])
  func statusDistinguishesPublicationCommitAndCompletedRegistration(
    phase: V3RecoveryRegistrationServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    let keys = Keys()
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish(observer: Observer { if $0 == phase { throw Core.FixtureError.cancelled } }) {
        _, key in keys.append(key)
      }
    }
    let committed = phase != .manifestPublished
    let checkpoint = try V3ManifestCheckpoint(
      vaultID: Core.vaultID,
      envelopeDigest: committed ? pending.candidate.digest : f.core.parent.digest)
    // Read the exact software identity wrapper only to obtain the committed key
    // for this fixture. The status service itself cannot perform this operation.
    let key =
      try committed
      ? f.core.owner.unwrapDeviceWrappedVaultKey(
        #require(pending.candidate.body.fields.wrappedKeys.first).wrappedKey,
        context: pending.candidate.body.deviceContext(
          recipientDeviceID: f.core.owner.publicIdentity.deviceID),
        reason: "Software status fixture")
      : Core.oldKey
    let unwraps = f.core.owner.unwraps
    let sessions = f.card.publicSessions
    let ownership = f.ownership.value
    // Registration status remains about stored authority, not token presence.
    f.card.anchor = nil
    let expected: V3RecoveryRegistrationStatus =
      phase == .ownershipCleared
      ? .registered(checkpoint: checkpoint, recipients: [pending.intent.anchor.recipientID])
      : .pending(checkpoint: checkpoint, activationCommitted: committed)
    #expect(try f.status(key: key) == expected)
    #expect(try f.status(key: Data(repeating: 8, count: 32)) == .attentionRequired)
    #expect(f.core.owner.unwraps == unwraps && f.card.publicSessions == sessions)
    #expect(f.provider.requests == 1 && f.ownership.value == ownership)
  }

  @Test(arguments: 0..<8)
  func statusInspectionFailuresRequireAttentionWithoutClearingOwnership(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    var key = Core.oldKey
    switch variant {
    case 0: f.checkpoints.value = nil
    case 1: f.checkpoints.value = Data("invalid checkpoint".utf8)
    case 2: key = Data(repeating: 7, count: 32)
    case 3: f.ownership.rejectRead = true
    case 4:
      try f.ownership.replaceRecoveryAnchor(
        Data("invalid ownership".utf8), expectedAnchor: nil, vaultID: Core.vaultID)
    case 5:
      let export = try f.prepare()
      try FileManager.default.removeItem(at: f.bundleURL(export.operationID))
    case 6:
      let export = try f.prepare()
      try Data("invalid bundle".utf8).write(to: f.bundleURL(export.operationID))
    default:
      try FileManager.default.removeItem(at: f.entryURL(#require(f.core.entries.values.first)))
    }
    let pin = f.ownership.value
    let sessions = f.card.publicSessions
    #expect(try f.status(key: key) == .attentionRequired)
    #expect(f.ownership.value == pin && f.card.publicSessions == sessions)
    #expect(f.provider.requests == 0 && f.core.owner.unwraps == 0)
  }

  @Test(arguments: [false, true])
  func statusNeverTreatsOtherPendingMutationsOrUnavailableStoresAsAbsence(adoption: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let store = adoption ? f.adoption : f.transactions
    try store.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    #expect(try f.status() == .attentionRequired)
    try store.replaceRecoveryAnchor(nil, expectedAnchor: Data([1]), vaultID: Core.vaultID)
    store.rejectRead = true
    #expect(try f.status() == .attentionRequired)
    #expect(f.ownership.value == nil && f.card.publicSessions == 0)
  }

  @Test func statusCannotAdoptAnUnownedProviderBundle() throws {
    let f = try Fixture()
    defer { f.remove() }
    let preparation = try f.core.prepare()
    let bundle = try V3RecoveryRegistrationBundle(preparation: preparation)
    try f.store.persistRegistrationBundle(
      bundle.canonicalBytes, operationID: preparation.intent.operationID)
    #expect(try f.status() == .unregistered(checkpoint: f.core.checkpoint))
    #expect(f.ownership.value == nil && f.provider.requests == 0)
  }

  @Test func statusAuthenticatesPendingIntentRatherThanOnlyParsingItsLocalPin() throws {
    let f = try Fixture()
    defer { f.remove() }
    let original = try f.core.prepare()
    let old = original.intent
    let intent = try V3RecoveryRegistrationIntent(
      operationID: old.operationID, expectedCheckpoint: old.expectedCheckpoint,
      ownerDeviceID: old.ownerDeviceID, publicKey: old.publicKey, anchor: old.anchor,
      stagedEntries: old.stagedEntries, currentVaultKey: Data(repeating: 9, count: 32))
    let preparation = V3RecoveryRegistrationPreparation(
      intent: intent, candidate: original.candidate, stagedEntries: original.stagedEntries)
    let bundle = try V3RecoveryRegistrationBundle(preparation: preparation)
    try f.store.persistRegistrationBundle(bundle.canonicalBytes, operationID: intent.operationID)
    let ownership = try V3ImmutableTransactionRecoveryAnchor(
      operationID: intent.operationID, vaultID: Core.vaultID,
      intentDigest: Data(SHA256.hash(data: intent.canonicalBytes)), phase: .recoverable)
    try f.ownership.replaceRecoveryAnchor(
      ownership.canonicalBytes, expectedAnchor: nil, vaultID: Core.vaultID)
    #expect(try f.pending() == preparation)
    #expect(try f.status() == .attentionRequired)
    #expect(f.ownership.value == ownership.canonicalBytes)
    #expect(f.core.owner.unwraps == 0 && f.card.publicSessions == 0)
  }

  @Test(arguments: 0..<4)
  func statusRejectsChangesDuringInspection(variant: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let export = try variant == 3 ? f.prepare() : nil
    let sessions = f.card.publicSessions
    let source = StatusSource(store: f.store) { count in
      guard count == (variant == 3 ? 2 : 1) else { return }
      switch variant {
      case 0: f.checkpoints.value = nil
      case 1:
        try f.ownership.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
      case 2:
        try FileManager.default.removeItem(at: f.entryURL(#require(f.core.entries.values.first)))
      default:
        try Data("changed pending bundle".utf8).write(
          to: f.bundleURL(#require(export).operationID))
      }
    }
    #expect(try f.status(source: source) == .attentionRequired)
    #expect(f.provider.requests == 0 && f.card.publicSessions == sessions)
    #expect(source.writes == 0)
  }

  @Test func statusRechecksTheExactSnapshotAndNeverWrites() throws {
    let f = try Fixture()
    defer { f.remove() }
    let source = StatusSource(store: f.store) { _ in }
    #expect(try f.status(source: source) == .unregistered(checkpoint: f.core.checkpoint))
    #expect(source.listings == 2 && source.writes == 0)
  }

  @Test func prepareExportsOneDurableCandidateWithoutActivatingOrAgreeing() throws {
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let pending = try #require(try f.pending())
    #expect(export.anchor == pending.exportedAnchor)
    #expect(export.operationID == pending.intent.operationID)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 0 && f.core.owner.unwraps == 0)
    #expect(f.core.owner.signatures == 1)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
    #expect(
      try f.service().resumeExport(observation: f.observation(), currentVaultKey: Core.oldKey)
        == export)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 1)
    #expect(f.provider.requests == 0)
  }

  @Test func finishPublishesEntriesFirstManifestLastAndInstallsTheExactKey() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let pending = try #require(try f.pending())
    f.card.anchor = export.anchor
    let observer = Observer { phase in
      if phase == .entriesVerified {
        #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
        #expect(
          !FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
        for entry in pending.stagedEntries {
          let published = try f.published(entry)
          #expect(published == entry.canonicalBytes)
        }
      }
      if phase == .manifestVerified {
        #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
        let published = try Data(contentsOf: f.manifestURL(pending.candidate.digest))
        #expect(published == pending.candidate.canonicalBytes)
      }
    }
    let keys = Keys()
    let result = try f.finish(observer: observer) { checkpoint, key in
      #expect(f.checkpoints.value == checkpoint.canonicalBytes)
      keys.append(key)
      try V3RecoveryEpochBoundary().verifyCurrentAuthentication(pending.candidate, vaultKey: key)
    }
    #expect(!result.alreadyActivated && !result.cleanupPending)
    #expect(result.checkpoint.envelopeDigest == pending.candidate.digest)
    #expect(f.provider.requests == 1 && f.core.owner.unwraps == 1)
    #expect(keys.count == 1 && f.ownership.value == nil)
    #expect(FileManager.default.fileExists(atPath: f.bundleURL(pending.intent.operationID).path))
  }

  @Test(arguments: [
    V3RecoveryRegistrationServicePhase.possessionVerified, .artifactsStaged,
    .entryPublished(index: 0), .entriesVerified, .manifestPublished, .manifestVerified,
    .checkpointAdvanced, .localSessionUpdated,
  ])
  func interruptionResumesExactCandidateWithoutRepeatingCommittedPublication(
    phase: V3RecoveryRegistrationServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let pending = try #require(try f.pending())
    let bundle = try Data(contentsOf: f.bundleURL(pending.intent.operationID))
    f.card.anchor = export.anchor
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish(observer: Observer { if $0 == phase { throw Core.FixtureError.cancelled } })
    }
    #expect(try Data(contentsOf: f.bundleURL(pending.intent.operationID)) == bundle)
    #expect(f.ownership.value != nil)
    let committed = phase == .checkpointAdvanced || phase == .localSessionUpdated
    let result = try f.finish()
    #expect(result.alreadyActivated == committed)
    #expect(result.checkpoint.envelopeDigest == pending.candidate.digest)
    #expect(f.provider.requests == (committed ? 1 : 2))
    #expect(f.core.owner.signatures == 1)
    #expect(f.ownership.value == nil)
  }

  @Test(arguments: [V3RecoveryRegistrationServicePhase.candidatePrepared, .exportPrepared])
  func preparationInterruptionCannotReturnAnExportOrRegeneratePendingState(
    phase: V3RecoveryRegistrationServicePhase
  ) throws {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: Core.FixtureError.cancelled) {
      try f.prepare(observer: Observer { if $0 == phase { throw Core.FixtureError.cancelled } })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 0)
    if phase == .exportPrepared {
      let pending = try #require(try f.pending())
      let result = try f.service().resumeExport(
        observation: f.observation(), currentVaultKey: Core.oldKey)
      #expect(result.anchor == pending.exportedAnchor)
      #expect(f.core.owner.signatures == 1)
    } else {
      #expect(f.ownership.value == nil)
    }
  }

  @Test func lostReplyAfterOwnershipCleanupIsRecognizedWithoutAnotherAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish(
        observer: Observer {
          if $0 == .ownershipCleared { throw Core.FixtureError.cancelled }
        })
    }
    #expect(f.ownership.value == nil && f.provider.requests == 1)
    let result = try f.finish()
    #expect(result.alreadyActivated && !result.cleanupPending)
    #expect(f.provider.requests == 1 && f.core.owner.signatures == 1)
    f.card.anchor = nil
    let unwraps = f.core.owner.unwraps
    #expect(throws: V3RecoveryRegistrationServiceError.noPendingRegistration) { try f.finish() }
    #expect(f.core.owner.unwraps == unwraps && f.provider.requests == 1)
  }

  @Test func checkpointAdvanceFailureRetainsPublishedCandidateAndRequiresFreshPossession() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    f.checkpoints.rejectAdvance = true
    #expect(throws: Core.FixtureError.cancelled) { try f.finish() }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
    #expect(f.ownership.value != nil)
    f.checkpoints.rejectAdvance = false
    #expect(try !f.finish().alreadyActivated)
    #expect(f.provider.requests == 2 && f.core.owner.signatures == 1)
  }

  @Test func failedSessionInstallReconcilesCommittedCheckpointWithoutHardware() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    #expect(throws: Core.FixtureError.cancelled) {
      try f.finish { _, _ in throw Core.FixtureError.cancelled }
    }
    #expect(f.checkpoints.value != f.core.checkpoint.canonicalBytes)
    #expect(f.ownership.value != nil)
    let result = try f.finish()
    #expect(result.alreadyActivated && result.checkpoint.envelopeDigest == pending.candidate.digest)
    #expect(f.provider.requests == 1 && f.core.owner.unwraps == 2)
    #expect(f.ownership.value == nil)
  }

  @Test func cleanupFailureIsReportedAsCommittedNotAsUnpublished() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    f.ownership.rejectClear = true
    let result = try f.finish()
    #expect(!result.alreadyActivated && result.cleanupPending)
    #expect(f.ownership.value != nil)
    f.ownership.rejectClear = false
    let resumed = try f.finish()
    #expect(resumed.alreadyActivated && !resumed.cleanupPending)
    #expect(f.provider.requests == 1)
  }

  @Test func missingMismatchedOrWeakerTokenIsRefusedBeforeLocalAndHardwareOperations() throws {
    guard #available(macOS 26.0, *) else { return }
    for variant in 0..<3 {
      let f = try Fixture()
      defer { f.remove() }
      let export = try f.prepare()
      if variant == 1 { f.card.anchor = Data("unrecognized fixture".utf8) }
      if variant == 2 {
        f.card.anchor = export.anchor
        f.card.pinPolicy = 2
      }
      #expect(throws: (any Error).self) { try f.finish() }
      #expect(f.provider.requests == 0 && f.core.owner.unwraps == 0)
      #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes && f.ownership.value != nil)
    }
  }

  @Test func providerCancellationNeverRetriesOrPublishes() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    f.provider.cancel = true
    #expect(throws: PIVRecoveryAgreementError.cancelled) { try f.finish() }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
  }

  @Test func priorCancellationAndDeadlineStopBeforeLocalApproval() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let cancellation = PIVRecoveryCancellation()
    cancellation.cancel()
    #expect(throws: PIVRecoveryAgreementError.cancelled) {
      try f.service().finish(
        observation: f.observation(), currentVaultKey: Core.oldKey, cancellation: cancellation)
    }
    #expect(throws: PIVRecoveryAgreementError.deadlineExceeded) {
      try f.service().finish(
        observation: f.observation(), currentVaultKey: Core.oldKey, deadline: .now() - .seconds(1))
    }
    #expect(f.core.owner.unwraps == 0 && f.provider.requests == 0)
  }

  @Test func changedSourceAfterLocalApprovalIsDetectedBeforeAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let oldEntry = try #require(f.core.entries.values.first)
    f.core.owner.onUnwrap = {
      try Data("changed fixture bytes".utf8).write(to: f.entryURL(oldEntry))
    }
    #expect(throws: (any Error).self) { try f.finish() }
    #expect(f.core.owner.unwraps == 1 && f.provider.requests == 0)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func tokenChangeDuringAgreementDiscardsTheResultWithoutPublication() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    f.provider.onAgree = { f.card.anchor = Data("changed fixture anchor".utf8) }
    #expect(throws: PIVRecoveryTokenError.tokenChanged) { try f.finish() }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func changedCheckpointOrCompetingStateIsNeverSilentlyRebased() throws {
    guard #available(macOS 26.0, *) else { return }
    for checkpointOnly in [true, false] {
      let f = try Fixture()
      defer { f.remove() }
      f.card.anchor = try f.prepare().anchor
      let other = try f.core.prepare()
      try f.publish(other.candidate.canonicalBytes, digest: other.candidate.digest)
      if checkpointOnly {
        f.checkpoints.value = try V3ManifestCheckpoint(
          vaultID: Core.vaultID, envelopeDigest: other.candidate.digest
        ).canonicalBytes
      }
      #expect(throws: (any Error).self) { try f.finish() }
      #expect(f.core.owner.unwraps == 0 && f.provider.requests == 0)
      #expect(f.ownership.value != nil)
    }
  }

  @Test func checkpointChangeAfterPossessionCannotAdvanceThePreparedCandidate() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let changed = try V3ManifestCheckpoint(
      vaultID: Core.vaultID, envelopeDigest: Data(repeating: 5, count: 32))
    #expect(throws: V3RecoveryRegistrationServiceError.checkpointChanged) {
      try f.finish(
        observer: Observer {
          if $0 == .possessionVerified { f.checkpoints.value = changed.canonicalBytes }
        })
    }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(f.checkpoints.value == changed.canonicalBytes)
  }

  @Test func corruptPublishedEntryCannotBecomeTheCurrentManifest() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let pending = try #require(try f.pending())
    let entry = try #require(pending.stagedEntries.first)
    #expect(throws: V3RecoveryRegistrationServiceError.invalidPublishedObject) {
      try f.finish(
        observer: Observer {
          if $0 == .entriesVerified {
            try Data("changed fixture".utf8).write(to: f.entryURL(entry))
          }
        })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.ownership.value != nil)
    #expect(!FileManager.default.fileExists(atPath: f.manifestURL(pending.candidate.digest).path))
  }

  @Test func competingManifestAfterPublicationCannotAdvanceLocalTrust() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let other = try f.core.prepare()
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try f.finish(
        observer: Observer {
          if $0 == .manifestPublished {
            try f.publish(other.candidate.canonicalBytes, digest: other.candidate.digest)
          }
        })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
  }

  @Test func prepareRefusesWrongKeyOccupiedObjectAndProjectedLimits() throws {
    for variant in 0..<3 {
      let f = try Fixture()
      defer { f.remove() }
      if variant == 1 { f.card.anchor = Data("occupied fixture".utf8) }
      let service = f.service(limits: variant == 2 ? Core.Fixture.limits(entries: 2) : .standard)
      #expect(throws: (any Error).self) {
        try service.prepare(
          observation: f.observation(), currentVaultKey: variant == 0 ? Core.nextKey : Core.oldKey)
      }
      #expect(f.ownership.value == nil && f.provider.requests == 0)
      #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    }
  }

  @Test func serviceUsesTheSharedMutationOwnerAndStablePreparationID() throws {
    let f = try Fixture()
    defer { f.remove() }
    let fixed = VaultTransactionOperationID()
    let owner = VaultTransactionMutationOwner(makeOperationID: { fixed })
    let result = try f.service(mutationOwner: owner).prepare(
      observation: f.observation(), currentVaultKey: Core.oldKey)
    #expect(result.operationID == fixed)
    #expect(try f.pending()?.intent.operationID == fixed)
  }

  @Test(arguments: [false, true])
  func competingPendingWorkBlocksPrepareBeforeSigning(adoption: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    let barrier = adoption ? f.adoption : f.transactions
    try barrier.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) { try f.prepare() }
    #expect(f.core.owner.signatures == 0 && f.core.owner.unwraps == 0 && f.provider.requests == 0)
    #expect(f.ownership.value == nil && barrier.value == Data([1]))
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test(arguments: [false, true])
  func competingWorkBlocksExportResumeAndFinishWithoutChangingPreparation(adoption: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let export = try f.prepare()
    let preparation = try #require(try f.pending())
    let pin = f.ownership.value
    let barrier = adoption ? f.adoption : f.transactions
    try barrier.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) {
      try f.service().resumeExport(observation: f.observation(), currentVaultKey: Core.oldKey)
    }
    f.card.anchor = export.anchor
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) { try f.finish() }
    #expect(try f.pending() == preparation && f.ownership.value == pin)
    #expect(f.core.owner.signatures == 1 && f.core.owner.unwraps == 0 && f.provider.requests == 0)
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    try barrier.replaceRecoveryAnchor(nil, expectedAnchor: Data([1]), vaultID: Core.vaultID)
    #expect(try f.finish().checkpoint.envelopeDigest == preparation.candidate.digest)
    #expect(f.provider.requests == 1 && f.ownership.value == nil)
  }

  @Test(arguments: [V3RecoveryRegistrationServicePhase.candidatePrepared, .exportPrepared])
  func competingWorkDuringPreparationCannotReturnAnExport(phase: V3RecoveryRegistrationServicePhase)
    throws
  {
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) {
      try f.prepare(
        observer: Observer {
          if $0 == phase {
            try f.transactions.replaceRecoveryAnchor(
              Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
          }
        })
    }
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes && f.provider.requests == 0)
    #expect((f.ownership.value != nil) == (phase == .exportPrepared))
  }

  @Test(arguments: [false, true])
  func competingWorkDuringLocalApprovalStopsBeforeAgreement(adoption: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let barrier = adoption ? f.adoption : f.transactions
    f.core.owner.onUnwrap = {
      try barrier.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    }
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) { try f.finish() }
    #expect(f.core.owner.unwraps == 1 && f.provider.requests == 0)
    #expect(f.ownership.value != nil && f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func competingWorkDuringAgreementDiscardsResultAndRequiresExplicitFreshPossession() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let preparation = try #require(try f.pending())
    f.provider.onAgree = {
      try f.transactions.replaceRecoveryAnchor(
        Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    }
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) { try f.finish() }
    #expect(f.provider.requests == 1 && f.ownership.value != nil)
    #expect(
      !FileManager.default.fileExists(atPath: f.manifestURL(preparation.candidate.digest).path))
    #expect(f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    try f.transactions.replaceRecoveryAnchor(nil, expectedAnchor: Data([1]), vaultID: Core.vaultID)
    f.provider.onAgree = {}
    #expect(try !f.finish().alreadyActivated)
    #expect(f.provider.requests == 2 && f.core.owner.signatures == 1)
  }

  @Test(arguments: [
    V3RecoveryRegistrationServicePhase.artifactsStaged, .entriesVerified, .manifestVerified,
    .checkpointAdvanced, .localSessionUpdated,
  ])
  func lateCompetingWorkRetainsExactRegistrationAndStopsRemainingEffects(
    phase: V3RecoveryRegistrationServicePhase
  ) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    let preparation = try #require(try f.pending())
    let installed = Keys()
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) {
      try f.finish(
        observer: Observer {
          if $0 == phase {
            try f.adoption.replaceRecoveryAnchor(
              Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
          }
        }
      ) { _, key in installed.append(key) }
    }
    let committed = phase == .checkpointAdvanced || phase == .localSessionUpdated
    #expect((f.checkpoints.value != f.core.checkpoint.canonicalBytes) == committed)
    #expect(installed.count == (phase == .localSessionUpdated ? 1 : 0))
    #expect(try f.pending() == preparation && f.ownership.value != nil)
    try f.adoption.replaceRecoveryAnchor(nil, expectedAnchor: Data([1]), vaultID: Core.vaultID)
    #expect(try f.finish().alreadyActivated == committed)
    #expect(f.provider.requests == (committed ? 1 : 2))
    #expect(f.ownership.value == nil && f.core.owner.signatures == 1)
  }

  @Test(arguments: [false, true])
  func competingWorkBlocksCommittedRepairAndLostReplyRecognition(cleaned: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    f.card.anchor = try f.prepare().anchor
    if cleaned {
      _ = try f.finish()
    } else {
      #expect(throws: Core.FixtureError.cancelled) {
        try f.finish(
          observer: Observer { if $0 == .checkpointAdvanced { throw Core.FixtureError.cancelled } })
      }
    }
    let checkpoint = f.checkpoints.value
    let pin = f.ownership.value
    let unwraps = f.core.owner.unwraps
    try f.transactions.replaceRecoveryAnchor(Data([1]), expectedAnchor: nil, vaultID: Core.vaultID)
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) { try f.finish() }
    #expect(f.provider.requests == 1 && f.core.owner.unwraps == unwraps)
    #expect(f.checkpoints.value == checkpoint && f.ownership.value == pin)
  }

  @Test(arguments: [false, true])
  func unreadableCompetingOwnershipDoesNotMeanNoPendingWork(adoption: Bool) throws {
    let f = try Fixture()
    defer { f.remove() }
    (adoption ? f.adoption : f.transactions).rejectRead = true
    #expect(throws: Core.FixtureError.cancelled) { try f.prepare() }
    #expect(f.core.owner.signatures == 0 && f.core.owner.unwraps == 0 && f.provider.requests == 0)
    #expect(f.ownership.value == nil && f.checkpoints.value == f.core.checkpoint.canonicalBytes)
  }

  @Test func registrationAndOrdinarySavesShareTheSamePendingNamespacesAndSession() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let cache = V3CheckpointManifestFilesystemCache(
      rootHandle: try VaultRootDirectoryHandle(opening: f.root))
    let session = V3DeviceWrappedVaultKeySessionStore()
    try session.install(Core.oldKey, vaultID: Core.vaultID, keyID: f.core.parent.body.fields.keyID)
    let ordinary = V3RecoveryVaultMutationService(
      vaultID: Core.vaultID, session: session, objectStore: f.store,
      checkpointStore: f.checkpoints, recoveryAnchorStore: f.transactions,
      registrationAnchorStore: f.ownership, adoptionAnchorStore: f.adoption, cache: cache)
    f.card.anchor = try f.prepare().anchor
    #expect(throws: VaultUXServiceError.vaultIncomplete) {
      try f.mutationOwner.perform(.editEntry) { context in
        try ordinary.edit(
          name: "fixture/secret", secret: "not saved", type: .secret,
          operationID: context.operationID)
      }
    }
    let commit = try f.finish { checkpoint, key in
      let envelope = try V3RecoveryManifestCodec().parseEnvelope(
        Data(contentsOf: f.manifestURL(checkpoint.envelopeDigest)))
      try session.install(key, vaultID: Core.vaultID, keyID: envelope.body.fields.keyID)
    }
    try f.mutationOwner.perform(.editEntry) { context in
      try ordinary.edit(
        name: "fixture/secret", secret: "saved after registration", type: .secret,
        operationID: context.operationID)
    }
    #expect(try f.pending() == nil)
    let anchorBytes = try #require(f.card.anchor)
    let anchor = try V3RecoveryAnchorCodec().parseCanonical(anchorBytes)
    let selected = try V3RecoveryHistorySelector(source: f.store).select(
      anchor: anchor, credentialPublicKey: f.core.token.publicKey.x963Representation)
    let receiver = try PIVHPKEReceiver(publicBytes: f.core.token.publicKey.x963Representation) {
      peer in
      try f.core.token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      )
      .withUnsafeBytes { Data($0) }
    }
    let opened = try V3RecoverySnapshotVerifier(source: f.store).open(
      selected, boundAnchor: anchor, receiver: receiver)
    #expect(selected.head.parents == [commit.checkpoint.envelopeDigest])
    #expect(
      opened.entries.first { $0.name == "fixture/secret" }?.plaintext == "saved after registration")
    #expect(f.provider.requests == 1 && f.core.owner.signatures == 1 && f.transactions.value == nil)
  }

  @Test func aRealPinnedOrdinarySaveBlocksRegistrationUntilItsOwnerResumes() throws {
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try V3RecoveryContentMutationBuilder().build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "ordinary pending"),
      checkpoint: f.core.checkpoint, parent: f.core.parent, currentEntries: f.core.entries,
      vaultKey: Core.oldKey)
    let publisher = V3RecoveryContentMutationPublisher(
      mutationOwner: f.mutationOwner, objectStore: f.store, checkpointStore: f.checkpoints,
      recoveryAnchorStore: f.transactions, registrationAnchorStore: f.ownership,
      adoptionAnchorStore: f.adoption,
      cache: V3CheckpointManifestFilesystemCache(
        rootHandle: try VaultRootDirectoryHandle(opening: f.root)),
      phaseObserver: ContentInterrupt())
    #expect(throws: Core.FixtureError.cancelled) {
      try publisher.publish(candidate, vaultKey: Core.oldKey)
    }
    let pin = f.transactions.value
    #expect(throws: V3RecoveryRegistrationServiceError.otherMutationPending) { try f.prepare() }
    #expect(f.transactions.value == pin && f.ownership.value == nil && f.core.owner.signatures == 0)
    _ = try publisher.recoverInterruptedTransaction(vaultID: Core.vaultID, vaultKey: Core.oldKey)
    #expect(f.transactions.value == nil)
    _ = try f.prepare()
    #expect(try f.pending()?.intent.expectedCheckpoint.envelopeDigest == candidate.envelope.digest)
    #expect(f.core.owner.signatures == 1 && f.provider.requests == 0)
  }

  private struct ContentInterrupt: V3ImmutableTransactionPhaseObserving {
    func didReach(_ phase: V3ImmutableTransactionPhase, operationID _: VaultTransactionOperationID)
      throws
    {
      if phase == .manifestStaged { throw Core.FixtureError.cancelled }
    }
  }

  private final class StatusSource:
    V3ImmutableObjectReading, V3RecoveryRegistrationBundleStoring, @unchecked Sendable
  {
    let store: V3FilesystemTransactionArtifactStore
    let onListing: @Sendable (Int) throws -> Void
    private let lock = NSLock()
    private var count = 0
    private var writeCount = 0
    var listings: Int { lock.withLock { count } }
    var writes: Int { lock.withLock { writeCount } }
    init(
      store: V3FilesystemTransactionArtifactStore,
      onListing: @escaping @Sendable (Int) throws -> Void
    ) {
      self.store = store
      self.onListing = onListing
    }
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      let result = try store.manifestDigests(maximumCount: maximumCount)
      let current = lock.withLock {
        count += 1
        return count
      }
      try onListing(current)
      return result
    }
    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try store.readManifest(digest: digest, maximumBytes: maximumBytes)
    }
    func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try store.readEntry(entryID: entryID, digest: digest, maximumBytes: maximumBytes)
    }
    func readRegistrationBundle(operationID: VaultTransactionOperationID, maximumBytes: Int) throws
      -> V3RepositoryObjectRead
    {
      try store.readRegistrationBundle(operationID: operationID, maximumBytes: maximumBytes)
    }
    func persistRegistrationBundle(_: Data, operationID _: VaultTransactionOperationID) throws {
      lock.withLock { writeCount += 1 }
      throw Core.FixtureError.cancelled
    }
    func confirmRegistrationBundle(_: Data, operationID _: VaultTransactionOperationID) throws {
      lock.withLock { writeCount += 1 }
      throw Core.FixtureError.cancelled
    }
  }

  private struct Observer: V3RecoveryRegistrationServicePhaseObserving {
    let action: @Sendable (V3RecoveryRegistrationServicePhase) throws -> Void
    init(_ action: @escaping @Sendable (V3RecoveryRegistrationServicePhase) throws -> Void) {
      self.action = action
    }
    func didReach(_ phase: V3RecoveryRegistrationServicePhase) throws { try action(phase) }
  }

  private final class Keys: @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [Data] = []
    var count: Int { lock.withLock { keys.count } }
    func append(_ key: Data) { lock.withLock { keys.append(key) } }
  }

  private final class Checkpoints: V3ManifestCheckpointStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    var rejectAdvance = false
    var value: Data? {
      get { lock.withLock { data } }
      set { lock.withLock { data = newValue } }
    }
    init(_ data: Data) { self.data = data }
    func loadCheckpoint(vaultID _: String) throws -> Data? { value }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID _: String) throws
    {
      try lock.withLock {
        if rejectAdvance { throw Core.FixtureError.cancelled }
        guard data == expectedCheckpoint else { throw V3ManifestCheckpointStoreError.conflict }
        data = checkpoint
      }
    }
  }

  private final class Ownership: V3ImmutableTransactionRecoveryAnchorStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    var rejectClear = false
    var rejectRead = false
    var value: Data? { lock.withLock { data } }
    func loadRecoveryAnchor(vaultID _: String) throws -> Data? {
      if rejectRead { throw Core.FixtureError.cancelled }
      return value
    }
    func replaceRecoveryAnchor(_ anchor: Data?, expectedAnchor: Data?, vaultID _: String) throws {
      try lock.withLock {
        if rejectClear && anchor == nil { throw Core.FixtureError.cancelled }
        guard data == expectedAnchor else {
          throw V3ImmutableTransactionRecoveryAnchorError.conflict
        }
        data = anchor
      }
    }
  }

  @Test func configuredWorkflowComposesPrepareExternalImportFinishStatusAndOrdinaryReopen() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let workflow = try workflow(f)
    let selectors = (
      f.card.tokenID,
      try V3RecoveryRecipientID.derive(publicKey: f.core.credential.publicKey).rawValue
    )
    let initial = try workflow.handle(.status, scope: requestScope())
    #expect(
      initial.recoveryRegistration
        == .status(
          state: .unregistered, vaultID: Core.vaultID, recipients: [], activationCommitted: false))
    #expect(f.card.publicSessions == 0 && f.provider.requests == 0)
    let prepared = try workflow.handle(
      .prepare(tokenID: selectors.0, recipientID: selectors.1), scope: requestScope())
    guard case .export(let operation, _, _, let encoded) = prepared.recoveryRegistration,
      let anchor = Base64URL.decodeCanonical(encoded)
    else { throw Core.FixtureError.cancelled }
    let pending = try workflow.handle(.status, scope: requestScope())
    #expect(
      pending.recoveryRegistration
        == .status(
          state: .pending, vaultID: Core.vaultID, recipients: [], activationCommitted: false))
    let resumed = try workflow.handle(
      .resumeExport(tokenID: selectors.0, recipientID: selectors.1), scope: requestScope())
    #expect(resumed.recoveryRegistration == prepared.recoveryRegistration)
    #expect(f.provider.requests == 0)
    f.card.anchor = anchor  // Test-only simulation of the separate vendor import.
    let finished = try workflow.handle(
      .finish(tokenID: selectors.0, recipientID: selectors.1), scope: requestScope())
    guard case .completed(let vaultID, let digest, let cleanup) = finished.recoveryRegistration
    else {
      throw Core.FixtureError.cancelled
    }
    #expect(vaultID == Core.vaultID && !cleanup && f.ownership.value == nil)
    #expect(f.provider.requests == 1)
    #expect(try Data(contentsOf: f.bundleURL(.init(validating: operation))).count > 0)
    let status = try workflow.handle(.status, scope: requestScope())
    #expect(
      status.recoveryRegistration
        == .status(
          state: .registered, vaultID: Core.vaultID, recipients: [selectors.1],
          activationCommitted: false))
    let runtime = V3RecoveryVaultRuntime(
      vaultID: Core.vaultID, objectStore: f.store, checkpointStore: f.checkpoints,
      transactionOwnershipStore: f.transactions, registrationOwnershipStore: f.ownership,
      adoptionOwnershipStore: f.adoption, cache: workflow.cache,
      identityLoader: WorkflowLoader(identity: f.core.owner), session: .init(),
      mutationOwner: f.mutationOwner)
    #expect(
      try runtime.read(name: "fixture/secret", allowStale: false).plaintext
        == "Software fixture secret e\u{301}\r\n")
    #expect(try runtime.status().health == .ready)
    #expect(f.provider.requests == 1)
    #expect(Base64URL.decodeCanonical(digest)?.count == 32)
  }

  @Test(arguments: [false, true])
  func configuredWorkflowCancellationDuringMacOpeningCannotPrepareOrExport(resume: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    if resume { _ = try f.prepare() }
    let before = f.ownership.value
    let scope = requestScope()
    f.core.owner.onUnwrap = { scope.cancellation.cancel() }
    let action: KeyRecoveryRegistrationRequest =
      resume
      ? .resumeExport(
        tokenID: f.card.tokenID,
        recipientID: try V3RecoveryRecipientID.derive(publicKey: f.core.credential.publicKey)
          .rawValue)
      : .prepare(
        tokenID: f.card.tokenID,
        recipientID: try V3RecoveryRecipientID.derive(publicKey: f.core.credential.publicKey)
          .rawValue)
    #expect(throws: (any Error).self) { try workflow(f).handle(action, scope: scope) }
    #expect(f.ownership.value == before && f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 0)
  }

  @Test func configuredWorkflowWrongRecipientCannotCreatePendingWork() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: PIVRecoveryTokenError.anchorCredentialMismatch) {
      try workflow(f).handle(
        .prepare(
          tokenID: f.card.tokenID, recipientID: Base64URL.encode(Data(repeating: 7, count: 32))),
        scope: requestScope())
    }
    #expect(f.ownership.value == nil && f.provider.requests == 0)
  }

  @Test(arguments: [false, true])
  func configuredSelectionChangedDuringOpeningCannotPrepareOrResume(resume: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    if resume { _ = try f.prepare() }
    let before = f.ownership.value
    let changed = PIVRecoveryCancellation()
    let publicSessions = f.card.publicSessions
    f.core.owner.onUnwrap = { changed.cancel() }
    var subject = try workflow(f)
    subject.validateLocation = {
      if changed.isCancelled { throw Core.FixtureError.cancelled }
    }
    let recipient = try V3RecoveryRecipientID.derive(publicKey: f.core.credential.publicKey)
      .rawValue
    let action: KeyRecoveryRegistrationRequest =
      resume
      ? .resumeExport(tokenID: f.card.tokenID, recipientID: recipient)
      : .prepare(tokenID: f.card.tokenID, recipientID: recipient)
    #expect(throws: V3RecoveryVaultUnlockError.recoveryRequired) {
      try subject.handle(action, scope: requestScope())
    }
    #expect(f.ownership.value == before && f.checkpoints.value == f.core.checkpoint.canonicalBytes)
    #expect(f.provider.requests == 0 && f.card.publicSessions == publicSessions)
  }

  @Test(arguments: 0..<3)
  func checkpointProfileDispatchIsBoundToTheExactLocalSelection(invalid: Int) throws {
    let f = try Fixture()
    defer { f.remove() }
    let subject = try workflow(f)
    let selected = try v3SelectedCheckpointProfile(
      vaultID: Core.vaultID, checkpoints: f.checkpoints, source: f.store, cache: subject.cache)
    #expect(selected.checkpoint == f.core.checkpoint)
    guard case .recovery = selected.profile else {
      Issue.record("Recovery fixture dispatched as a different profile")
      return
    }
    if invalid == 0 {
      f.checkpoints.value = nil
    } else if invalid == 1 {
      f.checkpoints.value = Data([0])
    } else {
      try Data("different manifest bytes".utf8).write(to: f.manifestURL(f.core.parent.digest))
    }
    #expect(throws: (any Error).self) {
      try v3SelectedCheckpointProfile(
        vaultID: Core.vaultID, checkpoints: f.checkpoints, source: f.store, cache: subject.cache)
    }
    #expect(f.core.owner.unwraps == 0 && f.provider.requests == 0)
  }

  private func requestScope() -> KeyRecoveryRequestScope {
    .init(authentication: .init(), deadline: .now() + 90)
  }
  private func workflow(_ f: Fixture) throws -> KeyRecoveryRegistrationWorkflow {
    let root = f.root.appendingPathComponent(".test-local-cache", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return .init(
      vaultID: Core.vaultID, store: f.store, checkpoints: f.checkpoints,
      transaction: f.transactions, registration: f.ownership, adoption: f.adoption,
      cache: V3CheckpointManifestFilesystemCache(
        rootHandle: try VaultRootDirectoryHandle(opening: root)),
      identities: WorkflowLoader(identity: f.core.owner), reader: f.reader, agreement: f.agreement,
      owner: f.mutationOwner)
  }
  private struct WorkflowLoader: V3DeviceWrappedIdentityLoading {
    let identity: any V3DeviceWrappedVaultKeyUnwrapping
    func loadDeviceIdentity(vaultID _: String, reason _: String) throws -> (
      any V3DeviceWrappedVaultKeyUnwrapping
    )? { identity }
  }

  private struct Fixture: Sendable {
    let core: Core.Fixture
    let root: URL
    let store: V3FilesystemTransactionArtifactStore
    let checkpoints: Checkpoints
    let ownership = Ownership()
    let transactions = Ownership()
    let adoption = Ownership()
    let mutationOwner = VaultTransactionMutationOwner()
    let card: Card
    let reader: PIVRecoveryTokenReader
    let provider: Provider
    let agreement: PIVRecoveryAgreement
    init() throws {
      core = try Core.Fixture()
      root = FileManager.default.temporaryDirectory.appendingPathComponent(
        UUID().uuidString, isDirectory: true)
      try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
      store = V3FilesystemTransactionArtifactStore(
        rootHandle: try VaultRootDirectoryHandle(opening: root))
      checkpoints = Checkpoints(core.checkpoint.canonicalBytes)
      card = try Card(publicKey: core.credential.publicKey)
      reader = PIVRecoveryTokenReader(
        inventory: Inventory(card: card), gate: PIVTokenOperationGate())
      provider = Provider(token: core.token, card: card)
      agreement = PIVRecoveryAgreement(reader: reader, provider: provider)
      let operation = VaultTransactionOperationID()
      for entry in core.entries.values {
        let digest = Data(SHA256.hash(data: entry.canonicalBytes))
        try store.stageEntry(
          entry.canonicalBytes, entryID: entry.context.entryID, digest: digest,
          operationID: operation)
        try store.publishStagedEntry(
          entry.canonicalBytes, entryID: entry.context.entryID, digest: digest,
          operationID: operation)
      }
      try publish(core.parent.canonicalBytes, digest: core.parent.digest)
    }
    func service(
      observer: (any V3RecoveryRegistrationServicePhaseObserving)? = nil,
      limits: V3ManifestRepositoryLimits = .standard,
      mutationOwner: (any VaultTransactionMutationOwning)? = nil
    ) -> V3RecoveryRegistrationService {
      let observer = observer ?? Observer { _ in }
      return V3RecoveryRegistrationService(
        vaultID: Core.vaultID, identity: core.owner,
        mutationOwner: mutationOwner ?? self.mutationOwner,
        objectStore: store, checkpointStore: checkpoints, registrationOwnershipStore: ownership,
        transactionOwnershipStore: transactions, adoptionOwnershipStore: adoption,
        reader: reader, agreement: agreement, limits: limits, observer: observer)
    }
    func observation() throws -> PIVRecoveryTokenObservation {
      try reader.read(#require(try reader.candidates().first))
    }
    func prepare(observer: (any V3RecoveryRegistrationServicePhaseObserving)? = nil) throws
      -> V3RecoveryRegistrationExport
    {
      try service(observer: observer).prepare(
        observation: observation(), currentVaultKey: Core.oldKey)
    }
    @available(macOS 26.0, *)
    func finish(
      observer: (any V3RecoveryRegistrationServicePhaseObserving)? = nil,
      install: (V3ManifestCheckpoint, Data) throws -> Void = { _, _ in }
    ) throws -> V3RecoveryRegistrationCommit {
      try service(observer: observer).finish(
        observation: observation(), currentVaultKey: Core.oldKey, afterCheckpointAdvance: install)
    }
    func pending() throws -> V3RecoveryRegistrationPreparation? {
      try V3RecoveryRegistrationJournal(bundleStore: store, ownershipStore: ownership).loadPending(
        vaultID: Core.vaultID)
    }
    func status(
      key: Data = Core.oldKey,
      source: (any V3ImmutableObjectReading & V3RecoveryRegistrationBundleStoring)? = nil
    ) throws -> V3RecoveryRegistrationStatus {
      try V3RecoveryRegistrationStatusService(
        vaultID: Core.vaultID, mutationOwner: mutationOwner, source: source ?? store,
        checkpointStore: checkpoints, registrationOwnershipStore: ownership,
        transactionOwnershipStore: transactions, adoptionOwnershipStore: adoption
      ).status(currentVaultKey: key)
    }
    func publish(_ bytes: Data, digest: Data) throws {
      let operation = VaultTransactionOperationID()
      try store.stageManifest(bytes, digest: digest, operationID: operation)
      try store.publishStagedManifest(bytes, digest: digest, operationID: operation)
    }
    func manifestURL(_ digest: Data) -> URL {
      root.appendingPathComponent("manifests/\(v3LowercaseHex(digest)).json")
    }
    func entryURL(_ entry: V3EncryptedEntry) -> URL {
      root.appendingPathComponent(
        "entries/\(entry.context.entryID)/\(v3LowercaseHex(Data(SHA256.hash(data: entry.canonicalBytes)))).json"
      )
    }
    func bundleURL(_ operation: VaultTransactionOperationID) -> URL {
      root.appendingPathComponent(".recovery-registrations/\(operation)/preparation.json")
    }
    func published(_ entry: V3EncryptedEntry) throws -> Data {
      try Data(contentsOf: entryURL(entry))
    }
    func remove() { try? FileManager.default.removeItem(at: root) }
  }

  struct Inventory: PIVRecoveryTokenInventoryProviding {
    let card: Card
    func connections(maximumCount _: Int) throws -> [any PIVRecoveryTokenConnection] { [card] }
  }

  final class Card: PIVRecoveryTokenConnection, @unchecked Sendable {
    let tokenID = "registration-software-token"
    let readerSlotName = "registration-software-reader"
    let isValid = true
    private let lock = NSLock()
    private let certificate: Data
    private let publicKey: Data
    private var record: Data?
    private var pin: UInt8 = 3
    private var active = false
    private var sessions = 0
    var publicSessions: Int { lock.withLock { sessions } }
    var inSession: Bool { lock.withLock { active } }
    var anchor: Data? {
      get { lock.withLock { record } }
      set { lock.withLock { record = newValue } }
    }
    var pinPolicy: UInt8 {
      get { lock.withLock { pin } }
      set { lock.withLock { pin = newValue } }
    }
    init(publicKey: Data) throws {
      self.publicKey = publicKey
      // A public container fixture only. Signature/issuer trust is not claimed.
      var der = PIVRecoveryAgreementTests.certificate
      let point = try PIVRecoveryTokenReader.certificatePublicKey(der)
      let range = try #require(der.range(of: point))
      der.replaceSubrange(range, with: publicKey)
      certificate = der
      #expect(try PIVRecoveryTokenReader.certificatePublicKey(der) == publicKey)
    }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      lock.withLock {
        active = true
        sessions += 1
      }
      defer {
        lock.withLock { active = false }
        withExtendedLifetime(lease) {}
      }
      return try consume { command in
        switch command {
        case .selectApplication: return .init(data: nil, status: 0x9000)
        case .keyManagementCertificate:
          return .init(
            data: Self.tlv(0x53, Self.tlv(0x70, self.certificate) + Self.tlv(0x71, Data([0]))),
            status: 0x9000)
        case .keyManagementMetadata:
          return .init(
            data: Self.tlv(1, Data([0x11])) + Self.tlv(2, Data([self.pinPolicy, 2]))
              + Self.tlv(3, Data([1])) + Self.tlv(4, Self.tlv(0x86, self.publicKey)), status: 0x9000
          )
        case .recoveryAnchor:
          guard let anchor = self.anchor else { return .init(data: nil, status: 0x6a82) }
          return .init(data: Self.tlv(0x53, anchor), status: 0x9000)
        }
      }
    }
    private static func tlv(_ tag: UInt8, _ value: Data) -> Data {
      let size =
        value.count < 128
        ? [UInt8(value.count)] : [0x82, UInt8(value.count >> 8), UInt8(value.count & 255)]
      return Data([tag] + size) + value
    }
  }

  final class Provider: PIVRecoveryAgreementProviding, @unchecked Sendable {
    let token: P256.KeyAgreement.PrivateKey
    let card: Card
    private let lock = NSLock()
    private var count = 0
    var requests: Int { lock.withLock { count } }
    var cancel = false
    var onAgree: @Sendable () throws -> Void = {}
    init(token: P256.KeyAgreement.PrivateKey, card: Card) {
      self.token = token
      self.card = card
    }
    func makeSession() -> any PIVRecoveryAgreementSession { Session(provider: self) }
    func agree(_ peer: Data) throws -> Data {
      lock.withLock { count += 1 }
      #expect(!card.inSession)
      try onAgree()
      if cancel { throw PIVRecoveryAgreementError.cancelled }
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
  }

  private struct Key: PIVRecoveryAgreementKey {
    let tokenID = "registration-software-token"
    let publicKey: Data
    let isP256PrivateKey = true
    let supportsStandardECDH = true
  }

  private struct Session: PIVRecoveryAgreementSession {
    let provider: Provider
    func keys(tokenID _: String, publicKey _: Data) throws -> [any PIVRecoveryAgreementKey] {
      [Key(publicKey: provider.token.publicKey.x963Representation)]
    }
    func agree(key _: any PIVRecoveryAgreementKey, peer: Data) throws -> Data {
      try provider.agree(peer)
    }
    func invalidate() {}
  }
}
