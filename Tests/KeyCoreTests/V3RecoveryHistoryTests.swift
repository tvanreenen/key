import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3RecoveryHistoryTests {
  @Test
  func floorAndSuccessiveEpochsOpenOnlyTheFinalKeyAndCompleteSnapshot() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let first = try f.rotate(f.origin, from: 1, to: 2)
    let second = try f.rotate(first, from: 2, to: 3)
    let head = try f.edit(second, key: 3, value: "current value")
    f.source.keepEntries(for: head)
    let selection = try f.select()
    #expect(selection.epochRoot == second)
    #expect(selection.head == head)
    #expect(selection.currentEpoch == [second, head])
    let receiver = RecoveryAgreementRecorder(key: f.token)
    let snapshot = try V3RecoverySnapshotVerifier(source: f.source).open(
      selection, boundAnchor: f.anchor, receiver: receiver.receiver())
    #expect(receiver.calls == 1)
    #expect(snapshot.entries.map(\.name) == ["fixture/secret", "fixture/totp"])
    #expect(snapshot.entries.map(\.plaintext) == ["current value", "JBSWY3DPEHPK3PXP"])
    #expect(f.source.entryReadCount == 4)  // initial reads plus exact revalidation
  }

  @Test
  func anchoredFloorDoesNotReplayPreRegistrationAncestry() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let root = try f.rotate(f.origin, from: 1, to: 2)
    let anchor = try f.anchor(at: root)
    f.source.removeManifest(f.origin.digest)
    f.source.keepEntries(for: root)
    let selection = try f.select(anchor: anchor)
    #expect(selection.head == root)
    let recorder = RecoveryAgreementRecorder(key: f.token)
    _ = try V3RecoverySnapshotVerifier(source: f.source).open(
      selection, boundAnchor: anchor, receiver: recorder.receiver())
    #expect(recorder.calls == 1)
  }

  @Test
  func floorCredentialRegistrationAndVaultMustMatch() throws {
    let f = try RecoveryGraphFixture()
    let other = P256.KeyAgreement.PrivateKey()
    #expect(throws: V3RecoveryValidationError.anchorMismatch) {
      try V3RecoveryHistorySelector(source: f.source).select(
        anchor: f.anchor, credentialPublicKey: other.publicKey.x963Representation)
    }
    #expect(f.source.manifestReadCount == 0)
    let wrongRegistration = try V3RecoveryAnchor(
      floor: f.anchor.floor, recipientID: f.anchor.recipientID,
      registrationID: RecoveryGraphFixture.id(99), slot: .keyManagement)
    #expect(throws: V3RecoveryValidationError.anchorMismatch) {
      try f.select(anchor: wrongRegistration)
    }
    let wrongVault = try V3RecoveryAnchor(
      floor: V3VaultHead(vaultID: RecoveryGraphFixture.id(98), envelopeDigest: f.origin.digest),
      recipientID: f.anchor.recipientID, registrationID: f.anchor.registrationID,
      slot: .keyManagement)
    #expect(throws: V3RecoveryValidationError.anchorMismatch) { try f.select(anchor: wrongVault) }
  }

  @Test
  func currentEpochBranchesRequireAnExplicitAllParentMerge() throws {
    let f = try RecoveryGraphFixture()
    let a = try f.edit(f.origin, key: 1, value: "branch a")
    let b = try f.edit(f.origin, key: 1, value: "branch b")
    #expect(throws: V3RecoveryValidationError.contentConflict) { try f.select() }
    let merge = try f.edit(a, key: 1, value: "resolved", parents: [a, b])
    #expect(try f.select().head == merge)
  }

  @Test
  func everyMergeParentMustExistAndLeadBackToTheFloor() throws {
    let f = try RecoveryGraphFixture()
    let a = try f.edit(f.origin, key: 1, value: "a")
    let b = try f.edit(f.origin, key: 1, value: "b")
    _ = try f.edit(a, key: 1, value: "merged", parents: [a, b])
    f.source.removeManifest(b.digest)
    #expect(throws: V3RecoveryValidationError.sourceUnavailable) { try f.select() }
    f.source.add(b)
    let outsider = try V3RecoveryEpochBoundary().encode(
      body: f.origin.body, parents: [], vaultKey: RecoveryGraphFixture.key(1), authorizations: [])
    // Same body would be the same origin; an unrelated root needs a distinct body.
    let alternate = try f.edit(outsider, key: 1, value: "other origin")
    let detached = try V3RecoveryEpochBoundary().encode(
      body: alternate.body, parents: [], vaultKey: RecoveryGraphFixture.key(1), authorizations: [])
    f.source.add(detached)
    _ = try f.edit(a, key: 1, value: "outsider merge", parents: [a, detached])
    #expect(throws: V3RecoveryValidationError.unanchoredParent) { try f.select() }
  }

  @Test
  func competingEpochsAndClosedEpochBranchesNeverFallBack() throws {
    let f = try RecoveryGraphFixture()
    _ = try f.rotate(f.origin, from: 1, to: 2)
    let competitor = try f.rotate(f.origin, from: 1, to: 3)
    #expect(throws: V3RecoveryValidationError.authorityConflict) { try f.select() }
    f.source.removeManifest(competitor.digest)
    _ = try f.edit(f.origin, key: 1, value: "late old-epoch branch")
    #expect(throws: V3RecoveryValidationError.closedEpochBranch) { try f.select() }
  }

  @Test
  func unsupportedDescendantsAndOpaqueNamedObjectsRefuseSelection() throws {
    let f = try RecoveryGraphFixture()
    let edited = try f.edit(f.origin, key: 1, value: "future")
    let root = try CanonicalJSON.parse(edited.canonicalBytes)
    let content = try RecoveryGraphFixture.member("content", in: root)
    let body = try RecoveryGraphFixture.member("manifest", in: content)
    let future = RecoveryGraphFixture.replace(
      "content", in: root,
      with: RecoveryGraphFixture.replace(
        "manifest", in: content,
        with: RecoveryGraphFixture.replace("profileVersion", in: body, with: .integer(4))))
    f.source.removeManifest(edited.digest)
    let bytes = CanonicalJSON.encode(future)
    f.source.add(bytes: bytes)
    #expect(throws: V3RecoveryValidationError.unsupportedState) { try f.select() }
    f.source.removeManifest(Data(SHA256.hash(data: bytes)))
    f.source.addUnreadableNamedObject(Data(repeating: 0x55, count: 32))
    #expect(throws: V3RecoveryValidationError.sourceUnavailable) { try f.select() }
  }

  @Test
  func unrelatedValidProfileTwoObjectsAreNotInterpretedAsRecovery() throws {
    let f = try RecoveryGraphFixture()
    // Use the actual outer syntax from the fixture, only changing its body.
    let root = try CanonicalJSON.parse(f.origin.canonicalBytes)
    let content = try RecoveryGraphFixture.member("content", in: root)
    let old = f.origin.body.fields
    let unrelated = try V3DeviceWrappedManifestFields(
      vaultID: RecoveryGraphFixture.id(98),
      keyID: old.keyID, authorityTransitionID: old.authorityTransitionID,
      devices: old.devices, wrappedKeys: old.wrappedKeys, entries: old.entries)
    let bytes = CanonicalJSON.encode(
      RecoveryGraphFixture.replace(
        "content", in: root,
        with: RecoveryGraphFixture.replace(
          "manifest", in: content,
          with: V3DeviceWrappedManifestBody(fields: unrelated).canonicalValue)))
    #expect(try V3DeviceWrappedManifestEnvelopeCodec().parse(bytes).body.fields == unrelated)
    f.source.add(bytes: bytes)
    #expect(try f.select().head == f.origin)
  }

  @Test
  func missingIntermediateSameVaultTipCannotBeIgnoredAsUnrelated() throws {
    let f = try RecoveryGraphFixture()
    let middle = try f.edit(f.origin, key: 1, value: "middle")
    _ = try f.edit(middle, key: 1, value: "newer tip")
    f.source.removeManifest(middle.digest)
    #expect(throws: V3RecoveryValidationError.unanchoredParent) { try f.select() }
  }

  @Test
  func listedPreFloorHistoryNeedNotBeProfileThreeOrPrivatelyReplayed() throws {
    let f = try RecoveryGraphFixture()
    let root = try CanonicalJSON.parse(f.origin.canonicalBytes)
    let content = try RecoveryGraphFixture.member("content", in: root)
    let bytes = CanonicalJSON.encode(
      RecoveryGraphFixture.replace(
        "content", in: root,
        with: RecoveryGraphFixture.replace(
          "manifest", in: content,
          with: V3DeviceWrappedManifestBody(fields: f.origin.body.fields).canonicalValue)))
    f.source.removeManifest(f.origin.digest)
    f.source.add(bytes: bytes)
    let floor = try V3RecoveryEpochBoundary().encode(
      body: f.origin.body,
      parents: [Data(SHA256.hash(data: bytes))], vaultKey: RecoveryGraphFixture.key(1),
      authorizations: [])
    f.source.add(floor)
    #expect(try f.select(anchor: f.anchor(at: floor)).head == floor)
  }

  @Test
  func boundaryPolicyPreservesEntryRevisionAndRejectsRosterIdentityChanges() throws {
    let f = try RecoveryGraphFixture()
    let next = try f.prepare(key: 2, entries: f.origin.body.fields.entries, oldKey: 1)
    let changedDevice = V3DeviceWrappedManifestDevice(
      identity: try V3EnrollmentDeviceIdentity(
        displayName: "different name", signingPublicKey: f.signer.publicIdentity.signingPublicKey,
        wrappingPublicKey: f.signer.publicIdentity.wrappingPublicKey), status: .active)
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: next.fields.vaultID, keyID: next.fields.keyID,
      authorityTransitionID: next.fields.authorityTransitionID, devices: [changedDevice],
      wrappedKeys: next.fields.wrappedKeys, entries: next.fields.entries)
    let bad = try V3RecoveryManifestBody(
      fields: fields, epochSigningKey: next.epochSigningKey, transitionProof: nil,
      recovery: next.recovery)
    let boundary = try f.authorize(bad, parent: f.origin, from: 1, to: 2)
    #expect(throws: V3RecoveryValidationError.invalidTransition) { try f.select() }
    f.source.removeManifest(boundary.digest)
    let good = try f.authorize(next, parent: f.origin, from: 1, to: 2)
    #expect(
      good.body.fields.entries.map(\.revision) == f.origin.body.fields.entries.map(\.revision))
    #expect(try f.select().head == good)
  }

  @Test
  func unchangedRosterCannotAcquireNewGenerationAndRecipientRevocationIsPublic() throws {
    let f = try RecoveryGraphFixture()
    let next = try f.prepare(key: 2, entries: f.origin.body.fields.entries, oldKey: 1)
    let changedGeneration = try V3RecoveryRoster(
      generationID: RecoveryGraphFixture.id(88), recipients: next.recovery.recipients,
      wrappedKeys: next.recovery.wrappedKeys)
    let wrong = try V3RecoveryManifestBody(
      fields: next.fields, epochSigningKey: next.epochSigningKey,
      transitionProof: nil, recovery: changedGeneration)
    let invalid = try f.authorize(wrong, parent: f.origin, from: 1, to: 2)
    #expect(throws: V3RecoveryValidationError.invalidTransition) { try f.select() }
    f.source.removeManifest(invalid.digest)
    let revoked = try V3RecoveryRecipient(
      registrationID: f.recipient.registrationID, publicKey: f.recipient.publicKey,
      slot: .keyManagement, status: .revoked)
    let roster = try V3RecoveryRoster(
      generationID: RecoveryGraphFixture.id(88), recipients: [revoked], wrappedKeys: [])
    let body = try V3RecoveryManifestBody(
      fields: next.fields, epochSigningKey: next.epochSigningKey, transitionProof: nil,
      recovery: roster)
    _ = try f.authorize(body, parent: f.origin, from: 1, to: 2)
    #expect(throws: V3RecoveryValidationError.recipientRevoked) { try f.select() }
  }

  @Test
  func revisionRollbackAndSkippedRevisionsAreRejected() throws {
    let f = try RecoveryGraphFixture()
    let a = try f.edit(f.origin, key: 1, value: "revision two")
    let bad = try V3RecoveryEpochBoundary().encode(
      body: f.origin.body, parents: [a.digest], vaultKey: RecoveryGraphFixture.key(1),
      authorizations: [])
    f.source.add(bad)
    #expect(throws: V3RecoveryValidationError.invalidTransition) { try f.select() }
    f.source.removeManifest(bad.digest)
    let skipped = try f.edit(a, key: 1, value: "skip", revision: 4)
    #expect(throws: V3RecoveryValidationError.invalidTransition) { try f.select() }
    f.source.removeManifest(skipped.digest)
    #expect(try f.select().head == a)
  }

  @Test
  func manifestObjectDepthByteReferenceAndEdgeBudgetsAreEnforced() throws {
    let f = try RecoveryGraphFixture()
    let a = try f.edit(f.origin, key: 1, value: "a")
    let b = try f.edit(a, key: 1, value: "b")
    for limits in [
      Self.limits(objects: 2), Self.limits(depth: 1), Self.limits(references: 1),
      Self.limits(manifestBytes: f.origin.canonicalBytes.count - 1),
      Self.limits(
        manifestBytes: max(
          f.origin.canonicalBytes.count, a.canonicalBytes.count, b.canonicalBytes.count),
        totalManifestBytes: f.source.allManifestBytes - 1),
    ] {
      #expect(throws: V3RecoveryValidationError.resourceLimit) {
        try V3RecoveryHistorySelector(source: f.source, limits: limits).select(
          anchor: f.anchor, credentialPublicKey: f.recipient.publicKey)
      }
    }
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try V3RecoveryHistorySelector(source: f.source, maximumParentEdges: 1).select(
        anchor: f.anchor, credentialPublicKey: f.recipient.publicKey)
    }
    f.source.hideFromListing(b.digest)
    f.source.extraObjectCount = 1  // Two listed digests plus a non-object directory name.
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try V3RecoveryHistorySelector(source: f.source, limits: Self.limits(objects: 3)).select(
        anchor: f.anchor(at: b), credentialPublicKey: f.recipient.publicKey)
    }
  }

  @Test
  func digestSubstitutionAndOversizeSourceResponsesAreRejected() throws {
    let f = try RecoveryGraphFixture()
    f.source.overrideManifest(f.origin.digest, bytes: Data("different".utf8))
    #expect(throws: V3RecoveryValidationError.invalidObject) { try f.select() }
    f.source.overrideManifest(f.origin.digest, bytes: Data(repeating: 0, count: 2_097_153))
    #expect(throws: V3RecoveryValidationError.resourceLimit) { try f.select() }
  }

  @Test
  func changedSourceOrBoundCredentialStopsBeforeAgreement() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let selection = try f.select()
    let recorder = RecoveryAgreementRecorder(key: f.token)
    _ = try f.edit(f.origin, key: 1, value: "changed after selection")
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try V3RecoverySnapshotVerifier(source: f.source).open(
        selection, boundAnchor: f.anchor, receiver: recorder.receiver())
    }
    #expect(recorder.calls == 0)
    let wrong = RecoveryAgreementRecorder(key: P256.KeyAgreement.PrivateKey())
    #expect(throws: V3RecoveryValidationError.anchorMismatch) {
      try V3RecoverySnapshotVerifier(source: f.source).open(
        selection, boundAnchor: f.anchor, receiver: wrong.receiver())
    }
    #expect(wrong.calls == 0)
  }

  @Test
  func cancellationIsOneAttemptAndCurrentMACFailureDoesNotFallback() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let recorder = RecoveryAgreementRecorder(key: f.token, cancel: true)
    #expect(throws: RecoveryAgreementRecorder.Failure.cancelled) {
      try V3RecoverySnapshotVerifier(source: f.source).open(
        f.select(), boundAnchor: f.anchor, receiver: recorder.receiver())
    }
    #expect(recorder.calls == 1)
    let edited = try f.edit(f.origin, key: 1, value: "changed")
    f.source.removeManifest(edited.digest)
    let root = try CanonicalJSON.parse(edited.canonicalBytes)
    let authentication = try RecoveryGraphFixture.member("authentication", in: root)
    let bytes = CanonicalJSON.encode(
      RecoveryGraphFixture.replace(
        "authentication", in: root,
        with: RecoveryGraphFixture.replace(
          "tag", in: authentication, with: .string(Base64URL.encode(Data(repeating: 0, count: 32))))
      ))
    f.source.add(bytes: bytes)
    let validReceiver = RecoveryAgreementRecorder(key: f.token)
    #expect(throws: V3RecoveryManifestError.authenticationFailed) {
      try V3RecoverySnapshotVerifier(source: f.source).open(
        f.select(), boundAnchor: f.anchor, receiver: validReceiver.receiver())
    }
    #expect(validReceiver.calls == 1)
  }

  @Test
  func everyCurrentEntryMustBeAvailableAndDigestAuthenticated() throws {
    guard #available(macOS 26.0, *) else { return }
    for unavailable in [true, false] {
      let f = try RecoveryGraphFixture()
      let entry = try #require(f.origin.body.fields.entries.last)
      let key = V3EntryObjectKey(
        entryID: entry.entryID,
        digest: try #require(Base64URL.decodeCanonical(entry.ciphertextDigest)))
      f.source.setEntry(key, bytes: unavailable ? nil : Data("substituted bytes".utf8))
      let recorder = RecoveryAgreementRecorder(key: f.token)
      #expect(throws: (any Error).self) {
        try V3RecoverySnapshotVerifier(source: f.source).open(
          f.select(), boundAnchor: f.anchor, receiver: recorder.receiver())
      }
      #expect(recorder.calls == 1)
    }
  }

  @Test
  func payloadSemanticsContextUTF8AndAEADAreCheckedAfterOneOpen() throws {
    guard #available(macOS 26.0, *) else { return }
    for kind in 0..<4 {
      let f = try RecoveryGraphFixture()
      let keyID = f.origin.body.fields.keyID
      let context = try V3EntryAuthenticationContext(
        vaultID: RecoveryGraphFixture.vaultID, entryID: RecoveryGraphFixture.id(20),
        name: kind == 1 ? "different/name" : "fixture/totp", type: .totp, keyID: keyID, revision: 2)
      let plaintext = kind == 2 ? Data([0xff]) : Data("not a valid base32 seed!".utf8)
      let encrypted = try V3EntryCipher().seal(
        plaintext, context: context, vaultKey: RecoveryGraphFixture.key(1), nonce: AES.GCM.Nonce())
      var bytes = encrypted.canonicalBytes
      if kind == 3 {
        let root = try CanonicalJSON.parse(bytes)
        let encryption = try RecoveryGraphFixture.member("encryption", in: root)
        bytes = CanonicalJSON.encode(
          RecoveryGraphFixture.replace(
            "encryption", in: root,
            with: RecoveryGraphFixture.replace(
              "tag", in: encryption, with: .string(Base64URL.encode(Data(repeating: 0, count: 16))))
          ))
      }
      let entry = V3ManifestEntry(
        entryID: context.entryID, name: "fixture/totp", type: .totp, revision: 2, keyID: keyID,
        ciphertextDigest: Base64URL.encode(Data(SHA256.hash(data: bytes))))
      f.source.setEntry(
        V3EntryObjectKey(entryID: entry.entryID, digest: Data(SHA256.hash(data: bytes))),
        bytes: bytes)
      let entries = [f.origin.body.fields.entries[0], entry]
      _ = try f.content(f.origin, entries: entries, key: 1)
      let recorder = RecoveryAgreementRecorder(key: f.token)
      #expect(throws: (any Error).self) {
        try V3RecoverySnapshotVerifier(source: f.source).open(
          f.select(), boundAnchor: f.anchor, receiver: recorder.receiver())
      }
      #expect(recorder.calls == 1)
    }
  }

  @Test
  func entryByteBudgetsAndSourceChangesAfterAgreementRefuseSnapshot() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let selection = try f.select()
    let recorder = RecoveryAgreementRecorder(key: f.token)
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try V3RecoverySnapshotVerifier(source: f.source, limits: Self.limits(entryBytes: 1)).open(
        selection, boundAnchor: f.anchor, receiver: recorder.receiver())
    }
    #expect(recorder.calls == 1)
    let changing = RecoveryAgreementRecorder(
      key: f.token,
      afterAgreement: { [source = f.source] in
        source.extraObjectCount = 1
      })
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try V3RecoverySnapshotVerifier(source: f.source).open(
        selection, boundAnchor: f.anchor, receiver: changing.receiver())
    }
    #expect(changing.calls == 1)
  }

  @Test
  func verifiedSnapshotRevalidationDetectsEntryChangesWithoutNewApproval() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let recorder = RecoveryAgreementRecorder(key: f.token)
    let verifier = V3RecoverySnapshotVerifier(source: f.source)
    let snapshot = try verifier.open(
      f.select(), boundAnchor: f.anchor, receiver: recorder.receiver())
    let entry = f.origin.body.fields.entries[0]
    f.source.setEntry(
      V3EntryObjectKey(
        entryID: entry.entryID,
        digest: try #require(Base64URL.decodeCanonical(entry.ciphertextDigest))), bytes: Data())
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try verifier.revalidate(
        snapshot, boundAnchor: f.anchor, credentialPublicKey: f.recipient.publicKey)
    }
    #expect(recorder.calls == 1)
  }

  @Test
  func entryChangeDuringVerificationAndAggregateBytesRefuseSnapshot() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let selection = try f.select()
    let sizes = try f.origin.body.fields.entries.map { try #require(f.source.entryBytes($0)).count }
    let limits = Self.limits(
      entryBytes: try #require(sizes.max()), totalEntryBytes: sizes.reduce(0, +) - 1)
    let budgetReceiver = RecoveryAgreementRecorder(key: f.token)
    #expect(throws: V3RecoveryValidationError.resourceLimit) {
      try V3RecoverySnapshotVerifier(source: f.source, limits: limits).open(
        selection, boundAnchor: f.anchor, receiver: budgetReceiver.receiver())
    }
    #expect(budgetReceiver.calls == 1)
    let fresh = try RecoveryGraphFixture()
    let entry = fresh.origin.body.fields.entries[0]
    let entryKey = V3EntryObjectKey(
      entryID: entry.entryID,
      digest: try #require(Base64URL.decodeCanonical(entry.ciphertextDigest)))
    fresh.source.afterEntryRead { [weak source = fresh.source] count in
      if count == 1 { source?.setEntry(entryKey, bytes: Data()) }
    }
    let recorder = RecoveryAgreementRecorder(key: fresh.token)
    #expect(throws: V3RecoveryValidationError.sourceChanged) {
      try V3RecoverySnapshotVerifier(source: fresh.source).open(
        fresh.select(), boundAnchor: fresh.anchor, receiver: recorder.receiver())
    }
    #expect(recorder.calls == 1)
  }

  @Test
  func finalCapsuleMustAuthenticateEvenWithAValidManifestMAC() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let capsule = try V3EpochSigningKeyCapsule(
      publicKey: f.origin.body.epochSigningKey.publicKey,
      protectedSigningKey: Data(repeating: 0, count: 60))
    let body = try V3RecoveryManifestBody(
      fields: f.origin.body.fields,
      epochSigningKey: capsule, transitionProof: nil, recovery: f.origin.body.recovery)
    let floor = try V3RecoveryEpochBoundary().encode(
      body: body, parents: [],
      vaultKey: RecoveryGraphFixture.key(1), authorizations: [])
    f.source.removeManifest(f.origin.digest)
    f.source.add(floor)
    let anchor = try f.anchor(at: floor)
    let recorder = RecoveryAgreementRecorder(key: f.token)
    #expect(throws: V3EpochSigningKeyError.authenticationFailed) {
      try V3RecoverySnapshotVerifier(source: f.source).open(
        f.select(anchor: anchor), boundAnchor: anchor, receiver: recorder.receiver())
    }
    #expect(recorder.calls == 1)
  }

  @Test
  func emptyCurrentSnapshotStillRequiresKeyMACAndCapsuleVerification() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    _ = try f.content(f.origin, entries: [], key: 1)
    let recorder = RecoveryAgreementRecorder(key: f.token)
    let snapshot = try V3RecoverySnapshotVerifier(source: f.source).open(
      f.select(), boundAnchor: f.anchor, receiver: recorder.receiver())
    #expect(snapshot.entries.isEmpty)
    #expect(recorder.calls == 1)
    #expect(f.source.entryReadCount == 0)
  }

  @Test
  func realDirectorySourceVerifiesDisposableObjectsAndRejectsSymlinkedEntry() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try RecoveryGraphFixture()
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
      "recovery-graph-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let manifests = root.appendingPathComponent("manifests")
    try FileManager.default.createDirectory(at: manifests, withIntermediateDirectories: true)
    try f.origin.canonicalBytes.write(
      to: root.appendingPathComponent(manifestPath(for: f.origin.digest)))
    for entry in f.origin.body.fields.entries {
      let directory = root.appendingPathComponent("entries/\(entry.entryID)")
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
      let bytes = try #require(f.source.entryBytes(entry))
      try bytes.write(
        to: root.appendingPathComponent(
          entryPath(entryID: entry.entryID, digest: entry.ciphertextDigest)))
    }
    let source = V3FilesystemImmutableObjectSource(
      rootHandle: try VaultRootDirectoryHandle(opening: root))
    let selection = try V3RecoveryHistorySelector(source: source).select(
      anchor: f.anchor, credentialPublicKey: f.recipient.publicKey)
    let recorder = RecoveryAgreementRecorder(key: f.token)
    let verifier = V3RecoverySnapshotVerifier(source: source)
    let snapshot = try verifier.open(
      selection, boundAnchor: f.anchor, receiver: recorder.receiver())
    #expect(snapshot.entries.count == 2)
    let entry = f.origin.body.fields.entries[0]
    let path = root.appendingPathComponent(
      entryPath(entryID: entry.entryID, digest: entry.ciphertextDigest))
    try FileManager.default.removeItem(at: path)
    try FileManager.default.createSymbolicLink(
      at: path,
      withDestinationURL: root.appendingPathComponent(manifestPath(for: f.origin.digest)))
    #expect(throws: (any Error).self) {
      try verifier.revalidate(
        snapshot, boundAnchor: f.anchor, credentialPublicKey: f.recipient.publicKey)
    }
    #expect(recorder.calls == 1)
  }

  private static func limits(
    objects: Int = 4_096, depth: Int = 1_024,
    references: Int = 16_384, manifestBytes: Int = 2_097_152,
    totalManifestBytes: Int = 67_108_864, entryBytes: Int = 16_777_216,
    totalEntryBytes: Int = 268_435_456
  )
    -> V3ManifestRepositoryLimits
  {
    V3ManifestRepositoryLimits(
      maximumManifestObjects: objects, maximumHistoryDepth: depth,
      maximumReferencedEntryObjects: references, maximumManifestBytes: manifestBytes,
      maximumEntryBytes: entryBytes, maximumTotalManifestBytes: totalManifestBytes,
      maximumTotalEntryBytes: totalEntryBytes)
  }
}

private final class RecoveryGraphFixture {
  static let vaultID = id(1)
  let source = RecoveryMemorySource()
  let signer: RecoverySoftwareSigner
  let token = P256.KeyAgreement.PrivateKey()
  let recipient: V3RecoveryRecipient
  var origin: V3RecoveryManifestEnvelope!
  var anchor: V3RecoveryAnchor { get throws { try anchor(at: origin) } }
  static func id(_ value: Int) -> String { String(format: "018f4d38-7d5a-7b20-b0f1-%012x", value) }
  static func key(_ value: UInt8) -> Data { Data(repeating: value, count: 32) }

  init() throws {
    signer = try RecoverySoftwareSigner(vaultID: Self.vaultID)
    recipient = try V3RecoveryRecipient(
      registrationID: Self.id(8), publicKey: token.publicKey.x963Representation,
      slot: .keyManagement, status: .active)
    let body = try prepare(key: 1)
    origin = try V3RecoveryEpochBoundary().encode(
      body: body, parents: [], vaultKey: Self.key(1), authorizations: [])
    source.add(origin)
  }

  func anchor(at envelope: V3RecoveryManifestEnvelope) throws -> V3RecoveryAnchor {
    try V3RecoveryAnchor(
      floor: V3VaultHead(vaultID: Self.vaultID, envelopeDigest: envelope.digest),
      recipientID: recipient.recipientID, registrationID: recipient.registrationID,
      slot: .keyManagement)
  }
  func select(anchor: V3RecoveryAnchor? = nil) throws -> V3RecoveryPublicSelection {
    try V3RecoveryHistorySelector(source: source).select(
      anchor: anchor ?? self.anchor, credentialPublicKey: recipient.publicKey)
  }
  func prepare(key: UInt8, entries: [V3ManifestEntry]? = nil, oldKey: UInt8? = nil) throws
    -> V3RecoveryManifestBody
  {
    let bytes = Self.key(key)
    let keyID = try V3VaultKeyID.derive(vaultKey: bytes, vaultID: Self.vaultID)
    let transition = Self.id(100 + Int(key))
    var prepared: [V3ManifestEntry] = []
    if let entries, let oldKey {
      for entry in entries {
        let plaintext = try V3EntryCipher().openTrusted(
          try #require(source.entryBytes(entry)),
          vaultID: Self.vaultID, manifestEntry: entry, vaultKey: Self.key(oldKey))
        prepared.append(
          try seal(
            plaintext, entryID: entry.entryID, name: entry.name,
            type: entry.type, revision: entry.revision, key: key))
      }
    } else {
      prepared = try [
        seal(
          "initial value", entryID: Self.id(19), name: "fixture/secret", type: .secret, revision: 1,
          key: key),
        seal(
          "JBSWY3DPEHPK3PXP", entryID: Self.id(20), name: "fixture/totp", type: .totp, revision: 1,
          key: key),
      ]
    }
    let wrapped = try V3DeviceWrappedManifestKey(
      recipientDeviceID: signer.publicIdentity.deviceID,
      wrappedKey: V3VaultKeyHPKE().wrap(
        vaultKey: bytes, recipientPublicKey: signer.publicIdentity.wrappingPublicKey,
        context: V3VaultKeyHPKEContext(
          vaultID: Self.vaultID, keyID: keyID, authorityTransitionID: transition,
          recipientDeviceID: signer.publicIdentity.deviceID, wrappingProfile: .recovery)))
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: Self.vaultID, keyID: keyID, authorityTransitionID: transition,
      devices: [.init(identity: signer.publicIdentity, status: .active)], wrappedKeys: [wrapped],
      entries: prepared)
    let context = try V3RecoveryHPKEContext(
      vaultID: Self.vaultID, keyID: keyID, authorityTransitionID: transition,
      recoveryGenerationID: Self.id(9), recipient: recipient)
    let roster = try V3RecoveryRoster(
      generationID: Self.id(9), recipients: [recipient],
      wrappedKeys: [V3RecoveryVaultKeyHPKE().wrap(vaultKey: bytes, context: context)])
    let capsule = try V3EpochSigningKeyCipher().prepare(
      context: V3EpochSigningKeyContext(
        vaultID: Self.vaultID, keyID: keyID, authorityTransitionID: transition), vaultKey: bytes)
    return try V3RecoveryManifestBody(
      fields: fields, epochSigningKey: capsule, transitionProof: nil, recovery: roster)
  }
  func seal(
    _ value: String, entryID: String, name: String, type: SecretEntryType, revision: UInt64,
    key: UInt8
  ) throws -> V3ManifestEntry {
    let keyID = try V3VaultKeyID.derive(vaultKey: Self.key(key), vaultID: Self.vaultID)
    let encrypted = try V3EntryCipher().seal(
      value,
      context: V3EntryAuthenticationContext(
        vaultID: Self.vaultID, entryID: entryID, name: name, type: type,
        keyID: keyID, revision: revision), vaultKey: Self.key(key))
    source.setEntry(
      V3EntryObjectKey(entryID: entryID, digest: Data(SHA256.hash(data: encrypted.canonicalBytes))),
      bytes: encrypted.canonicalBytes)
    return V3ManifestEntry(
      entryID: entryID, name: name, type: type, revision: revision, keyID: keyID,
      ciphertextDigest: encrypted.ciphertextDigest)
  }
  func rotate(_ parent: V3RecoveryManifestEnvelope, from: UInt8, to: UInt8) throws
    -> V3RecoveryManifestEnvelope
  {
    try authorize(
      prepare(key: to, entries: parent.body.fields.entries, oldKey: from), parent: parent,
      from: from, to: to)
  }
  func authorize(
    _ body: V3RecoveryManifestBody, parent: V3RecoveryManifestEnvelope, from: UInt8, to: UInt8
  ) throws -> V3RecoveryManifestEnvelope {
    let result = try V3RecoveryEpochBoundary().authorize(
      candidate: body, parent: parent,
      currentVaultKey: Self.key(from), nextVaultKey: Self.key(to), signer: signer,
      reason: "Software fixture boundary")
    source.add(result)
    return result
  }
  func edit(
    _ parent: V3RecoveryManifestEnvelope, key: UInt8, value: String,
    revision: UInt64? = nil, parents: [V3RecoveryManifestEnvelope]? = nil
  ) throws -> V3RecoveryManifestEnvelope {
    let old = parent.body.fields.entries[0]
    let entry = try seal(
      value, entryID: old.entryID, name: old.name, type: old.type,
      revision: revision ?? old.revision + 1, key: key)
    return try content(
      parent, entries: [entry] + Array(parent.body.fields.entries.dropFirst()), key: key,
      parents: parents)
  }
  func content(
    _ parent: V3RecoveryManifestEnvelope, entries: [V3ManifestEntry], key: UInt8,
    parents: [V3RecoveryManifestEnvelope]? = nil
  ) throws -> V3RecoveryManifestEnvelope {
    let old = parent.body
    let fields = try V3DeviceWrappedManifestFields(
      vaultID: old.fields.vaultID, keyID: old.fields.keyID,
      authorityTransitionID: old.fields.authorityTransitionID, devices: old.fields.devices,
      wrappedKeys: old.fields.wrappedKeys, entries: entries)
    let body = try V3RecoveryManifestBody(
      fields: fields, epochSigningKey: old.epochSigningKey,
      transitionProof: old.transitionProof, recovery: old.recovery)
    let result = try V3RecoveryEpochBoundary().encode(
      body: body,
      parents: (parents ?? [parent]).map(\.digest).sorted { $0.lexicographicallyPrecedes($1) },
      vaultKey: Self.key(key), authorizations: [])
    source.add(result)
    return result
  }
  static func member(_ name: String, in value: CanonicalJSONValue) throws -> CanonicalJSONValue {
    try #require(value.objectValue?.first { $0.0 == name }?.1)
  }
  static func replace(
    _ name: String, in value: CanonicalJSONValue, with replacement: CanonicalJSONValue
  ) -> CanonicalJSONValue {
    .object((value.objectValue ?? []).map { ($0.0, $0.0 == name ? replacement : $0.1) })
  }
}

private struct RecoverySoftwareSigner: V3EnrollmentMessageSigning {
  let vaultID: String
  let key = P256.Signing.PrivateKey()
  let publicIdentity: V3EnrollmentDeviceIdentity
  init(vaultID: String) throws {
    self.vaultID = vaultID
    publicIdentity = try V3EnrollmentDeviceIdentity(
      displayName: "Software fixture",
      signingPublicKey: key.publicKey.x963Representation,
      wrappingPublicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
  }
  func signature(for input: Data, reason: String) throws -> Data {
    try key.signature(for: input).rawRepresentation
  }
}

private final class RecoveryMemorySource: V3ImmutableObjectReading, @unchecked Sendable {
  private let lock = NSLock()
  private var manifests: [Data: Data] = [:]
  private var missing = Set<Data>()
  private var hidden = Set<Data>()
  private var entries: [V3EntryObjectKey: Data] = [:]
  private var extraCount = 0
  private var manifestReads = 0
  private var entryReads = 0
  private var entryHook: @Sendable (Int) -> Void = { _ in }
  func afterEntryRead(_ operation: @escaping @Sendable (Int) -> Void) {
    lock.withLock { entryHook = operation }
  }
  var extraObjectCount: Int {
    get { lock.withLock { extraCount } }
    set { lock.withLock { extraCount = newValue } }
  }
  var manifestReadCount: Int { lock.withLock { manifestReads } }
  var entryReadCount: Int { lock.withLock { entryReads } }
  var allManifestBytes: Int { lock.withLock { manifests.values.reduce(0) { $0 + $1.count } } }
  func add(_ value: V3RecoveryManifestEnvelope) { add(bytes: value.canonicalBytes) }
  func add(bytes: Data) { lock.withLock { manifests[Data(SHA256.hash(data: bytes))] = bytes } }
  func removeManifest(_ digest: Data) {
    lock.withLock { _ = manifests.removeValue(forKey: digest) }
  }
  func hideFromListing(_ digest: Data) { lock.withLock { _ = hidden.insert(digest) } }
  func addUnreadableNamedObject(_ digest: Data) { lock.withLock { _ = missing.insert(digest) } }
  func overrideManifest(_ digest: Data, bytes: Data) { lock.withLock { manifests[digest] = bytes } }
  func setEntry(_ key: V3EntryObjectKey, bytes: Data?) { lock.withLock { entries[key] = bytes } }
  func entryBytes(_ entry: V3ManifestEntry) -> Data? {
    guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest) else { return nil }
    return lock.withLock { entries[V3EntryObjectKey(entryID: entry.entryID, digest: digest)] }
  }
  func keepEntries(for envelope: V3RecoveryManifestEnvelope) {
    let keys = Set(
      envelope.body.fields.entries.map {
        V3EntryObjectKey(
          entryID: $0.entryID, digest: Base64URL.decodeCanonical($0.ciphertextDigest)!)
      })
    lock.withLock { entries = entries.filter { keys.contains($0.key) } }
  }
  func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
    lock.withLock {
      let digests = Set(manifests.keys).union(missing).subtracting(hidden)
      return .available(digests: Array(digests), objectCount: digests.count + extraCount)
    }
  }
  func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
    lock.withLock {
      manifestReads += 1
      return manifests[digest].map(V3RepositoryObjectRead.available) ?? .unavailable
    }
  }
  func readEntry(entryID: String, digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead
  {
    let (result, count, hook) = lock.withLock {
      entryReads += 1
      let result =
        entries[V3EntryObjectKey(entryID: entryID, digest: digest)].map(
          V3RepositoryObjectRead.available) ?? .unavailable
      return (result, entryReads, entryHook)
    }
    hook(count)
    return result
  }
}

private final class RecoveryAgreementRecorder: @unchecked Sendable {
  enum Failure: Error { case cancelled }
  let key: P256.KeyAgreement.PrivateKey
  let cancel: Bool
  let afterAgreement: @Sendable () -> Void
  private let lock = NSLock()
  private var count = 0
  var calls: Int { lock.withLock { count } }
  init(
    key: P256.KeyAgreement.PrivateKey, cancel: Bool = false,
    afterAgreement: @escaping @Sendable () -> Void = {}
  ) {
    self.key = key
    self.cancel = cancel
    self.afterAgreement = afterAgreement
  }
  @available(macOS 26.0, *)
  func receiver() throws -> PIVHPKEReceiver {
    try PIVHPKEReceiver(publicBytes: key.publicKey.x963Representation) { [self] peer in
      lock.withLock { count += 1 }
      if cancel { throw Failure.cancelled }
      let result = try key.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
      afterAgreement()
      return result
    }
  }
}
