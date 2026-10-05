import CryptoKit
import Foundation

/// Fully authenticated selected current contents, held in scoped memory only.
/// Construction is confined to this verifier. Restore must still revalidate
/// source, token/directory bindings and destination transaction state. This is
/// not a claim of historical resealing replay or provider-global freshness.
struct V3RecoveryVerifiedSnapshot: Sendable {
  let selection: V3RecoveryPublicSelection
  let entries: [V3GenesisSourceEntry]
  // This access level also confines the synthesized initializer to this file.
  fileprivate let entryBytes: [V3EntryObjectKey: Data]
}

/// Crypto/source verification only. Product platform code must obtain and
/// recheck anchor/credential provenance from the bound physical token. No real
/// token implementation, restore publication, checkpoint or CLI is enabled.
struct V3RecoverySnapshotVerifier: Sendable {
  private let selector: V3RecoveryHistorySelector

  init(
    source: any V3ImmutableObjectReading, limits: V3ManifestRepositoryLimits = .standard,
    maximumParentEdges: Int = 16_384
  ) {
    selector = V3RecoveryHistorySelector(
      source: source, limits: limits, maximumParentEdges: maximumParentEdges)
  }

  /// Recheck all public source state before the one private callback. Preserve
  /// agreement/cancellation errors without retry, fallback, or another epoch.
  @available(macOS 26.0, *)
  func open(
    _ selection: V3RecoveryPublicSelection, boundAnchor: V3RecoveryAnchor,
    receiver: PIVHPKEReceiver
  ) throws -> V3RecoveryVerifiedSnapshot {
    let current = try selector.select(
      anchor: boundAnchor, credentialPublicKey: receiver.publicKey.bytes)
    guard current == selection else { throw V3RecoveryValidationError.sourceChanged }
    let vaultKey = try V3RecoveryVaultKeyHPKE().unwrap(
      selection.wrappedKey, recipientPrivateKey: receiver, context: selection.context)
    // Exactly the final epoch. Never attempt to reopen older epochs.
    try V3RecoveryEpochBoundary().verifyCurrentAuthentication(
      selection.epochRoot, vaultKey: vaultKey)
    for envelope in selection.currentEpoch {
      guard
        try V3ManifestAuthenticator.isValidAuthenticationTag(
          envelope.authenticationTag, canonicalContent: envelope.canonicalContentBytes,
          vaultID: envelope.body.fields.vaultID, vaultKey: vaultKey)
      else { throw V3RecoveryManifestError.authenticationFailed }
    }
    guard selection.head.body.fields.entries.count <= selector.limits.maximumReferencedEntryObjects
    else {
      throw V3RecoveryValidationError.resourceLimit
    }
    var bytesByEntry: [V3EntryObjectKey: Data] = [:]
    var entries: [V3GenesisSourceEntry] = []
    var totalBytes = 0
    for entry in selection.head.body.fields.entries {
      guard let digest = Base64URL.decodeCanonical(entry.ciphertextDigest), digest.count == 32
      else {
        throw V3RecoveryValidationError.invalidObject
      }
      let key = V3EntryObjectKey(entryID: entry.entryID, digest: digest)
      let bytes = try readEntry(key)
      guard bytes.count <= selector.limits.maximumTotalEntryBytes - totalBytes else {
        throw V3RecoveryValidationError.resourceLimit
      }
      totalBytes += bytes.count
      let plaintext = try V3EntryCipher().openTrusted(
        bytes, vaultID: selection.head.body.fields.vaultID, manifestEntry: entry, vaultKey: vaultKey
      )
      if entry.type == .totp {
        guard (try? TOTPGenerator.normalizeBase32Seed(plaintext)) == plaintext else {
          throw V3RecoveryValidationError.invalidPayload
        }
      }
      entries.append(V3GenesisSourceEntry(name: entry.name, type: entry.type, plaintext: plaintext))
      bytesByEntry[key] = bytes
    }
    let snapshot = V3RecoveryVerifiedSnapshot(
      selection: selection, entries: entries, entryBytes: bytesByEntry)
    try revalidate(
      snapshot, boundAnchor: boundAnchor, credentialPublicKey: receiver.publicKey.bytes)
    return snapshot
  }

  /// Restore must call this again immediately before publication and combine
  /// it with a fresh native anchor/credential and directory-identity recheck.
  /// Source state cannot be made permanently fresh by this one observation.
  func revalidate(
    _ snapshot: V3RecoveryVerifiedSnapshot, boundAnchor: V3RecoveryAnchor,
    credentialPublicKey: Data
  ) throws {
    guard
      try selector.select(anchor: boundAnchor, credentialPublicKey: credentialPublicKey)
        == snapshot.selection
    else {
      throw V3RecoveryValidationError.sourceChanged
    }
    for (key, bytes) in snapshot.entryBytes {
      guard try readEntry(key) == bytes else { throw V3RecoveryValidationError.sourceChanged }
    }
  }

  private func readEntry(_ key: V3EntryObjectKey) throws -> Data {
    switch try selector.source.readEntry(
      entryID: key.entryID, digest: key.digest, maximumBytes: selector.limits.maximumEntryBytes)
    {
    case .available(let data):
      guard data.count <= selector.limits.maximumEntryBytes else {
        throw V3RecoveryValidationError.resourceLimit
      }
      return data
    case .unavailable: throw V3RecoveryValidationError.entryUnavailable
    case .tooLarge: throw V3RecoveryValidationError.resourceLimit
    case .invalid: throw V3RecoveryValidationError.invalidObject
    }
  }
}
