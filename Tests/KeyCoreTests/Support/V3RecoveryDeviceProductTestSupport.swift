import CryptoKit
import Foundation

@testable import KeyCore

/// Independent Mac-local records for the product ceremonies. Shared encrypted
/// objects use the existing filesystem fixtures; no native/keychain APIs run.
enum V3RecoveryDeviceProductTestSupport {
  final class Ceremonies: V3EnrollmentCeremonyStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [Data: Data] = [:]
    func loadState(vaultID: String, invitationDigest: Data) throws -> Data? {
      lock.withLock { values[invitationDigest] }
    }
    func replaceState(_ state: Data, expectedState: Data?, vaultID: String, invitationDigest: Data)
      throws
    {
      try lock.withLock {
        guard values[invitationDigest] == expectedState else {
          throw V3EnrollmentCeremonyStateError.conflict
        }
        values[invitationDigest] = state
      }
    }
  }
  final class Records: V3EnrollmentDeviceKeyRecordStoring, V3EnrollmentDeviceKeyRecordDeleting,
    @unchecked Sendable
  {
    var value: Data?
    var afterDeletion: @Sendable () throws -> Void = {}
    init(_ value: Data?) { self.value = value }
    func loadRecord(vaultID: String) throws -> Data? { value }
    func insertRecord(_ record: Data, vaultID: String) throws {
      guard value == nil else { throw V3EnrollmentDeviceIdentityStoreError.identityAlreadyExists }
      value = record
    }
    func deleteRecord(expectedRecordDigest: Data, vaultID: String) throws {
      if let value {
        guard Data(SHA256.hash(data: value)) == expectedRecordDigest else {
          throw V3EnrollmentDeviceIdentityStoreError.conflict
        }
        self.value = nil
      }
      try afterDeletion()
    }
  }
  final class Checkpoints: V3ManifestCheckpointStoring, V3ManifestCheckpointDeleting,
    @unchecked Sendable
  {
    let base: V3RecoveryPublicationTestSupport.Checkpoints
    var value: Data? {
      get { base.value }
      set { base.value = newValue }
    }
    var afterDeletion: @Sendable () throws -> Void = {}
    init(_ value: Data) { base = .init(value) }
    func loadCheckpoint(vaultID: String) throws -> Data? {
      try base.loadCheckpoint(vaultID: vaultID)
    }
    func replaceCheckpoint(_ checkpoint: Data, expectedCheckpoint: Data?, vaultID: String) throws {
      try base.replaceCheckpoint(
        checkpoint, expectedCheckpoint: expectedCheckpoint, vaultID: vaultID)
    }
    func deleteCheckpoint(expectedCheckpoint: Data, vaultID: String) throws {
      if let value {
        guard value == expectedCheckpoint else { throw V3ManifestCheckpointStoreError.conflict }
        self.value = nil
      }
      try afterDeletion()
    }
  }
  final class Intents: V3ReplacementEnrollmentIntentStoring, @unchecked Sendable {
    var value: Data?
    var afterPersist: @Sendable (V3ReplacementEnrollmentIntentPhase) throws -> Void = { _ in }
    func loadReplacementIntent(vaultID: String) throws -> Data? { value }
    func replaceReplacementIntent(_ intent: Data?, expectedIntent: Data?, vaultID: String) throws {
      guard value == expectedIntent else { throw V3ReplacementEnrollmentIntentError.conflict }
      value = intent
      if let intent {
        try afterPersist(V3ReplacementEnrollmentIntent(canonicalBytes: intent).phase)
      }
    }
  }
}
