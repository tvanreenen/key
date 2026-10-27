import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Signed software enrollment ceremonies, enrolled history, and local ceremony-state failure controls.
enum V3RecoveryEnrollmentTestSupport {
  typealias Core = V3RecoveryRegistrationTestSupport
  typealias Publication = V3RecoveryPublicationTestSupport
  private typealias Stop = Publication.Stop
  static let now: UInt64 = 4_102_444_800
  static func ceremony(
    parentDigest: Data, owner: any V3EnrollmentMessageSigning,
    joiner: any V3EnrollmentMessageSigning
  ) throws -> V3EnrollmentCeremonyState {
    let invitation = try V3EnrollmentInvitation(
      vaultID: Core.vaultID, parentManifestDigest: parentDigest,
      invitingDevice: owner.publicIdentity,
      nonce: P256.KeyAgreement.PrivateKey().rawRepresentation, expiresAt: Self.now)
    let authenticator = V3EnrollmentMessageAuthenticator()
    let signedInvitation = try authenticator.sign(
      invitation, using: owner, reason: "Software invitation fixture")
    let request = try V3EnrollmentJoinRequest(
      invitationDigest: invitation.digest, joiningDevice: joiner.publicIdentity,
      nonce: P256.KeyAgreement.PrivateKey().rawRepresentation)
    let signedRequest = try authenticator.sign(
      request, answering: authenticator.verify(signedInvitation), using: joiner,
      reason: "Software join fixture")
    return try V3EnrollmentCeremonyState(
      vaultID: Core.vaultID, invitationDigest: invitation.digest, role: .inviter,
      phase: .awaitingComparison,
      signedInvitation: signedInvitation, signedJoinRequest: signedRequest)
  }
  struct Fixture: Sendable {
    let disk: Publication.Fixture
    let joiner: Core.Owner
    let state: V3EnrollmentCeremonyState
    let local: StateStore
    let signatures: Int
    init(empty: Bool = false) throws {
      disk = try Publication.Fixture(empty: empty)
      joiner = try Core.Owner()
      state = try V3RecoveryEnrollmentTestSupport.ceremony(
        parentDigest: disk.parent.digest, owner: disk.core.owner, joiner: joiner)
      local = StateStore(state.canonicalBytes)
      signatures = disk.core.owner.signatures
    }
    func savedState() throws -> V3EnrollmentCeremonyState {
      try .init(canonicalBytes: #require(local.value))
    }
  }
  final class StateStore: V3EnrollmentCeremonyStateStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: Data?
    private var rejected = false
    private var count = 0
    init(_ value: Data) { bytes = value }
    var value: Data? {
      get { lock.withLock { bytes } }
      set { lock.withLock { bytes = newValue } }
    }
    var rejectConsume: Bool {
      get { lock.withLock { rejected } }
      set { lock.withLock { rejected = newValue } }
    }
    var consumptions: Int { lock.withLock { count } }
    func loadState(vaultID _: String, invitationDigest _: Data) throws -> Data? { value }
    func replaceState(
      _ state: Data, expectedState: Data?, vaultID _: String, invitationDigest _: Data
    ) throws {
      try lock.withLock {
        guard bytes == expectedState else { throw V3EnrollmentCeremonyStateError.conflict }
        if rejected { throw Stop.interrupted }
        bytes = state
        count += 1
      }
    }
  }
}
