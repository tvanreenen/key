import CryptoKit
import Foundation

/// Dispatch by the exact locally compared invitation parent. Format detection
/// cannot authenticate the parent, choose an approval or authorize first trust.
func v3EnrollmentParentProfile(
  _ invitation: V3EnrollmentInvitation, source: any V3ImmutableObjectReading
) throws -> V3DeviceWrappedManifestProfile {
  let bytes = try V3ExactTransitionRepository(source: source, limits: .standard)
    .readManifest(invitation.parentManifestDigest)
  guard Data(SHA256.hash(data: bytes)) == invitation.parentManifestDigest else {
    throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
  }
  let container = try V3DeviceWrappedManifestEnvelopeCodec().parseContainer(bytes)
  let profile = try V3RecoveryManifestCodec().decodeBody(container.manifestValue)
  let fields: V3DeviceWrappedManifestFields
  switch profile {
  case .permanent(let body): fields = body.fields
  case .recovery(let body): fields = body.fields
  }
  guard fields.vaultID == invitation.vaultID else {
    throw V3DeviceWrappedEnrollmentAdoptionError.invalidApproval
  }
  return profile
}

struct V3ProfiledEnrollmentAdoptionService: V3EnrollmentFirstTrustAdopting, Sendable {
  let source: any V3ImmutableObjectReading
  let exchange: V3EnrollmentExchangeCoordinator
  let permanent: any V3EnrollmentFirstTrustAdopting
  let recovery: (any V3EnrollmentFirstTrustAdopting)?
  var validateScope: @Sendable () throws -> Void = {}

  func adopt(
    vaultID: String, invitationDigest: Data, approvedTranscriptDigest: Data,
    at unixTime: UInt64, operationID: VaultTransactionOperationID
  ) throws -> V3DeviceEnrollmentAdoptionReport {
    try validateScope()
    let state = try exchange.resumeJoinerAdoption(
      vaultID: vaultID,
      invitationDigest: invitationDigest, at: unixTime)
    guard let transcript = state.transcript, transcript.digest == approvedTranscriptDigest else {
      throw V3DeviceWrappedEnrollmentAdoptionError.invalidCeremony
    }
    let selected: any V3EnrollmentFirstTrustAdopting
    switch try v3EnrollmentParentProfile(transcript.invitation, source: source) {
    case .permanent: selected = permanent
    case .recovery:
      guard let recovery else { throw V3DeviceWrappedEnrollmentAdoptionError.upgradeRequired }
      selected = recovery
    }
    try validateScope()
    let result = try selected.adopt(
      vaultID: vaultID, invitationDigest: invitationDigest,
      approvedTranscriptDigest: approvedTranscriptDigest, at: unixTime, operationID: operationID)
    try validateScope()
    return result
  }
}

/// Product selection follows exact first trust and an ordinary runtime reopen.
/// Both are guarded by the actual installed ticket, never a new authentication.
struct V3RecoveryEnrollmentProductAdoption: V3EnrollmentFirstTrustAdopting, Sendable {
  typealias RuntimeVerifier =
    @Sendable (
      V3RecoveryEnrollmentAdoptionCommit,
      V3DeviceWrappedVaultKeySessionStore.AuthenticationTicket
    ) throws -> Void
  let source: any V3ImmutableObjectReading
  let checkpoints: any V3ManifestCheckpointStoring
  let ownership: any V3ImmutableTransactionRecoveryAnchorStoring
  let registration: any V3ImmutableTransactionRecoveryAnchorStoring
  let adoption: any V3ImmutableTransactionRecoveryAnchorStoring
  let ceremonies: any V3EnrollmentCeremonyStateStoring
  let cache: any V3CheckpointManifestCaching
  let session: V3DeviceWrappedVaultKeySessionStore
  let loadIdentity: @Sendable (String) throws -> (any V3DeviceWrappedVaultKeyUnwrapping)?
  let verifyRuntime: RuntimeVerifier
  let selectVault: @Sendable (String) throws -> Void
  var completeReplacement: @Sendable (String) throws -> Void = { _ in }
  var validateScope: @Sendable () throws -> Void = {}

  func adopt(
    vaultID: String, invitationDigest: Data, approvedTranscriptDigest: Data,
    at unixTime: UInt64, operationID: VaultTransactionOperationID
  ) throws -> V3DeviceEnrollmentAdoptionReport {
    try validateScope()
    guard let identity = try loadIdentity(vaultID) else {
      throw V3RecoveryEnrollmentAdoptionError.identityUnavailable
    }
    let guarded = V3ScopedDeviceUnwrapper(base: identity, validate: validateScope)
    _ = try V3RecoveryEnrollmentAdoptionService(
      vaultID: vaultID, identity: guarded,
      source: source, checkpointStore: checkpoints, recoveryAnchorStore: ownership,
      registrationAnchorStore: registration, adoptionAnchorStore: adoption,
      ceremonyStore: ceremonies, cache: cache, session: session, validateScope: validateScope
    )
    .adopt(
      invitationDigest: invitationDigest, approvedTranscriptDigest: approvedTranscriptDigest,
      operationID: operationID
    ) { commit, ticket in
      try validateScope()
      try session.requireCurrent(ticket)
      try verifyRuntime(commit, ticket)
      try session.requireCurrent(ticket)
      try validateScope()
      try selectVault(vaultID)
      try session.requireCurrent(ticket)
      try validateScope()
      try completeReplacement(vaultID)
      try session.requireCurrent(ticket)
      try validateScope()
    }
    return .init(vaultID: vaultID, deviceName: identity.publicIdentity.displayName)
  }
}

struct V3ScopedDeviceUnwrapper: V3DeviceWrappedVaultKeyUnwrapping {
  let base: any V3DeviceWrappedVaultKeyUnwrapping
  let validate: @Sendable () throws -> Void
  var vaultID: String { base.vaultID }
  var publicIdentity: V3EnrollmentDeviceIdentity { base.publicIdentity }
  func unwrapDeviceWrappedVaultKey(
    _ ciphertext: V3HPKEWrappedVaultKey,
    context: V3VaultKeyHPKEContext, reason: String
  ) throws -> Data {
    try validate()
    let result = try base.unwrapDeviceWrappedVaultKey(ciphertext, context: context, reason: reason)
    try validate()
    return result
  }
}
