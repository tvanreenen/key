import Foundation

/// Eligibility to delete one exact revoked local identity. This verifies signed
/// roster history from the Mac's authenticated floor; it never adopts a future
/// checkpoint, opens a revoked epoch, or grants access to future vault data.
struct V3RecoveryReplacementDeviceIdentityAuthorityAdapter:
  V3ReplacementDeviceIdentityAuthorityClassifying, Sendable
{
  let vaultID: String
  let source: any V3ImmutableObjectReading
  let unlock: V3RecoveryVaultUnlockRuntime
  let loadIdentity: @Sendable () throws -> any V3DeviceWrappedVaultKeyUnwrapping
  var validateScope: @Sendable () throws -> Void = {}
  var limits: V3ManifestRepositoryLimits = .standard

  func classifyCurrentAuthority(for target: V3EnrollmentDeviceIdentityDeletionTarget) throws
    -> V3ReplacementDeviceIdentityClassification
  {
    try validateScope()
    guard target.vaultID == vaultID else {
      throw V3ReplacementDeviceIdentityClassificationError.invalidAuthority
    }
    let identity = try loadIdentity()
    guard identity.vaultID == vaultID, identity.publicIdentity == target.identity else {
      throw V3ReplacementDeviceIdentityClassificationError.identityMismatch
    }
    let context = try unlock.authenticatedReadContext(
      reason: "Verify that this Mac's old credentials were revoked before replacing them.")
    let current = context.current
    let initial = try V3ReplacementDeviceIdentityClassifier().classify(
      target, devices: current.envelope.body.fields.devices,
      authority: .trustedCheckpoint(current.checkpoint))
    guard case .active = initial else {
      try context.revalidate()
      try validateScope()
      return initial
    }
    let key = try context.loadVaultKey(keyID: current.envelope.body.fields.keyID)
    let observer = V3RecoveryKeyTransitionRepositoryObserver(
      source: source, limits: limits, maximumParentEdges: 16_384)
    let observed = try observer.observe(from: current, vaultKey: key)
    let matching = observed.head.body.fields.devices.filter {
      $0.identity.deviceID == target.identity.deviceID
    }
    guard matching.count == 1, let terminal = matching.first, terminal.identity == target.identity
    else {
      throw V3ReplacementDeviceIdentityClassificationError.identityMismatch
    }
    let result: V3ReplacementDeviceIdentityClassification
    if terminal.status == .active {
      result = initial
    } else {
      var revocations: [(V3RecoveryManifestEnvelope, V3EnrollmentDeviceIdentity)] = []
      for digest in observed.order {
        guard let child = observed.envelopes[digest], child.parents.count == 1,
          let parentDigest = child.parents.first, let parent = observed.envelopes[parentDigest],
          parent.body.fields.devices.contains(.init(identity: target.identity, status: .active)),
          child.body.fields.devices.contains(.init(identity: target.identity, status: .revoked))
        else { continue }
        guard let signer = child.authorizations.first?.signerDeviceID else {
          throw V3ReplacementDeviceIdentityClassificationError.invalidAuthority
        }
        let plan = try V3DeviceRevocationRosterPolicy().plan(
          checkpoint: .init(vaultID: vaultID, envelopeDigest: parent.digest),
          devices: parent.body.fields.devices, authorizingDeviceID: signer,
          revoking: target.identity.deviceID)
        try V3RecoveryDeviceRevocationValidator(limits: limits).preflightPublic(
          .init(
            plan: plan, envelope: child, stagedEntries: Array(try observed.snapshot(child).values)),
          parent: parent, expectedOwner: plan.authorizingDevice.identity)
        revocations.append((child, plan.authorizingDevice.identity))
      }
      guard revocations.count == 1, let (revocation, owner) = revocations.first else {
        throw V3ReplacementDeviceIdentityClassificationError.conflictingAuthority
      }
      result = try V3ReplacementDeviceIdentityClassifier().classify(
        target, devices: revocation.body.fields.devices,
        authority: .ownerAuthorizedRevocation(
          parentCheckpoint: current.checkpoint,
          manifestDigest: revocation.digest, authorizingDevice: owner))
    }
    // The source cannot change while a Mac approval is pending or while the
    // public history is being inspected. Every later cleanup reclassifies too.
    try context.revalidate()
    guard try observer.observe(from: current, vaultKey: key) == observed else {
      throw V3RecoveryValidationError.sourceChanged
    }
    guard try loadIdentity().publicIdentity == target.identity else {
      throw V3ReplacementDeviceIdentityClassificationError.identityMismatch
    }
    try context.revalidate()
    try validateScope()
    return result
  }
}
