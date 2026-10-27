import Foundation

/// Public format dispatch produces an invocation, never authenticated authority.
/// The host owns serialization, cancellation and retirement of resident state.
struct KeyRecoverySharingInvocation {
  let changesCheckpoint: Bool
  let perform: () throws -> KeyServiceResponse
}

struct KeyRecoverySharingCapability {
  let prepare:
    (
      KeyShareRequest, String?, KeyRecoveryRequestScope
    ) throws -> KeyRecoverySharingInvocation?
}
