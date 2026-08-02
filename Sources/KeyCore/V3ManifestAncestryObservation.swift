import Foundation

/// Produces a complete authenticated ancestry proof from current repository
/// state.
///
/// Implementations must not return incomplete, recovery-required, or
/// unauthenticated state as a proof. Callers use this only from a serialized
/// mutation boundary. Resource usage must be the exact bounded usage captured
/// while producing the proof.
struct V3ManifestAncestryObservation: Equatable, Sendable {
    let proof: V3ManifestAncestryProof
    let resourceUsage: V3ManifestRepositoryUsage
}

protocol V3ManifestAncestryObserving: Sendable {
    func observeAncestry() throws -> V3ManifestAncestryObservation
}
