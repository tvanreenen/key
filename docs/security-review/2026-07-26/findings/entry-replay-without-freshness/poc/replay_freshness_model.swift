import Foundation

struct AuthenticatedEnvelope {
    let revision: UInt64
    let payloadLabel: String
    let authenticationValid: Bool
}

struct TrustedEntryState {
    let currentRevision: UInt64
}

func legacyPolicyAccepts(_ envelope: AuthenticatedEnvelope) -> Bool {
    envelope.authenticationValid
}

func freshnessAwarePolicyAccepts(
    _ envelope: AuthenticatedEnvelope,
    trustedState: TrustedEntryState
) -> Bool {
    envelope.authenticationValid
        && envelope.revision == trustedState.currentRevision
}

let historicalEnvelope = AuthenticatedEnvelope(
    revision: 1,
    payloadLabel: "historical",
    authenticationValid: true
)
let currentEnvelope = AuthenticatedEnvelope(
    revision: 2,
    payloadLabel: "current",
    authenticationValid: true
)
let trustedState = TrustedEntryState(currentRevision: currentEnvelope.revision)

let legacyCurrent = legacyPolicyAccepts(currentEnvelope)
let legacyHistorical = legacyPolicyAccepts(historicalEnvelope)
let fixedHistorical = freshnessAwarePolicyAccepts(
    historicalEnvelope,
    trustedState: trustedState
)

print("[legacy] current authentic envelope accepted: \(legacyCurrent)")
print("[legacy] historical authentic envelope accepted: \(legacyHistorical)")
print(
    "[fixed] historical revision \(historicalEnvelope.revision) " +
    "vs pinned revision \(trustedState.currentRevision) accepted: " +
    "\(fixedHistorical)"
)

precondition(legacyCurrent)
precondition(legacyHistorical)
precondition(!fixedHistorical)
print("[+] regression invariant holds")
