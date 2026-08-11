import CryptoKit
import Foundation

/// The next publicly authenticated key transition, if one can be selected
/// without assigning authority to provider ordering or timestamps.
enum V3DeviceWrappedKeyTransitionDiscoveryOutcome: Equatable, Sendable {
    case none
    case candidate(manifestData: Data, manifestDigest: Data)
    case competingCandidates([Data])
}

protocol V3DeviceWrappedKeyTransitionDiscovering: Sendable {
    func discover(
        from parent: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey: Data
    ) throws -> V3DeviceWrappedKeyTransitionDiscoveryOutcome
}

/// Finds direct owner-authorized key transitions from one exact checkpoint.
///
/// Discovery is deliberately public-key-only. It validates the current trust
/// anchor and each candidate's active-owner signature, but it never invokes a
/// device wrapper or changes the checkpoint. Unrelated, incomplete, and
/// unauthenticated provider objects gain no authority from being present.
struct V3DeviceWrappedKeyTransitionDiscovery:
    V3DeviceWrappedKeyTransitionDiscovering,
    Sendable
{
    private struct Candidate: Sendable {
        let manifestData: Data
        let manifestDigest: Data
    }

    private let source: any V3ImmutableObjectReading
    private let limits: V3ManifestRepositoryLimits
    private let validator: V3DeviceWrappedEnrollmentTransitionValidator

    init(
        source: any V3ImmutableObjectReading,
        limits: V3ManifestRepositoryLimits = .standard
    ) {
        self.source = source
        self.limits = limits
        validator = V3DeviceWrappedEnrollmentTransitionValidator(
            limits: limits
        )
    }

    func discover(
        from parent: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey: Data
    ) throws -> V3DeviceWrappedKeyTransitionDiscoveryOutcome {
        let parentData = parent.envelope.canonicalBytes
        guard parent.checkpoint.vaultID == parent.envelope.body.vaultID,
              Data(SHA256.hash(data: parentData))
                == parent.checkpoint.envelopeDigest,
              (try? V3VaultKeyID.derive(
                  vaultKey: currentVaultKey,
                  vaultID: parent.checkpoint.vaultID
              )) == parent.envelope.body.keyID,
              (try? V3ManifestAuthenticator.isValidAuthenticationTag(
                  parent.envelope.authenticationTag,
                  canonicalContent: parent.envelope.canonicalContentBytes,
                  vaultID: parent.checkpoint.vaultID,
                  vaultKey: currentVaultKey
              )) == true
        else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        let listing = try loadListing()
        guard listing.objectCount <= limits.maximumManifestObjects,
              listing.objectCount >= listing.digests.count,
              listing.digests.allSatisfy({ $0.count == 32 }),
              Set(listing.digests).count == listing.digests.count
        else {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }

        var candidates: [Candidate] = []
        var totalBytes = 0
        for digest in listing.digests.sorted(by: {
            $0.lexicographicallyPrecedes($1)
        }) {
            let read: V3RepositoryObjectRead
            do {
                read = try source.readManifest(
                    digest: digest,
                    maximumBytes: limits.maximumManifestBytes
                )
            } catch {
                throw V3DeviceWrappedCatchUpError.recoveryRequired
            }
            let data: Data
            switch read {
            case let .available(value):
                data = value
            case .unavailable:
                // The child relationship cannot be checked until the listed
                // object arrives. Advancing past it could hide a competing
                // owner-authorized transition and fork the key history.
                throw V3DeviceWrappedCatchUpError.temporaryUnavailable
            case .invalid, .tooLarge:
                // Invalid unrelated objects do not acquire authority from a
                // filename alone. Reachable candidates are authenticated
                // below before they can affect the result.
                continue
            }
            guard data.count <= limits.maximumManifestBytes,
                  data.count
                    <= limits.maximumTotalManifestBytes - totalBytes
            else {
                throw V3DeviceWrappedCatchUpError.recoveryRequired
            }
            totalBytes += data.count
            guard Data(SHA256.hash(data: data)) == digest else {
                continue
            }
            guard digest != parent.checkpoint.envelopeDigest else {
                continue
            }
            do {
                _ = try validator.preflightOwnerAuthorizedCandidate(
                    manifestData: data,
                    manifestDigest: digest,
                    parent: parent,
                    currentVaultKey: currentVaultKey
                )
                candidates.append(Candidate(
                    manifestData: data,
                    manifestDigest: digest
                ))
            } catch is V3DeviceWrappedEnrollmentValidationError {
                // Invalid or unrelated objects are not authority inputs.
                continue
            } catch is V3DeviceWrappedUnlockError {
                // A provider candidate cannot force an upgrade before it can
                // be authenticated under a format this client understands.
                continue
            } catch {
                throw V3DeviceWrappedCatchUpError.recoveryRequired
            }
        }

        switch candidates.count {
        case 0:
            return .none
        case 1:
            let candidate = candidates[0]
            return .candidate(
                manifestData: candidate.manifestData,
                manifestDigest: candidate.manifestDigest
            )
        default:
            return .competingCandidates(candidates.map(\.manifestDigest))
        }
    }

    private func loadListing() throws -> (
        digests: [Data],
        objectCount: Int
    ) {
        let listing: V3RepositoryDirectoryListing
        do {
            listing = try source.manifestDigests(
                maximumCount: limits.maximumManifestObjects
            )
        } catch {
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
        switch listing {
        case let .available(digests, objectCount):
            return (digests, objectCount)
        case .unavailable:
            throw V3DeviceWrappedCatchUpError.temporaryUnavailable
        case .invalid, .limitExceeded:
            throw V3DeviceWrappedCatchUpError.recoveryRequired
        }
    }
}
