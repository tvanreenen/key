import CryptoKit
import Foundation

enum V3DeviceWrappedCatchUpTransitionOpeningError:
    Error,
    Equatable,
    LocalizedError
{
    case temporaryUnavailable
    case authenticationCancelled
    case deviceRevoked
    case recoveryRequired

    var errorDescription: String? {
        switch self {
        case .temporaryUnavailable:
            "The complete authenticated key transition is not available from the file provider yet."
        case .authenticationCancelled:
            "Device authentication was cancelled while opening the next vault key."
        case .deviceRevoked:
            "This Mac is no longer active in the next vault-key epoch."
        case .recoveryRequired:
            "The owner-authorized key transition could not be authenticated completely."
        }
    }
}

/// One fully authenticated enrollment transition and its transient next key.
/// The caller still owns checkpoint comparison and in-memory session change.
struct V3DeviceWrappedOpenedCatchUpTransition: Equatable, Sendable {
    let trustedCheckpoint: V3DeviceWrappedTrustedCheckpoint
    let vaultKey: Data
    let authorizingOwner: V3EnrollmentDeviceIdentity
}

/// Opens one owner-authorized enrollment transition without changing trust.
///
/// Provider bytes must first pass the public owner-signature preflight. Only
/// then may this type invoke the wrapper addressed to the exact local device.
/// The recovered key authenticates the candidate HMAC before entry reads, and
/// the existing anchored validator proves the complete snapshot was resealed
/// without changing plaintext.
struct V3DeviceWrappedCatchUpTransitionOpener: Sendable {
    private struct EntryBudget {
        var objects: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        var totalBytes = 0
    }

    private let source: any V3ImmutableObjectReading
    private let limits: V3ManifestRepositoryLimits
    private let validator: V3DeviceWrappedEnrollmentTransitionValidator
    private let entryCipher = V3EntryCipher()

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

    func open(
        manifestData: Data,
        manifestDigest: Data,
        parent: V3DeviceWrappedTrustedCheckpoint,
        currentVaultKey: Data,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        reason: String
    ) throws -> V3DeviceWrappedOpenedCatchUpTransition {
        let authorized = try validator.preflightOwnerAuthorizedCandidate(
            manifestData: manifestData,
            manifestDigest: manifestDigest,
            parent: parent,
            currentVaultKey: currentVaultKey
        )
        let nextVaultKey = try openAddressedVaultKey(
            authorized.candidate,
            identity: identity,
            reason: reason
        )
        guard (try? V3ManifestAuthenticator.isValidAuthenticationTag(
            authorized.candidate.authenticationTag,
            canonicalContent: authorized.candidate.canonicalContentBytes,
            vaultID: authorized.candidate.body.vaultID,
            vaultKey: nextVaultKey
        )) == true else {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }

        var budget = EntryBudget()
        let currentEntries = try loadEntries(
            parent.envelope.body.entries,
            vaultID: parent.envelope.body.vaultID,
            budget: &budget
        )
        let candidateEntries = try loadEntries(
            authorized.candidate.body.entries,
            vaultID: authorized.candidate.body.vaultID,
            budget: &budget
        )
        let stagedEntries = try authorized.candidate.body.entries.map {
            guard let entry = candidateEntries[try entryObjectKey($0)] else {
                throw V3DeviceWrappedCatchUpTransitionOpeningError
                    .recoveryRequired
            }
            return entry
        }
        let transition = V3DeviceWrappedEnrollmentTransitionCandidate(
            expectedCheckpoint: parent.checkpoint,
            body: authorized.candidate.body,
            manifestData: manifestData,
            manifestDigest: manifestDigest,
            stagedEntries: stagedEntries,
            // Catch-up revalidates immutable owner authorization and does not
            // depend on the expired interactive enrollment transcript.
            transcriptDigest: Data(repeating: 0, count: 32)
        )
        let validated: V3DeviceWrappedValidatedEnrollmentTransition
        do {
            validated = try validator.validateAnchored(
                transition,
                parent: parent,
                currentEntries: currentEntries,
                currentVaultKey: currentVaultKey,
                nextVaultKey: nextVaultKey,
                expectedOwner: authorized.authorizingOwner
            )
        } catch {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }
        let checkpoint: V3ManifestCheckpoint
        do {
            checkpoint = try V3ManifestCheckpoint(
                vaultID: validated.candidate.body.vaultID,
                envelopeDigest: validated.manifestDigest
            )
        } catch {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }
        return V3DeviceWrappedOpenedCatchUpTransition(
            trustedCheckpoint: V3DeviceWrappedTrustedCheckpoint(
                checkpoint: checkpoint,
                envelope: validated.candidate
            ),
            vaultKey: nextVaultKey,
            authorizingOwner: authorized.authorizingOwner
        )
    }

    private func openAddressedVaultKey(
        _ candidate: V3DeviceWrappedManifestEnvelope,
        identity: any V3DeviceWrappedVaultKeyUnwrapping,
        reason: String
    ) throws -> Data {
        let deviceID = identity.publicIdentity.deviceID
        guard !reason.isEmpty,
              identity.vaultID == candidate.body.vaultID,
              let device = candidate.body.devices.first(where: {
                  $0.identity.deviceID == deviceID
              }),
              device.identity == identity.publicIdentity
        else {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }
        guard device.status == .active else {
            throw V3DeviceWrappedCatchUpTransitionOpeningError.deviceRevoked
        }
        guard let wrapped = candidate.body.wrappedKeys.first(where: {
            $0.recipientDeviceID == deviceID
        }), let context = try? V3VaultKeyHPKEContext(
            vaultID: candidate.body.vaultID,
            keyID: candidate.body.keyID,
            authorityTransitionID: candidate.body.authorityTransitionID,
            recipientDeviceID: deviceID
        ) else {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }

        let key: Data
        do {
            key = try identity.unwrapDeviceWrappedVaultKey(
                wrapped.wrappedKey,
                context: context,
                reason: reason
            )
        } catch V3EnrollmentDeviceIdentityStoreError.authenticationCancelled {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .authenticationCancelled
        } catch {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }
        guard key.count == 32,
              (try? V3VaultKeyID.derive(
                  vaultKey: key,
                  vaultID: candidate.body.vaultID
              )) == candidate.body.keyID
        else {
            throw V3DeviceWrappedCatchUpTransitionOpeningError
                .recoveryRequired
        }
        return key
    }

    private func loadEntries(
        _ entries: [V3ManifestEntry],
        vaultID: String,
        budget: inout EntryBudget
    ) throws -> [V3EntryObjectKey: V3EncryptedEntry] {
        var result: [V3EntryObjectKey: V3EncryptedEntry] = [:]
        for manifestEntry in entries {
            let key: V3EntryObjectKey
            let context: V3EntryAuthenticationContext
            do {
                key = try entryObjectKey(manifestEntry)
                context = try V3EntryAuthenticationContext(
                    vaultID: vaultID,
                    entry: manifestEntry
                )
            } catch {
                throw V3DeviceWrappedCatchUpTransitionOpeningError
                    .recoveryRequired
            }
            let encrypted: V3EncryptedEntry
            if let existing = budget.objects[key] {
                encrypted = existing
            } else {
                guard budget.objects.count
                        < limits.maximumReferencedEntryObjects
                else {
                    throw V3DeviceWrappedCatchUpTransitionOpeningError
                        .recoveryRequired
                }
                let read: V3RepositoryObjectRead
                do {
                    read = try source.readEntry(
                        entryID: key.entryID,
                        digest: key.digest,
                        maximumBytes: limits.maximumEntryBytes
                    )
                } catch {
                    throw V3DeviceWrappedCatchUpTransitionOpeningError
                        .recoveryRequired
                }
                let data: Data
                switch read {
                case let .available(value):
                    data = value
                case .unavailable:
                    throw V3DeviceWrappedCatchUpTransitionOpeningError
                        .temporaryUnavailable
                case .invalid, .tooLarge:
                    throw V3DeviceWrappedCatchUpTransitionOpeningError
                        .recoveryRequired
                }
                guard data.count <= limits.maximumEntryBytes,
                      data.count
                        <= limits.maximumTotalEntryBytes - budget.totalBytes,
                      Data(SHA256.hash(data: data)) == key.digest,
                      let parsed = try? entryCipher.parse(data)
                else {
                    throw V3DeviceWrappedCatchUpTransitionOpeningError
                        .recoveryRequired
                }
                budget.totalBytes += data.count
                budget.objects[key] = parsed
                encrypted = parsed
            }
            guard encrypted.context == context,
                  result.updateValue(encrypted, forKey: key) == nil
            else {
                throw V3DeviceWrappedCatchUpTransitionOpeningError
                    .recoveryRequired
            }
        }
        return result
    }
}
