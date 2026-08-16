import CryptoKit
import Foundation
internal import JSONCanonicalization
import Security

enum V3ReplacementEnrollmentIntentError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidReview
    case invalidIntent
    case invalidPhaseTransition
    case conflict
    case invalidConfiguration
    case keychainStatus(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidReview:
            "The replacement-device review is invalid."
        case .invalidIntent:
            "The replacement-device intent is invalid."
        case .invalidPhaseTransition:
            "The replacement-device intent cannot advance to that phase."
        case .conflict:
            "The replacement-device intent changed concurrently."
        case .invalidConfiguration:
            "Replacement-device intent storage is not configured."
        case let .keychainStatus(status):
            "Replacement-device intent Keychain operation failed (\(status))."
        }
    }
}

/// Stable, public evidence displayed before one revoked local identity is
/// replaced. This record binds confirmation to exact authenticated authority
/// and an exact retry-safe deletion target; it contains no private key bytes.
///
/// Persisting a review does not make it authoritative. The replacement
/// coordinator must re-observe and revalidate its authority before beginning
/// cleanup from the prepared phase.
struct V3ReplacementEnrollmentReview: Equatable, Sendable {
    private static let maximumCanonicalBytes = 64 * 1024

    let target: V3EnrollmentDeviceIdentityDeletionTarget
    let authority: V3ReplacementDeviceIdentityAuthority

    var vaultID: String { target.vaultID }

    var expectedCheckpoint: V3ManifestCheckpoint {
        switch authority {
        case let .trustedCheckpoint(checkpoint):
            checkpoint
        case let .ownerAuthorizedRevocation(parent, _, _):
            parent
        }
    }

    init(
        target: V3EnrollmentDeviceIdentityDeletionTarget,
        authority: V3ReplacementDeviceIdentityAuthority
    ) throws {
        let checkpoint: V3ManifestCheckpoint
        switch authority {
        case let .trustedCheckpoint(value):
            checkpoint = value
        case let .ownerAuthorizedRevocation(
            parentCheckpoint,
            manifestDigest,
            authorizingDevice
        ):
            guard manifestDigest.count == 32,
                  authorizingDevice.deviceID != target.identity.deviceID
            else {
                throw V3ReplacementEnrollmentIntentError.invalidReview
            }
            checkpoint = parentCheckpoint
        }
        guard target.vaultID == checkpoint.vaultID else {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        self.target = target
        self.authority = authority
    }

    init(
        classification: V3ReplacementDeviceIdentityClassification
    ) throws {
        guard case let .revoked(target, authority) = classification else {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        try self.init(target: target, authority: authority)
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= Self.maximumCanonicalBytes else {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        guard CanonicalJSON.encode(json) == canonicalBytes,
              let object = json.objectValue,
              Set(object.map(\.0)) == Set([
                  "authority", "format", "target", "version"
              ]),
              replacementString("format", in: object)
                == "key-vault-replacement-enrollment-review",
              replacementInteger("version", in: object) == 1,
              let targetValue = replacementMember("target", in: object),
              let authorityValue = replacementMember(
                  "authority",
                  in: object
              )
        else {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        do {
            try self.init(
                target: Self.decodeTarget(targetValue),
                authority: Self.decodeAuthority(authorityValue)
            )
        } catch {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            (
                "format",
                .string("key-vault-replacement-enrollment-review")
            ),
            ("version", .integer(1)),
            ("target", targetValue),
            ("authority", authorityValue),
        ]))
    }

    var digest: Data {
        Data(SHA256.hash(data: canonicalBytes))
    }

    private var targetValue: CanonicalJSONValue {
        .object([
            ("vaultID", .string(target.vaultID)),
            ("identity", target.identity.canonicalValue),
            (
                "recordDigest",
                .string(Base64URL.encode(target.recordDigest))
            ),
        ])
    }

    private var authorityValue: CanonicalJSONValue {
        switch authority {
        case let .trustedCheckpoint(checkpoint):
            .object([
                ("kind", .string("trusted-checkpoint")),
                (
                    "checkpoint",
                    .string(Base64URL.encode(checkpoint.canonicalBytes))
                ),
            ])
        case let .ownerAuthorizedRevocation(
            parentCheckpoint,
            manifestDigest,
            authorizingDevice
        ):
            .object([
                ("kind", .string("owner-authorized-revocation")),
                (
                    "parentCheckpoint",
                    .string(Base64URL.encode(
                        parentCheckpoint.canonicalBytes
                    ))
                ),
                (
                    "manifestDigest",
                    .string(Base64URL.encode(manifestDigest))
                ),
                ("authorizingDevice", authorizingDevice.canonicalValue),
            ])
        }
    }

    private static func decodeTarget(
        _ value: CanonicalJSONValue
    ) throws -> V3EnrollmentDeviceIdentityDeletionTarget {
        guard let object = value.objectValue,
              Set(object.map(\.0)) == Set([
                  "identity", "recordDigest", "vaultID"
              ]),
              let vaultID = replacementString("vaultID", in: object),
              let identityValue = replacementMember("identity", in: object),
              let digestValue = replacementString(
                  "recordDigest",
                  in: object
              ),
              let recordDigest = Base64URL.decodeCanonical(digestValue)
        else {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        return try V3EnrollmentDeviceIdentityDeletionTarget(
            vaultID: vaultID,
            identity: decodeEnrollmentDevice(identityValue),
            recordDigest: recordDigest
        )
    }

    private static func decodeAuthority(
        _ value: CanonicalJSONValue
    ) throws -> V3ReplacementDeviceIdentityAuthority {
        guard let object = value.objectValue,
              let kind = replacementString("kind", in: object)
        else {
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
        switch kind {
        case "trusted-checkpoint":
            guard Set(object.map(\.0)) == Set(["checkpoint", "kind"]),
                  let encoded = replacementString(
                      "checkpoint",
                      in: object
                  ),
                  let bytes = Base64URL.decodeCanonical(encoded)
            else {
                throw V3ReplacementEnrollmentIntentError.invalidReview
            }
            return .trustedCheckpoint(
                try V3ManifestCheckpoint(canonicalBytes: bytes)
            )
        case "owner-authorized-revocation":
            guard Set(object.map(\.0)) == Set([
                "authorizingDevice", "kind", "manifestDigest",
                "parentCheckpoint",
            ]),
                  let checkpointValue = replacementString(
                      "parentCheckpoint",
                      in: object
                  ),
                  let checkpointBytes = Base64URL.decodeCanonical(
                      checkpointValue
                  ),
                  let digestValue = replacementString(
                      "manifestDigest",
                      in: object
                  ),
                  let manifestDigest = Base64URL.decodeCanonical(
                      digestValue
                  ),
                  let deviceValue = replacementMember(
                      "authorizingDevice",
                      in: object
                  )
            else {
                throw V3ReplacementEnrollmentIntentError.invalidReview
            }
            return .ownerAuthorizedRevocation(
                parentCheckpoint: try V3ManifestCheckpoint(
                    canonicalBytes: checkpointBytes
                ),
                manifestDigest: manifestDigest,
                authorizingDevice: try decodeEnrollmentDevice(deviceValue)
            )
        default:
            throw V3ReplacementEnrollmentIntentError.invalidReview
        }
    }
}

enum V3ReplacementEnrollmentIntentPhase: String, Equatable, Sendable {
    /// Confirmation is durable, but current authority must still be checked
    /// before any destructive operation may begin.
    case prepared

    /// Current authority was revalidated and the exact identity deletion was
    /// committed. A retry must not require the key this step may have removed.
    case identityDeletionStarted

    case identityDeleted
    case checkpointDeleted
}

/// Device-only resumption state for ordered replacement cleanup.
///
/// The identity is removed before its rollback checkpoint. Both deletions use
/// exact compare-and-delete primitives, so a crash at either boundary can be
/// retried without deleting newly installed enrollment state.
struct V3ReplacementEnrollmentIntent: Equatable, Sendable {
    private static let maximumCanonicalBytes = 96 * 1024

    let review: V3ReplacementEnrollmentReview
    let phase: V3ReplacementEnrollmentIntentPhase

    var vaultID: String { review.vaultID }

    init(
        review: V3ReplacementEnrollmentReview,
        phase: V3ReplacementEnrollmentIntentPhase = .prepared
    ) {
        self.review = review
        self.phase = phase
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= Self.maximumCanonicalBytes else {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        guard CanonicalJSON.encode(json) == canonicalBytes,
              let object = json.objectValue,
              Set(object.map(\.0)) == Set([
                  "format", "phase", "review", "vaultID", "version"
              ]),
              replacementString("format", in: object)
                == "key-vault-replacement-enrollment-intent",
              replacementInteger("version", in: object) == 1,
              let vaultID = replacementString("vaultID", in: object),
              let reviewValue = replacementString("review", in: object),
              let reviewBytes = Base64URL.decodeCanonical(reviewValue),
              let phaseValue = replacementString("phase", in: object),
              let phase = V3ReplacementEnrollmentIntentPhase(
                  rawValue: phaseValue
              )
        else {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
        do {
            let review = try V3ReplacementEnrollmentReview(
                canonicalBytes: reviewBytes
            )
            guard review.vaultID == vaultID else {
                throw V3ReplacementEnrollmentIntentError.invalidIntent
            }
            self.init(review: review, phase: phase)
        } catch {
            throw V3ReplacementEnrollmentIntentError.invalidIntent
        }
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            (
                "format",
                .string("key-vault-replacement-enrollment-intent")
            ),
            ("version", .integer(1)),
            ("vaultID", .string(vaultID)),
            (
                "review",
                .string(Base64URL.encode(review.canonicalBytes))
            ),
            ("phase", .string(phase.rawValue)),
        ]))
    }

    func advanced(
        to next: V3ReplacementEnrollmentIntentPhase
    ) throws -> V3ReplacementEnrollmentIntent {
        let valid = switch (phase, next) {
        case (.prepared, .identityDeletionStarted),
             (.identityDeletionStarted, .identityDeleted),
             (.identityDeleted, .checkpointDeleted):
            true
        default:
            false
        }
        guard valid else {
            throw V3ReplacementEnrollmentIntentError
                .invalidPhaseTransition
        }
        return V3ReplacementEnrollmentIntent(review: review, phase: next)
    }
}

protocol V3ReplacementEnrollmentIntentStoring: Sendable {
    func loadReplacementIntent(vaultID: String) throws -> Data?

    func replaceReplacementIntent(
        _ intent: Data?,
        expectedIntent: Data?,
        vaultID: String
    ) throws
}

/// Persists replacement progress outside file-provider and Keychain sync.
final class V3ReplacementEnrollmentIntentKeychainStore:
    V3ReplacementEnrollmentIntentStoring,
    @unchecked Sendable
{
    private let configuration: RuntimeConfiguration
    private static let lock = NSLock()

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func loadReplacementIntent(vaultID: String) throws -> Data? {
        Self.lock.lock()
        defer { Self.lock.unlock() }
        return try loadWithoutLock(vaultID: vaultID)
    }

    func replaceReplacementIntent(
        _ intent: Data?,
        expectedIntent: Data?,
        vaultID: String
    ) throws {
        if let intent {
            let decoded = try V3ReplacementEnrollmentIntent(
                canonicalBytes: intent
            )
            guard decoded.vaultID == vaultID else {
                throw V3ReplacementEnrollmentIntentError.invalidIntent
            }
        }

        Self.lock.lock()
        defer { Self.lock.unlock() }
        let current = try loadWithoutLock(vaultID: vaultID)
        guard current == expectedIntent else {
            throw V3ReplacementEnrollmentIntentError.conflict
        }

        let query = try baseQuery(vaultID: vaultID)
        if let intent {
            if current == nil {
                var attributes = query
                attributes[kSecAttrLabel as String] =
                    "key v3 replacement enrollment intent"
                attributes[kSecAttrAccessible as String] =
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                attributes[kSecValueData as String] = intent
                let status = SecItemAdd(attributes as CFDictionary, nil)
                if status == errSecDuplicateItem {
                    throw V3ReplacementEnrollmentIntentError.conflict
                }
                guard status == errSecSuccess else {
                    throw V3ReplacementEnrollmentIntentError
                        .keychainStatus(status)
                }
                return
            }
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: intent] as CFDictionary
            )
            if status == errSecItemNotFound {
                throw V3ReplacementEnrollmentIntentError.conflict
            }
            guard status == errSecSuccess else {
                throw V3ReplacementEnrollmentIntentError
                    .keychainStatus(status)
            }
            return
        }

        guard current != nil else { return }
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            throw V3ReplacementEnrollmentIntentError.conflict
        }
        guard status == errSecSuccess else {
            throw V3ReplacementEnrollmentIntentError
                .keychainStatus(status)
        }
    }

    private func loadWithoutLock(vaultID: String) throws -> Data? {
        var query = try baseQuery(vaultID: vaultID)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        // SAFETY: Security.framework writes one retained result into the
        // stack-local optional for the duration of this synchronous call.
        let status = unsafe SecItemCopyMatching(
            query as CFDictionary,
            &item
        )
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw V3ReplacementEnrollmentIntentError.keychainStatus(
                status == errSecSuccess ? errSecInternalError : status
            )
        }
        return data
    }

    private func baseQuery(vaultID: String) throws -> [String: Any] {
        guard isValidV3UUID(vaultID),
              !configuration.vaultService.isEmpty,
              let accessGroup = configuration.keychainAccessGroup,
              !accessGroup.isEmpty
        else {
            throw V3ReplacementEnrollmentIntentError.invalidConfiguration
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String:
                "\(configuration.vaultService).v3-replacement-enrollment",
            kSecAttrAccount as String: vaultID,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false,
        ]
        if configuration.useDataProtectionKeychain {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        return query
    }
}

private func replacementMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func replacementString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    replacementMember(name, in: object)?.stringValue
}

private func replacementInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    replacementMember(name, in: object)?.integerValue
}
