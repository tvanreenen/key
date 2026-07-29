import CryptoKit
import Foundation
import JSONCanonicalization

public enum V3ManifestReplayError: Error, Equatable, LocalizedError {
    case invalidCheckpoint
    case checkpointNotFound
    case vaultMismatch
    case unexpectedHead

    public var errorDescription: String? {
        switch self {
        case .invalidCheckpoint:
            "The local version 3 manifest checkpoint is invalid."
        case .checkpointNotFound:
            "No local version 3 manifest checkpoint exists for this vault."
        case .vaultMismatch:
            "The observed manifest belongs to a different vault."
        case .unexpectedHead:
            "The observed manifest is not the exact head trusted by this device; verify its authenticated ancestry before changing the checkpoint."
        }
    }
}

public enum V3ManifestCheckpointStoreError: Error, Equatable, LocalizedError {
    case invalidConfiguration
    case conflict
    case keychainStatus(Int32)

    public var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            "Version 3 manifest checkpoint storage is not configured."
        case .conflict:
            "The local version 3 manifest checkpoint changed concurrently."
        case let .keychainStatus(status):
            "Version 3 manifest checkpoint Keychain operation failed (\(status))."
        }
    }
}

/// Device-local rollback anchor for one version 3 vault.
///
/// The digest is SHA-256 over the exact canonical manifest-envelope bytes.
/// Checkpoints are deliberately small so they can be stored outside the
/// synchronized vault in this device's non-synchronizing Keychain.
public struct V3ManifestCheckpoint: Equatable, Sendable {
    public let head: V3VaultHead

    public var vaultID: String {
        head.vaultID
    }

    public var envelopeDigest: Data {
        head.envelopeDigest
    }

    public init(head: V3VaultHead) {
        self.head = head
    }

    public init(
        vaultID: String,
        envelopeDigest: Data
    ) throws {
        do {
            self.init(head: try V3VaultHead(
                vaultID: vaultID,
                envelopeDigest: envelopeDigest
            ))
        } catch {
            throw V3ManifestReplayError.invalidCheckpoint
        }
    }

    public init(canonicalBytes: Data) throws {
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3ManifestReplayError.invalidCheckpoint
        }
        guard CanonicalJSON.encode(json) == canonicalBytes,
              let object = json.objectValue,
              Set(object.map(\.0)) == Set([
                "envelopeDigest", "format", "vaultID", "version"
              ]),
              checkpointString("format", in: object) == "key-vault-manifest-checkpoint",
              checkpointInteger("version", in: object) == 1,
              let vaultID = checkpointString("vaultID", in: object),
              let digestString = checkpointString("envelopeDigest", in: object),
              let envelopeDigest = Base64URL.decodeCanonical(digestString)
        else {
            throw V3ManifestReplayError.invalidCheckpoint
        }
        try self.init(
            vaultID: vaultID,
            envelopeDigest: envelopeDigest
        )
    }

    public var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            ("format", .string("key-vault-manifest-checkpoint")),
            ("version", .integer(1)),
            ("vaultID", .string(vaultID)),
            ("envelopeDigest", .string(Base64URL.encode(envelopeDigest)))
        ]))
    }

    init(verifiedManifest: V3VerifiedManifest) throws {
        self.init(head: try V3VaultHead(verifiedManifest: verifiedManifest))
    }
}

/// Authenticated manifest state whose exact head has also passed the
/// device-local freshness gate.
public struct V3TrustedManifest: Equatable, Sendable {
    public let verifiedManifest: V3VerifiedManifest
    public let checkpoint: V3ManifestCheckpoint

    public var envelope: V3ManifestEnvelope {
        verifiedManifest.envelope
    }

    init(
        verifiedManifest: V3VerifiedManifest,
        checkpoint: V3ManifestCheckpoint
    ) {
        self.verifiedManifest = verifiedManifest
        self.checkpoint = checkpoint
    }
}

/// Persists exact checkpoint bytes with an expected-value guard.
///
/// Implementations must never silently replace a value different from
/// `expectedCheckpoint` inside their single mutation owner. Cross-process and
/// manifest/file serialization remain the helper transaction owner's
/// responsibility; clients must not write checkpoints directly.
protocol V3ManifestCheckpointStoring: Sendable {
    func loadCheckpoint(vaultID: String) throws -> Data?

    func replaceCheckpoint(
        _ checkpoint: Data,
        expectedCheckpoint: Data?,
        vaultID: String
    ) throws
}

public struct V3ManifestReplayProtector: Sendable {
    private let store: any V3ManifestCheckpointStoring
    private let authenticator: V3ManifestAuthenticator

    public init(configuration: RuntimeConfiguration) {
        store = V3ManifestCheckpointKeychainStore(configuration: configuration)
        authenticator = V3ManifestAuthenticator()
    }

    init(
        store: any V3ManifestCheckpointStoring,
        authenticator: V3ManifestAuthenticator = V3ManifestAuthenticator()
    ) {
        self.store = store
        self.authenticator = authenticator
    }

    /// Establishes first trust only for an independently anchored local
    /// genesis. Repeating bootstrap with the exact current manifest is
    /// idempotent; a different existing checkpoint is never overwritten.
    public func bootstrapLocalGenesis(
        _ manifestData: Data,
        expectedVaultID: String,
        vaultKey: Data
    ) throws -> V3TrustedManifest {
        if try store.loadCheckpoint(vaultID: expectedVaultID) != nil {
            return try trustCurrent(
                manifestData,
                expectedVaultID: expectedVaultID,
                vaultKey: vaultKey
            )
        }

        let verified = try authenticator.verify(
            manifestData,
            vaultKey: vaultKey,
            trustAnchor: .localGenesis(vaultID: expectedVaultID)
        )
        let checkpoint = try V3ManifestCheckpoint(verifiedManifest: verified)
        try store.replaceCheckpoint(
            checkpoint.canonicalBytes,
            expectedCheckpoint: nil,
            vaultID: expectedVaultID
        )
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: checkpoint
        )
    }

    /// Re-opens only the exact head already anchored in this device's local
    /// checkpoint.
    public func trustCurrent(
        _ manifestData: Data,
        expectedVaultID: String,
        vaultKey: Data
    ) throws -> V3TrustedManifest {
        guard let checkpointData = try store.loadCheckpoint(vaultID: expectedVaultID) else {
            throw V3ManifestReplayError.checkpointNotFound
        }
        let checkpoint = try V3ManifestCheckpoint(canonicalBytes: checkpointData)
        guard checkpoint.vaultID == expectedVaultID else {
            throw V3ManifestReplayError.vaultMismatch
        }

        let observed = try authenticator.parse(manifestData)
        let observedBody = observed.content.manifest
        guard observedBody.vaultID == expectedVaultID else {
            throw V3ManifestReplayError.vaultMismatch
        }

        let observedDigest = Data(SHA256.hash(data: manifestData))
        guard observedDigest == checkpoint.envelopeDigest else {
            throw V3ManifestReplayError.unexpectedHead
        }

        let verified = try authenticator.verifyCheckpointedCurrent(
            manifestData,
            vaultKey: vaultKey,
            checkpoint: checkpoint
        )
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: checkpoint
        )
    }

    /// Accepts one durably committed exact child of the locally trusted
    /// current manifest and advances the checkpoint only after every
    /// authentication and semantic check succeeds.
    ///
    /// The transaction layer must retain the parent for recovery and durably
    /// publish the candidate before calling this method. Parent and candidate
    /// keys are separate because an authorized transition may replace the
    /// vault key.
    public func acceptCommittedChild(
        to candidateData: Data,
        from trustedParentData: Data,
        expectedVaultID: String,
        trustedParentVaultKey: Data,
        candidateVaultKey: Data
    ) throws -> V3TrustedManifest {
        let parent = try trustCurrent(
            trustedParentData,
            expectedVaultID: expectedVaultID,
            vaultKey: trustedParentVaultKey
        )
        let verified = try authenticator.verify(
            candidateData,
            vaultKey: candidateVaultKey,
            trustAnchor: .parent(trustedParentData)
        )
        guard verified.envelope.content.manifest.vaultID == expectedVaultID else {
            throw V3ManifestReplayError.vaultMismatch
        }

        let nextCheckpoint = try V3ManifestCheckpoint(verifiedManifest: verified)
        try store.replaceCheckpoint(
            nextCheckpoint.canonicalBytes,
            expectedCheckpoint: parent.checkpoint.canonicalBytes,
            vaultID: expectedVaultID
        )
        return V3TrustedManifest(
            verifiedManifest: verified,
            checkpoint: nextCheckpoint
        )
    }
}

private func checkpointString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    object.first(where: { $0.0 == name })?.1.stringValue
}

private func checkpointInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    object.first(where: { $0.0 == name })?.1.integerValue
}
