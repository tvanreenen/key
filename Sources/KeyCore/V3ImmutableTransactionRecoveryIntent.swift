import Foundation
import JSONCanonicalization

enum V3ImmutableTransactionRecoveryIntentError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidFormat

    var errorDescription: String? {
        "The version 3 transaction recovery intent is invalid."
    }
}

struct V3ImmutableTransactionRecoveryEntry: Equatable, Sendable {
    let entryID: String
    let digest: Data
}

/// Durable, non-authoritative evidence of one version 3 publication attempt.
///
/// The record contains no secret material and cannot authorize a mutation.
/// Recovery must authenticate the referenced manifest and entry objects, and
/// must still satisfy the expected checkpoint guard, before it can publish or
/// advance anything.
struct V3ImmutableTransactionRecoveryIntent: Equatable, Sendable {
    static let maximumBytes = 4 * 1_024 * 1_024
    static let maximumHeads = 4_096
    static let maximumStagedEntries = 16_384

    let operationID: VaultTransactionOperationID
    let kind: VaultTransactionMutationKind
    let vaultID: String
    let expectedCheckpoint: V3ManifestCheckpoint
    let expectedHeads: [Data]
    let candidateManifestDigest: Data
    let stagedEntries: [V3ImmutableTransactionRecoveryEntry]

    init(
        operationID: VaultTransactionOperationID,
        kind: VaultTransactionMutationKind,
        vaultID: String,
        expectedCheckpoint: V3ManifestCheckpoint,
        expectedHeads: [Data],
        candidateManifestDigest: Data,
        stagedEntries: [V3ImmutableTransactionRecoveryEntry]
    ) throws {
        guard kind != .recoverInterruptedTransaction,
              isValidV3UUID(vaultID),
              expectedCheckpoint.vaultID == vaultID,
              !expectedHeads.isEmpty,
              expectedHeads.count <= Self.maximumHeads,
              expectedHeads.allSatisfy({ $0.count == 32 }),
              Set(expectedHeads).count == expectedHeads.count,
              expectedHeads == expectedHeads.sorted(by: {
                  $0.lexicographicallyPrecedes($1)
              }),
              candidateManifestDigest.count == 32,
              stagedEntries.count <= Self.maximumStagedEntries,
              stagedEntries.allSatisfy({
                  isValidV3UUID($0.entryID) && $0.digest.count == 32
              }),
              Set(stagedEntries.map {
                  V3RecoveryEntryKey(
                      entryID: $0.entryID,
                      digest: $0.digest
                  )
              }).count == stagedEntries.count,
              stagedEntries == stagedEntries.sorted(
                  by: recoveryEntryPrecedes
              )
        else {
            throw V3ImmutableTransactionRecoveryIntentError.invalidFormat
        }
        self.operationID = operationID
        self.kind = kind
        self.vaultID = vaultID
        self.expectedCheckpoint = expectedCheckpoint
        self.expectedHeads = expectedHeads
        self.candidateManifestDigest = candidateManifestDigest
        self.stagedEntries = stagedEntries
    }

    init(canonicalBytes: Data) throws {
        let json: CanonicalJSONValue
        do {
            json = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3ImmutableTransactionRecoveryIntentError.invalidFormat
        }
        guard canonicalBytes.count <= Self.maximumBytes,
              CanonicalJSON.encode(json) == canonicalBytes,
              let object = json.objectValue,
              Set(object.map(\.0)) == Set([
                  "candidateManifestDigest",
                  "expectedCheckpoint",
                  "expectedHeads",
                  "format",
                  "kind",
                  "operationID",
                  "stagedEntries",
                  "vaultID",
                  "version"
              ]),
              recoveryString("format", in: object)
                == "key-vault-transaction-recovery",
              recoveryInteger("version", in: object) == 1,
              let operationIDValue = recoveryString(
                  "operationID",
                  in: object
              ),
              let operationID = try? VaultTransactionOperationID(
                  validating: operationIDValue
              ),
              let kindValue = recoveryString("kind", in: object),
              let kind = VaultTransactionMutationKind(rawValue: kindValue),
              let vaultID = recoveryString("vaultID", in: object),
              let expectedCheckpoint = decodeRecoveryCheckpoint(
                  recoveryMember("expectedCheckpoint", in: object)
              ),
              let expectedHeadValues = recoveryMember(
                  "expectedHeads",
                  in: object
              )?.arrayValue,
              let expectedHeads = decodeRecoveryDigests(
                  expectedHeadValues
              ),
              let candidateDigestValue = recoveryString(
                  "candidateManifestDigest",
                  in: object
              ),
              let candidateManifestDigest = Base64URL.decodeCanonical(
                  candidateDigestValue
              ),
              let entryValues = recoveryMember(
                  "stagedEntries",
                  in: object
              )?.arrayValue,
              let stagedEntries = decodeRecoveryEntries(entryValues)
        else {
            throw V3ImmutableTransactionRecoveryIntentError.invalidFormat
        }
        try self.init(
            operationID: operationID,
            kind: kind,
            vaultID: vaultID,
            expectedCheckpoint: expectedCheckpoint,
            expectedHeads: expectedHeads,
            candidateManifestDigest: candidateManifestDigest,
            stagedEntries: stagedEntries
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            ("format", .string("key-vault-transaction-recovery")),
            ("version", .integer(1)),
            ("operationID", .string(operationID.rawValue)),
            ("kind", .string(kind.rawValue)),
            ("vaultID", .string(vaultID)),
            (
                "expectedCheckpoint",
                .object([
                    (
                        "format",
                        .string("key-vault-manifest-checkpoint")
                    ),
                    ("version", .integer(1)),
                    ("vaultID", .string(expectedCheckpoint.vaultID)),
                    (
                        "envelopeDigest",
                        .string(Base64URL.encode(
                            expectedCheckpoint.envelopeDigest
                        ))
                    )
                ])
            ),
            (
                "expectedHeads",
                .array(expectedHeads.map {
                    .string(Base64URL.encode($0))
                })
            ),
            (
                "candidateManifestDigest",
                .string(Base64URL.encode(candidateManifestDigest))
            ),
            (
                "stagedEntries",
                .array(stagedEntries.map { entry in
                    .object([
                        ("entryID", .string(entry.entryID)),
                        ("digest", .string(Base64URL.encode(entry.digest)))
                    ])
                })
            )
        ]))
    }
}

private struct V3RecoveryEntryKey: Hashable {
    let entryID: String
    let digest: Data
}

private func recoveryEntryPrecedes(
    _ lhs: V3ImmutableTransactionRecoveryEntry,
    _ rhs: V3ImmutableTransactionRecoveryEntry
) -> Bool {
    Data(lhs.entryID.utf8).lexicographicallyPrecedes(Data(rhs.entryID.utf8))
        || (lhs.entryID == rhs.entryID
            && lhs.digest.lexicographicallyPrecedes(rhs.digest))
}

private func decodeRecoveryDigests(
    _ values: [CanonicalJSONValue]
) -> [Data]? {
    var result: [Data] = []
    result.reserveCapacity(values.count)
    for value in values {
        guard let encoded = value.stringValue,
              let digest = Base64URL.decodeCanonical(encoded),
              digest.count == 32
        else {
            return nil
        }
        result.append(digest)
    }
    return result
}

private func decodeRecoveryCheckpoint(
    _ value: CanonicalJSONValue?
) -> V3ManifestCheckpoint? {
    guard let value else {
        return nil
    }
    return try? V3ManifestCheckpoint(
        canonicalBytes: CanonicalJSON.encode(value)
    )
}

private func decodeRecoveryEntries(
    _ values: [CanonicalJSONValue]
) -> [V3ImmutableTransactionRecoveryEntry]? {
    var result: [V3ImmutableTransactionRecoveryEntry] = []
    result.reserveCapacity(values.count)
    for value in values {
        guard let object = value.objectValue,
              Set(object.map(\.0)) == Set(["digest", "entryID"]),
              let entryID = recoveryString("entryID", in: object),
              let encodedDigest = recoveryString("digest", in: object),
              let digest = Base64URL.decodeCanonical(encodedDigest)
        else {
            return nil
        }
        result.append(V3ImmutableTransactionRecoveryEntry(
            entryID: entryID,
            digest: digest
        ))
    }
    return result
}

private func recoveryMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func recoveryString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    recoveryMember(name, in: object)?.stringValue
}

private func recoveryInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    recoveryMember(name, in: object)?.integerValue
}
