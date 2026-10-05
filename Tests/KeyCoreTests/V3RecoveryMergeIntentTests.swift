import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3RecoveryMergeIntentTests {
  private static let vaultID = V3RecoveryRegistrationTests.vaultID
  private let heads = [Data(repeating: 1, count: 32), Data(repeating: 2, count: 32)]
  private let choice = VaultConflictResolution(
    conflictID: "c-" + String(repeating: "a", count: 64),
    versionID: String(repeating: "b", count: 16))

  @Test(arguments: [false, true])
  func versionThreeRoundTripsExactSortedHeadsAndSelectorsWithoutPlaintext(automatic: Bool) throws {
    let intent = try make(
      kind: automatic ? .mergeHeads : .resolveConflict, choices: automatic ? [] : [choice])
    let decoded = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: intent.canonicalBytes)
    #expect(decoded == intent && decoded.canonicalBytes == intent.canonicalBytes)
    let object = try #require(CanonicalJSON.parse(intent.canonicalBytes).objectValue)
    #expect(object.first { $0.0 == "version" }?.1.integerValue == 3)
    #expect(decoded.expectedHeads == heads && decoded.enrollmentTranscriptDigest == nil)
    #expect(decoded.recoveryMergeResolutions == (automatic ? [] : [choice]))
    #expect(
      Set(object.map(\.0))
        == Set([
          "format", "version", "operationID", "kind", "vaultID", "expectedCheckpoint",
          "expectedHeads",
          "candidateManifestDigest", "stagedEntries", "recoveryMergeResolutions",
        ]))
  }

  @Test(arguments: [false, true])
  func existingOrdinaryAndEnrollmentSchemasRetainExactVersions(enrollment: Bool) throws {
    let intent = try make(
      kind: enrollment ? .enrollDevice : .mergeHeads, choices: nil,
      enrollment: enrollment ? Data(repeating: 5, count: 32) : nil)
    let decoded = try V3ImmutableTransactionRecoveryIntent(canonicalBytes: intent.canonicalBytes)
    let object = try #require(CanonicalJSON.parse(intent.canonicalBytes).objectValue)
    #expect(decoded == intent && decoded.recoveryMergeResolutions == nil)
    #expect(object.first { $0.0 == "version" }?.1.integerValue == (enrollment ? 2 : 1))
    // The existing generic publisher already supports multi-head version 1.
    // New merge support must not reinterpret or rewrite that schema.
    #expect(decoded.expectedHeads == heads)
  }

  @Test(arguments: 0..<11)
  func malformedMergeContextRefusesBeforePersisting(variant: Int) throws {
    let context: [VaultConflictResolution]?
    let kind: VaultTransactionMutationKind
    let expected: [Data]
    let enrollment: Data?
    switch variant {
    case 0:
      context = [choice]
      kind = .mergeHeads
      expected = heads
      enrollment = nil
    case 1:
      context = []
      kind = .resolveConflict
      expected = heads
      enrollment = nil
    case 2:
      context = []
      kind = .editEntry
      expected = heads
      enrollment = nil
    case 3:
      context = []
      kind = .mergeHeads
      expected = [heads[0]]
      enrollment = nil
    case 4:
      context = [choice, choice]
      kind = .resolveConflict
      expected = heads
      enrollment = nil
    case 5:
      context = [choice]
      kind = .resolveConflict
      expected = heads.reversed()
      enrollment = nil
    case 6:
      context = [choice]
      kind = .resolveConflict
      expected = heads
      enrollment = Data(repeating: 5, count: 32)
    case 7:
      context = [.init(conflictID: "name instead of selector", versionID: choice.versionID)]
      kind = .resolveConflict
      expected = heads
      enrollment = nil
    case 8:
      context = [.init(conflictID: choice.conflictID, versionID: "../unexpected-path")]
      kind = .resolveConflict
      expected = heads
      enrollment = nil
    case 9:
      context = [.init(conflictID: choice.conflictID, versionID: "short")]
      kind = .resolveConflict
      expected = heads
      enrollment = nil
    default:
      context = [.init(conflictID: choice.conflictID, versionID: String(repeating: "a", count: 65))]
      kind = .resolveConflict
      expected = heads
      enrollment = nil
    }
    #expect(throws: V3ImmutableTransactionRecoveryIntentError.invalidFormat) {
      try make(kind: kind, choices: context, enrollment: enrollment, expected: expected)
    }
  }

  @Test(arguments: 0..<7)
  func strictCanonicalVersionedSchemaRejectsUnknownMissingAndSubstitutedFields(variant: Int) throws
  {
    let intent = try make(kind: .resolveConflict, choices: [choice])
    var object = try #require(CanonicalJSON.parse(intent.canonicalBytes).objectValue)
    switch variant {
    case 0:
      object.append(
        ("enrollmentTranscriptDigest", .string(Base64URL.encode(Data(repeating: 5, count: 32)))))
    case 1: object.removeAll { $0.0 == "recoveryMergeResolutions" }
    case 2: object = object.map { $0.0 == "version" ? ($0.0, .integer(1)) : $0 }
    case 3: object = object.map { $0.0 == "version" ? ($0.0, .integer(4)) : $0 }
    case 4: object = object.map { $0.0 == "recoveryMergeResolutions" ? ($0.0, .null) : $0 }
    case 5:
      object = object.map {
        $0.0 == "recoveryMergeResolutions"
          ? (
            $0.0,
            .array([
              .object([
                ("conflictID", .string(choice.conflictID)),
                ("versionID", .string(choice.versionID)), ("extra", .string("no")),
              ])
            ])
          ) : $0
      }
    default: break
    }
    let bytes = CanonicalJSON.encode(.object(object)) + (variant == 6 ? Data(" ".utf8) : Data())
    #expect(throws: V3ImmutableTransactionRecoveryIntentError.invalidFormat) {
      try V3ImmutableTransactionRecoveryIntent(canonicalBytes: bytes)
    }
  }

  @Test func oversizedIntentRefusesBeforeParsing() {
    #expect(throws: V3ImmutableTransactionRecoveryIntentError.invalidFormat) {
      try V3ImmutableTransactionRecoveryIntent(
        canonicalBytes: Data(
          repeating: 123, count: V3ImmutableTransactionRecoveryIntent.maximumBytes + 1))
    }
  }

  private func make(
    kind: VaultTransactionMutationKind, choices: [VaultConflictResolution]?,
    enrollment: Data? = nil,
    expected: [Data]? = nil
  ) throws -> V3ImmutableTransactionRecoveryIntent {
    try V3ImmutableTransactionRecoveryIntent(
      operationID: VaultTransactionOperationID(), kind: kind, vaultID: Self.vaultID,
      expectedCheckpoint: V3ManifestCheckpoint(
        vaultID: Self.vaultID, envelopeDigest: Data(repeating: 0, count: 32)),
      expectedHeads: expected ?? heads, candidateManifestDigest: Data(repeating: 3, count: 32),
      stagedEntries: [],
      enrollmentTranscriptDigest: enrollment, recoveryMergeResolutions: choices)
  }
}
