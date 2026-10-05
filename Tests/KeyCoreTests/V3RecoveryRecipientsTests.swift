import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

struct V3RecoveryRecipientsTests {
  private static let generation = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
  private static let registration = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6"
  private static let publicKey =
    "BG_wO5SSQc4drdQ1GeaWDgqFtBppoFwygQOqK84VlMoWPE91OlW_AdxT9sCwx-7ni0DG_30lqW4igrmJzvccFEo"
  private static let recipientID = "1C44ovwuYKXCbX5whdWXuFLGjBACYSCx3E2H-cnO7yU"

  @Test
  func recipientIdentityAndRosterHaveExactCanonicalFixtures() throws {
    let roster = try Self.fixture()
    #expect(roster.recipients[0].recipientID.rawValue == Self.recipientID)
    // Fixed software point and framing bytes, not a hardware credential or valid AEAD box.
    let expected =
      "{\"generationID\":\"\(Self.generation)\",\"recipients\":[{\"publicKey\":{\"algorithm\":\"P-256-ECDH\",\"encoding\":\"x963\",\"value\":\"\(Self.publicKey)\"},\"recipientID\":\"\(Self.recipientID)\",\"registrationID\":\"\(Self.registration)\",\"slot\":\"9d\",\"status\":\"active\"}],\"version\":1,\"wrappedKeys\":[{\"ciphertext\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\",\"encapsulatedKey\":\"\(Self.publicKey)\",\"recipientID\":\"\(Self.recipientID)\",\"registrationID\":\"\(Self.registration)\"}]}"
    #expect(roster.canonicalBytes == Data(expected.utf8))
    #expect(try V3RecoveryRosterCodec().parseCanonical(Data(expected.utf8)) == roster)
    #expect(try V3RecoveryRosterCodec().decode(roster.canonicalValue) == roster)
    let key = try #require(Base64URL.decodeCanonical(Self.publicKey))
    #expect(
      try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
        .publicKey.x963Representation == key)
    var independentInput = Data("work.tvr.key/v3/recovery-recipient-id/v1\0".utf8)
    independentInput.append(key)
    #expect(Base64URL.encode(Data(SHA256.hash(data: independentInput))) == Self.recipientID)
  }

  @Test
  func constructorsRejectNoncanonicalIdentifiersAndInvalidPoints() throws {
    for key in [Data(), Data(repeating: 0, count: 65), Data([4]) + Data(repeating: 0, count: 64)] {
      #expect(throws: V3RecoveryRecipientError.invalidRecipient) {
        try V3RecoveryRecipient(
          registrationID: Self.registration, publicKey: key, slot: .keyManagement, status: .active)
      }
    }
    for registration in ["", "not-a-uuid", Self.registration.uppercased()] {
      #expect(throws: V3RecoveryRecipientError.invalidRecipient) {
        try Self.recipient(registration: registration)
      }
    }
    for id in ["", Self.recipientID + "=", String(repeating: "a", count: 100_000)] {
      #expect(throws: V3RecoveryRecipientError.invalidRecipient) {
        try V3RecoveryRecipientID(rawValue: id)
      }
    }
  }

  @Test
  func exactCoverageRejectsMissingExtraRevokedAndMismatchedRegistrations() throws {
    let good = try Self.fixture()
    let record = good.recipients[0]
    let wrapped = good.wrappedKeys[0]
    let wrongRegistration = try V3RecoveryWrappedKey(
      recipientID: wrapped.recipientID, registrationID: Self.generation,
      wrappedKey: wrapped.wrappedKey)
    let unknown = try V3RecoveryWrappedKey(
      recipientID: V3RecoveryRecipientID(rawValue: Base64URL.encode(Data(repeating: 0, count: 32))),
      registrationID: record.registrationID, wrappedKey: wrapped.wrappedKey)
    for wrappers in [[], [wrapped, wrapped], [wrongRegistration], [unknown]] {
      #expect(throws: V3RecoveryRecipientError.invalidCoverage) {
        try V3RecoveryRoster(
          generationID: Self.generation, recipients: [record], wrappedKeys: wrappers)
      }
    }
    let revoked = try Self.recipient(status: .revoked)
    #expect(throws: V3RecoveryRecipientError.invalidCoverage) {
      try V3RecoveryRoster(
        generationID: Self.generation, recipients: [revoked], wrappedKeys: [wrapped])
    }
    _ = try V3RecoveryRoster(generationID: Self.generation, recipients: [revoked], wrappedKeys: [])
    _ = try V3RecoveryRoster(generationID: Self.generation, recipients: [], wrappedKeys: [])
  }

  @Test
  func duplicateCredentialsRegistrationsAndWrongOrderAreRejected() throws {
    let good = try Self.fixture()
    let sameKeyNewRegistration = try Self.recipient(registration: Self.generation, status: .revoked)
    #expect(throws: V3RecoveryRecipientError.invalidCoverage) {
      try V3RecoveryRoster(
        generationID: Self.generation,
        recipients: [good.recipients[0], sameKeyNewRegistration], wrappedKeys: good.wrappedKeys)
    }
    let different = try V3RecoveryRecipient(
      registrationID: Self.registration,
      publicKey: P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 2, count: 32))
        .publicKey.x963Representation,
      slot: .keyManagement, status: .revoked)
    let repeatedRegistration = [good.recipients[0], different].sorted {
      $0.recipientID.rawValue < $1.recipientID.rawValue
    }
    #expect(throws: V3RecoveryRecipientError.invalidCoverage) {
      try V3RecoveryRoster(
        generationID: Self.generation, recipients: repeatedRegistration,
        wrappedKeys: good.wrappedKeys)
    }
    let second = try V3RecoveryRecipient(
      registrationID: Self.generation, publicKey: different.publicKey, slot: .keyManagement,
      status: .active)
    let secondWrapper = try V3RecoveryWrappedKey(
      recipientID: second.recipientID, registrationID: second.registrationID,
      wrappedKey: good.wrappedKeys[0].wrappedKey)
    let records = [good.recipients[0], second].sorted {
      $0.recipientID.rawValue < $1.recipientID.rawValue
    }
    let wrappers = [good.wrappedKeys[0], secondWrapper].sorted {
      $0.recipientID.rawValue < $1.recipientID.rawValue
    }
    _ = try V3RecoveryRoster(
      generationID: Self.generation, recipients: records, wrappedKeys: wrappers)
    for (recipients, keys) in [
      (Array(records.reversed()), wrappers), (records, Array(wrappers.reversed())),
    ] {
      #expect(throws: V3RecoveryRecipientError.invalidCoverage) {
        try V3RecoveryRoster(
          generationID: Self.generation, recipients: recipients, wrappedKeys: keys)
      }
    }
  }

  @Test
  func codecsRejectUnknownMissingAndDuplicateFieldsAtEveryLevel() throws {
    let root = try Self.fixture().canonicalValue
    let recipient = try #require(Self.member("recipients", in: root).arrayValue?.first)
    let key = try Self.member("publicKey", in: recipient)
    let wrapper = try #require(Self.member("wrappedKeys", in: root).arrayValue?.first)
    func variants(_ value: CanonicalJSONValue) throws -> [CanonicalJSONValue] {
      let fields = try #require(value.objectValue)
      return [
        .object(fields + [("extra", .null)]), .object(Array(fields.dropFirst())),
        .object(fields + [fields[0]]),
      ]
    }
    var invalid = try variants(root)
    invalid += try variants(recipient).map {
      Self.replacing("recipients", in: root, with: .array([$0]))
    }
    invalid += try variants(key).map {
      Self.replacing(
        "recipients", in: root, with: .array([Self.replacing("publicKey", in: recipient, with: $0)])
      )
    }
    invalid += try variants(wrapper).map {
      Self.replacing("wrappedKeys", in: root, with: .array([$0]))
    }
    for value in invalid {
      #expect(throws: (any Error).self) { try V3RecoveryRosterCodec().decode(value) }
      #expect(throws: (any Error).self) {
        try V3RecoveryRosterCodec().parseCanonical(CanonicalJSON.encode(value))
      }
    }
  }

  @Test
  func unsupportedFieldsVersionsAndSubstitutedKeyIdentityAreRejected() throws {
    let root = try Self.fixture().canonicalValue
    let recipient = try #require(Self.member("recipients", in: root).arrayValue?.first)
    for (name, value) in [
      ("slot", "9a"), ("status", "pending"), ("registrationID", Self.registration.uppercased()),
      ("recipientID", Base64URL.encode(Data(repeating: 0, count: 32))),
    ] {
      let changed = Self.replacing(
        "recipients", in: root,
        with: .array([Self.replacing(name, in: recipient, with: .string(value))]))
      #expect(throws: (any Error).self) { try V3RecoveryRosterCodec().decode(changed) }
    }
    let key = try Self.member("publicKey", in: recipient)
    for (name, value) in [
      ("algorithm", "unsupported"), ("encoding", "compressed"), ("value", Self.publicKey + "="),
    ] {
      let changedKey = Self.replacing(name, in: key, with: .string(value))
      let changed = Self.replacing(
        "recipients", in: root,
        with: .array([Self.replacing("publicKey", in: recipient, with: changedKey)]))
      #expect(throws: (any Error).self) { try V3RecoveryRosterCodec().decode(changed) }
    }
    #expect(throws: V3RecoveryRecipientError.unsupportedVersion(2)) {
      try V3RecoveryRosterCodec().decode(Self.replacing("version", in: root, with: .integer(2)))
    }
    let wrapper = try #require(Self.member("wrappedKeys", in: root).arrayValue?.first)
    for (name, value) in [
      ("encapsulatedKey", Base64URL.encode(Data(repeating: 0, count: 65))),
      ("ciphertext", Base64URL.encode(Data(repeating: 0, count: 47))),
    ] {
      #expect(throws: V3RecoveryRecipientError.invalidWrappedKey) {
        try V3RecoveryRosterCodec().decode(
          Self.replacing(
            "wrappedKeys", in: root,
            with: .array([Self.replacing(name, in: wrapper, with: .string(value))])))
      }
    }
  }

  @Test
  func boundsAndEveryTruncatedPrefixFailClosed() throws {
    let fixture = try Self.fixture()
    let bytes = fixture.canonicalBytes
    for count in 0..<bytes.count {
      #expect(throws: (any Error).self) {
        try V3RecoveryRosterCodec().parseCanonical(Data(bytes.prefix(count)))
      }
    }
    for input in [
      Data([0xff]), Data([0xef, 0xbb, 0xbf]) + bytes, Data("null".utf8), bytes + Data([0]),
    ] {
      #expect(throws: (any Error).self) { try V3RecoveryRosterCodec().parseCanonical(input) }
    }
    #expect(throws: V3RecoveryRecipientError.nonCanonicalEncoding) {
      try V3RecoveryRosterCodec().parseCanonical(bytes + Data([10]))
    }
    #expect(throws: V3RecoveryRecipientError.invalidEncoding) {
      try V3RecoveryRosterCodec().parseCanonical(
        Data(repeating: 0x20, count: V3RecoveryRosterCodec.maximumBytes + 1))
    }
    let tooMany = Self.replacing(
      "recipients", in: fixture.canonicalValue,
      with: .array(
        Array(
          repeating: fixture.recipients[0].canonicalValue,
          count: V3RecoveryRoster.maximumRecipients + 1)))
    #expect(throws: V3RecoveryRecipientError.invalidStructure) {
      try V3RecoveryRosterCodec().decode(tooMany)
    }
    #expect(throws: V3RecoveryRecipientError.invalidCoverage) {
      try V3RecoveryRoster(
        generationID: Self.generation,
        recipients: Array(
          repeating: fixture.recipients[0], count: V3RecoveryRoster.maximumRecipients + 1),
        wrappedKeys: [])
    }
    let tooManyWrappers = Self.replacing(
      "wrappedKeys", in: fixture.canonicalValue,
      with: .array(
        Array(
          repeating: fixture.wrappedKeys[0].canonicalValue,
          count: V3RecoveryRoster.maximumRecipients + 1)))
    #expect(throws: V3RecoveryRecipientError.invalidStructure) {
      try V3RecoveryRosterCodec().decode(tooManyWrappers)
    }
    let largestRecipients = try (1...V3RecoveryRoster.maximumRecipients).map { index in
      try V3RecoveryRecipient(
        registrationID: String(format: "018f4d38-7d5a-7b20-b0f1-%012x", index),
        publicKey: P256.KeyAgreement.PrivateKey(
          rawRepresentation: Data(repeating: 0, count: 31) + Data([UInt8(index)])
        )
        .publicKey.x963Representation,
        slot: .keyManagement, status: .active)
    }.sorted { $0.recipientID.rawValue < $1.recipientID.rawValue }
    let largestWrappers = try largestRecipients.map {
      try V3RecoveryWrappedKey(
        recipientID: $0.recipientID, registrationID: $0.registrationID,
        wrappedKey: fixture.wrappedKeys[0].wrappedKey)
    }
    let largest = try V3RecoveryRoster(
      generationID: Self.generation, recipients: largestRecipients, wrappedKeys: largestWrappers)
    #expect(largest.canonicalBytes.count <= V3RecoveryRosterCodec.maximumBytes)
    #expect(try V3RecoveryRosterCodec().parseCanonical(largest.canonicalBytes) == largest)
  }

  private static func recipient(
    registration: String = registration, status: V3RecoveryRecipientStatus = .active
  ) throws -> V3RecoveryRecipient {
    try V3RecoveryRecipient(
      registrationID: registration, publicKey: #require(Base64URL.decodeCanonical(publicKey)),
      slot: .keyManagement, status: status)
  }

  private static func fixture() throws -> V3RecoveryRoster {
    let record = try recipient()
    let wrapped = try V3HPKEWrappedVaultKey(
      encapsulatedKey: record.publicKey, ciphertext: Data(0..<48))
    return try V3RecoveryRoster(
      generationID: generation, recipients: [record],
      wrappedKeys: [
        V3RecoveryWrappedKey(
          recipientID: record.recipientID, registrationID: record.registrationID,
          wrappedKey: wrapped)
      ])
  }

  private static func member(_ name: String, in value: CanonicalJSONValue) throws
    -> CanonicalJSONValue
  {
    try #require(value.objectValue?.first(where: { $0.0 == name })?.1)
  }

  private static func replacing(
    _ name: String, in value: CanonicalJSONValue, with replacement: CanonicalJSONValue
  ) -> CanonicalJSONValue {
    .object((value.objectValue ?? []).map { ($0.0, $0.0 == name ? replacement : $0.1) })
  }
}
