import CryptoKit
import Foundation
import JSONCanonicalization
import Testing

@testable import KeyCore

/// Contained disposable filesystem and software keys only. No real config,
/// protected credential, YubiKey, checkpoint or immutable publication changes.
struct V3RecoveryRestoreIntentTests {
  private typealias Core = V3RecoveryRegistrationTests
  private typealias Source = V3RecoveryContentMutationPublisherTests.Fixture
  private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c4900"
  private static let transitionID = "018f4d38-7d5a-7b20-b0f1-97d6e96c4901"
  private static let entryIDs = [
    "018f4d38-7d5a-7b20-b0f1-97d6e96c4902", "018f4d38-7d5a-7b20-b0f1-97d6e96c4903",
  ]
  private static let key = Data(repeating: 0xC7, count: 32)

  @Test(arguments: [false, true])
  func exactIntentRoundTripsAndAuthenticatesWithoutPersistingSecrets(empty: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture(empty: empty)
    defer { f.remove() }
    let signatures = f.source.core.owner.signatures
    let before = try fileBytes(f.source.root)
    let candidate = try f.candidate()
    let intent = try f.intent(candidate)
    let parsed = try V3RecoveryRestoreIntent(canonicalBytes: intent.canonicalBytes)
    #expect(parsed == intent && parsed.canonicalBytes == intent.canonicalBytes)
    try parsed.authenticate(destinationVaultKey: Self.key)
    try parsed.requireCandidate(candidate)
    try f.environment.requireCurrent(parsed.locations)
    #expect(intent.destinationCheckpoint.vaultID == Self.vaultID)
    #expect(intent.sourceHeadDigest == candidate.snapshot.selection.head.digest)
    #expect(intent.locations.destination.identity == f.environment.destination.identity)
    #expect(intent.canonicalBytes.count <= V3RecoveryRestoreIntent.maximumBytes)
    let text = try #require(String(data: intent.canonicalBytes, encoding: .utf8))
    for entry in candidate.snapshot.entries {
      #expect(!text.contains(entry.plaintext))
    }
    #expect(!text.contains(Base64URL.encode(Self.key)))
    #expect(try fileBytes(f.source.root) == before)
    #expect(try !f.config.hasConfiguration())
    #expect(
      try FileManager.default.contentsOfDirectory(atPath: f.environment.destination.rootURL.path)
        .isEmpty)
    #expect(f.calls.value == 1 && f.source.core.owner.signatures == signatures)
    #expect(f.source.core.owner.unwraps == 0)
  }

  @Test(arguments: [0, 31, 32, 33])
  func incorrectDestinationKeyNeverAuthenticates(length: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let candidate = try f.candidate()
    let intent = try f.intent(candidate)
    #expect(throws: V3RecoveryRestoreError.authenticationFailed) {
      try intent.authenticate(destinationVaultKey: Data(repeating: 0, count: length))
    }
    #expect(throws: (any Error).self) {
      try V3RecoveryRestoreIntent(
        operationID: .init(), candidate: candidate, environment: f.environment,
        destinationVaultKey: Data(repeating: 0, count: length))
    }
  }

  @Test(arguments: 0..<10)
  func changedPublicRecordIsNotAuthenticated(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let original = try f.intent(f.candidate())
    let bytes = try replacing(original.canonicalBytes) { root in
      switch variant {
      case 0: root["operationID"] = .string(VaultTransactionOperationID().rawValue)
      case 1, 2, 3, 4:
        root[
          ["sourceHeadDigest", "sourceObservationDigest", "ownerDeviceID", "authenticationTag"][
            variant - 1]] =
          .string(Base64URL.encode(Data(repeating: 0x42, count: 32)))
      case 5: root["destinationKeyID"] = .string(Base64URL.encode(Data(repeating: 0x42, count: 32)))
      case 6:
        root["destinationCheckpoint"] = replacingObject(root["destinationCheckpoint"]!) {
          $0["envelopeDigest"] = .string(Base64URL.encode(Data(repeating: 0x42, count: 32)))
        }
      case 7:
        root["sourceAnchor"] = replacingObject(root["sourceAnchor"]!) {
          $0["registrationID"] = .string(VaultTransactionOperationID().rawValue)
        }
      case 8, 9:
        root["locations"] = replacingObject(root["locations"]!) { locations in
          locations["destination"] = replacingObject(locations["destination"]!) {
            $0[variant == 8 ? "path" : "fileID"] = .string(variant == 8 ? "/different/folder" : "0")
          }
        }
      default: break
      }
    }
    let changed = try V3RecoveryRestoreIntent(canonicalBytes: bytes)
    #expect(throws: V3RecoveryRestoreError.authenticationFailed) {
      try changed.authenticate(destinationVaultKey: Self.key)
    }
    #expect(f.calls.value == 1)
  }

  @Test(arguments: 0..<9)
  func malformedAndUnboundedRecordsAreRejected(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let original = try f.intent(f.candidate())
    var bytes = try replacing(original.canonicalBytes) { root in
      switch variant {
      case 0: root["extra"] = .bool(true)
      case 1: root["version"] = .integer(2)
      case 2: root["authenticationAlgorithm"] = .string("unsupported")
      case 3: root.removeValue(forKey: "ownerDeviceID")
      case 4, 5, 6:
        root["locations"] = replacingObject(root["locations"]!) { locations in
          locations["source"] = replacingObject(locations["source"]!) {
            if variant == 4 { $0["path"] = .string("/source/../different") }
            if variant == 5 { $0["deviceID"] = .string("01") }
            if variant == 6 { $0["fileID"] = .integer(1) }
          }
        }
      default: break
      }
    }
    if variant == 7 { bytes.append(0x20) }
    if variant == 8 { bytes = Data(repeating: 0, count: V3RecoveryRestoreIntent.maximumBytes + 1) }
    #expect(throws: (any Error).self) { try V3RecoveryRestoreIntent(canonicalBytes: bytes) }
  }

  @Test func anotherCandidateOrLaterSourceIsNotTheSavedAttempt() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let first = try f.candidate()
    let intent = try f.intent(first)
    let second = try f.candidate()
    #expect(first.publication.genesis.manifestDigest != second.publication.genesis.manifestDigest)
    #expect(throws: V3RecoveryRestoreError.invalidIntent) { try intent.requireCandidate(second) }
    let edited = try f.source.build(
      .edit(name: "fixture/secret", type: .secret, plaintext: "later"))
    _ = try f.source.publisher().publish(edited, vaultKey: Core.nextKey)
    #expect(throws: V3RecoveryValidationError.sourceChanged) { try f.intent(first) }
    let later = try f.candidate()
    #expect(throws: V3RecoveryRestoreError.invalidIntent) { try intent.requireCandidate(later) }
  }

  @Test(arguments: 0..<4)
  func configurationAppearingDuringApprovalStopsPreparation(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let path = f.config.initializationConfigFileURL
    switch variant {
    case 0: try Data("malformed config".utf8).write(to: path)
    case 1: try Data("vault_dir = \"/unrelated\"\nkeychain_mode = \"local\"".utf8).write(to: path)
    case 2: try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false)
    default:
      try FileManager.default.createSymbolicLink(
        at: path, withDestinationURL: f.base.appendingPathComponent("missing"))
    }
    #expect(throws: V3RecoveryRestoreError.configurationPresent) {
      try f.environment.requireCurrent(f.environment.locations)
    }
    #expect(try f.config.hasConfiguration())
    #expect(throws: (any Error).self) {
      try V3RecoveryRestoreEnvironment.create(
        source: .init(opening: f.source.root), in: f.environment.destinationParent,
        name: "must-not-appear", configStore: f.config)
    }
    #expect(
      !FileManager.default.fileExists(
        atPath: f.environment.destinationParent.rootURL.appendingPathComponent("must-not-appear")
          .path))
  }

  @Test(arguments: 0..<4)
  func replacedPhysicalFoldersStopTheAttempt(variant: Int) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let location = [
      f.source.root, f.environment.destination.rootURL, f.environment.destinationParent.rootURL,
      f.config.initializationConfigFileURL.deletingLastPathComponent(),
    ][variant]
    let moved = location.appendingPathExtension("preserved")
    try FileManager.default.moveItem(at: location, to: moved)
    defer {
      try? FileManager.default.removeItem(at: location)
      try? FileManager.default.moveItem(at: moved, to: location)
    }
    try FileManager.default.createDirectory(at: location, withIntermediateDirectories: false)
    #expect(throws: (any Error).self) {
      try f.environment.requireCurrent(f.environment.locations)
    }
  }

  @Test func existingEmptyAndNonemptyDestinationsAreNotRestoreAuthority() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    #expect(throws: (any Error).self) {
      try V3RecoveryRestoreEnvironment.create(
        source: .init(opening: f.source.root), in: f.environment.destinationParent,
        name: "restored", configStore: f.config)
    }
    try Data("unrelated".utf8).write(
      to: f.environment.destination.rootURL.appendingPathComponent("file"))
    #expect(throws: (any Error).self) {
      try V3RecoveryRestoreEnvironment.create(
        source: .init(opening: f.source.root), in: f.environment.destinationParent,
        name: "restored", configStore: f.config)
    }
  }

  @Test(arguments: [false, true])
  func physicalSourceDescendantsCannotBeDestinations(aliased: Bool) throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let parentURL = f.source.root.appendingPathComponent("parent")
    try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: false)
    let alias = f.base.appendingPathComponent("source-alias")
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: f.source.root)
    let parent = try VaultRootDirectoryHandle(
      opening: aliased ? alias.appendingPathComponent("parent") : parentURL)
    #expect(throws: V3RecoveryRestoreError.overlappingDirectories) {
      try V3RecoveryRestoreEnvironment.create(
        source: .init(opening: f.source.root), in: parent, name: "nested", configStore: f.config)
    }
    #expect(
      !FileManager.default.fileExists(atPath: parentURL.appendingPathComponent("nested").path))
  }

  @Test func missingConfigurationRootIsNotCreatedByInspection() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let config = KeyConfigStore(homeDirectoryURL: home)
    #expect(throws: (any Error).self) { try config.unconfiguredRestoreRoot() }
    #expect(!FileManager.default.fileExists(atPath: home.path))
  }

  @Test func configurationContainedPathsAreRefusedBeforeFolderCreation() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let root = try VaultRootDirectoryHandle(
      opening: f.config.initializationConfigFileURL.deletingLastPathComponent())
    #expect(throws: V3RecoveryRestoreError.overlappingDirectories) {
      try V3RecoveryRestoreEnvironment.create(
        source: .init(opening: f.source.root), in: root, name: "nested", configStore: f.config)
    }
    #expect(
      !FileManager.default.fileExists(atPath: root.rootURL.appendingPathComponent("nested").path))
    #expect(throws: V3RecoveryRestoreError.overlappingDirectories) {
      try V3RecoveryRestoreEnvironment.create(
        source: root, in: f.environment.destinationParent, name: "another", configStore: f.config)
    }
    #expect(
      !FileManager.default.fileExists(
        atPath: f.environment.destinationParent.rootURL.appendingPathComponent("another").path))
  }

  @Test func parsedLocationsCannotReplaceTheLiveBinding() throws {
    guard #available(macOS 26.0, *) else { return }
    let f = try Fixture()
    defer { f.remove() }
    let value = replacingObject(f.environment.locations.value) { locations in
      locations["destination"] = replacingObject(locations["destination"]!) {
        $0["fileID"] = .string("0")
      }
    }
    let different = try V3RecoveryRestoreLocations(value: value)
    #expect(throws: V3RecoveryRestoreError.locationChanged) {
      try f.environment.requireCurrent(different)
    }
  }

  @available(macOS 26.0, *)
  private struct Fixture {
    let source: Source
    let base: URL
    let config: KeyConfigStore
    let environment: V3RecoveryRestoreEnvironment
    let calls = Core.Counter()
    init(empty: Bool = false) throws {
      source = try Source(empty: empty)
      base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      config = .init(homeDirectoryURL: base.appendingPathComponent("home"))
      try FileManager.default.createDirectory(
        at: config.initializationConfigFileURL.deletingLastPathComponent(),
        withIntermediateDirectories: true)
      let parentURL = base.appendingPathComponent("destinations")
      try FileManager.default.createDirectory(at: parentURL, withIntermediateDirectories: false)
      environment = try .create(
        source: .init(opening: source.root), in: .init(opening: parentURL), name: "restored",
        configStore: config)
    }
    func candidate() throws -> V3RecoveryRestoreCandidate {
      let receiver = try PIVHPKEReceiver(publicBytes: source.core.credential.publicKey) {
        [calls, token = source.core.token] peer in
        calls.increment()
        return try token.sharedSecretFromKeyAgreement(
          with: P256.KeyAgreement.PublicKey(x963Representation: peer)
        ).withUnsafeBytes { Data($0) }
      }
      let selection = try V3RecoveryHistorySelector(source: source.store).select(
        anchor: source.anchor, credentialPublicKey: receiver.publicKey.bytes)
      let snapshot = try V3RecoverySnapshotVerifier(source: source.store).open(
        selection, boundAnchor: source.anchor, receiver: receiver)
      let identity = try V3EnrollmentDeviceIdentity(
        displayName: "Fresh test Mac",
        signingPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
        wrappingPublicKey: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
      return try V3RecoveryRestoreCandidateBuilder(source: source.store).build(
        restoring: snapshot, vaultID: V3RecoveryRestoreIntentTests.vaultID,
        authorityTransitionID: V3RecoveryRestoreIntentTests.transitionID,
        entryIDs: Array(V3RecoveryRestoreIntentTests.entryIDs.prefix(snapshot.entries.count)),
        vaultKey: V3RecoveryRestoreIntentTests.key, ownerIdentity: identity)
    }
    func intent(_ candidate: V3RecoveryRestoreCandidate) throws -> V3RecoveryRestoreIntent {
      try .init(
        operationID: .init(), candidate: candidate, environment: environment,
        destinationVaultKey: V3RecoveryRestoreIntentTests.key)
    }
    func remove() {
      source.remove()
      try? FileManager.default.removeItem(at: base)
    }
  }

  private func replacing(_ bytes: Data, change: (inout [String: CanonicalJSONValue]) -> Void) throws
    -> Data
  {
    let value = try CanonicalJSON.parse(bytes)
    return CanonicalJSON.encode(replacingObject(value, change: change))
  }
  private func replacingObject(
    _ value: CanonicalJSONValue, change: (inout [String: CanonicalJSONValue]) -> Void
  ) -> CanonicalJSONValue {
    var root = Dictionary(uniqueKeysWithValues: value.objectValue!)
    change(&root)
    return .object(root.map { ($0.key, $0.value) })
  }
  private func fileBytes(_ root: URL) throws -> [String: Data] {
    let urls = try #require(
      FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]))
    var result: [String: Data] = [:]
    for case let url as URL in urls {
      if try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true {
        result[url.path] = try Data(contentsOf: url)
      }
    }
    return result
  }
}
