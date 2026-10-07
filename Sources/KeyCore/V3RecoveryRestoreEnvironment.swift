import Darwin
import Foundation
internal import JSONCanonicalization

enum V3RecoveryRestoreError: Error, Equatable {
  case invalidIntent
  case authenticationFailed
  case locationChanged
  case overlappingDirectories
  case configurationPresent
  case resourceLimit
}

/// Public path and physical-directory binding, not permission to open a path
/// read from JSON. Resume must match it against independently opened handles.
struct V3RecoveryRestoreLocation: Equatable, Sendable {
  let path: String
  let identity: VaultRootDirectoryIdentity

  init(_ handle: VaultRootDirectoryHandle) {
    path = handle.rootURL.standardizedFileURL.path
    identity = handle.identity
  }

  init(value: CanonicalJSONValue) throws {
    guard let fields = value.objectValue, fields.count == 3,
      Set(fields.map(\.0)) == ["path", "deviceID", "fileID"]
    else { throw V3RecoveryRestoreError.invalidIntent }
    let root = Dictionary(uniqueKeysWithValues: fields)
    guard let path = root["path"]?.stringValue, path.hasPrefix("/"),
      path.utf8.count <= 4_096, !path.utf8.contains(0),
      Data(URL(fileURLWithPath: path).standardizedFileURL.path.utf8) == Data(path.utf8),
      let deviceText = root["deviceID"]?.stringValue, let device = UInt64(deviceText),
      String(device) == deviceText,
      let fileText = root["fileID"]?.stringValue, let file = UInt64(fileText),
      String(file) == fileText
    else { throw V3RecoveryRestoreError.invalidIntent }
    self.path = path
    identity = .init(deviceID: device, fileID: file)
  }

  var value: CanonicalJSONValue {
    .object([
      ("path", .string(path)),
      // Decimal strings preserve exact filesystem identifiers across codecs.
      ("deviceID", .string(String(identity.deviceID))),
      ("fileID", .string(String(identity.fileID))),
    ])
  }

  func requireMatch(_ handle: VaultRootDirectoryHandle) throws {
    guard identity == handle.identity,
      Data(path.utf8) == Data(handle.rootURL.standardizedFileURL.path.utf8)
    else { throw V3RecoveryRestoreError.locationChanged }
    try handle.requireConfiguredRootIdentity()
  }
}

struct V3RecoveryRestoreLocations: Equatable, Sendable {
  let source: V3RecoveryRestoreLocation
  let destination: V3RecoveryRestoreLocation
  let destinationParent: V3RecoveryRestoreLocation
  let configuration: V3RecoveryRestoreLocation

  init(
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    destinationParent: VaultRootDirectoryHandle, configuration: VaultRootDirectoryHandle
  ) {
    self.source = .init(source)
    self.destination = .init(destination)
    self.destinationParent = .init(destinationParent)
    self.configuration = .init(configuration)
  }

  init(value: CanonicalJSONValue) throws {
    guard let fields = value.objectValue, fields.count == 4,
      Set(fields.map(\.0)) == ["source", "destination", "destinationParent", "configuration"]
    else { throw V3RecoveryRestoreError.invalidIntent }
    let root = Dictionary(uniqueKeysWithValues: fields)
    guard let sourceValue = root["source"], let destinationValue = root["destination"],
      let parentValue = root["destinationParent"], let configurationValue = root["configuration"]
    else { throw V3RecoveryRestoreError.invalidIntent }
    source = try .init(value: sourceValue)
    destination = try .init(value: destinationValue)
    destinationParent = try .init(value: parentValue)
    configuration = try .init(value: configurationValue)
  }

  var value: CanonicalJSONValue {
    .object([
      ("source", source.value), ("destination", destination.value),
      ("destinationParent", destinationParent.value), ("configuration", configuration.value),
    ])
  }
}

/// Retained filesystem authority for internal restore preparation. Capture
/// accepts only a newly-created, empty destination and an unconfigured Mac.
/// Creation makes only the requested final directory after checking its parent.
/// No record, credential, checkpoint or configuration is written.
struct V3RecoveryRestoreEnvironment: Sendable {
  let locations: V3RecoveryRestoreLocations
  let destination: VaultRootDirectoryHandle
  let destinationParent: VaultRootDirectoryHandle
  private let source: VaultRootDirectoryHandle
  private let configuration: VaultRootDirectoryHandle
  private let newDirectory: V3NewVaultDirectory?

  static func create(
    source: VaultRootDirectoryHandle, in parent: VaultRootDirectoryHandle, name: String,
    configStore: KeyConfigStore
  ) throws -> Self {
    let configuration = try configStore.unconfiguredRestoreRoot()
    try source.requireConfiguredRootIdentity()
    try parent.requireConfiguredRootIdentity()
    guard try !contains(source, parent), try !contains(configuration, parent),
      try !contains(source, configuration), try !contains(configuration, source)
    else { throw V3RecoveryRestoreError.overlappingDirectories }
    try requireAbsentConfiguration(configuration)
    try source.requireConfiguredRootIdentity()
    try parent.requireConfiguredRootIdentity()
    try configuration.requireConfiguredRootIdentity()
    let directory = try V3NewVaultDirectory.create(in: parent, name: name)
    return try Self(
      source: source, destination: directory.rootHandle, parent: parent,
      configuration: configuration, newDirectory: directory)
  }

  /// Independently supplied handles/path. Caller obtains `expected` from the
  /// journal's locally pinned reservation, not provider metadata.
  /// This path can never start another reservation or create a directory.
  static func reopen(
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, configStore: KeyConfigStore,
    expected: V3RecoveryRestoreLocations
  ) throws -> Self {
    let environment = try Self(
      source: source, destination: destination, parent: parent,
      configuration: configStore.unconfiguredRestoreRoot(), newDirectory: nil)
    try environment.requireCurrent(expected)
    return environment
  }

  private init(
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, configuration: VaultRootDirectoryHandle,
    newDirectory: V3NewVaultDirectory?
  ) throws {
    self.source = source
    self.destination = destination
    destinationParent = parent
    self.configuration = configuration
    self.newDirectory = newDirectory
    locations = .init(
      source: source, destination: destination,
      destinationParent: parent, configuration: configuration)
    try requireCurrent(locations)
  }

  /// Shared single-use directory gate survives copies of this value. Resume
  /// cannot reserve again, even when the owned destination is still empty.
  func beginReservation() throws {
    try requireCurrent(locations)
    guard let newDirectory else { throw V3RecoveryRestoreError.invalidIntent }
    try newDirectory.begin(for: destination.rootURL)
  }

  /// Call across approvals and before each durable transition. A parsed record
  /// cannot substitute new paths, folders or an existing configuration.
  func requireCurrent(_ expected: V3RecoveryRestoreLocations) throws {
    guard expected == locations else { throw V3RecoveryRestoreError.locationChanged }
    try expected.source.requireMatch(source)
    try expected.destination.requireMatch(destination)
    try expected.destinationParent.requireMatch(destinationParent)
    try expected.configuration.requireMatch(configuration)
    for (left, right) in [
      (source, destination), (source, configuration), (destination, configuration),
    ] {
      guard try !Self.contains(left, right), try !Self.contains(right, left) else {
        throw V3RecoveryRestoreError.overlappingDirectories
      }
    }
    try Self.requireAbsentConfiguration(configuration)
    // Parent walking is an observation, not a filesystem lock.
    try expected.source.requireMatch(source)
    try expected.destination.requireMatch(destination)
    try expected.destinationParent.requireMatch(destinationParent)
    try expected.configuration.requireMatch(configuration)
  }

  /// The snapshot must still describe the retained source descriptor, not an
  /// independently supplied reader or a path obtained from a saved record.
  func requireSnapshot(_ snapshot: V3RecoveryVerifiedSnapshot) throws {
    try requireCurrent(locations)
    try V3RecoverySnapshotVerifier(
      source: V3FilesystemTransactionArtifactStore(rootHandle: source)
    ).revalidate(
      snapshot, boundAnchor: snapshot.selection.anchor,
      credentialPublicKey: snapshot.selection.credentialPublicKey)
    try requireCurrent(locations)
  }

  func validateCandidate(
    _ publication: V3DeviceWrappedGenesisPublicationCandidate,
    restoring snapshot: V3RecoveryVerifiedSnapshot, vaultKey: Data,
    expectedOwner: V3EnrollmentDeviceIdentity, limits: V3ManifestRepositoryLimits
  ) throws -> V3RecoveryRestoreCandidate {
    try requireCurrent(locations)
    let candidate = try V3RecoveryRestoreCandidateBuilder(
      source: V3FilesystemTransactionArtifactStore(rootHandle: source), limits: limits
    ).validateAndBind(
      publication, restoring: snapshot, vaultKey: vaultKey, expectedOwner: expectedOwner)
    try requireCurrent(locations)
    return candidate
  }

  private static func requireAbsentConfiguration(_ configuration: VaultRootDirectoryHandle) throws {
    try configuration.withFileDescriptor { descriptor in
      var metadata = stat()
      guard fstatat(descriptor, "config.toml", &metadata, AT_SYMLINK_NOFOLLOW) != 0 else {
        throw V3RecoveryRestoreError.configurationPresent
      }
      guard errno == ENOENT else { throw V3RecoveryRestoreError.locationChanged }
    }
  }

  /// Walk physical parents instead of comparing path prefixes: a symlinked
  /// ancestor must not permit writes into the read-only recovery source.
  private static func contains(
    _ ancestor: VaultRootDirectoryHandle, _ child: VaultRootDirectoryHandle
  ) throws -> Bool {
    try child.withFileDescriptor { descriptor in
      var current = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
      guard current >= 0 else { throw V3RecoveryRestoreError.locationChanged }
      defer { close(current) }
      for _ in 0..<1_024 {
        var metadata = stat()
        guard fstat(current, &metadata) == 0 else { throw V3RecoveryRestoreError.locationChanged }
        let identity = VaultRootDirectoryIdentity(
          deviceID: UInt64(metadata.st_dev), fileID: UInt64(metadata.st_ino))
        if identity == ancestor.identity { return true }
        let parent = openat(current, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { throw V3RecoveryRestoreError.locationChanged }
        var parentMetadata = stat()
        guard fstat(parent, &parentMetadata) == 0 else {
          close(parent)
          throw V3RecoveryRestoreError.locationChanged
        }
        let parentIdentity = VaultRootDirectoryIdentity(
          deviceID: UInt64(parentMetadata.st_dev), fileID: UInt64(parentMetadata.st_ino))
        close(current)
        current = parent
        if identity == parentIdentity { return false }
      }
      throw V3RecoveryRestoreError.resourceLimit
    }
  }
}
