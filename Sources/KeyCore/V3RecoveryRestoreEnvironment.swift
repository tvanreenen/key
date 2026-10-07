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

/// Retained filesystem authority for internal restore. Capture
/// accepts only a newly-created, empty destination and an unconfigured Mac.
/// Creation makes only the requested final directory after checking its parent.
/// Capture writes no record, credential, checkpoint or configuration. Explicit
/// completion can select exact configuration after fresh trust/read checks.
struct V3RecoveryRestoreEnvironment: Sendable {
  let locations: V3RecoveryRestoreLocations
  let destination: VaultRootDirectoryHandle
  let destinationParent: VaultRootDirectoryHandle
  private let source: VaultRootDirectoryHandle
  private let configuration: VaultRootDirectoryHandle
  private let newDirectory: V3NewVaultDirectory?
  private struct SelectedConfiguration: Sendable {
    let vaultID: String
    let bytes: Data
  }
  private let selectedConfiguration: SelectedConfiguration?

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

  /// Only explicit completion can accept an already-selected configuration.
  /// The ID/locations must come from the locally owned preparation. No paths
  /// from that record are opened here; all handles are supplied independently.
  static func reopenForCompletion(
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, configStore: KeyConfigStore,
    expected: V3RecoveryRestoreLocations, vaultID: String
  ) throws -> Self {
    let root = try configStore.restoreCompletionRoot()
    let bytes = try configStore.restoredVaultConfigurationData(
      root: destination.rootURL, vaultID: vaultID)
    let selected = try configurationPresent(root)
    let environment = try Self(
      source: source, destination: destination, parent: parent, configuration: root,
      newDirectory: nil,
      selectedConfiguration: selected ? .init(vaultID: vaultID, bytes: bytes) : nil)
    try environment.requireCurrent(expected)
    return environment
  }

  private init(
    source: VaultRootDirectoryHandle, destination: VaultRootDirectoryHandle,
    parent: VaultRootDirectoryHandle, configuration: VaultRootDirectoryHandle,
    newDirectory: V3NewVaultDirectory?, selectedConfiguration: SelectedConfiguration? = nil
  ) throws {
    self.source = source
    self.destination = destination
    destinationParent = parent
    self.configuration = configuration
    self.newDirectory = newDirectory
    self.selectedConfiguration = selectedConfiguration
    locations = .init(
      source: source, destination: destination,
      destinationParent: parent, configuration: configuration)
    try requireCurrent(locations)
  }

  /// Shared single-use directory gate survives copies of this value. Resume
  /// cannot reserve again, even when the owned destination is still empty.
  func beginReservation() throws {
    try requireUnselectedConfiguration()
    try requireCurrent(locations)
    guard let newDirectory else { throw V3RecoveryRestoreError.invalidIntent }
    try newDirectory.begin(for: destination.rootURL)
  }

  /// Call across approvals and before each durable transition. A parsed record
  /// cannot substitute new paths, folders or an unrelated configuration.
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
    if let selectedConfiguration {
      try requireExactConfiguration(selectedConfiguration.bytes)
    } else {
      try Self.requireAbsentConfiguration(configuration)
    }
    // Parent walking is an observation, not a filesystem lock.
    try expected.source.requireMatch(source)
    try expected.destination.requireMatch(destination)
    try expected.destinationParent.requireMatch(destinationParent)
    try expected.configuration.requireMatch(configuration)
  }

  var hasSelectedConfiguration: Bool { selectedConfiguration != nil }

  func requireSelectionMatches(vaultID: String) throws {
    guard selectedConfiguration == nil || selectedConfiguration?.vaultID == vaultID else {
      throw V3RecoveryRestoreError.configurationPresent
    }
  }

  func requireUnselectedConfiguration() throws {
    guard selectedConfiguration == nil else {
      throw V3RecoveryRestoreError.configurationPresent
    }
    try Self.requireAbsentConfiguration(configuration)
  }

  /// Called only after fresh trust and ordinary-read verification. Retrying a
  /// selected environment verifies/synchronizes exact bytes without rewriting.
  func selectConfiguration(
    configStore: KeyConfigStore, vaultID: String,
    beforePublication: @escaping @Sendable () throws -> Void,
    writeObserver: any V3AtomicStagedObjectWriteObserving = V3NoopAtomicStagedObjectWriteObserver()
  ) throws -> Self {
    let root = try configStore.restoreCompletionRoot()
    try locations.configuration.requireMatch(root)
    let bytes = try configStore.restoredVaultConfigurationData(
      root: destination.rootURL, vaultID: vaultID)
    try requireCurrent(locations)
    try beforePublication()
    if let selectedConfiguration {
      guard selectedConfiguration.vaultID == vaultID, selectedConfiguration.bytes == bytes else {
        throw V3RecoveryRestoreError.configurationPresent
      }
    } else {
      let gate = V3RestoreConfigurationWriteGate(
        environment: self, validate: beforePublication, observer: writeObserver)
      try V3AtomicStagedObjectWriter(rootHandle: configuration, observer: gate)
        .install(bytes, at: "config.toml")
    }
    let selected = try Self(
      source: source, destination: destination, parent: destinationParent,
      configuration: configuration, newDirectory: nil,
      selectedConfiguration: .init(vaultID: vaultID, bytes: bytes))
    try selected.requireCurrent(locations)
    try V3FilesystemTransactionArtifactStore(rootHandle: configuration)
      .confirmDurableRecoveryObject(bytes, at: "config.toml", directories: [])
    try selected.requireCurrent(locations)
    return selected
  }

  private func requireExactConfiguration(_ bytes: Data) throws {
    guard
      case .available(let observed) = try V3FilesystemTransactionArtifactStore(
        rootHandle: configuration
      ).readRecoveryObject(at: "config.toml", maximumBytes: bytes.count), observed == bytes
    else {
      throw V3RecoveryRestoreError.configurationPresent
    }
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
    guard try !configurationPresent(configuration) else {
      throw V3RecoveryRestoreError.configurationPresent
    }
  }

  private static func configurationPresent(_ configuration: VaultRootDirectoryHandle) throws -> Bool
  {
    try configuration.withFileDescriptor { descriptor in
      var metadata = stat()
      if fstatat(descriptor, "config.toml", &metadata, AT_SYMLINK_NOFOLLOW) == 0 { return true }
      guard errno == ENOENT else { throw V3RecoveryRestoreError.locationChanged }
      return false
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

private struct V3RestoreConfigurationWriteGate: V3AtomicStagedObjectWriteObserving {
  let environment: V3RecoveryRestoreEnvironment
  let validate: @Sendable () throws -> Void
  let observer: any V3AtomicStagedObjectWriteObserving

  func didReach(_ phase: V3AtomicStagedObjectWritePhase) throws {
    try observer.didReach(phase)
    try environment.requireCurrent(environment.locations)
    try validate()
  }
}
