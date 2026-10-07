import Darwin
import Foundation

private struct V3NoopRestoreWorkflowObserver: V3RecoveryRestoreServicePhaseObserving {
  func didReach(_: V3RecoveryRestoreServicePhase) throws {}
}

/// Composes one explicitly admitted restore request. Public selectors are
/// resolved independently here, not accepted as native observations or consent.
/// Never retained as the configured ordinary runtime; live dispatch stays gated.
struct V3RecoveryRestoreWorkflow {
  private let configStore: KeyConfigStore
  private let ownership: any V3RecoveryRestoreOwnershipChecking
  private let reservations: any V3ImmutableTransactionRecoveryAnchorStoring
  private let preparations: any V3ImmutableTransactionRecoveryAnchorStoring
  private let identities: any V3DeviceWrappedGenesisIdentityManaging
  private let checkpoints: any V3ManifestCheckpointStoring
  private let reader: PIVRecoveryTokenReader
  private let agreement: PIVRecoveryAgreement
  private let owner: any VaultTransactionMutationOwning
  private let observer: any V3RecoveryRestoreServicePhaseObserving

  init(
    configStore: KeyConfigStore, ownership: any V3RecoveryRestoreOwnershipChecking,
    reservations: any V3ImmutableTransactionRecoveryAnchorStoring,
    preparations: any V3ImmutableTransactionRecoveryAnchorStoring,
    identities: any V3DeviceWrappedGenesisIdentityManaging,
    checkpoints: any V3ManifestCheckpointStoring,
    reader: PIVRecoveryTokenReader, agreement: PIVRecoveryAgreement,
    mutationOwner: any VaultTransactionMutationOwning,
    observer: any V3RecoveryRestoreServicePhaseObserving = V3NoopRestoreWorkflowObserver()
  ) {
    self.configStore = configStore
    self.ownership = ownership
    self.reservations = reservations
    self.preparations = preparations
    self.identities = identities
    self.checkpoints = checkpoints
    self.reader = reader
    self.agreement = agreement
    owner = mutationOwner
    self.observer = observer
  }

  var capability: KeyRecoveryCapability { .init(ownership: ownership, recover: handle) }

  func handle(_ request: KeyRecoveryRequest, scope: KeyRecoveryRequestScope) throws
    -> KeyServiceResponse
  {
    guard #available(macOS 26.0, *) else {
      throw AppError.operationRefused("Vault recovery requires macOS 26 or later.")
    }
    try scope.requireCurrent()
    try request.validate()
    let paths: (source: String, destination: String, token: String, recipient: String)
    let deviceName: String?
    switch request {
    case .restore(let source, let destination, let token, let recipient, let name):
      paths = (source, destination, token, recipient)
      deviceName = name
      try configStore.requireUnconfigured()
      try capability.requireNoPendingRestore()
    case .resume(let source, let destination, let token, let recipient):
      paths = (source, destination, token, recipient)
      deviceName = nil
    }
    let destinationURL = URL(fileURLWithPath: paths.destination, isDirectory: true)
      .standardizedFileURL
    let name = destinationURL.lastPathComponent
    guard !name.isEmpty, name != "/", name != ".", name != ".." else {
      throw V3RecoveryRestoreError.invalidIntent
    }
    let source = try VaultRootDirectoryHandle(
      opening: URL(fileURLWithPath: paths.source, isDirectory: true).standardizedFileURL)
    let parent = try VaultRootDirectoryHandle(opening: destinationURL.deletingLastPathComponent())
    guard try !V3RecoveryRestoreEnvironment.contains(source, parent) else {
      throw V3RecoveryRestoreError.overlappingDirectories
    }
    let destination: VaultRootDirectoryHandle?
    if request.isInitialRestore {
      try parent.withFileDescriptor { descriptor in
        var metadata = stat()
        guard fstatat(descriptor, name, &metadata, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
          throw AppError.operationRefused(
            "Restore requires a missing destination folder. Existing folders, files and links are never adopted or replaced."
          )
        }
      }
      destination = nil
    } else {
      destination = try VaultRootDirectoryHandle(opening: destinationURL)
    }
    try scope.requireCurrent()
    let candidates = try reader.candidates().filter { $0.tokenID == paths.token }
    guard candidates.count == 1, let candidate = candidates.first else {
      throw PIVRecoveryTokenError.invalidSelection
    }
    let observation = try reader.read(candidate)
    guard observation.recipientID.rawValue == paths.recipient else {
      throw PIVRecoveryTokenError.anchorCredentialMismatch
    }
    try observation.keyMetadata.requireRecoveryPolicy()
    guard case .recognized = observation.anchor else {
      throw V3RecoveryRestoreServiceError.recognizedAnchorRequired
    }
    func recheck() throws {
      try scope.requireCurrent()
      try source.requireConfiguredRootIdentity()
      try parent.requireConfiguredRootIdentity()
      try destination?.requireConfiguredRootIdentity()
    }
    try recheck()
    let roots = try configStore.restoreMetadataRoots(
      source: source, parent: parent, name: name, create: request.isInitialRestore,
      validateScope: recheck)
    let service = V3RecoveryRestoreService(
      configStore: configStore,
      journal: .init(
        configurationRoot: roots.configuration, reservationOwnership: reservations,
        preparationOwnership: preparations),
      identities: identities, checkpoints: checkpoints,
      cache: V3CheckpointManifestFilesystemCache(rootHandle: roots.cache),
      mutationOwner: owner, reader: reader, agreement: agreement,
      authentication: scope.authentication, observer: observer)
    try recheck()
    let report: V3RecoveryRestoreReport
    if let deviceName {
      report = try service.restore(
        source: source, parent: parent, name: name, deviceName: deviceName,
        observation: observation, cancellation: scope.cancellation, deadline: scope.deadline)
    } else if let destination {
      report = try service.resume(
        source: source, destination: destination, parent: parent, observation: observation,
        cancellation: scope.cancellation, deadline: scope.deadline)
    } else {
      throw V3RecoveryRestoreError.invalidIntent
    }
    try recheck()
    return .success(
      "Restored \(report.entryCount) entries into a new vault at '\(report.destinationPath)'.\nVault ID: \(report.checkpoint.vaultID)\nThe source vault was not changed. This new vault has no recovery key registered yet. The helper must restart before ordinary use.\n"
    )
  }

  /// Composition alone performs no card/Keychain operation and creates no path.
  /// The shipping host must explicitly install this paired capability later.
  static func live(configStore: KeyConfigStore, runtimeConfiguration: RuntimeConfiguration) -> Self
  {
    let reader = PIVRecoveryTokenReader.live()
    return Self(
      configStore: configStore,
      ownership: V3RecoveryRestoreKeychainOwnership(configuration: runtimeConfiguration),
      reservations: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: runtimeConfiguration, namespace: .restoreReservation),
      preparations: V3ImmutableTransactionRecoveryAnchorKeychainStore(
        configuration: runtimeConfiguration, namespace: .restorePreparation),
      identities: V3EnrollmentDeviceIdentityManager(
        recordStore: V3EnrollmentDeviceKeyRecordKeychainStore(configuration: runtimeConfiguration),
        keyOperations: V3SecureEnclaveEnrollmentDeviceKeyOperations()),
      checkpoints: V3ManifestCheckpointKeychainStore(configuration: runtimeConfiguration),
      reader: reader, agreement: .live(reader: reader),
      mutationOwner: VaultTransactionMutationOwner())
  }
}
