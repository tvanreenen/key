import Foundation

/// Closed public-read requests. No destination, private operation, saved
/// attempt, native observation or confirmation reference can be supplied.
public enum KeyRecoveryReviewRequest: Codable, Equatable, Sendable {
  case tokens
  case source(path: String, tokenID: String)

  func validate() throws {
    guard case .source(let path, let token) = self else { return }
    guard path.hasPrefix("/"), path.utf8.count <= 4_096, !path.utf8.contains(0),
      !token.isEmpty, token.utf8.count <= 1_024,
      !token.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    else {
      throw AppError.operationRefused(
        "Recovery review requires an absolute source path and one complete token ID.")
    }
  }
}

/// Public observations only, never possession proof, restored contents or
/// consent. There is deliberately no readiness or confirmation-token field.
public enum KeyRecoveryReviewResult: Codable, Equatable, Sendable {
  public enum Assurance: String, Codable, Equatable, Sendable {
    case publicObservationOnly = "public-observation-only"
  }
  public struct Token: Codable, Equatable, Sendable {
    public let tokenID: String
    public let readerSlotName: String
  }

  public struct Source: Codable, Equatable, Sendable {
    public let assurance: Assurance
    public let path: String
    public let token: Token
    public let recipientID: String
    public let reportedPINPolicy: String
    public let reportedTouchPolicy: String
    public let reportedKeyOrigin: String
    public let vaultID: String
    public let registrationID: String
    public let registrationManifestDigest: String
    public let observedHeadDigest: String
    public let listedEntryCount: Int
    public let observedManifestCount: Int
  }

  case tokens([Token])
  case source(Source)
}

/// Public token reads and bounded public-history selection only. Does not own
/// config, journal, Keychain, mutation, agreement or Mac-identity dependencies.
struct KeyRecoveryReviewWorkflow {
  let reader: PIVRecoveryTokenReader

  static func live() -> Self { .init(reader: .live()) }

  func handle(_ request: KeyRecoveryReviewRequest, scope: KeyRecoveryRequestScope) throws
    -> KeyServiceResponse
  {
    try scope.requireCurrent()
    try request.validate()
    let result: KeyRecoveryReviewResult
    switch request {
    case .tokens:
      let tokens = try reader.candidates().map {
        KeyRecoveryReviewResult.Token(tokenID: $0.tokenID, readerSlotName: $0.readerSlotName)
      }
      try scope.requireCurrent()
      result = .tokens(tokens)
    case .source(let path, let tokenID):
      let root = try VaultRootDirectoryHandle(
        opening: URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL)
      try scope.requireCurrent()
      let candidates = try reader.candidates().filter { $0.tokenID == tokenID }
      guard candidates.count == 1, let candidate = candidates.first else {
        throw PIVRecoveryTokenError.invalidSelection
      }
      let observation = try reader.read(candidate)
      try scope.requireCurrent()
      try observation.keyMetadata.requireRecoveryPolicy()
      guard case .recognized(let anchor) = observation.anchor else {
        throw AppError.operationRefused(
          "Public source review requires a recognized recovery anchor on the explicitly selected token."
        )
      }
      let source = PublicSource(root: root, scope: scope)
      let selector = V3RecoveryHistorySelector(source: source)
      let selection = try selector.select(
        anchor: anchor, credentialPublicKey: observation.publicKey)
      try reader.revalidate(observation)
      try source.requireCurrent()
      guard
        try selector.select(anchor: anchor, credentialPublicKey: observation.publicKey)
          == selection
      else { throw V3RecoveryValidationError.sourceChanged }
      try reader.revalidate(observation)
      try source.requireCurrent()
      result = .source(
        .init(
          assurance: .publicObservationOnly, path: root.rootURL.path,
          token: .init(tokenID: candidate.tokenID, readerSlotName: candidate.readerSlotName),
          recipientID: observation.recipientID.rawValue,
          reportedPINPolicy: "always", reportedTouchPolicy: "always",
          reportedKeyOrigin: "generated",
          vaultID: anchor.floor.vaultID, registrationID: anchor.registrationID,
          registrationManifestDigest: Base64URL.encode(anchor.floor.envelopeDigest),
          observedHeadDigest: Base64URL.encode(selection.head.digest),
          listedEntryCount: selection.head.body.fields.entries.count,
          observedManifestCount: selection.observedManifestBytes.count))
    }
    try scope.requireCurrent()
    return .init(exitCode: EXIT_SUCCESS, value: nil, errorMessage: nil, recoveryReview: result)
  }

  /// Adds scope/path checks around each bounded read without changing the
  /// history selector. The public review path cannot open any entry object.
  private struct PublicSource: V3ImmutableObjectReading {
    let root: VaultRootDirectoryHandle
    let scope: KeyRecoveryRequestScope

    func requireCurrent() throws {
      try scope.requireCurrent()
      try root.requireConfiguredRootIdentity()
    }

    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
      try requireCurrent()
      let listing = try V3FilesystemImmutableObjectSource(rootHandle: root)
        .manifestDigests(maximumCount: maximumCount)
      try requireCurrent()
      return listing
    }

    func readManifest(digest: Data, maximumBytes: Int) throws -> V3RepositoryObjectRead {
      try requireCurrent()
      let object = try V3FilesystemImmutableObjectSource(rootHandle: root)
        .readManifest(digest: digest, maximumBytes: maximumBytes)
      try requireCurrent()
      return object
    }

    func readEntry(entryID _: String, digest _: Data, maximumBytes _: Int) throws
      -> V3RepositoryObjectRead
    {
      throw AppError.operationRefused("Public recovery review cannot open entry objects.")
    }
  }
}
