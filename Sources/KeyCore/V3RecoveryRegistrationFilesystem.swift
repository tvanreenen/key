import Darwin
import Foundation

/// Uses the existing contained no-overwrite atomic writer. Registration records
/// are not ordinary transaction intents and cannot be discovered as such.
extension V3FilesystemTransactionArtifactStore: V3RecoveryRegistrationBundleStoring {
  func persistRegistrationBundle(_ data: Data, operationID: VaultTransactionOperationID) throws {
    let bundle = try V3RecoveryRegistrationBundle(canonicalBytes: data)
    guard bundle.preparation.intent.operationID == operationID else {
      throw V3ImmutableObjectPublicationError.invalidPath
    }
    try writeStagedObject(data, at: registrationBundlePath(operationID))
  }

  func readRegistrationBundle(
    operationID: VaultTransactionOperationID, maximumBytes: Int
  ) throws -> V3RepositoryObjectRead {
    try readRecoveryObject(at: registrationBundlePath(operationID), maximumBytes: maximumBytes)
  }

  func confirmRegistrationBundle(_ data: Data, operationID: VaultTransactionOperationID) throws {
    let path = registrationBundlePath(operationID)
    try rootHandle.withResolvedDescriptor(at: path, expecting: .regularFile) { descriptor in
      guard
        case .available(let bytes) = readObjectData(
          descriptor: descriptor.rawValue, maximumBytes: data.count), bytes == data
      else { throw V3ImmutableObjectPublicationError.conflictingObject(path: path) }
      try synchronizeFile(descriptor.rawValue, path: path)
      guard Darwin.lseek(descriptor.rawValue, 0, SEEK_SET) == 0 else {
        throw V3ImmutableObjectPublicationError.operationFailed(path: path, code: errno)
      }
      guard
        case .available(let bytes) = readObjectData(
          descriptor: descriptor.rawValue, maximumBytes: data.count), bytes == data
      else { throw V3ImmutableObjectPublicationError.conflictingObject(path: path) }
    }
    // Confirm the directory links as well as the file. Never infer durability
    // from a prior attempt that may have failed after installation.
    for directory in [".recovery-registrations/\(operationID)", ".recovery-registrations"] {
      try rootHandle.withResolvedDescriptor(at: directory, expecting: .directory) { descriptor in
        try synchronizeDirectory(descriptor.rawValue, path: directory)
      }
    }
    try rootHandle.withFileDescriptor { descriptor in
      try synchronizeDirectory(descriptor, path: ".")
    }
  }
}

private func registrationBundlePath(_ operationID: VaultTransactionOperationID) -> String {
  ".recovery-registrations/\(operationID)/preparation.json"
}
