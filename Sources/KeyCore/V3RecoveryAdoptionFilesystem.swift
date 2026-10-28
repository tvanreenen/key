import Foundation

extension V3FilesystemTransactionArtifactStore: V3RecoveryAdoptionPreparationStoring {
  func persistAdoptionPreparation(_ data: Data, operationID: VaultTransactionOperationID) throws {
    guard try V3RecoveryAdoptionPreparation(canonicalBytes: data).operationID == operationID else {
      throw V3RecoveryAdoptionServiceError.invalidPreparation
    }
    try writeStagedObject(data, at: adoptionPreparationPath(operationID))
  }
  func readAdoptionPreparation(operationID: VaultTransactionOperationID, maximumBytes: Int) throws
    -> V3RepositoryObjectRead
  {
    try readRecoveryObject(at: adoptionPreparationPath(operationID), maximumBytes: maximumBytes)
  }
  func confirmAdoptionPreparation(_ data: Data, operationID: VaultTransactionOperationID) throws {
    try confirmDurableRecoveryObject(
      data, at: adoptionPreparationPath(operationID),
      directories: [
        ".recovery-adoptions/\(operationID)", ".recovery-adoptions",
      ])
  }
}

private func adoptionPreparationPath(_ operationID: VaultTransactionOperationID) -> String {
  ".recovery-adoptions/\(operationID)/preparation.json"
}
