import CryptoKit
import Darwin
import Foundation
import System

enum V3ImmutableObjectPublicationError: Error, Equatable, LocalizedError {
    case invalidPath
    case digestMismatch
    case conflictingObject(path: String)
    case operationFailed(path: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .invalidPath:
            "An immutable version 3 object path is invalid."
        case .digestMismatch:
            "Immutable version 3 object bytes do not match their content-addressed digest."
        case let .conflictingObject(path):
            "Immutable version 3 object '\(path)' already contains different bytes."
        case let .operationFailed(path, code):
            "Failed to publish immutable version 3 object '\(path)' (POSIX error \(code))."
        }
    }
}

struct V3FilesystemTransactionArtifactStore:
    V3ImmutableObjectPublishing,
    Sendable
{
    let rootHandle: VaultRootDirectoryHandle
    private let reader: V3FilesystemImmutableObjectSource
    private let stagedObjectWriter: V3AtomicStagedObjectWriter

    init(
        rootHandle: VaultRootDirectoryHandle,
        writeObserver: any V3AtomicStagedObjectWriteObserving =
            V3NoopAtomicStagedObjectWriteObserver()
    ) {
        self.rootHandle = rootHandle
        reader = V3FilesystemImmutableObjectSource(rootHandle: rootHandle)
        stagedObjectWriter = V3AtomicStagedObjectWriter(
            rootHandle: rootHandle,
            observer: writeObserver
        )
    }

    func manifestDigests(
        maximumCount: Int
    ) throws -> V3RepositoryDirectoryListing {
        try reader.manifestDigests(maximumCount: maximumCount)
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try reader.readManifest(digest: digest, maximumBytes: maximumBytes)
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try reader.readEntry(
            entryID: entryID,
            digest: digest,
            maximumBytes: maximumBytes
        )
    }
}

extension V3FilesystemTransactionArtifactStore {
    func readStagedEntry(
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        guard isValidV3UUID(entryID), digest.count == 32 else {
            return .invalid
        }
        return try readRecoveryObject(
            at: stagedEntryPath(
                operationID: operationID,
                entryID: entryID,
                digest: digest
            ),
            maximumBytes: maximumBytes
        )
    }

    func readStagedManifest(
        digest: Data,
        operationID: VaultTransactionOperationID,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        guard digest.count == 32 else {
            return .invalid
        }
        return try readRecoveryObject(
            at: stagedManifestPath(
                operationID: operationID,
                digest: digest
            ),
            maximumBytes: maximumBytes
        )
    }

    func stageEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try validateImmutableObject(
            data,
            digest: digest,
            entryID: entryID
        )
        try writeStagedObject(
            data,
            at: stagedEntryPath(
                operationID: operationID,
                entryID: entryID,
                digest: digest
            )
        )
    }

    func stageManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try validateImmutableObject(data, digest: digest)
        try writeStagedObject(
            data,
            at: stagedManifestPath(
                operationID: operationID,
                digest: digest
            )
        )
    }

    func publishStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try validateImmutableObject(
            data,
            digest: digest,
            entryID: entryID
        )
        try publishStagedObject(
            data,
            from: stagedEntryPath(
                operationID: operationID,
                entryID: entryID,
                digest: digest
            ),
            to: entryPath(
                entryID: entryID,
                digest: Base64URL.encode(digest)
            )
        )
    }

    func publishStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try validateImmutableObject(data, digest: digest)
        try publishStagedObject(
            data,
            from: stagedManifestPath(
                operationID: operationID,
                digest: digest
            ),
            to: manifestPath(for: digest)
        )
    }

    func removeStagedEntry(
        _ data: Data,
        entryID: String,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try validateImmutableObject(
            data,
            digest: digest,
            entryID: entryID
        )
        try removeExactRecoveryObject(
            data,
            at: stagedEntryPath(
                operationID: operationID,
                entryID: entryID,
                digest: digest
            )
        )
    }

    func removeStagedManifest(
        _ data: Data,
        digest: Data,
        operationID: VaultTransactionOperationID
    ) throws {
        try validateImmutableObject(data, digest: digest)
        try removeExactRecoveryObject(
            data,
            at: stagedManifestPath(
                operationID: operationID,
                digest: digest
            )
        )
    }

    func removeEmptyTransactionDirectories(
        operationID: VaultTransactionOperationID,
        entryIDs: [String]
    ) throws {
        guard entryIDs.allSatisfy(isValidV3UUID) else {
            throw V3ImmutableObjectPublicationError.invalidPath
        }
        for entryID in Set(entryIDs).sorted() {
            try removeDirectoryIfEmpty(
                at: ".transactions/\(operationID)/entries/\(entryID)"
            )
        }
        try removeDirectoryIfEmpty(
            at: ".transactions/\(operationID)/entries"
        )
        try removeDirectoryIfEmpty(
            at: ".transactions/\(operationID)/manifests"
        )
        try removeDirectoryIfEmpty(
            at: ".transactions/\(operationID)"
        )
        try removeDirectoryIfEmpty(at: ".transactions")
    }

    func readRecoveryObject(
        at path: String,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        do {
            return try rootHandle.withResolvedDescriptor(
                at: path,
                expecting: .regularFile
            ) { descriptor in
                readObjectData(
                    descriptor: descriptor.rawValue,
                    maximumBytes: maximumBytes
                )
            }
        } catch let error as VaultRootDirectoryHandleError {
            throw error
        } catch VaultPathResolutionError.notFound,
                VaultPathResolutionError.providerPlaceholder {
            return .unavailable
        } catch {
            return .invalid
        }
    }

    func writeStagedObject(
        _ data: Data,
        at path: String
    ) throws {
        try stagedObjectWriter.install(data, at: path)
    }

    private func publishStagedObject(
        _ data: Data,
        from stagingPath: String,
        to destinationPath: String
    ) throws {
        try requireExactObject(data, at: stagingPath)
        try rootHandle.ensureParentDirectories(of: destinationPath)

        try rootHandle.withResolvedParentDescriptors(
            at: stagingPath,
            and: destinationPath
        ) {
            stagingParent,
            stagingName,
            destinationParent,
            destinationName in
            while true {
                // SAFETY: both names are validated terminal components and
                // both descriptors remain open beneath the same vault root.
                let result = unsafe renameatx_np(
                    stagingParent,
                    stagingName,
                    destinationParent,
                    destinationName,
                    UInt32(RENAME_EXCL)
                )
                if result == 0 {
                    try synchronizeDirectory(
                        destinationParent,
                        path: destinationPath
                    )
                    if stagingParent != destinationParent {
                        try synchronizeDirectory(
                            stagingParent,
                            path: stagingPath
                        )
                    }
                    return
                }

                let code = errno
                if code == EINTR {
                    continue
                }
                if code == EEXIST {
                    try requireExactObject(data, at: destinationPath)
                    return
                }
                throw V3ImmutableObjectPublicationError.operationFailed(
                    path: destinationPath,
                    code: code
                )
            }
        }
    }

    private func requireExactObject(
        _ expected: Data,
        at path: String
    ) throws {
        let result = try rootHandle.withResolvedDescriptor(
            at: path,
            expecting: .regularFile
        ) { descriptor in
            readObjectData(
                descriptor: descriptor.rawValue,
                maximumBytes: expected.count
            )
        }
        guard case let .available(observed) = result,
              observed == expected
        else {
            throw V3ImmutableObjectPublicationError.conflictingObject(
                path: path
            )
        }
    }

    func removeExactRecoveryObject(
        _ expected: Data,
        at path: String
    ) throws {
        do {
            try requireExactObject(expected, at: path)
            try rootHandle.withResolvedParentDescriptor(at: path) {
                parentDescriptor, name in
                while true {
                    // SAFETY: `name` is a validated terminal component and
                    // `parentDescriptor` is retained beneath the vault root.
                    if unsafe unlinkat(parentDescriptor, name, 0) == 0 {
                        try synchronizeDirectory(
                            parentDescriptor,
                            path: path
                        )
                        return
                    }
                    let code = errno
                    if code == EINTR {
                        continue
                    }
                    if code == ENOENT {
                        return
                    }
                    throw V3ImmutableObjectPublicationError.operationFailed(
                        path: path,
                        code: code
                    )
                }
            }
        } catch VaultPathResolutionError.notFound {
            return
        }
    }

    private func removeDirectoryIfEmpty(at path: String) throws {
        do {
            try rootHandle.withResolvedParentDescriptor(at: path) {
                parentDescriptor, name in
                while true {
                    // SAFETY: `name` is a validated terminal component and
                    // the directory-relative removal cannot follow it.
                    if unsafe unlinkat(
                        parentDescriptor,
                        name,
                        AT_REMOVEDIR
                    ) == 0 {
                        try synchronizeDirectory(
                            parentDescriptor,
                            path: path
                        )
                        return
                    }
                    let code = errno
                    if code == EINTR {
                        continue
                    }
                    if code == ENOENT || code == ENOTEMPTY {
                        return
                    }
                    throw V3ImmutableObjectPublicationError.operationFailed(
                        path: path,
                        code: code
                    )
                }
            }
        } catch VaultPathResolutionError.notFound {
            return
        }
    }

    private func validateImmutableObject(
        _ data: Data,
        digest: Data,
        entryID: String? = nil
    ) throws {
        guard entryID.map(isValidV3UUID) ?? true else {
            throw V3ImmutableObjectPublicationError.invalidPath
        }
        guard digest.count == 32,
              Data(SHA256.hash(data: data)) == digest
        else {
            throw V3ImmutableObjectPublicationError.digestMismatch
        }
    }
}

extension VaultRootDirectoryHandle {
    func ensureParentDirectories(of relativePath: String) throws {
        try withCreatedParentDescriptor(at: relativePath) { _, _ in }
    }

    func withCreatedParentDescriptor<Result>(
        at relativePath: String,
        _ operation: (Int32, String) throws -> Result
    ) throws -> Result {
        let components = relativePath.split(
            separator: "/",
            omittingEmptySubsequences: false
        ).map(String.init)
        guard !components.isEmpty,
              components.allSatisfy({
                  !$0.isEmpty && $0 != "." && $0 != ".."
                      && !$0.utf8.contains(0)
              })
        else {
            throw V3ImmutableObjectPublicationError.invalidPath
        }

        return try withFileDescriptor { rootDescriptor in
            var openedDirectories: [FileDescriptor] = []
            defer {
                for descriptor in openedDirectories.reversed() {
                    try? descriptor.close()
                }
            }
            var parentDescriptor = rootDescriptor
            for component in components.dropLast() {
                var created = false
                while true {
                    // SAFETY: `component` is validated and NUL-free, and the
                    // parent descriptor remains within the opened vault root.
                    if unsafe mkdirat(
                        parentDescriptor,
                        component,
                        S_IRWXU
                    ) == 0 {
                        created = true
                        break
                    }
                    let code = errno
                    if code == EINTR {
                        continue
                    }
                    guard code == EEXIST else {
                        throw V3ImmutableObjectPublicationError.operationFailed(
                            path: relativePath,
                            code: code
                        )
                    }
                    break
                }
                if created {
                    try synchronizeDirectory(
                        parentDescriptor,
                        path: relativePath
                    )
                }

                let descriptor = try openValidatedComponent(
                    component,
                    relativeTo: parentDescriptor,
                    path: relativePath,
                    expecting: .directory,
                    rootDeviceID: identity.deviceID
                )
                openedDirectories.append(descriptor)
                parentDescriptor = descriptor.rawValue
            }
            guard let terminal = components.last else {
                throw V3ImmutableObjectPublicationError.invalidPath
            }
            return try operation(parentDescriptor, terminal)
        }
    }
}

private func stagedEntryPath(
    operationID: VaultTransactionOperationID,
    entryID: String,
    digest: Data
) -> String {
    ".transactions/\(operationID)/entries/\(entryID)/\(v3LowercaseHex(digest)).json"
}

private func stagedManifestPath(
    operationID: VaultTransactionOperationID,
    digest: Data
) -> String {
    ".transactions/\(operationID)/manifests/\(v3LowercaseHex(digest)).json"
}

func synchronizeFile(
    _ descriptor: Int32,
    path: String
) throws {
    // F_FULLFSYNC requests the strongest macOS local durability guarantee.
    // Some provider-backed filesystems reject it, so retain fsync fallback.
    while true {
        if fcntl(descriptor, F_FULLFSYNC) == 0 {
            return
        }
        let code = errno
        if code == EINTR {
            continue
        }
        guard code == ENOTSUP || code == EINVAL || code == ENOTTY else {
            throw V3ImmutableObjectPublicationError.operationFailed(
                path: path,
                code: code
            )
        }
        break
    }
    while fsync(descriptor) != 0 {
        let code = errno
        if code == EINTR {
            continue
        }
        throw V3ImmutableObjectPublicationError.operationFailed(
            path: path,
            code: code
        )
    }
}

func synchronizeDirectory(
    _ descriptor: Int32,
    path: String
) throws {
    while fsync(descriptor) != 0 {
        let code = errno
        if code == EINTR {
            continue
        }
        throw V3ImmutableObjectPublicationError.operationFailed(
            path: path,
            code: code
        )
    }
}
