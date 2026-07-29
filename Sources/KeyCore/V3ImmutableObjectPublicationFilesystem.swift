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

extension V3FilesystemImmutableObjectSource: V3ImmutableObjectPublishing {
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

    private func writeStagedObject(
        _ data: Data,
        at path: String
    ) throws {
        try rootHandle.withCreatedParentDescriptor(at: path) {
            parentDescriptor, name in
            let descriptor: Int32
            while true {
                // SAFETY: `name` is one validated, NUL-free component and the
                // descriptor is an already validated directory beneath the
                // opened vault root.
                let result = unsafe Darwin.openat(
                    parentDescriptor,
                    name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    S_IRUSR | S_IWUSR
                )
                if result >= 0 {
                    descriptor = result
                    break
                }
                let code = errno
                if code == EINTR {
                    continue
                }
                if code == EEXIST {
                    try requireExactObject(data, at: path)
                    return
                }
                throw V3ImmutableObjectPublicationError.operationFailed(
                    path: path,
                    code: code
                )
            }
            defer { Darwin.close(descriptor) }

            do {
                _ = try FileDescriptor(rawValue: descriptor).writeAll(data)
            } catch {
                throw V3ImmutableObjectPublicationError.operationFailed(
                    path: path,
                    code: (error as? Errno)?.rawValue ?? EIO
                )
            }
            try synchronizeFile(descriptor, path: path)
            try synchronizeDirectory(parentDescriptor, path: path)
        }
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

private extension VaultRootDirectoryHandle {
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

private func synchronizeFile(
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

private func synchronizeDirectory(
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
