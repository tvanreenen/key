import Darwin
import Foundation

enum VaultContainedMutationOperation: String, Equatable, Sendable {
    case replace
    case move
    case remove
}

enum VaultContainedMutationError: Error, Equatable, LocalizedError {
    case sourceAndDestinationAreSame(path: String)
    case destinationExists(path: String)
    case directoryNotEmpty(path: String)
    case operationFailed(
        operation: VaultContainedMutationOperation,
        path: String,
        code: Int32
    )

    var errorDescription: String? {
        switch self {
        case let .sourceAndDestinationAreSame(path):
            return "Vault mutation source and destination both name '\(path)'."
        case let .destinationExists(path):
            return "Vault mutation destination '\(path)' already exists."
        case let .directoryNotEmpty(path):
            return "Vault directory '\(path)' is not empty."
        case let .operationFailed(operation, path, code):
            return "Failed to \(operation.rawValue) vault path '\(path)' (POSIX error \(code))."
        }
    }
}

private struct VaultContainedItemIdentity: Equatable {
    let deviceID: UInt64
    let fileID: UInt64
}

extension VaultRootDirectoryHandle {
    /// Atomically replaces one regular file with a staged regular file.
    ///
    /// Both files must already exist and pass the vault path protections. The
    /// source is removed by the rename. This primitive provides path
    /// containment and atomic namespace replacement, not crash durability;
    /// the transaction layer remains responsible for synchronization.
    func replaceRegularFile(
        at destinationPath: String,
        withStagedFileAt sourcePath: String
    ) throws {
        let sourceIdentity = try resolvedRegularFileIdentity(at: sourcePath)
        let destinationIdentity = try resolvedRegularFileIdentity(
            at: destinationPath
        )
        guard sourceIdentity != destinationIdentity else {
            throw VaultContainedMutationError.sourceAndDestinationAreSame(
                path: sourcePath
            )
        }

        try withResolvedParentDescriptors(
            at: sourcePath,
            and: destinationPath
        ) { sourceParent, sourceName, destinationParent, destinationName in
            try retryingInterruptedCall(
                operation: .replace,
                path: destinationPath
            ) {
                renameat(
                    sourceParent,
                    sourceName,
                    destinationParent,
                    destinationName
                )
            }
        }

        try withResolvedDescriptor(
            at: destinationPath,
            expecting: .regularFile
        ) { _ in }
    }

    /// Moves one validated item to an unoccupied path beneath the vault root.
    ///
    /// `RENAME_EXCL` makes the no-overwrite policy part of the rename itself,
    /// rather than a check that another actor could invalidate.
    func moveItem(
        at sourcePath: String,
        to destinationPath: String,
        expecting expectedKind: VaultResolvedPathKind
    ) throws {
        try withResolvedDescriptor(
            at: sourcePath,
            expecting: expectedKind
        ) { _ in }

        try withResolvedParentDescriptors(
            at: sourcePath,
            and: destinationPath
        ) { sourceParent, sourceName, destinationParent, destinationName in
            while true {
                let result = renameatx_np(
                    sourceParent,
                    sourceName,
                    destinationParent,
                    destinationName,
                    UInt32(RENAME_EXCL)
                )
                if result == 0 {
                    break
                }

                let code = errno
                if code == EINTR {
                    continue
                }
                if code == EEXIST {
                    throw VaultContainedMutationError.destinationExists(
                        path: destinationPath
                    )
                }
                throw VaultContainedMutationError.operationFailed(
                    operation: .move,
                    path: "\(sourcePath) -> \(destinationPath)",
                    code: code
                )
            }
        }

        try withResolvedDescriptor(
            at: destinationPath,
            expecting: expectedKind
        ) { _ in }
    }

    /// Removes one validated regular file or already-empty directory.
    ///
    /// Directory removal deliberately uses `AT_REMOVEDIR`; this API never
    /// recursively traverses and deletes a subtree.
    func removeItem(
        at path: String,
        expecting expectedKind: VaultResolvedPathKind
    ) throws {
        try withResolvedDescriptor(at: path, expecting: expectedKind) { _ in }

        try withResolvedParentDescriptor(at: path) { parent, name in
            let flags = expectedKind == .directory ? AT_REMOVEDIR : 0

            while true {
                let result = unlinkat(parent, name, flags)
                if result == 0 {
                    break
                }

                let code = errno
                if code == EINTR {
                    continue
                }
                if expectedKind == .directory,
                   code == ENOTEMPTY || code == EEXIST {
                    throw VaultContainedMutationError.directoryNotEmpty(
                        path: path
                    )
                }
                throw VaultContainedMutationError.operationFailed(
                    operation: .remove,
                    path: path,
                    code: code
                )
            }
        }
    }

    private func resolvedRegularFileIdentity(
        at path: String
    ) throws -> VaultContainedItemIdentity {
        try withResolvedDescriptor(at: path, expecting: .regularFile) {
            descriptor in
            var metadata = stat()
            guard fstat(descriptor.rawValue, &metadata) == 0 else {
                throw VaultContainedMutationError.operationFailed(
                    operation: .replace,
                    path: path,
                    code: errno
                )
            }
            return VaultContainedItemIdentity(
                deviceID: UInt64(metadata.st_dev),
                fileID: UInt64(metadata.st_ino)
            )
        }
    }
}

private func retryingInterruptedCall(
    operation: VaultContainedMutationOperation,
    path: String,
    _ call: () -> Int32
) throws {
    while true {
        if call() == 0 {
            return
        }

        let code = errno
        if code == EINTR {
            continue
        }
        throw VaultContainedMutationError.operationFailed(
            operation: operation,
            path: path,
            code: code
        )
    }
}
