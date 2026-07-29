import Darwin
import Foundation
import System

enum V3AtomicStagedObjectWritePhase: Equatable, Sendable {
    case temporaryFileSynchronized(destinationPath: String)
}

protocol V3AtomicStagedObjectWriteObserving: Sendable {
    func didReach(_ phase: V3AtomicStagedObjectWritePhase) throws
}

struct V3NoopAtomicStagedObjectWriteObserver:
    V3AtomicStagedObjectWriteObserving
{
    func didReach(_: V3AtomicStagedObjectWritePhase) throws {}
}

/// Installs complete recovery bytes at one canonical staging path.
///
/// The destination transitions atomically from absent to complete. An
/// interruption can leave only a hidden, non-authoritative `.partial` file.
struct V3AtomicStagedObjectWriter: Sendable {
    private let rootHandle: VaultRootDirectoryHandle
    private let observer: any V3AtomicStagedObjectWriteObserving

    init(
        rootHandle: VaultRootDirectoryHandle,
        observer: any V3AtomicStagedObjectWriteObserving =
            V3NoopAtomicStagedObjectWriteObserver()
    ) {
        self.rootHandle = rootHandle
        self.observer = observer
    }

    func install(_ data: Data, at path: String) throws {
        try rootHandle.withCreatedParentDescriptor(at: path) {
            parentDescriptor, name in
            let (temporaryName, descriptor) = try openTemporaryFile(
                for: name,
                relativeTo: parentDescriptor,
                destinationPath: path
            )
            var temporaryFileExists = true
            defer {
                Darwin.close(descriptor)
                if temporaryFileExists {
                    // This file is never authoritative or discoverable as a
                    // recovery object. Best-effort removal covers ordinary
                    // failures; a process crash can leave it inert.
                    _ = unsafe unlinkat(
                        parentDescriptor,
                        temporaryName,
                        0
                    )
                }
            }

            do {
                _ = try FileDescriptor(rawValue: descriptor).writeAll(data)
            } catch {
                throw V3ImmutableObjectPublicationError.operationFailed(
                    path: path,
                    code: (error as? Errno)?.rawValue ?? EIO
                )
            }
            try synchronizeFile(descriptor, path: path)
            try observer.didReach(
                .temporaryFileSynchronized(destinationPath: path)
            )

            while true {
                // SAFETY: both names are validated terminal components in the
                // same retained directory. `RENAME_EXCL` makes the complete,
                // synchronized bytes visible without overwriting an existing
                // recovery object.
                let result = unsafe renameatx_np(
                    parentDescriptor,
                    temporaryName,
                    parentDescriptor,
                    name,
                    UInt32(RENAME_EXCL)
                )
                if result == 0 {
                    temporaryFileExists = false
                    try synchronizeDirectory(parentDescriptor, path: path)
                    return
                }

                let code = errno
                if code == EINTR {
                    continue
                }
                if code == EEXIST {
                    try requireExactObject(
                        data,
                        at: path,
                        rootHandle: rootHandle
                    )
                    return
                }
                throw V3ImmutableObjectPublicationError.operationFailed(
                    path: path,
                    code: code
                )
            }
        }
    }

    private func openTemporaryFile(
        for destinationName: String,
        relativeTo parentDescriptor: Int32,
        destinationPath: String
    ) throws -> (name: String, descriptor: Int32) {
        while true {
            let temporaryName =
                ".\(destinationName).\(UUID().uuidString.lowercased()).partial"
            // SAFETY: `temporaryName` is a fresh, NUL-free terminal component
            // and `parentDescriptor` is an already validated directory beneath
            // the opened vault root. `O_EXCL` ensures an existing hard link,
            // symbolic link, FIFO, or another writer's temporary file is never
            // opened or modified.
            let result = unsafe Darwin.openat(
                parentDescriptor,
                temporaryName,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
            if result >= 0 {
                return (temporaryName, result)
            }
            let code = errno
            if code == EINTR {
                continue
            }
            if code == EEXIST {
                continue
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
    at path: String,
    rootHandle: VaultRootDirectoryHandle
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
        throw V3ImmutableObjectPublicationError.conflictingObject(path: path)
    }
}
