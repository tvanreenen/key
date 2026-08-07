import CryptoKit
import Darwin
import Foundation
import System

enum V3CheckpointManifestCacheLookup: Equatable, Sendable {
    case available(Data)
    case missing
    case unusable
}

enum V3CheckpointManifestCacheError: Error, Equatable, LocalizedError {
    case invalidManifest
    case operationFailed(code: Int32)

    var errorDescription: String? {
        switch self {
        case .invalidManifest:
            "The checkpoint-manifest cache requires the exact bounded manifest named by the local checkpoint."
        case let .operationFailed(code):
            "The checkpoint-manifest cache operation failed (POSIX error \(code))."
        }
    }
}

protocol V3CheckpointManifestCaching: Sendable {
    func load(
        for checkpoint: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws
}

/// Device-local cache of the exact manifest bytes named by the Keychain
/// checkpoint.
///
/// Cache files contain no plaintext or vault key and grant no authority. A
/// missing, malformed, substituted, or unsafe cache path is reported as
/// unavailable so the caller can request the exact provider object. Only the
/// digest in the non-synchronizing Keychain checkpoint establishes identity.
final class V3CheckpointManifestFilesystemCache:
    V3CheckpointManifestCaching,
    @unchecked Sendable
{
    private let rootHandle: VaultRootDirectoryHandle
    private let maximumManifestBytes: Int
    private let lock = NSLock()

    init(
        rootHandle: VaultRootDirectoryHandle,
        maximumManifestBytes: Int =
            V3ManifestRepositoryLimits.standard.maximumManifestBytes
    ) {
        precondition(maximumManifestBytes > 0)
        self.rootHandle = rootHandle
        self.maximumManifestBytes = maximumManifestBytes
    }

    func load(
        for checkpoint: V3ManifestCheckpoint
    ) throws -> V3CheckpointManifestCacheLookup {
        lock.lock()
        defer { lock.unlock() }

        do {
            let read = try rootHandle.withResolvedDescriptor(
                at: cachePath(for: checkpoint),
                expecting: .regularFile
            ) { descriptor in
                readObjectData(
                    descriptor: descriptor.rawValue,
                    maximumBytes: maximumManifestBytes
                )
            }
            guard case let .available(data) = read,
                  Data(SHA256.hash(data: data)) == checkpoint.envelopeDigest
            else {
                return .unusable
            }
            return .available(data)
        } catch VaultPathResolutionError.notFound {
            return .missing
        } catch is VaultPathResolutionError {
            return .unusable
        }
    }

    func store(
        _ manifestData: Data,
        for checkpoint: V3ManifestCheckpoint
    ) throws {
        guard !manifestData.isEmpty,
              manifestData.count <= maximumManifestBytes,
              Data(SHA256.hash(data: manifestData))
                == checkpoint.envelopeDigest
        else {
            throw V3CheckpointManifestCacheError.invalidManifest
        }

        lock.lock()
        defer { lock.unlock() }
        try rootHandle.withFileDescriptor { rootDescriptor in
            let destination = cachePath(for: checkpoint)
            let (temporary, descriptor) = try openTemporaryFile(
                for: checkpoint,
                relativeTo: rootDescriptor
            )
            var temporaryExists = true
            defer {
                Darwin.close(descriptor)
                if temporaryExists {
                    _ = unsafe unlinkat(rootDescriptor, temporary, 0)
                }
            }

            do {
                _ = try FileDescriptor(rawValue: descriptor)
                    .writeAll(manifestData)
                try synchronizeFile(descriptor, path: destination)
            } catch let error as V3ImmutableObjectPublicationError {
                throw cacheError(for: error)
            } catch {
                throw V3CheckpointManifestCacheError.operationFailed(
                    code: (error as? Errno)?.rawValue ?? EIO
                )
            }

            while true {
                // Both names are terminal components beneath the retained
                // cache-directory descriptor. `renameat` exposes either the
                // complete old bytes or the complete synchronized new bytes.
                if unsafe renameat(
                    rootDescriptor,
                    temporary,
                    rootDescriptor,
                    destination
                ) == 0 {
                    temporaryExists = false
                    do {
                        try synchronizeDirectory(
                            rootDescriptor,
                            path: destination
                        )
                    } catch let error as V3ImmutableObjectPublicationError {
                        throw cacheError(for: error)
                    }
                    return
                }
                let code = errno
                if code == EINTR {
                    continue
                }
                throw V3CheckpointManifestCacheError.operationFailed(
                    code: code
                )
            }
        }
    }

    private func cachePath(for checkpoint: V3ManifestCheckpoint) -> String {
        "\(checkpoint.vaultID).json"
    }

    private func openTemporaryFile(
        for checkpoint: V3ManifestCheckpoint,
        relativeTo rootDescriptor: Int32
    ) throws -> (name: String, descriptor: Int32) {
        while true {
            let name = ".\(checkpoint.vaultID).\(UUID().uuidString.lowercased()).partial"
            let descriptor = unsafe Darwin.openat(
                rootDescriptor,
                name,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                S_IRUSR | S_IWUSR
            )
            if descriptor >= 0 {
                return (name, descriptor)
            }
            let code = errno
            if code == EINTR || code == EEXIST {
                continue
            }
            throw V3CheckpointManifestCacheError.operationFailed(code: code)
        }
    }

    private func cacheError(
        for error: V3ImmutableObjectPublicationError
    ) -> V3CheckpointManifestCacheError {
        if case let .operationFailed(_, code) = error {
            return .operationFailed(code: code)
        }
        return .operationFailed(code: EIO)
    }
}
