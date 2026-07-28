import Darwin
import Foundation

public struct VaultRootDirectoryIdentity: Equatable, Sendable {
    public let deviceID: UInt64
    public let fileID: UInt64

    public init(deviceID: UInt64, fileID: UInt64) {
        self.deviceID = deviceID
        self.fileID = fileID
    }
}

public enum VaultRootDirectoryHandleError: Error, Equatable, LocalizedError {
    case notFileURL
    case invalidPath
    case notFound(path: String)
    case notDirectoryOrSymbolicLink(path: String)
    case openFailed(path: String, code: Int32)
    case identityFailed(path: String, code: Int32)

    public var errorDescription: String? {
        switch self {
        case .notFileURL:
            return "The vault root must be a local file URL."
        case .invalidPath:
            return "The vault root path is not valid for filesystem access."
        case let .notFound(path):
            return "The vault root '\(path)' does not exist."
        case let .notDirectoryOrSymbolicLink(path):
            return "The vault root '\(path)' must be a real directory, not a file or symbolic link."
        case let .openFailed(path, code):
            return "Failed to open the vault root '\(path)' (POSIX error \(code))."
        case let .identityFailed(path, code):
            return "Failed to inspect the opened vault root '\(path)' (POSIX error \(code))."
        }
    }
}

/// Owns the directory descriptor that identifies the trusted vault root.
///
/// Future contained filesystem operations must be relative to this descriptor,
/// rather than rebuilding authority from `rootURL`.
public final class VaultRootDirectoryHandle: @unchecked Sendable {
    public let rootURL: URL
    public let identity: VaultRootDirectoryIdentity

    private let descriptor: Int32

    public init(opening rootURL: URL) throws {
        guard rootURL.isFileURL else {
            throw VaultRootDirectoryHandleError.notFileURL
        }

        let displayPath = rootURL.path(percentEncoded: false)
        var openPath = rootURL.standardizedFileURL.path(percentEncoded: false)
        while openPath.count > 1, openPath.hasSuffix("/") {
            openPath.removeLast()
        }
        guard
            !openPath.isEmpty,
            !displayPath.utf8.contains(0),
            !openPath.utf8.contains(0)
        else {
            throw VaultRootDirectoryHandleError.invalidPath
        }

        let descriptor = Self.openDirectory(at: openPath)
        guard descriptor >= 0 else {
            let code = errno
            switch code {
            case ENOENT:
                throw VaultRootDirectoryHandleError.notFound(path: displayPath)
            case ELOOP, ENOTDIR:
                throw VaultRootDirectoryHandleError.notDirectoryOrSymbolicLink(path: displayPath)
            default:
                throw VaultRootDirectoryHandleError.openFailed(path: displayPath, code: code)
            }
        }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw VaultRootDirectoryHandleError.identityFailed(path: displayPath, code: code)
        }
        guard metadata.st_mode & S_IFMT == S_IFDIR else {
            Darwin.close(descriptor)
            throw VaultRootDirectoryHandleError.notDirectoryOrSymbolicLink(path: displayPath)
        }

        self.rootURL = rootURL
        self.identity = VaultRootDirectoryIdentity(
            deviceID: UInt64(metadata.st_dev),
            fileID: UInt64(metadata.st_ino)
        )
        self.descriptor = descriptor
    }

    deinit {
        Darwin.close(descriptor)
    }

    func withFileDescriptor<Result>(
        _ operation: (Int32) throws -> Result
    ) rethrows -> Result {
        try operation(descriptor)
    }

    private static func openDirectory(at path: String) -> Int32 {
        while true {
            let descriptor = Darwin.open(
                path,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
            if descriptor >= 0 || errno != EINTR {
                return descriptor
            }
        }
    }
}
