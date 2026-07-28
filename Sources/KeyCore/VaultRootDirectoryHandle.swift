import Darwin
import Foundation
import System

/// The stable filesystem identity of an opened vault-root directory.
public struct VaultRootDirectoryIdentity: Equatable, Sendable {
    /// The device containing the vault root.
    public let deviceID: UInt64

    /// The file identifier of the vault-root directory on `deviceID`.
    public let fileID: UInt64

    /// Creates a filesystem identity from a device and file identifier.
    public init(deviceID: UInt64, fileID: UInt64) {
        self.deviceID = deviceID
        self.fileID = fileID
    }
}

/// An error encountered while establishing or revalidating vault-root authority.
public enum VaultRootDirectoryHandleError: Error, Equatable, LocalizedError {
    /// The supplied URL is not a file URL.
    case notFileURL

    /// The supplied file URL cannot name an absolute local path.
    case invalidPath

    /// No filesystem object exists at the supplied path.
    case notFound(path: String)

    /// The supplied path names a file or symbolic link instead of a directory.
    case notDirectoryOrSymbolicLink(path: String)

    /// The vault-root directory could not be opened.
    case openFailed(path: String, code: Int32)

    /// The opened vault-root directory could not be inspected.
    case identityFailed(path: String, code: Int32)

    /// The configured path no longer names the directory opened for this session.
    case configuredRootChanged(path: String)

    /// A localized description of the root-authority failure.
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
        case let .configuredRootChanged(path):
            return "The configured vault root '\(path)' no longer names the directory opened for this session."
        }
    }
}

/// Owns the directory descriptor that identifies the trusted vault root.
///
/// Future contained filesystem operations must be relative to this descriptor,
/// rather than rebuilding authority from `rootURL`.
public final class VaultRootDirectoryHandle: Sendable {
    /// The configured URL used only to establish and revalidate this handle.
    ///
    /// Contained filesystem operations must use the retained descriptor rather
    /// than reconstructing authority from this URL.
    public let rootURL: URL

    /// The stable identity captured from the opened vault-root descriptor.
    public let identity: VaultRootDirectoryIdentity

    private let descriptor: FileDescriptor

    /// Opens a trusted, nonsymlink vault-root directory.
    public init(opening rootURL: URL) throws {
        guard rootURL.isFileURL else {
            throw VaultRootDirectoryHandleError.notFileURL
        }

        let displayPath = rootURL.path(percentEncoded: false)
        if let host = rootURL.host,
           !host.isEmpty,
           host.caseInsensitiveCompare("localhost") != .orderedSame {
            throw VaultRootDirectoryHandleError.invalidPath
        }
        guard displayPath.hasPrefix("/") else {
            throw VaultRootDirectoryHandleError.invalidPath
        }

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

        let descriptor: FileDescriptor
        do {
            descriptor = try FileDescriptor.open(
                FilePath(openPath),
                .readOnly,
                options: [.directory, .noFollow, .closeOnExec]
            )
        } catch let error as Errno {
            switch error {
            case .noSuchFileOrDirectory:
                throw VaultRootDirectoryHandleError.notFound(path: displayPath)
            case .notDirectory:
                throw VaultRootDirectoryHandleError.notDirectoryOrSymbolicLink(path: displayPath)
            default:
                if error.rawValue == ELOOP {
                    throw VaultRootDirectoryHandleError.notDirectoryOrSymbolicLink(path: displayPath)
                }
                throw VaultRootDirectoryHandleError.openFailed(
                    path: displayPath,
                    code: error.rawValue
                )
            }
        }

        var metadata = stat()
        guard fstat(descriptor.rawValue, &metadata) == 0 else {
            let code = errno
            try? descriptor.close()
            throw VaultRootDirectoryHandleError.identityFailed(path: displayPath, code: code)
        }
        guard metadata.st_mode & S_IFMT == S_IFDIR else {
            try? descriptor.close()
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
        try? descriptor.close()
    }

    func withFileDescriptor<Result>(
        _ operation: (Int32) throws -> Result
    ) throws -> Result {
        try verifyConfiguredRootIdentity()
        return try operation(descriptor.rawValue)
    }

    private func verifyConfiguredRootIdentity() throws {
        let displayPath = rootURL.path(percentEncoded: false)
        let currentRoot: VaultRootDirectoryHandle
        do {
            currentRoot = try VaultRootDirectoryHandle(opening: rootURL)
        } catch {
            throw VaultRootDirectoryHandleError.configuredRootChanged(
                path: displayPath
            )
        }

        guard currentRoot.identity == identity else {
            throw VaultRootDirectoryHandleError.configuredRootChanged(
                path: displayPath
            )
        }
    }
}
