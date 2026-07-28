import Darwin
import Foundation
import System

enum VaultResolvedPathKind: Equatable, Sendable {
    case directory
    case regularFile

    fileprivate var displayName: String {
        switch self {
        case .directory:
            return "directory"
        case .regularFile:
            return "regular file"
        }
    }
}

enum VaultPathResolutionError: Error, Equatable, LocalizedError {
    case invalidRelativePath
    case notFound(component: String)
    case symbolicLink(component: String)
    case notDirectory(component: String)
    case filesystemAlias(component: String)
    case providerPlaceholder(component: String)
    case crossedFilesystem(component: String)
    case unexpectedType(path: String, expected: VaultResolvedPathKind)
    case openFailed(component: String, code: Int32)
    case inspectionFailed(path: String, code: Int32)

    var errorDescription: String? {
        switch self {
        case .invalidRelativePath:
            return "A vault path must be a nonempty relative path without empty, '.', '..', or NUL components."
        case let .notFound(component):
            return "Vault path component '\(component)' does not exist."
        case let .symbolicLink(component):
            return "Vault path component '\(component)' must not be a symbolic link."
        case let .notDirectory(component):
            return "Vault path component '\(component)' must be a directory."
        case let .filesystemAlias(component):
            return "Vault path component '\(component)' must not be a filesystem alias or hard link."
        case let .providerPlaceholder(component):
            return "Vault path component '\(component)' is an unmaterialized provider placeholder."
        case let .crossedFilesystem(component):
            return "Vault path component '\(component)' crosses out of the vault root filesystem."
        case let .unexpectedType(path, expected):
            return "Vault path '\(path)' must resolve to a \(expected.displayName)."
        case let .openFailed(component, code):
            return "Failed to open vault path component '\(component)' (POSIX error \(code))."
        case let .inspectionFailed(path, code):
            return "Failed to inspect vault path '\(path)' (POSIX error \(code))."
        }
    }
}

extension VaultRootDirectoryHandle {
    /// Opens one validated descendant and lends its descriptor to `operation`.
    ///
    /// - Important: The descriptor is valid only for the dynamic extent of
    ///   `operation`. The closure must not store or return it.
    func withResolvedDescriptor<Result>(
        at relativePath: String,
        expecting expectedKind: VaultResolvedPathKind,
        _ operation: (FileDescriptor) throws -> Result
    ) throws -> Result {
        let path = try ValidatedVaultRelativePath(relativePath)

        return try withFileDescriptor { rootDescriptor in
            var ownedParent: FileDescriptor?
            defer {
                try? ownedParent?.close()
            }

            var parentDescriptor = rootDescriptor

            for (index, component) in path.components.enumerated() {
                let isTerminal = index == path.components.index(before: path.components.endIndex)
                let requiredKind: VaultResolvedPathKind = isTerminal ? expectedKind : .directory
                let child = try openValidatedComponent(
                    component,
                    relativeTo: parentDescriptor,
                    path: relativePath,
                    expecting: requiredKind,
                    rootDeviceID: identity.deviceID
                )

                if isTerminal {
                    return try child.closeAfter {
                        try operation(child)
                    }
                }

                if let previousParent = ownedParent {
                    try? previousParent.close()
                }
                ownedParent = child
                parentDescriptor = child.rawValue
            }

            preconditionFailure("A validated vault path must contain at least one component.")
        }
    }

    /// Lends the trusted parent descriptor and terminal name for one path.
    ///
    /// This is the mutation-side counterpart to `withResolvedDescriptor`.
    /// Every parent component is opened and validated beneath the retained
    /// vault root. The terminal name is never interpreted as a path.
    ///
    /// - Important: The descriptor is valid only for the dynamic extent of
    ///   `operation`. The closure must not store or return it.
    func withResolvedParentDescriptor<Result>(
        at relativePath: String,
        _ operation: (Int32, String) throws -> Result
    ) throws -> Result {
        let path = try ValidatedVaultRelativePath(relativePath)

        return try withFileDescriptor { rootDescriptor in
            let ownedParent = try openValidatedParent(
                of: path,
                rootDescriptor: rootDescriptor,
                path: relativePath
            )
            defer {
                try? ownedParent?.close()
            }

            return try operation(
                ownedParent?.rawValue ?? rootDescriptor,
                path.terminalComponent
            )
        }
    }

    /// Lends trusted parent descriptors and terminal names for two paths.
    ///
    /// Both paths are resolved during one root-identity check so a rename can
    /// operate only between already-opened directories beneath that root.
    ///
    /// - Important: The descriptors are valid only for the dynamic extent of
    ///   `operation`. The closure must not store or return either descriptor.
    func withResolvedParentDescriptors<Result>(
        at firstRelativePath: String,
        and secondRelativePath: String,
        _ operation: (Int32, String, Int32, String) throws -> Result
    ) throws -> Result {
        let firstPath = try ValidatedVaultRelativePath(firstRelativePath)
        let secondPath = try ValidatedVaultRelativePath(secondRelativePath)

        return try withFileDescriptor { rootDescriptor in
            let firstOwnedParent = try openValidatedParent(
                of: firstPath,
                rootDescriptor: rootDescriptor,
                path: firstRelativePath
            )
            defer {
                try? firstOwnedParent?.close()
            }

            let secondOwnedParent = try openValidatedParent(
                of: secondPath,
                rootDescriptor: rootDescriptor,
                path: secondRelativePath
            )
            defer {
                try? secondOwnedParent?.close()
            }

            return try operation(
                firstOwnedParent?.rawValue ?? rootDescriptor,
                firstPath.terminalComponent,
                secondOwnedParent?.rawValue ?? rootDescriptor,
                secondPath.terminalComponent
            )
        }
    }

    private func openValidatedParent(
        of path: ValidatedVaultRelativePath,
        rootDescriptor: Int32,
        path displayPath: String
    ) throws -> FileDescriptor? {
        var ownedParent: FileDescriptor?
        var parentDescriptor = rootDescriptor

        do {
            for component in path.components.dropLast() {
                let child = try openValidatedComponent(
                    component,
                    relativeTo: parentDescriptor,
                    path: displayPath,
                    expecting: .directory,
                    rootDeviceID: identity.deviceID
                )
                if let previousParent = ownedParent {
                    try? previousParent.close()
                }
                ownedParent = child
                parentDescriptor = child.rawValue
            }
            return ownedParent
        } catch {
            try? ownedParent?.close()
            throw error
        }
    }
}

private struct ValidatedVaultRelativePath {
    let components: [String]

    var terminalComponent: String {
        components[components.index(before: components.endIndex)]
    }

    init(_ path: String) throws {
        guard
            !path.isEmpty,
            !path.hasPrefix("/"),
            !path.utf8.contains(0)
        else {
            throw VaultPathResolutionError.invalidRelativePath
        }

        let components = path.split(
            separator: "/",
            omittingEmptySubsequences: false
        )
        guard components.allSatisfy({
            !$0.isEmpty && $0 != "." && $0 != ".."
        }) else {
            throw VaultPathResolutionError.invalidRelativePath
        }

        self.components = components.map(String.init)
    }
}

private func openValidatedComponent(
    _ component: String,
    relativeTo parentDescriptor: Int32,
    path: String,
    expecting expectedKind: VaultResolvedPathKind,
    rootDeviceID: UInt64
) throws -> FileDescriptor {
    try rejectDatalessPlaceholder(
        component,
        relativeTo: parentDescriptor,
        path: path
    )
    let child = try openComponent(
        component,
        relativeTo: parentDescriptor,
        expecting: expectedKind
    )
    do {
        try validateOpenedComponent(
            child,
            component: component,
            path: path,
            expecting: expectedKind,
            rootDeviceID: rootDeviceID
        )
        if expectedKind == .regularFile {
            try rejectFinderAlias(
                child,
                component: component,
                path: path
            )
        }
        return child
    } catch {
        try? child.close()
        throw error
    }
}

private func openComponent(
    _ component: String,
    relativeTo parentDescriptor: Int32,
    expecting expectedKind: VaultResolvedPathKind
) throws -> FileDescriptor {
    var flags = O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
    if expectedKind == .directory {
        flags |= O_DIRECTORY
    }

    let rawDescriptor: Int32
    while true {
        let result = Darwin.openat(parentDescriptor, component, flags)
        if result >= 0 {
            rawDescriptor = result
            break
        }
        if errno != EINTR {
            let code = errno
            switch code {
            case ENOENT:
                throw VaultPathResolutionError.notFound(component: component)
            case ELOOP:
                throw VaultPathResolutionError.symbolicLink(component: component)
            case ENOTDIR:
                throw VaultPathResolutionError.notDirectory(component: component)
            default:
                throw VaultPathResolutionError.openFailed(
                    component: component,
                    code: code
                )
            }
        }
    }

    return FileDescriptor(rawValue: rawDescriptor)
}

private func rejectFinderAlias(
    _ descriptor: FileDescriptor,
    component: String,
    path: String
) throws {
    var finderInfo = [UInt8](repeating: 0, count: 32)
    let count = finderInfo.withUnsafeMutableBytes { bytes in
        fgetxattr(
            descriptor.rawValue,
            "com.apple.FinderInfo",
            bytes.baseAddress,
            bytes.count,
            0,
            0
        )
    }

    if count < 0 {
        guard errno == ENOATTR else {
            throw VaultPathResolutionError.inspectionFailed(
                path: path,
                code: errno
            )
        }
        return
    }

    guard count >= 10 else {
        throw VaultPathResolutionError.filesystemAlias(
            component: component
        )
    }
    let finderFlags = UInt16(finderInfo[8]) << 8 | UInt16(finderInfo[9])
    guard finderFlags & 0x8000 == 0 else {
        throw VaultPathResolutionError.filesystemAlias(
            component: component
        )
    }
}

private func rejectDatalessPlaceholder(
    _ component: String,
    relativeTo parentDescriptor: Int32,
    path: String
) throws {
    var metadata = stat()
    while true {
        let result = fstatat(
            parentDescriptor,
            component,
            &metadata,
            AT_SYMLINK_NOFOLLOW
        )
        if result == 0 {
            break
        }

        let code = errno
        if code == EINTR {
            continue
        }
        switch code {
        case ENOENT:
            throw VaultPathResolutionError.notFound(component: component)
        case ENOTDIR:
            throw VaultPathResolutionError.notDirectory(component: component)
        default:
            throw VaultPathResolutionError.inspectionFailed(
                path: path,
                code: code
            )
        }
    }

    guard metadata.st_flags & UInt32(SF_DATALESS) == 0 else {
        throw VaultPathResolutionError.providerPlaceholder(
            component: component
        )
    }
}

private func validateOpenedComponent(
    _ descriptor: FileDescriptor,
    component: String,
    path: String,
    expecting expectedKind: VaultResolvedPathKind,
    rootDeviceID: UInt64
) throws {
    var metadata = stat()
    guard fstat(descriptor.rawValue, &metadata) == 0 else {
        throw VaultPathResolutionError.inspectionFailed(
            path: path,
            code: errno
        )
    }

    try validateOpenedComponentMetadata(
        VaultPathMetadata(metadata),
        component: component,
        path: path,
        expecting: expectedKind,
        rootDeviceID: rootDeviceID
    )
}

struct VaultPathMetadata: Equatable, Sendable {
    enum ObjectKind: Equatable, Sendable {
        case directory
        case regularFile
        case other
    }

    let objectKind: ObjectKind
    let deviceID: UInt64
    let linkCount: UInt64
    let isDataless: Bool
    let isFirmlink: Bool

    init(
        objectKind: ObjectKind,
        deviceID: UInt64,
        linkCount: UInt64,
        isDataless: Bool,
        isFirmlink: Bool
    ) {
        self.objectKind = objectKind
        self.deviceID = deviceID
        self.linkCount = linkCount
        self.isDataless = isDataless
        self.isFirmlink = isFirmlink
    }

    fileprivate init(_ metadata: stat) {
        let objectType = metadata.st_mode & S_IFMT
        switch objectType {
        case S_IFDIR:
            objectKind = .directory
        case S_IFREG:
            objectKind = .regularFile
        default:
            objectKind = .other
        }
        deviceID = UInt64(metadata.st_dev)
        linkCount = UInt64(metadata.st_nlink)
        isDataless = metadata.st_flags & UInt32(SF_DATALESS) != 0
        isFirmlink = metadata.st_flags & UInt32(SF_FIRMLINK) != 0
    }
}

func validateOpenedComponentMetadata(
    _ metadata: VaultPathMetadata,
    component: String,
    path: String,
    expecting expectedKind: VaultResolvedPathKind,
    rootDeviceID: UInt64
) throws {
    let expectedObjectKind: VaultPathMetadata.ObjectKind = expectedKind == .directory
        ? .directory
        : .regularFile
    guard metadata.objectKind == expectedObjectKind else {
        throw VaultPathResolutionError.unexpectedType(
            path: path,
            expected: expectedKind
        )
    }

    guard metadata.deviceID == rootDeviceID else {
        throw VaultPathResolutionError.crossedFilesystem(
            component: component
        )
    }
    guard !metadata.isDataless else {
        throw VaultPathResolutionError.providerPlaceholder(
            component: component
        )
    }
    guard !metadata.isFirmlink else {
        throw VaultPathResolutionError.filesystemAlias(
            component: component
        )
    }
    if expectedKind == .regularFile, metadata.linkCount != 1 {
        throw VaultPathResolutionError.filesystemAlias(
            component: component
        )
    }
}
