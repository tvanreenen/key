import Darwin
import Foundation
import Testing
@testable import KeyCore

struct VaultRootDirectoryHandleTests {
    @Test
    func opensDirectoryWithStableIdentityAndCloseOnExec() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let handle = try VaultRootDirectoryHandle(opening: root)
        let rootIdentity = try identity(at: root)

        #expect(handle.rootURL == root)
        #expect(handle.identity == rootIdentity)
        #expect(handle.withFileDescriptor { fcntl($0, F_GETFD) } & FD_CLOEXEC != 0)
    }

    @Test
    func retainedDescriptorRemainsBoundToOriginalDirectoryAfterPathReplacement() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("vault", isDirectory: true)
        let movedRoot = parent.appendingPathComponent("original-vault", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let handle = try VaultRootDirectoryHandle(opening: root)

        try FileManager.default.moveItem(at: root, to: movedRoot)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        let movedIdentity = try identity(at: movedRoot)
        let replacementIdentity = try identity(at: root)
        let descriptorIdentity = try handle.withFileDescriptor { try identity(of: $0) }

        #expect(handle.identity == movedIdentity)
        #expect(handle.identity != replacementIdentity)
        #expect(descriptorIdentity == handle.identity)
    }

    @Test
    func rejectsSymbolicLinkAsVaultRoot() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let actualRoot = parent.appendingPathComponent("actual", isDirectory: true)
        let linkedRoot = parent.appendingPathComponent("linked", isDirectory: true)
        try FileManager.default.createDirectory(at: actualRoot, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: linkedRoot, withDestinationURL: actualRoot)

        #expect(throws: VaultRootDirectoryHandleError.notDirectoryOrSymbolicLink(
            path: linkedRoot.path(percentEncoded: false)
        )) {
            _ = try VaultRootDirectoryHandle(opening: linkedRoot)
        }
    }

    @Test
    func rejectsRegularFileAndMissingRoot() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let file = parent.appendingPathComponent("vault-file", isDirectory: false)
        let missing = parent.appendingPathComponent("missing", isDirectory: true)
        try Data().write(to: file)

        #expect(throws: VaultRootDirectoryHandleError.notDirectoryOrSymbolicLink(
            path: file.path(percentEncoded: false)
        )) {
            _ = try VaultRootDirectoryHandle(opening: file)
        }
        #expect(throws: VaultRootDirectoryHandleError.notFound(
            path: missing.path(percentEncoded: false)
        )) {
            _ = try VaultRootDirectoryHandle(opening: missing)
        }
    }

    @Test
    func rejectsNonFileURL() {
        #expect(throws: VaultRootDirectoryHandleError.notFileURL) {
            _ = try VaultRootDirectoryHandle(
                opening: URL(string: "https://example.com/vault")!
            )
        }
    }

    @Test
    func rejectsPathContainingNullByte() {
        #expect(throws: VaultRootDirectoryHandleError.invalidPath) {
            _ = try VaultRootDirectoryHandle(
                opening: URL(fileURLWithPath: "/private/tmp/vault\u{0}suffix")
            )
        }
    }
}

private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    return url
}

private func identity(at url: URL) throws -> VaultRootDirectoryIdentity {
    var metadata = stat()
    guard lstat(url.path(percentEncoded: false), &metadata) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return identity(from: metadata)
}

private func identity(of descriptor: Int32) throws -> VaultRootDirectoryIdentity {
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    return identity(from: metadata)
}

private func identity(from metadata: stat) -> VaultRootDirectoryIdentity {
    VaultRootDirectoryIdentity(
        deviceID: UInt64(metadata.st_dev),
        fileID: UInt64(metadata.st_ino)
    )
}
