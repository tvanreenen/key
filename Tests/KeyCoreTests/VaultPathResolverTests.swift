import Darwin
import Foundation
import System
import Testing
@testable import KeyCore

struct VaultPathResolverTests {
    @Test
    func opensNestedRegularFileAndDirectoryRelativeToTrustedRoot() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let nestedDirectory = root
            .appendingPathComponent("generations", isDirectory: true)
            .appendingPathComponent("7", isDirectory: true)
        try FileManager.default.createDirectory(
            at: nestedDirectory,
            withIntermediateDirectories: true
        )
        let manifest = nestedDirectory.appendingPathComponent(
            "manifest.json",
            isDirectory: false
        )
        try Data("trusted manifest".utf8).write(to: manifest)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        let contents = try rootHandle.withResolvedDescriptor(
            at: "generations/7/manifest.json",
            expecting: .regularFile
        ) { descriptor in
            var bytes = [UInt8](repeating: 0, count: 64)
            let count = try bytes.withUnsafeMutableBytes {
                try descriptor.read(into: $0)
            }
            #expect(fcntl(descriptor.rawValue, F_GETFD) & FD_CLOEXEC != 0)
            return String(decoding: bytes.prefix(count), as: UTF8.self)
        }

        #expect(contents == "trusted manifest")
        try rootHandle.withResolvedDescriptor(
            at: "generations/7",
            expecting: .directory
        ) { descriptor in
            var metadata = stat()
            #expect(fstat(descriptor.rawValue, &metadata) == 0)
            #expect(metadata.st_mode & S_IFMT == S_IFDIR)
        }
    }

    @Test
    func rejectsInvalidRelativePathsBeforeFilesystemAccess() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let rootHandle = try VaultRootDirectoryHandle(opening: root)
        let invalidPaths = [
            "",
            "/absolute",
            "trailing/",
            "double//component",
            ".",
            "./manifest",
            "..",
            "../outside",
            "generation/../outside",
            "entry\u{0}suffix"
        ]

        for path in invalidPaths {
            #expect(throws: VaultPathResolutionError.invalidRelativePath) {
                try rootHandle.withResolvedDescriptor(
                    at: path,
                    expecting: .regularFile
                ) { _ in
                    Issue.record("Invalid path '\(path)' reached the descriptor operation.")
                }
            }
        }
    }

    @Test
    func rejectsIntermediateAndTerminalSymbolicLinks() throws {
        let parent = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("vault", isDirectory: true)
        let outside = parent.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
        let outsideFile = outside.appendingPathComponent("manifest.json", isDirectory: false)
        try Data("outside".utf8).write(to: outsideFile)
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("linked-directory", isDirectory: true),
            withDestinationURL: outside
        )
        try FileManager.default.createSymbolicLink(
            at: root.appendingPathComponent("linked-file", isDirectory: false),
            withDestinationURL: outsideFile
        )
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        // Darwin reports ENOTDIR when O_DIRECTORY and O_NOFOLLOW encounter
        // a directory symlink. The important contract is that it is rejected
        // before traversal, not that a second lookup guesses why openat failed.
        #expect(throws: VaultPathResolutionError.notDirectory(
            component: "linked-directory"
        )) {
            try rootHandle.withResolvedDescriptor(
                at: "linked-directory/manifest.json",
                expecting: .regularFile
            ) { _ in
                Issue.record("Intermediate symlink reached the descriptor operation.")
            }
        }
        #expect(throws: VaultPathResolutionError.symbolicLink(
            component: "linked-file"
        )) {
            try rootHandle.withResolvedDescriptor(
                at: "linked-file",
                expecting: .regularFile
            ) { _ in
                Issue.record("Terminal symlink reached the descriptor operation.")
            }
        }
    }

    @Test
    func rejectsMissingComponentsAndUnexpectedObjectTypes() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let regularFile = root.appendingPathComponent("entry", isDirectory: false)
        try Data("entry".utf8).write(to: regularFile)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        #expect(throws: VaultPathResolutionError.notFound(component: "missing")) {
            try rootHandle.withResolvedDescriptor(
                at: "missing/entry",
                expecting: .regularFile
            ) { _ in
                Issue.record("Missing component reached the descriptor operation.")
            }
        }
        #expect(throws: VaultPathResolutionError.notDirectory(component: "entry")) {
            try rootHandle.withResolvedDescriptor(
                at: "entry/child",
                expecting: .regularFile
            ) { _ in
                Issue.record("Regular intermediate component was traversed.")
            }
        }
        #expect(throws: VaultPathResolutionError.notDirectory(component: "entry")) {
            try rootHandle.withResolvedDescriptor(
                at: "entry",
                expecting: .directory
            ) { _ in
                Issue.record("Wrong terminal object type reached the descriptor operation.")
            }
        }
    }

    @Test
    func rejectsSpecialFileWithoutBlocking() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fifo = root.appendingPathComponent("provider-placeholder", isDirectory: false)
        #expect(mkfifo(fifo.path(percentEncoded: false), 0o600) == 0)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        #expect(throws: VaultPathResolutionError.unexpectedType(
            path: "provider-placeholder",
            expected: .regularFile
        )) {
            try rootHandle.withResolvedDescriptor(
                at: "provider-placeholder",
                expecting: .regularFile
            ) { _ in
                Issue.record("Special file reached the descriptor operation.")
            }
        }
    }
}

private func temporaryVaultDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    return url
}
