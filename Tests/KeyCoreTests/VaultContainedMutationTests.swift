import Darwin
import Foundation
import Testing
@testable import KeyCore

struct VaultContainedMutationTests {
    @Test
    func replacesRegularFileAcrossValidatedParentDirectories() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        let current = root.appendingPathComponent("current", isDirectory: true)
        try createDirectories([staging, current])
        let source = staging.appendingPathComponent("candidate", isDirectory: false)
        let destination = current.appendingPathComponent("manifest", isDirectory: false)
        try Data("candidate".utf8).write(to: source)
        try Data("current".utf8).write(to: destination)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        try rootHandle.replaceRegularFile(
            at: "current/manifest",
            withStagedFileAt: "staging/candidate"
        )

        #expect(!FileManager.default.fileExists(atPath: source.path()))
        #expect(try String(contentsOf: destination, encoding: .utf8) == "candidate")
    }

    @Test
    func replaceRejectsSameFileAndFilesystemAliases() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let entry = root.appendingPathComponent("entry", isDirectory: false)
        try Data("entry".utf8).write(to: entry)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        #expect(throws: VaultContainedMutationError.sourceAndDestinationAreSame(
            path: "entry"
        )) {
            try rootHandle.replaceRegularFile(
                at: "entry",
                withStagedFileAt: "entry"
            )
        }

        let source = root.appendingPathComponent("source", isDirectory: false)
        let alias = root.appendingPathComponent("source-alias", isDirectory: false)
        let destination = root.appendingPathComponent("destination", isDirectory: false)
        try Data("source".utf8).write(to: source)
        #expect(link(source.path(), alias.path()) == 0)
        try Data("destination".utf8).write(to: destination)

        #expect(throws: VaultPathResolutionError.filesystemAlias(
            component: "source"
        )) {
            try rootHandle.replaceRegularFile(
                at: "destination",
                withStagedFileAt: "source"
            )
        }
        #expect(try String(contentsOf: destination, encoding: .utf8) == "destination")
    }

    @Test
    func movesRegularFileWithoutOverwritingDestination() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source", isDirectory: false)
        let destination = root.appendingPathComponent("destination", isDirectory: false)
        try Data("source".utf8).write(to: source)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        try rootHandle.moveItem(
            at: "source",
            to: "destination",
            expecting: .regularFile
        )

        #expect(!FileManager.default.fileExists(atPath: source.path()))
        #expect(try String(contentsOf: destination, encoding: .utf8) == "source")

        let secondSource = root.appendingPathComponent("second-source", isDirectory: false)
        try Data("second".utf8).write(to: secondSource)
        #expect(throws: VaultContainedMutationError.destinationExists(
            path: "destination"
        )) {
            try rootHandle.moveItem(
                at: "second-source",
                to: "destination",
                expecting: .regularFile
            )
        }
        #expect(try String(contentsOf: secondSource, encoding: .utf8) == "second")
        #expect(try String(contentsOf: destination, encoding: .utf8) == "source")
    }

    @Test
    func movesDirectoryWithoutRebuildingAnAbsolutePath() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let staging = root.appendingPathComponent("staging", isDirectory: true)
        let generations = root.appendingPathComponent("generations", isDirectory: true)
        let candidate = staging.appendingPathComponent("7", isDirectory: true)
        try createDirectories([staging, generations, candidate])
        try Data("manifest".utf8).write(
            to: candidate.appendingPathComponent("manifest", isDirectory: false)
        )
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        try rootHandle.moveItem(
            at: "staging/7",
            to: "generations/7",
            expecting: .directory
        )

        #expect(!FileManager.default.fileExists(atPath: candidate.path()))
        #expect(
            try String(
                contentsOf: generations
                    .appendingPathComponent("7", isDirectory: true)
                    .appendingPathComponent("manifest", isDirectory: false),
                encoding: .utf8
            ) == "manifest"
        )
    }

    @Test
    func removesRegularFileAndOnlyEmptyDirectory() throws {
        let root = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let obsolete = root.appendingPathComponent("obsolete", isDirectory: false)
        let empty = root.appendingPathComponent("empty", isDirectory: true)
        let nonempty = root.appendingPathComponent("nonempty", isDirectory: true)
        try Data("obsolete".utf8).write(to: obsolete)
        try createDirectories([empty, nonempty])
        let retained = nonempty.appendingPathComponent("retained", isDirectory: false)
        try Data("retained".utf8).write(to: retained)
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        try rootHandle.removeItem(at: "obsolete", expecting: .regularFile)
        try rootHandle.removeItem(at: "empty", expecting: .directory)

        #expect(!FileManager.default.fileExists(atPath: obsolete.path()))
        #expect(!FileManager.default.fileExists(atPath: empty.path()))
        #expect(throws: VaultContainedMutationError.directoryNotEmpty(
            path: "nonempty"
        )) {
            try rootHandle.removeItem(at: "nonempty", expecting: .directory)
        }
        #expect(try String(contentsOf: retained, encoding: .utf8) == "retained")
    }

    @Test
    func cleanupRejectsSymlinkWithoutDeletingItsTarget() throws {
        let parent = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("vault", isDirectory: true)
        let outside = parent.appendingPathComponent("outside", isDirectory: false)
        let link = root.appendingPathComponent("outside-link", isDirectory: false)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        try Data("outside".utf8).write(to: outside)
        try FileManager.default.createSymbolicLink(
            at: link,
            withDestinationURL: outside
        )
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        #expect(throws: VaultPathResolutionError.symbolicLink(
            component: "outside-link"
        )) {
            try rootHandle.removeItem(
                at: "outside-link",
                expecting: .regularFile
            )
        }
        #expect(try String(contentsOf: outside, encoding: .utf8) == "outside")
        #expect(FileManager.default.fileExists(atPath: link.path()))
    }

    @Test
    func mutationsRejectInvalidDestinationsAndRootReplacement() throws {
        let parent = try temporaryVaultDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("vault", isDirectory: true)
        let movedRoot = parent.appendingPathComponent("moved", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        try Data("source".utf8).write(
            to: root.appendingPathComponent("source", isDirectory: false)
        )
        let rootHandle = try VaultRootDirectoryHandle(opening: root)

        #expect(throws: VaultPathResolutionError.invalidRelativePath) {
            try rootHandle.moveItem(
                at: "source",
                to: "../outside",
                expecting: .regularFile
            )
        }

        try FileManager.default.moveItem(at: root, to: movedRoot)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        #expect(throws: VaultRootDirectoryHandleError.configuredRootChanged(
            path: root.path()
        )) {
            try rootHandle.removeItem(
                at: "source",
                expecting: .regularFile
            )
        }
        #expect(
            try String(
                contentsOf: movedRoot.appendingPathComponent(
                    "source",
                    isDirectory: false
                ),
                encoding: .utf8
            ) == "source"
        )
    }
}

private func temporaryVaultDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: url,
        withIntermediateDirectories: false
    )
    return url
}

private func createDirectories(_ directories: [URL]) throws {
    for directory in directories {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
    }
}
