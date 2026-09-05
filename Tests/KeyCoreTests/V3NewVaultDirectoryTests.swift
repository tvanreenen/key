import Foundation
import Testing
@testable import KeyCore

struct V3NewVaultDirectoryTests {
    @Test(arguments: [false, true])
    func explicitPreparationAcceptsEmptyOrCreatesMissingDirectory(existing: Bool) throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        let root = parent.rootURL.appendingPathComponent("Vault")
        if existing { try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false) }
        let destination = try V3NewVaultDirectory.prepare(at: root)
        try destination.begin(for: root)
        #expect(throws: AppError.self) { try destination.begin(for: root) }
    }

    @Test(arguments: [".DS_Store", "manifests", "entry.secret"])
    func explicitPreparationRefusesAllExistingContents(name: String) throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        let file = parent.rootURL.appendingPathComponent(name)
        try Data("existing".utf8).write(to: file)
        #expect(throws: AppError.self) { try V3NewVaultDirectory.prepare(at: parent.rootURL) }
        #expect(try Data(contentsOf: file) == Data("existing".utf8))
    }

    @Test
    func explicitPreparationDoesNotCreateMissingParentsOrFollowDestinationLinks() throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        #expect(throws: VaultRootDirectoryHandleError.self) {
            try V3NewVaultDirectory.prepare(at: parent.rootURL.appendingPathComponent("Missing/Vault"))
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.rootURL.path).isEmpty)
        for target in [parent.rootURL, parent.rootURL.appendingPathComponent("Missing")] {
            let link = parent.rootURL.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
            #expect(throws: (any Error).self) { try V3NewVaultDirectory.prepare(at: link) }
        }
    }

    @Test(arguments: ["directory", "file", "symlink", "danglingSymlink"])
    func existingDestinationsAreNeverAdopted(kind: String) throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        let target = parent.rootURL.appendingPathComponent("New Vault")
        switch kind {
        case "directory":
            try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
        case "file":
            try Data("existing".utf8).write(to: target)
        case "symlink":
            try FileManager.default.createSymbolicLink(at: target, withDestinationURL: parent.rootURL)
        default:
            try FileManager.default.createSymbolicLink(
                at: target,
                withDestinationURL: parent.rootURL.appendingPathComponent("Missing")
            )
        }
        #expect(throws: AppError.self) {
            try V3NewVaultDirectory.create(in: parent, name: "New Vault")
        }
        let names = try FileManager.default.contentsOfDirectory(atPath: parent.rootURL.path)
        #expect(names == ["New Vault"])
        if kind == "file" {
            #expect(try Data(contentsOf: target) == Data("existing".utf8))
        }
    }

    @Test(arguments: ["", ".", "..", "../outside", "nested/name", "bad\0name"])
    func invalidNamesCreateNothing(name: String) throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        #expect(throws: AppError.self) {
            try V3NewVaultDirectory.create(in: parent, name: name)
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.rootURL.path).isEmpty)
    }

    @Test
    func directoryReplacementPreventsBeginning() throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        let destination = try V3NewVaultDirectory.create(in: parent, name: "New Vault")
        let root = destination.rootHandle.rootURL
        try FileManager.default.moveItem(at: root, to: parent.rootURL.appendingPathComponent("Original"))
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        #expect(throws: VaultRootDirectoryHandleError.self) {
            try destination.begin(for: root)
        }
    }

    @Test
    func parentReplacementPreventsCreationInTheWrongDirectory() throws {
        let parent = try temporaryParent()
        let moved = parent.rootURL.appendingPathExtension("moved")
        defer {
            try? FileManager.default.removeItem(at: parent.rootURL)
            try? FileManager.default.removeItem(at: moved)
        }
        try FileManager.default.moveItem(at: parent.rootURL, to: moved)
        try FileManager.default.createDirectory(at: parent.rootURL, withIntermediateDirectories: false)
        #expect(throws: VaultRootDirectoryHandleError.self) {
            try V3NewVaultDirectory.create(in: parent, name: "New Vault")
        }
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.rootURL.path).isEmpty)
        #expect(try FileManager.default.contentsOfDirectory(atPath: moved.path).isEmpty)
    }

    @Test
    func freshDirectoryChecksDetectDataAfterAnEarlierEmptyRead() throws {
        let parent = try temporaryParent()
        defer { try? FileManager.default.removeItem(at: parent.rootURL) }
        let destination = try V3NewVaultDirectory.create(in: parent, name: "New Vault")
        // create() already enumerated this directory. A second enumeration
        // must not share an exhausted directory offset and miss new data.
        try Data("arrived".utf8).write(to: destination.rootHandle.rootURL.appendingPathComponent(".hidden"))
        #expect(throws: AppError.self) {
            try destination.begin(for: destination.rootHandle.rootURL)
        }
    }

    private func temporaryParent() throws -> VaultRootDirectoryHandle {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return try VaultRootDirectoryHandle(opening: url)
    }
}
