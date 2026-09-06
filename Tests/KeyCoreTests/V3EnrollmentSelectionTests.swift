import Foundation
import Testing
@testable import KeyCore

struct V3EnrollmentSelectionTests {
    private let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c4504"
    private let digest = Data(repeating: 7, count: 32)

    @Test
    func bindingSurvivesRestartAndSelectsOnlyWhenVerifiedWorkflowCallsBack() throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = try rootHandle(home)
        _ = try config.prepareEnrollmentSelection(rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: true)
        #expect(try !config.hasConfiguration())
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.rootURL.path).isEmpty)
        let restarted = KeyConfigStore(homeDirectoryURL: home)
        let select = try restarted.prepareEnrollmentSelection(rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: false)
        try select(vaultID)
        #expect(try config.load().vaultID == vaultID)
        #expect(try config.load().vaultDirectoryURL.standardizedFileURL == root.rootURL.standardizedFileURL)
        #expect(throws: AppError.self) { try select(vaultID) }
    }

    @Test(arguments: [false, true])
    func copiedOrReplacedRootCannotReuseCeremony(replace: Bool) throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = try rootHandle(home)
        let select = try config.prepareEnrollmentSelection(rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: true)
        let otherURL = home.appendingPathComponent("Other")
        if replace {
            try FileManager.default.moveItem(at: root.rootURL, to: otherURL)
            try FileManager.default.createDirectory(at: root.rootURL, withIntermediateDirectories: false)
        } else {
            try FileManager.default.copyItem(at: root.rootURL, to: otherURL)
        }
        let other = try VaultRootDirectoryHandle(opening: replace ? root.rootURL : otherURL)
        #expect(throws: AppError.self) {
            try config.prepareEnrollmentSelection(rootHandle: other, invitationDigest: digest, vaultID: vaultID, create: true)
        }
        if replace { #expect(throws: (any Error).self) { try select(vaultID) } }
        #expect(try !config.hasConfiguration())
    }

    @Test
    func missingBindingCannotBeCreatedByAcceptAndExactJoinRetryIsAllowed() throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = try rootHandle(home)
        #expect(throws: (any Error).self) {
            try config.prepareEnrollmentSelection(rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: false)
        }
        #expect(!FileManager.default.fileExists(atPath: config.initializationConfigFileURL.deletingLastPathComponent().path))
        for _ in 0..<2 {
            _ = try config.prepareEnrollmentSelection(rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: true)
        }
        #expect(try !config.hasConfiguration())
    }

    @Test(arguments: ["config", "record", "configDirectory", "wrongVault"])
    func changedStateRefusesSelection(change: String) throws {
        let home = try temporaryHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let config = KeyConfigStore(homeDirectoryURL: home)
        let root = try rootHandle(home)
        let select = try config.prepareEnrollmentSelection(rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: true)
        let directory = config.initializationConfigFileURL.deletingLastPathComponent()
        switch change {
        case "config": try Data("another selection".utf8).write(to: config.initializationConfigFileURL)
        case "record":
            let record = directory.appendingPathComponent("v3-enrollment-roots/\(v3LowercaseHex(digest)).json")
            try Data("changed".utf8).write(to: record)
        case "configDirectory":
            try FileManager.default.moveItem(at: directory, to: directory.appendingPathExtension("moved"))
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        default: break
        }
        #expect(throws: (any Error).self) { try select(change == "wrongVault" ? "018f4d38-7d5a-7b20-b0f1-97d6e96c4505" : vaultID) }
        if change == "config" {
            #expect(try Data(contentsOf: config.initializationConfigFileURL) == Data("another selection".utf8))
        } else {
            #expect(try !config.hasConfiguration())
        }
    }

    private func temporaryHome() throws -> URL {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: false)
        return home
    }

    private func rootHandle(_ home: URL) throws -> VaultRootDirectoryHandle {
        let root = home.appendingPathComponent("Vault")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        return try VaultRootDirectoryHandle(opening: root)
    }
}
