import CryptoKit
import Darwin
import Foundation
import Testing

@testable import KeyCore

struct V3CheckpointManifestCacheTests {
    @Test
    func missingCacheDoesNotChangeCheckpointAuthority() throws {
        let fixture = try Fixture()

        #expect(try fixture.cache.load(for: fixture.checkpoint) == .missing)
        #expect(fixture.checkpoint.envelopeDigest == fixture.digest)
    }

    @Test
    func storesAndLoadsOnlyTheExactCheckpointManifest() throws {
        let fixture = try Fixture()

        try fixture.cache.store(
            fixture.manifestData,
            for: fixture.checkpoint
        )

        #expect(
            try fixture.cache.load(for: fixture.checkpoint)
                == .available(fixture.manifestData)
        )
    }

    @Test
    func atomicallyReplacesAnOlderCheckpointCache() throws {
        let fixture = try Fixture()
        try fixture.cache.store(
            fixture.manifestData,
            for: fixture.checkpoint
        )
        let nextData = Data("next canonical manifest".utf8)
        let nextCheckpoint = try V3ManifestCheckpoint(
            vaultID: Fixture.vaultID,
            envelopeDigest: Data(SHA256.hash(data: nextData))
        )

        try fixture.cache.store(nextData, for: nextCheckpoint)

        #expect(
            try fixture.cache.load(for: nextCheckpoint)
                == .available(nextData)
        )
        #expect(try fixture.cache.load(for: fixture.checkpoint) == .unusable)
        #expect(
            try fixture.partialFiles().isEmpty
        )
    }

    @Test
    func substitutedOrOversizedCacheBytesAreNeverReturned() throws {
        let fixture = try Fixture(maximumManifestBytes: 64)
        try Data("substituted".utf8).write(to: fixture.cacheFileURL)

        #expect(try fixture.cache.load(for: fixture.checkpoint) == .unusable)
        #expect(throws: V3CheckpointManifestCacheError.invalidManifest) {
            try fixture.cache.store(
                Data(repeating: 0, count: 65),
                for: fixture.checkpoint
            )
        }
        #expect(try fixture.cache.load(for: fixture.checkpoint) == .unusable)
    }

    @Test
    func unsafeCacheSymlinkIsIgnoredAndSafelyReplaced() throws {
        let fixture = try Fixture()
        let outsideURL = fixture.containerURL
            .appendingPathComponent("outside.txt")
        let outsideData = Data("do not replace".utf8)
        try outsideData.write(to: outsideURL)
        try FileManager.default.createSymbolicLink(
            at: fixture.cacheFileURL,
            withDestinationURL: outsideURL
        )

        #expect(try fixture.cache.load(for: fixture.checkpoint) == .unusable)
        try fixture.cache.store(
            fixture.manifestData,
            for: fixture.checkpoint
        )

        #expect(try Data(contentsOf: outsideURL) == outsideData)
        #expect(
            try fixture.cache.load(for: fixture.checkpoint)
                == .available(fixture.manifestData)
        )
    }
}

private final class Fixture {
    static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"

    let containerURL: URL
    let rootURL: URL
    let manifestData = Data("canonical checkpoint manifest".utf8)
    let digest: Data
    let checkpoint: V3ManifestCheckpoint
    let cache: V3CheckpointManifestFilesystemCache

    var cacheFileURL: URL {
        rootURL.appendingPathComponent("\(Self.vaultID).json")
    }

    init(maximumManifestBytes: Int = 2 * 1_024 * 1_024) throws {
        containerURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: containerURL,
            withIntermediateDirectories: false
        )
        rootURL = containerURL.appendingPathComponent(
            "checkpoint-manifests",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: rootURL,
            withIntermediateDirectories: false
        )
        digest = Data(SHA256.hash(data: manifestData))
        checkpoint = try V3ManifestCheckpoint(
            vaultID: Self.vaultID,
            envelopeDigest: digest
        )
        cache = V3CheckpointManifestFilesystemCache(
            rootHandle: try VaultRootDirectoryHandle(opening: rootURL),
            maximumManifestBytes: maximumManifestBytes
        )
    }

    deinit {
        try? FileManager.default.removeItem(at: containerURL)
    }

    func partialFiles() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: rootURL.path)
            .filter { $0.hasSuffix(".partial") }
    }
}
