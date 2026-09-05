import Darwin
import Foundation

/// A single-use destination for an explicit new-vault initialization.
/// An empty listing does not prove that a sync provider has finished delivery.
final class V3NewVaultDirectory {
    let rootHandle: VaultRootDirectoryHandle
    private let parentHandle: VaultRootDirectoryHandle
    private let lock = NSLock()
    private var used = false

    private init(
        rootHandle: VaultRootDirectoryHandle,
        parentHandle: VaultRootDirectoryHandle
    ) {
        self.rootHandle = rootHandle
        self.parentHandle = parentHandle
    }

    /// The caller explicitly requested initialization here, not enrollment.
    /// Only a missing final component is created; parents must already exist.
    static func prepare(at url: URL) throws -> V3NewVaultDirectory {
        let parent = try VaultRootDirectoryHandle(opening: url.deletingLastPathComponent())
        do {
            let root = try VaultRootDirectoryHandle(opening: url)
            let destination = V3NewVaultDirectory(rootHandle: root, parentHandle: parent)
            try destination.requireRootNames([])
            return destination
        } catch VaultRootDirectoryHandleError.notFound {
            return try create(in: parent, name: url.lastPathComponent)
        }
    }

    static func create(
        in parent: VaultRootDirectoryHandle,
        name: String
    ) throws -> V3NewVaultDirectory {
        guard !name.isEmpty, name != ".", name != "..",
              !name.contains("/"), !name.utf8.contains(0)
        else {
            throw AppError.invalidConfiguration("A new vault needs one nonempty directory name.")
        }
        try parent.withFileDescriptor { descriptor in
            guard mkdirat(descriptor, name, mode_t(0o700)) == 0 else {
                let code = errno
                throw AppError.operationRefused(
                    "Cannot create a new vault directory (POSIX error \(code)). Choose a new, unused directory name; existing directories are never adopted."
                )
            }
            guard fsync(descriptor) == 0 else {
                throw AppError.io("Could not synchronize the new vault directory. Leave it in place for inspection; no vault was selected.")
            }
        }
        try parent.requireConfiguredRootIdentity()
        let root = try VaultRootDirectoryHandle(
            opening: parent.rootURL.appendingPathComponent(name, isDirectory: true)
        )
        let destination = V3NewVaultDirectory(rootHandle: root, parentHandle: parent)
        try destination.requireRootNames([])
        return destination
    }

    func begin(for rootURL: URL) throws {
        try lock.withLock {
            guard !used else {
                throw AppError.operationRefused("This new-vault attempt was already started. Do not reuse its directory or silently create another identity.")
            }
            guard rootURL.standardizedFileURL == rootHandle.rootURL.standardizedFileURL else {
                throw AppError.operationRefused("The new-vault installer does not own this destination.")
            }
            try requireRootNames([])
            used = true
        }
    }

    /// Staging must have been removed. Only this attempt's empty genesis may
    /// remain before selection; any delivered or concurrently added data stops it.
    func requireInstalledGenesis(digest: Data) throws {
        try requireRootNames(["manifests"])
        try rootHandle.withResolvedDescriptor(at: "manifests", expecting: .directory) {
            try requireNames(
                ["\(v3LowercaseHex(digest)).json"],
                descriptor: $0.rawValue
            )
        }
    }

    private func requireRootNames(_ names: Set<String>) throws {
        try parentHandle.requireConfiguredRootIdentity()
        try rootHandle.withFileDescriptor { descriptor in
            // A new open description avoids sharing the root descriptor's
            // directory position when directoryEntryNames duplicates its fd.
            let listing = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard listing >= 0 else {
                throw AppError.io("Could not inspect the new-vault directory.")
            }
            defer { close(listing) }
            try requireNames(names, descriptor: listing)
        }
    }

    private func requireNames(_ expected: Set<String>, descriptor: Int32) throws {
        guard case let .names(names, count) = directoryEntryNames(
            descriptor: descriptor,
            maximumCount: expected.count + 1
        ), count == expected.count, Set(names) == expected else {
            throw AppError.operationRefused("The new-vault directory contains unexpected data. Nothing was selected; leave it in place for inspection.")
        }
    }
}
