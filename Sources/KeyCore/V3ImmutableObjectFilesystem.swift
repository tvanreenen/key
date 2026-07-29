import Darwin
import Foundation
import System

enum V3RepositoryDirectoryListing {
    case available([Data])
    case unavailable
    case invalid
    case limitExceeded
}

enum V3RepositoryObjectRead {
    case available(Data)
    case unavailable
    case invalid
    case tooLarge
}

protocol V3ImmutableObjectReading: Sendable {
    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead
}

struct V3FilesystemImmutableObjectSource: V3ImmutableObjectReading {
    let rootHandle: VaultRootDirectoryHandle

    func manifestDigests(maximumCount: Int) throws -> V3RepositoryDirectoryListing {
        do {
            return try rootHandle.withResolvedDescriptor(
                at: "manifests",
                expecting: .directory
            ) { descriptor in
                switch directoryEntryNames(
                    descriptor: descriptor.rawValue,
                    maximumCount: maximumCount
                ) {
                case let .names(names):
                    return .available(names.compactMap(manifestDigest(fromFilename:)))
                case .limitExceeded:
                    return .limitExceeded
                case .invalid:
                    return .invalid
                }
            }
        } catch let error as VaultRootDirectoryHandleError {
            throw error
        } catch VaultPathResolutionError.notFound,
                VaultPathResolutionError.providerPlaceholder {
            return .unavailable
        } catch {
            return .invalid
        }
    }

    func readManifest(
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try readObject(
            at: manifestPath(for: digest),
            maximumBytes: maximumBytes
        )
    }

    func readEntry(
        entryID: String,
        digest: Data,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        try readObject(
            at: entryPath(
                entryID: entryID,
                digest: Base64URL.encode(digest)
            ),
            maximumBytes: maximumBytes
        )
    }

    private func readObject(
        at path: String,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        do {
            return try rootHandle.withResolvedDescriptor(
                at: path,
                expecting: .regularFile
            ) { descriptor in
                readObjectData(
                    descriptor: descriptor.rawValue,
                    maximumBytes: maximumBytes
                )
            }
        } catch let error as VaultRootDirectoryHandleError {
            throw error
        } catch VaultPathResolutionError.notFound,
                VaultPathResolutionError.providerPlaceholder {
            return .unavailable
        } catch {
            return .invalid
        }
    }
}

private enum DirectoryEntries {
    case names([String])
    case limitExceeded
    case invalid
}

private func directoryEntryNames(
    descriptor: Int32,
    maximumCount: Int
) -> DirectoryEntries {
    let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
    guard duplicate >= 0 else {
        return .invalid
    }
    guard let directory = fdopendir(duplicate) else {
        Darwin.close(duplicate)
        return .invalid
    }
    defer { closedir(directory) }

    var names: [String] = []
    var observedCount = 0
    while true {
        errno = 0
        guard let entry = readdir(directory) else {
            return errno == 0 ? .names(names) : .invalid
        }
        var nameBytes = entry.pointee.d_name
        let name = withUnsafeBytes(of: &nameBytes) { bytes -> String? in
            let count = min(Int(entry.pointee.d_namlen), bytes.count)
            return String(data: Data(bytes.prefix(count)), encoding: .utf8)
        }
        observedCount += 1
        guard observedCount <= maximumCount else {
            return .limitExceeded
        }
        guard let name else {
            continue
        }
        guard name != ".", name != ".." else {
            observedCount -= 1
            continue
        }
        names.append(name)
    }
}

private func readObjectData(
    descriptor: Int32,
    maximumBytes: Int
) -> V3RepositoryObjectRead {
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0,
          metadata.st_size >= 0
    else {
        return .invalid
    }
    guard metadata.st_size <= maximumBytes else {
        return .tooLarge
    }

    var data = Data()
    data.reserveCapacity(Int(metadata.st_size))
    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
    while true {
        let count = buffer.withUnsafeMutableBytes { bytes in
            Darwin.read(descriptor, bytes.baseAddress, bytes.count)
        }
        if count == 0 {
            return .available(data)
        }
        if count < 0 {
            if errno == EINTR {
                continue
            }
            return .invalid
        }
        guard data.count <= maximumBytes - count else {
            return .tooLarge
        }
        data.append(contentsOf: buffer.prefix(count))
    }
}

private func manifestDigest(fromFilename filename: String) -> Data? {
    guard filename.hasSuffix(".json") else {
        return nil
    }
    let stem = filename.dropLast(5)
    guard stem.utf8.count == 64,
          stem.utf8.allSatisfy({
              ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
          })
    else {
        return nil
    }

    var bytes = Data()
    bytes.reserveCapacity(32)
    var index = stem.startIndex
    for _ in 0..<32 {
        let next = stem.index(after: index)
        let end = stem.index(after: next)
        guard let byte = UInt8(stem[index..<end], radix: 16) else {
            return nil
        }
        bytes.append(byte)
        index = end
    }
    return bytes
}
