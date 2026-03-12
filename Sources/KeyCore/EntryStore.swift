import Foundation

public struct EntryStore {
    public let rootURL: URL
    private let fileManager: FileManager
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(rootURL: URL, fileManager: FileManager = .default) {
        self.rootURL = rootURL
        self.fileManager = fileManager
    }

    public static func defaultRootURL(fileManager: FileManager = .default) throws -> URL {
        let appSupport = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return appSupport.appendingPathComponent("key", isDirectory: true)
            .appendingPathComponent("vault", isDirectory: true)
    }

    public func validateEntryName(_ name: String) throws {
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else {
            throw AppError.invalidEntryName("Entry name must not be empty.")
        }
        guard !normalized.hasPrefix("/") else {
            throw AppError.invalidEntryName("Entry name must be relative.")
        }

        let components = normalized.split(separator: "/", omittingEmptySubsequences: false)
        for component in components {
            guard !component.isEmpty else {
                throw AppError.invalidEntryName("Entry name must not contain empty path segments.")
            }
            guard component != "." && component != ".." else {
                throw AppError.invalidEntryName("Entry name must not contain '.' or '..' segments.")
            }
        }
    }

    public func url(for name: String) throws -> URL {
        try validateEntryName(name)
        let components = name.split(separator: "/").map(String.init)
        let resolved = components.dropLast().reduce(rootURL) { partialResult, component in
            partialResult.appendingPathComponent(component, isDirectory: true)
        }
        return resolved
            .appendingPathComponent(components.last ?? name, isDirectory: false)
            .appendingPathExtension("secret")
    }

    public func exists(_ name: String) throws -> Bool {
        fileManager.fileExists(atPath: try url(for: name).path(percentEncoded: false))
    }

    public func listEntries() throws -> [String] {
        guard fileManager.fileExists(atPath: rootURL.path(percentEncoded: false)) else {
            return []
        }

        let normalizedRoot = rootURL.resolvingSymlinksInPath().standardizedFileURL
        guard let enumerator = fileManager.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            throw AppError.io("Failed to enumerate stored secrets.")
        }

        var entries: [String] = []
        for case let fileURL as URL in enumerator {
            guard fileURL.pathExtension == "secret" else {
                continue
            }

            let normalizedFile = fileURL.resolvingSymlinksInPath().standardizedFileURL
            let rootComponents = normalizedRoot.pathComponents
            let fileComponents = normalizedFile.pathComponents
            guard fileComponents.count >= rootComponents.count + 1 else {
                continue
            }

            let relativeComponents = Array(fileComponents.dropFirst(rootComponents.count))
            let relativePath = relativeComponents.joined(separator: "/")
            let entry = (relativePath as NSString).deletingPathExtension
            entries.append(entry)
        }

        return entries.sorted()
    }

    public func load(_ name: String) throws -> SecretFile {
        let fileURL = try url(for: name)
        guard fileManager.fileExists(atPath: fileURL.path(percentEncoded: false)) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }

        do {
            let data = try Data(contentsOf: fileURL)
            return try decoder.decode(SecretFile.self, from: data)
        } catch let error as AppError {
            throw error
        } catch {
            throw AppError.invalidSecretFile("Secret file for '\(name)' is unreadable.")
        }
    }

    public func save(_ file: SecretFile, as name: String, overwrite: Bool) throws {
        let destination = try url(for: name)
        let directory = destination.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)

        if fileManager.fileExists(atPath: destination.path(percentEncoded: false)), !overwrite {
            throw AppError.entryExists("Secret '\(name)' already exists. Use --force to overwrite it.")
        }

        let tempURL = directory.appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
        defer {
            try? fileManager.removeItem(at: tempURL)
        }

        do {
            let data = try encoder.encode(file)
            try data.write(to: tempURL, options: .completeFileProtection)
            if fileManager.fileExists(atPath: destination.path(percentEncoded: false)) {
                _ = try fileManager.replaceItemAt(destination, withItemAt: tempURL)
            } else {
                try fileManager.moveItem(at: tempURL, to: destination)
            }
        } catch let error as AppError {
            throw error
        } catch {
            throw AppError.io("Failed to store secret '\(name)': \(error.localizedDescription)")
        }
    }

    public func copyEntry(from sourceName: String, to destinationName: String, overwrite: Bool) throws {
        let source = try url(for: sourceName)
        let destination = try url(for: destinationName)

        guard fileManager.fileExists(atPath: source.path(percentEncoded: false)) else {
            throw AppError.entryNotFound("Secret '\(sourceName)' was not found.")
        }

        let directory = destination.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)

        if fileManager.fileExists(atPath: destination.path(percentEncoded: false)), !overwrite {
            throw AppError.entryExists("Secret '\(destinationName)' already exists. Use --force to overwrite it.")
        }

        let tempURL = directory.appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
        defer {
            try? fileManager.removeItem(at: tempURL)
        }

        do {
            try fileManager.copyItem(at: source, to: tempURL)
            if fileManager.fileExists(atPath: destination.path(percentEncoded: false)) {
                _ = try fileManager.replaceItemAt(destination, withItemAt: tempURL)
            } else {
                try fileManager.moveItem(at: tempURL, to: destination)
            }
        } catch let error as AppError {
            throw error
        } catch {
            throw AppError.io("Failed to copy secret '\(sourceName)' to '\(destinationName)': \(error.localizedDescription)")
        }
    }

    public func moveEntry(from sourceName: String, to destinationName: String, overwrite: Bool) throws {
        let source = try url(for: sourceName)
        let destination = try url(for: destinationName)

        guard fileManager.fileExists(atPath: source.path(percentEncoded: false)) else {
            throw AppError.entryNotFound("Secret '\(sourceName)' was not found.")
        }

        if source.standardizedFileURL == destination.standardizedFileURL {
            return
        }

        let directory = destination.deletingLastPathComponent()
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)

        if fileManager.fileExists(atPath: destination.path(percentEncoded: false)), !overwrite {
            throw AppError.entryExists("Secret '\(destinationName)' already exists. Use --force to overwrite it.")
        }

        do {
            if fileManager.fileExists(atPath: destination.path(percentEncoded: false)) {
                let tempURL = directory.appendingPathComponent(".\(destination.lastPathComponent).\(UUID().uuidString).tmp")
                defer {
                    try? fileManager.removeItem(at: tempURL)
                }
                try fileManager.moveItem(at: source, to: tempURL)
                _ = try fileManager.replaceItemAt(destination, withItemAt: tempURL)
            } else {
                try fileManager.moveItem(at: source, to: destination)
            }
        } catch let error as AppError {
            throw error
        } catch {
            throw AppError.io("Failed to move secret '\(sourceName)' to '\(destinationName)': \(error.localizedDescription)")
        }
    }

    public func removeEntry(_ name: String) throws {
        let url = try url(for: name)
        guard fileManager.fileExists(atPath: url.path(percentEncoded: false)) else {
            throw AppError.entryNotFound("Secret '\(name)' was not found.")
        }

        do {
            try fileManager.removeItem(at: url)
            try pruneEmptyDirectories(startingAt: url.deletingLastPathComponent())
        } catch let error as AppError {
            throw error
        } catch {
            throw AppError.io("Failed to remove secret '\(name)': \(error.localizedDescription)")
        }
    }

    private func pruneEmptyDirectories(startingAt directory: URL) throws {
        let normalizedRoot = rootURL.standardizedFileURL
        var current = directory.standardizedFileURL

        while current.path.hasPrefix(normalizedRoot.path), current != normalizedRoot {
            let contents = try fileManager.contentsOfDirectory(atPath: current.path(percentEncoded: false))
            guard contents.isEmpty else {
                return
            }
            try fileManager.removeItem(at: current)
            current = current.deletingLastPathComponent().standardizedFileURL
        }
    }
}
