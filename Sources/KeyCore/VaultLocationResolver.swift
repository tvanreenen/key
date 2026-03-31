import Foundation

public struct VaultLocation: Equatable, Sendable {
    public let rootURL: URL
    public let configFileURL: URL
    public let sourceDescription: String

    public init(rootURL: URL, configFileURL: URL, sourceDescription: String) {
        self.rootURL = rootURL
        self.configFileURL = configFileURL
        self.sourceDescription = sourceDescription
    }
}

public struct VaultLocationResolver {
    private let fileManager: FileManager
    private let homeDirectoryURL: URL

    public init(fileManager: FileManager = .default, homeDirectoryURL: URL? = nil) {
        self.fileManager = fileManager
        self.homeDirectoryURL = homeDirectoryURL ?? fileManager.homeDirectoryForCurrentUser
    }

    public func resolve() throws -> VaultLocation {
        let keyDirectoryURL = homeDirectoryURL
            .appendingPathComponent(".key", isDirectory: true)
        let configFileURL = keyDirectoryURL
            .appendingPathComponent("config.toml", isDirectory: false)
        let defaultVaultURL = keyDirectoryURL
            .appendingPathComponent("vault", isDirectory: true)

        try fileManager.createDirectory(at: keyDirectoryURL, withIntermediateDirectories: true)

        let configuredVaultURL: URL
        let sourceDescription: String

        if fileManager.fileExists(atPath: configFileURL.path(percentEncoded: false)) {
            let configuration = try loadConfiguration(from: configFileURL)
            configuredVaultURL = configuration.vaultDirectoryURL
            sourceDescription = configuration.vaultDirectoryURL.standardizedFileURL == defaultVaultURL.standardizedFileURL
                ? "Config file (default)"
                : "Config file (custom)"
        } else {
            configuredVaultURL = defaultVaultURL
            sourceDescription = "Config file (default)"
            try writeConfiguration(vaultDirectoryURL: defaultVaultURL, to: configFileURL)
        }

        try fileManager.createDirectory(at: configuredVaultURL, withIntermediateDirectories: true)

        return VaultLocation(
            rootURL: configuredVaultURL,
            configFileURL: configFileURL,
            sourceDescription: sourceDescription
        )
    }

    private func loadConfiguration(from configFileURL: URL) throws -> VaultConfiguration {
        let data: Data
        do {
            data = try Data(contentsOf: configFileURL)
        } catch {
            throw AppError.io("Failed to read vault configuration at '\(configFileURL.path)': \(error.localizedDescription)")
        }

        guard let text = String(data: data, encoding: .utf8) else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' is not valid UTF-8.")
        }

        var vaultDirectory: URL?

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }

            guard let separatorIndex = line.firstIndex(of: "=") else {
                continue
            }

            let key = line[..<separatorIndex].trimmingCharacters(in: .whitespaces)
            guard key == "vault_dir" else {
                continue
            }

            guard vaultDirectory == nil else {
                throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' declares 'vault_dir' more than once.")
            }

            let valuePortion = line[line.index(after: separatorIndex)...].trimmingCharacters(in: .whitespaces)
            let configuredPath = try parseQuotedString(
                valuePortion,
                configFileURL: configFileURL
            )
            vaultDirectory = try resolveConfiguredPath(configuredPath, configFileURL: configFileURL)
        }

        guard let vaultDirectory else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' is missing 'vault_dir'.")
        }

        return VaultConfiguration(vaultDirectoryURL: vaultDirectory)
    }

    private func writeConfiguration(vaultDirectoryURL: URL, to configFileURL: URL) throws {
        let escapedPath = vaultDirectoryURL.path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let contents = """
        # key configuration
        vault_dir = "\(escapedPath)"
        """

        do {
            try contents.write(to: configFileURL, atomically: true, encoding: .utf8)
        } catch {
            throw AppError.io("Failed to write vault configuration at '\(configFileURL.path)': \(error.localizedDescription)")
        }
    }

    private func parseQuotedString(
        _ valuePortion: String,
        configFileURL: URL
    ) throws -> String {
        guard valuePortion.first == "\"" else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' must quote 'vault_dir'.")
        }

        var result = ""
        var isEscaping = false
        var reachedClosingQuote = false
        var currentIndex = valuePortion.index(after: valuePortion.startIndex)
        var remainderStartIndex = valuePortion.endIndex

        while currentIndex < valuePortion.endIndex {
            let character = valuePortion[currentIndex]
            if isEscaping {
                switch character {
                case "\\", "\"":
                    result.append(character)
                case "n":
                    result.append("\n")
                case "r":
                    result.append("\r")
                case "t":
                    result.append("\t")
                default:
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' contains an unsupported escape in 'vault_dir'.")
                }
                isEscaping = false
                currentIndex = valuePortion.index(after: currentIndex)
                continue
            }

            if character == "\\" {
                isEscaping = true
                currentIndex = valuePortion.index(after: currentIndex)
                continue
            }

            if character == "\"" {
                reachedClosingQuote = true
                remainderStartIndex = valuePortion.index(after: currentIndex)
                break
            }

            result.append(character)
            currentIndex = valuePortion.index(after: currentIndex)
        }

        guard !isEscaping, reachedClosingQuote else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' has an unterminated 'vault_dir' value.")
        }

        let remainder = valuePortion[remainderStartIndex...].trimmingCharacters(in: .whitespaces)
        if !remainder.isEmpty && !remainder.hasPrefix("#") {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' contains unexpected content after 'vault_dir'.")
        }

        return result
    }

    private func resolveConfiguredPath(_ path: String, configFileURL: URL) throws -> URL {
        let resolvedPath: String
        if path == "~" {
            resolvedPath = homeDirectoryURL.path
        } else if path.hasPrefix("~/") {
            resolvedPath = homeDirectoryURL
                .appendingPathComponent(String(path.dropFirst(2)), isDirectory: true)
                .path
        } else {
            resolvedPath = path
        }

        guard resolvedPath.hasPrefix("/") else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' must use an absolute path or '~/' for 'vault_dir'.")
        }

        return URL(fileURLWithPath: resolvedPath, isDirectory: true)
    }
}

private struct VaultConfiguration {
    let vaultDirectoryURL: URL
}
