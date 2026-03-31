import Foundation

public enum VaultPathSource: Equatable, Sendable {
    case appSupportConfigDefault
    case appSupportConfigCustom

    public var displayString: String {
        switch self {
        case .appSupportConfigDefault:
            return "App Support config (default)"
        case .appSupportConfigCustom:
            return "App Support config (custom)"
        }
    }
}

public struct KeyConfiguration: Equatable, Sendable {
    public let configFileURL: URL
    public let vaultDirectoryURL: URL
    public let vaultPathSource: VaultPathSource

    public init(
        configFileURL: URL,
        vaultDirectoryURL: URL,
        vaultPathSource: VaultPathSource
    ) {
        self.configFileURL = configFileURL
        self.vaultDirectoryURL = vaultDirectoryURL
        self.vaultPathSource = vaultPathSource
    }
}

public struct KeyConfigValue: Equatable, Sendable {
    public let key: ConfigKey
    public let value: String

    public init(key: ConfigKey, value: String) {
        self.key = key
        self.value = value
    }
}

public struct VaultLocation: Equatable, Sendable {
    public let rootURL: URL
    public let configFileURL: URL
    public let pathSource: VaultPathSource

    public init(rootURL: URL, configFileURL: URL, pathSource: VaultPathSource) {
        self.rootURL = rootURL
        self.configFileURL = configFileURL
        self.pathSource = pathSource
    }
}

public struct KeyConfigStore {
    private let fileManager: FileManager
    private let homeDirectoryURL: URL

    public init(fileManager: FileManager = .default, homeDirectoryURL: URL? = nil) {
        self.fileManager = fileManager
        self.homeDirectoryURL = homeDirectoryURL ?? fileManager.homeDirectoryForCurrentUser
    }

    public func load() throws -> KeyConfiguration {
        let paths = try bootstrapPaths()

        let configuredVaultURL: URL
        let pathSource: VaultPathSource

        if fileManager.fileExists(atPath: paths.configFileURL.path(percentEncoded: false)) {
            try ensurePathIsNotDirectory(
                at: paths.configFileURL,
                failureMessage: "Key config file '\(paths.configFileURL.path)' exists but is a directory."
            )

            let configurationFile = try loadConfigurationFile(from: paths.configFileURL)
            configuredVaultURL = configurationFile.vaultDirectoryURL
            pathSource = configurationFile.vaultDirectoryURL.standardizedFileURL == paths.defaultVaultURL.standardizedFileURL
                ? .appSupportConfigDefault
                : .appSupportConfigCustom
        } else {
            configuredVaultURL = try prepareDefaultVaultDirectory(
                at: paths.defaultVaultURL,
                configFileURL: paths.configFileURL
            )
            pathSource = .appSupportConfigDefault
            try writeConfigurationFile(
                KeyConfigurationFile(vaultDirectoryURL: configuredVaultURL),
                to: paths.configFileURL
            )
        }

        try ensureDirectoryExists(
            at: configuredVaultURL,
            failureMessage: "Configured vault directory '\(configuredVaultURL.path)' exists but is not a directory."
        )

        return KeyConfiguration(
            configFileURL: paths.configFileURL,
            vaultDirectoryURL: configuredVaultURL,
            vaultPathSource: pathSource
        )
    }

    public func getValue(for key: ConfigKey) throws -> String {
        let configuration = try load()

        switch key {
        case .vaultDir:
            return configuration.vaultDirectoryURL.path(percentEncoded: false)
        }
    }

    public func setValue(_ value: String, for key: ConfigKey) throws -> KeyConfiguration {
        let paths = try bootstrapPaths()
        let updatedFile: KeyConfigurationFile

        switch key {
        case .vaultDir:
            let resolvedURL = try resolveConfiguredPath(value, configFileURL: paths.configFileURL)
            try ensureDirectoryExists(
                at: resolvedURL,
                failureMessage: "Configured vault directory '\(resolvedURL.path)' exists but is not a directory."
            )
            updatedFile = KeyConfigurationFile(vaultDirectoryURL: resolvedURL)
        }

        try writeConfigurationFile(updatedFile, to: paths.configFileURL)
        return try load()
    }

    public func listValues() throws -> [KeyConfigValue] {
        [
            KeyConfigValue(
                key: .vaultDir,
                value: try getValue(for: .vaultDir)
            )
        ]
    }

    private func bootstrapPaths() throws -> BootstrapPaths {
        let configDirectoryURL = homeDirectoryURL
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Key", isDirectory: true)
        let configFileURL = configDirectoryURL
            .appendingPathComponent("config.toml", isDirectory: false)
        let defaultVaultURL = homeDirectoryURL
            .appendingPathComponent(".key", isDirectory: true)

        try ensureDirectoryExists(
            at: configDirectoryURL,
            failureMessage: "Key config directory '\(configDirectoryURL.path)' exists but is not a directory."
        )

        return BootstrapPaths(
            configDirectoryURL: configDirectoryURL,
            configFileURL: configFileURL,
            defaultVaultURL: defaultVaultURL
        )
    }

    private func loadConfigurationFile(from configFileURL: URL) throws -> KeyConfigurationFile {
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

        return KeyConfigurationFile(vaultDirectoryURL: vaultDirectory)
    }

    private func writeConfigurationFile(_ configuration: KeyConfigurationFile, to configFileURL: URL) throws {
        let escapedPath = configuration.vaultDirectoryURL.path(percentEncoded: false)
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

    private func prepareDefaultVaultDirectory(at defaultVaultURL: URL, configFileURL: URL) throws -> URL {
        var isDirectory: ObjCBool = false
        let path = normalizedPath(for: defaultVaultURL)

        if fileManager.fileExists(atPath: path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw AppError.invalidConfiguration(
                    "Default vault directory '\(path)' exists but is not a directory. Run `key config set vault-dir <path>` to choose another vault directory."
                )
            }

            if try isDirectoryEmpty(defaultVaultURL) || directoryContainsSecretFiles(at: defaultVaultURL) {
                return defaultVaultURL.standardizedFileURL
            }

            throw AppError.invalidConfiguration(
                "Default vault directory '\(path)' already contains unrelated files. Run `key config set vault-dir <path>` to choose another vault directory."
            )
        }

        do {
            try fileManager.createDirectory(at: defaultVaultURL, withIntermediateDirectories: true)
        } catch {
            throw AppError.io("Failed to create directory at '\(path)': \(error.localizedDescription)")
        }

        return defaultVaultURL.standardizedFileURL
    }

    private func ensureDirectoryExists(at url: URL, failureMessage: String) throws {
        var isDirectory: ObjCBool = false
        let path = normalizedPath(for: url)

        if fileManager.fileExists(atPath: path, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw AppError.invalidConfiguration(failureMessage)
            }
            return
        }

        do {
            try fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        } catch {
            throw AppError.io("Failed to create directory at '\(path)': \(error.localizedDescription)")
        }
    }

    private func ensurePathIsNotDirectory(at url: URL, failureMessage: String) throws {
        var isDirectory: ObjCBool = false
        let path = normalizedPath(for: url)
        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return
        }

        throw AppError.invalidConfiguration(failureMessage)
    }

    private func isDirectoryEmpty(_ url: URL) throws -> Bool {
        do {
            return try fileManager.contentsOfDirectory(atPath: normalizedPath(for: url)).isEmpty
        } catch {
            throw AppError.io("Failed to inspect directory at '\(url.path)': \(error.localizedDescription)")
        }
    }

    private func directoryContainsSecretFiles(at url: URL) -> Bool {
        guard let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: nil,
            options: [.skipsPackageDescendants]
        ) else {
            return false
        }

        for case let childURL as URL in enumerator {
            if childURL.pathExtension == "secret" {
                return true
            }
        }

        return false
    }

    private func normalizedPath(for url: URL) -> String {
        let path = url.standardizedFileURL.path(percentEncoded: false)
        guard path.count > 1, path.hasSuffix("/") else {
            return path
        }
        return String(path.dropLast())
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
            resolvedPath = homeDirectoryURL.path(percentEncoded: false)
        } else if path.hasPrefix("~/") {
            resolvedPath = homeDirectoryURL
                .appendingPathComponent(String(path.dropFirst(2)), isDirectory: true)
                .path(percentEncoded: false)
        } else {
            resolvedPath = path
        }

        guard resolvedPath.hasPrefix("/") else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' must use an absolute path or '~/' for 'vault_dir'.")
        }

        return URL(fileURLWithPath: resolvedPath, isDirectory: true).standardizedFileURL
    }
}

public struct VaultLocationResolver {
    private let configStore: KeyConfigStore

    public init(fileManager: FileManager = .default, homeDirectoryURL: URL? = nil) {
        self.configStore = KeyConfigStore(
            fileManager: fileManager,
            homeDirectoryURL: homeDirectoryURL
        )
    }

    public func resolve() throws -> VaultLocation {
        let configuration = try configStore.load()
        return VaultLocation(
            rootURL: configuration.vaultDirectoryURL,
            configFileURL: configuration.configFileURL,
            pathSource: configuration.vaultPathSource
        )
    }
}

private struct KeyConfigurationFile {
    let vaultDirectoryURL: URL
}

private struct BootstrapPaths {
    let configDirectoryURL: URL
    let configFileURL: URL
    let defaultVaultURL: URL
}
