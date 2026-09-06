import Darwin
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

/// Active key authority, distinct from the mode retained in the legacy file.
enum ConfiguredVaultAuthority: Equatable, Sendable {
    case v2(keychainMode: KeychainMode)
    case v3(vaultID: String)

    init(keychainMode: KeychainMode, vaultID: String?) {
        if let vaultID {
            self = .v3(vaultID: vaultID)
        } else {
            self = .v2(keychainMode: keychainMode)
        }
    }

    var vaultID: String? {
        guard case let .v3(vaultID) = self else { return nil }
        return vaultID
    }
}

public struct KeyConfiguration: Equatable, Sendable {
    public let configFileURL: URL
    public let vaultDirectoryURL: URL
    public let vaultPathSource: VaultPathSource
    /// Active for v2; retained compatibility metadata for v3.
    public let keychainMode: KeychainMode
    /// The exact device-local v3 vault selection. A missing value means v2.
    public var vaultID: String? { authority.vaultID }
    let authority: ConfiguredVaultAuthority

    public init(
        configFileURL: URL,
        vaultDirectoryURL: URL,
        vaultPathSource: VaultPathSource,
        keychainMode: KeychainMode,
        vaultID: String? = nil
    ) {
        self.configFileURL = configFileURL
        self.vaultDirectoryURL = vaultDirectoryURL
        self.vaultPathSource = vaultPathSource
        self.keychainMode = keychainMode
        self.authority = ConfiguredVaultAuthority(
            keychainMode: keychainMode,
            vaultID: vaultID
        )
    }

    func value(for key: ConfigKey) -> String {
        switch key {
        case .vaultDir:
            vaultDirectoryURL.path(percentEncoded: false)
        case .keychainMode:
            keychainMode.rawValue
        }
    }

    var listedValues: [KeyConfigValue] {
        var values = [KeyConfigValue(key: .vaultDir, value: value(for: .vaultDir))]
        if case .v2 = authority {
            values.append(KeyConfigValue(
                key: .keychainMode,
                value: value(for: .keychainMode)
            ))
        }
        return values
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

struct ConfiguredVaultRuntimeSelection: Equatable, Sendable {
    let rootURL: URL
    // Compare retained metadata too, preserving the helper's fail-closed guard.
    let keychainMode: KeychainMode
    let authority: ConfiguredVaultAuthority
    var vaultID: String? { authority.vaultID }

    init(rootURL: URL, keychainMode: KeychainMode, vaultID: String?) {
        self.rootURL = rootURL
        self.keychainMode = keychainMode
        self.authority = ConfiguredVaultAuthority(
            keychainMode: keychainMode,
            vaultID: vaultID
        )
    }
}

public struct KeyConfigStore {
    private let fileManager: FileManager
    private let homeDirectoryURL: URL
    private let productIdentity: KeyProductIdentity

    public init(
        productIdentity: KeyProductIdentity = .stable,
        fileManager: FileManager = .default,
        homeDirectoryURL: URL? = nil
    ) {
        self.productIdentity = productIdentity
        self.fileManager = fileManager
        self.homeDirectoryURL = homeDirectoryURL ?? fileManager.homeDirectoryForCurrentUser
    }

    public func load() throws -> KeyConfiguration {
        guard try hasConfiguration() else {
            throw Self.notInitializedError
        }
        let paths = configurationPaths()
        try ensurePathIsNotDirectory(
            at: paths.configFileURL,
            failureMessage: "Key config file '\(paths.configFileURL.path)' exists but is a directory."
        )
        let configuration = try loadConfigurationFile(from: paths.configFileURL)
        try requireExistingVaultDirectory(configuration.vaultDirectoryURL)
        return KeyConfiguration(
            configFileURL: paths.configFileURL,
            vaultDirectoryURL: configuration.vaultDirectoryURL,
            vaultPathSource: configuration.vaultDirectoryURL.standardizedFileURL == paths.defaultVaultURL.standardizedFileURL
                ? .appSupportConfigDefault : .appSupportConfigCustom,
            keychainMode: configuration.keychainMode,
            vaultID: configuration.vaultID
        )
    }

    static var notInitializedError: AppError {
        .operationRefused("No vault is configured. Run `key init [directory]` to create a new vault. Use device enrollment for an existing vault from another Mac.")
    }

    private func requireExistingVaultDirectory(_ url: URL) throws {
        do {
            _ = try VaultRootDirectoryHandle(opening: url)
        } catch {
            throw AppError.invalidConfiguration("The configured vault directory is unavailable: \(error.localizedDescription) Restore the existing vault or correct its configured path; Key will not create a replacement.")
        }
    }

    public func getValue(for key: ConfigKey) throws -> String {
        try load().value(for: key)
    }

    /// Presence is intentionally not validity. Even a malformed file, directory,
    /// or dangling link must prevent init from replacing an existing selection.
    func hasConfiguration() throws -> Bool {
        var metadata = stat()
        if lstat(configurationPaths().configFileURL.path, &metadata) == 0 { return true }
        guard errno == ENOENT else {
            throw AppError.io("Could not inspect the existing Key configuration.")
        }
        return false
    }

    func requireUnconfigured() throws {
        guard try !hasConfiguration() else {
            throw AppError.operationRefused("Key already has a configuration. Init never replaces it. Run `key status`; use `key migrate --check` for v2 or device enrollment for an existing v3 vault.")
        }
    }

    var initializationConfigFileURL: URL { configurationPaths().configFileURL }

    /// Reserves this destination before any device identity is created. Records
    /// are local, contain no keys, and survive process failure. A later attempt
    /// at this path must be inspected, never silently initialized again.
    func reserveNewVaultSelection(
        rootHandle: VaultRootDirectoryHandle,
        operationID: VaultTransactionOperationID
    ) throws -> (String) throws -> Void {
        try requireUnconfigured()
        let paths = try bootstrapPaths()
        let configRoot = try VaultRootDirectoryHandle(opening: paths.configDirectoryURL)
        let rootPath = rootHandle.rootURL.standardizedFileURL.path
        // Directory identity also catches a retry through a renamed path or
        // a different spelling of a symlinked ancestor.
        let recordPath = "v3-init-attempts/\(rootHandle.identity.deviceID)-\(rootHandle.identity.fileID).json"
        let record = NewVaultInitializationRecord(
            operationID: operationID.rawValue,
            vaultDirectory: rootPath,
            deviceID: rootHandle.identity.deviceID,
            fileID: rootHandle.identity.fileID
        )
        let bytes = try JSONEncoder().encode(record)
        let writer = V3AtomicStagedObjectWriter(rootHandle: configRoot)
        do {
            try writer.install(bytes, at: recordPath)
        } catch {
            throw AppError.operationRefused("Cannot reserve initialization. An earlier attempt may need inspection at '\(paths.configDirectoryURL.appendingPathComponent(recordPath).path)'. Leave its files and device identity intact; init will not automatically retry or clean it up. \(error.localizedDescription)")
        }
        return { vaultID in
            guard isValidV3UUID(vaultID) else {
                throw AppError.invalidConfiguration("Cannot select an invalid version 3 vault ID.")
            }
            try requireUnconfigured()
            try rootHandle.requireConfiguredRootIdentity()
            try configRoot.requireConfiguredRootIdentity()
            // Recheck that our durable reservation was not replaced.
            let observed = try configRoot.withResolvedDescriptor(at: recordPath, expecting: .regularFile) {
                readObjectData(descriptor: $0.rawValue, maximumBytes: bytes.count)
            }
            guard case let .available(data) = observed, data == bytes else {
                throw AppError.operationRefused("The initialization reservation changed. Leave this attempt in place for inspection.")
            }
            let configuration = KeyConfigurationFile(
                vaultDirectoryURL: rootHandle.rootURL,
                keychainMode: .local,
                vaultID: vaultID
            )
            // Atomic, durable publication without replacing another writer's
            // config. Retain the attempt record as an inspection receipt.
            try writer.install(configurationData(configuration), at: paths.configFileURL.lastPathComponent)
        }
    }

    /// Binds an explicit joining ceremony to a root without selecting a vault.
    /// Call with `create` only after authenticating the selected invitation.
    func prepareEnrollmentSelection(
        rootHandle: VaultRootDirectoryHandle,
        invitationDigest: Data,
        vaultID: String,
        create: Bool
    ) throws -> (String) throws -> Void {
        try requireUnconfigured()
        guard invitationDigest.count == 32, isValidV3UUID(vaultID) else {
            throw AppError.invalidConfiguration("Invalid enrollment invitation or vault ID.")
        }
        try rootHandle.requireConfiguredRootIdentity()
        let paths = create ? try bootstrapPaths() : configurationPaths()
        let configRoot: VaultRootDirectoryHandle
        do {
            configRoot = try VaultRootDirectoryHandle(opening: paths.configDirectoryURL)
        } catch {
            throw AppError.operationRefused("Cannot open the local enrollment records: \(error.localizedDescription) Start with `key share join` in the existing vault folder. Do not use init for an existing vault.")
        }
        let recordPath = "v3-enrollment-roots/\(v3LowercaseHex(invitationDigest)).json"
        let record = EnrollmentRootRecord(
            version: 1, vaultID: vaultID,
            invitationID: v3LowercaseHex(invitationDigest),
            vaultDirectory: rootHandle.rootURL.standardizedFileURL.path,
            deviceID: rootHandle.identity.deviceID,
            fileID: rootHandle.identity.fileID
        )
        let writer = V3AtomicStagedObjectWriter(rootHandle: configRoot)
        if create {
            do {
                try writer.install(JSONEncoder().encode(record), at: recordPath)
            } catch {
                // An exact retry may reuse the durable record, never replace it.
                try requireEnrollmentRoot(record, at: recordPath, in: configRoot)
            }
        }
        try requireEnrollmentRoot(record, at: recordPath, in: configRoot)
        return { selectedID in
            guard selectedID == vaultID else {
                throw AppError.operationRefused("Enrollment verified a different vault than the selected invitation.")
            }
            try requireUnconfigured()
            try rootHandle.requireConfiguredRootIdentity()
            try configRoot.requireConfiguredRootIdentity()
            try requireEnrollmentRoot(record, at: recordPath, in: configRoot)
            let configuration = KeyConfigurationFile(
                vaultDirectoryURL: rootHandle.rootURL,
                keychainMode: .local,
                vaultID: vaultID
            )
            try writer.install(configurationData(configuration), at: paths.configFileURL.lastPathComponent)
        }
    }

    private func requireEnrollmentRoot(
        _ expected: EnrollmentRootRecord,
        at path: String,
        in root: VaultRootDirectoryHandle
    ) throws {
        let observed = try root.withResolvedDescriptor(at: path, expecting: .regularFile) {
            readObjectData(descriptor: $0.rawValue, maximumBytes: 16_384)
        }
        guard case let .available(bytes) = observed,
              let record = try? JSONDecoder().decode(EnrollmentRootRecord.self, from: bytes),
              record == expected
        else {
            throw AppError.operationRefused("This enrollment has no matching folder record. Use the same folder and invitation as the join request; leave existing enrollment records intact for inspection.")
        }
    }

    public func setValue(_ value: String, for key: ConfigKey) throws -> KeyConfiguration {
        guard try hasConfiguration() else { throw Self.notInitializedError }
        let paths = configurationPaths()
        let current = try loadConfigurationFile(from: paths.configFileURL)
        let updatedFile: KeyConfigurationFile

        switch key {
        case .vaultDir:
            let resolvedURL = try resolveConfiguredPath(value, configFileURL: paths.configFileURL)
            try requireExistingVaultDirectory(resolvedURL)
            updatedFile = KeyConfigurationFile(
                vaultDirectoryURL: resolvedURL,
                keychainMode: current.keychainMode,
                vaultID: current.vaultID
            )
        case .keychainMode:
            try requireExistingVaultDirectory(current.vaultDirectoryURL)
            guard let mode = KeychainMode(rawValue: value) else {
                throw AppError.invalidConfiguration("Unsupported keychain mode '\(value)'. Expected 'local' or 'icloud'.")
            }
            updatedFile = KeyConfigurationFile(
                vaultDirectoryURL: current.vaultDirectoryURL,
                keychainMode: mode,
                vaultID: current.vaultID
            )
        }

        try writeConfigurationFile(updatedFile, to: paths.configFileURL)
        return try load()
    }

    public func listValues() throws -> [KeyConfigValue] {
        try load().listedValues
    }

    /// Reads the existing configured root without creating config or vault
    /// state. The running helper uses this as a fail-closed consistency check.
    func configuredVaultDirectoryURL() throws -> URL {
        try configuredVaultRuntimeSelection().rootURL
    }

    /// Reads the running helper's complete storage selection without creating
    /// configuration, directories, checkpoints, or vault files.
    func configuredVaultRuntimeSelection()
        throws -> ConfiguredVaultRuntimeSelection
    {
        let paths = configurationPaths()
        let configPath = paths.configFileURL.path(percentEncoded: false)
        guard fileManager.fileExists(atPath: configPath) else {
            throw AppError.invalidConfiguration(
                "Key config file '\(paths.configFileURL.path)' does not exist."
            )
        }
        try ensurePathIsNotDirectory(
            at: paths.configFileURL,
            failureMessage: "Key config file '\(paths.configFileURL.path)' exists but is a directory."
        )
        let configuration = try loadConfigurationFile(
            from: paths.configFileURL
        )
        return ConfiguredVaultRuntimeSelection(
            rootURL: configuration.vaultDirectoryURL,
            keychainMode: configuration.keychainMode,
            vaultID: configuration.vaultID
        )
    }

    /// Selects one fully verified v3 vault without exposing `vault_id` as a
    /// general-purpose configuration mutation.
    ///
    /// Migration calls this last and supplies the exact v2 runtime selection
    /// under which it began. A changed root, key mode, or existing v3
    /// selection fails rather than being overwritten.
    func selectV3Vault(
        vaultID: String,
        expectedRootHandle: VaultRootDirectoryHandle,
        expectedKeychainMode: KeychainMode
    ) throws -> KeyConfiguration {
        guard isValidV3UUID(vaultID) else {
            throw AppError.invalidConfiguration(
                "Cannot select an invalid version 3 vault ID."
            )
        }
        let current = try configuredVaultRuntimeSelection()
        guard case let .v2(sourceMode) = current.authority else {
            throw AppError.operationRefused(
                "This device already selects a version 3 vault."
            )
        }
        guard current.rootURL.standardizedFileURL
                == expectedRootHandle.rootURL.standardizedFileURL,
              sourceMode == expectedKeychainMode
        else {
            throw AppError.operationRefused(
                "The vault configuration changed during migration. Version 2 remains selected; retry with the current configuration."
            )
        }
        try expectedRootHandle.requireConfiguredRootIdentity()

        let paths = configurationPaths()
        try writeConfigurationFile(
            KeyConfigurationFile(
                vaultDirectoryURL: current.rootURL,
                keychainMode: current.keychainMode,
                vaultID: vaultID
            ),
            to: paths.configFileURL
        )
        let pathSource: VaultPathSource =
            current.rootURL.standardizedFileURL
                == paths.defaultVaultURL.standardizedFileURL
            ? .appSupportConfigDefault
            : .appSupportConfigCustom
        return KeyConfiguration(
            configFileURL: paths.configFileURL,
            vaultDirectoryURL: current.rootURL,
            vaultPathSource: pathSource,
            keychainMode: current.keychainMode,
            vaultID: vaultID
        )
    }

    private func bootstrapPaths() throws -> BootstrapPaths {
        let paths = configurationPaths()

        try ensureDirectoryExists(
            at: paths.configDirectoryURL,
            failureMessage: "Key config directory '\(paths.configDirectoryURL.path)' exists but is not a directory."
        )

        return paths
    }

    private func configurationPaths() -> BootstrapPaths {
        let configDirectoryURL = homeDirectoryURL
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent(
                productIdentity.applicationSupportDirectoryName,
                isDirectory: true
            )
        let configFileURL = configDirectoryURL
            .appendingPathComponent("config.toml", isDirectory: false)
        let defaultVaultURL = homeDirectoryURL
            .appendingPathComponent(
                productIdentity.defaultVaultDirectoryName,
                isDirectory: true
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
        var keychainMode: KeychainMode?
        var vaultID: String?
        var sawVaultID = false

        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") {
                continue
            }

            guard let separatorIndex = line.firstIndex(of: "=") else {
                continue
            }

            let key = line[..<separatorIndex].trimmingCharacters(in: .whitespaces)
            let valuePortion = line[line.index(after: separatorIndex)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "vault_dir":
                guard vaultDirectory == nil else {
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' declares 'vault_dir' more than once.")
                }

                let configuredPath = try parseQuotedString(
                    valuePortion,
                    configFileURL: configFileURL,
                    keyName: "vault_dir"
                )
                vaultDirectory = try resolveConfiguredPath(configuredPath, configFileURL: configFileURL)
            case "keychain_mode":
                guard keychainMode == nil else {
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' declares 'keychain_mode' more than once.")
                }

                let rawMode = try parseQuotedString(
                    valuePortion,
                    configFileURL: configFileURL,
                    keyName: "keychain_mode"
                )
                guard let parsedMode = KeychainMode(rawValue: rawMode) else {
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' has unsupported 'keychain_mode' value '\(rawMode)'.")
                }
                keychainMode = parsedMode
            case "vault_id":
                guard !sawVaultID else {
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' declares 'vault_id' more than once.")
                }
                sawVaultID = true
                let rawVaultID = try parseQuotedString(
                    valuePortion,
                    configFileURL: configFileURL,
                    keyName: "vault_id"
                )
                guard isValidV3UUID(rawVaultID) else {
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' has an invalid canonical version 3 'vault_id'.")
                }
                vaultID = rawVaultID
            default:
                continue
            }
        }

        guard let vaultDirectory else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' is missing 'vault_dir'.")
        }

        return KeyConfigurationFile(
            vaultDirectoryURL: vaultDirectory,
            keychainMode: keychainMode ?? .local,
            vaultID: vaultID
        )
    }

    private func writeConfigurationFile(_ configuration: KeyConfigurationFile, to configFileURL: URL) throws {
        do {
            try configurationData(configuration).write(to: configFileURL, options: .atomic)
        } catch {
            throw AppError.io("Failed to write vault configuration at '\(configFileURL.path)': \(error.localizedDescription)")
        }
    }

    private func configurationData(_ configuration: KeyConfigurationFile) -> Data {
        let escapedPath = configuration.vaultDirectoryURL.path(percentEncoded: false)
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\t", with: "\\t")
        var contents = """
        # key configuration
        vault_dir = "\(escapedPath)"
        keychain_mode = "\(configuration.keychainMode.rawValue)"
        """
        if let vaultID = configuration.vaultID {
            contents += "\nvault_id = \"\(vaultID)\""
        }

        return Data(contents.utf8)
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


    private func normalizedPath(for url: URL) -> String {
        let path = url.standardizedFileURL.path(percentEncoded: false)
        guard path.count > 1, path.hasSuffix("/") else {
            return path
        }
        return String(path.dropLast())
    }

    private func parseQuotedString(
        _ valuePortion: String,
        configFileURL: URL,
        keyName: String
    ) throws -> String {
        guard valuePortion.first == "\"" else {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' must quote '\(keyName)'.")
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
                    throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' contains an unsupported escape in '\(keyName)'.")
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
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' has an unterminated '\(keyName)' value.")
        }

        let remainder = valuePortion[remainderStartIndex...].trimmingCharacters(in: .whitespaces)
        if !remainder.isEmpty && !remainder.hasPrefix("#") {
            throw AppError.invalidConfiguration("Vault configuration at '\(configFileURL.path)' contains unexpected content after '\(keyName)'.")
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

private struct EnrollmentRootRecord: Codable, Equatable {
    let version: Int
    let vaultID: String
    let invitationID: String
    let vaultDirectory: String
    let deviceID: UInt64
    let fileID: UInt64
}

private struct NewVaultInitializationRecord: Encodable {
    let operationID: String
    let vaultDirectory: String
    let deviceID: UInt64
    let fileID: UInt64
}

public struct VaultLocationResolver {
    private let configStore: KeyConfigStore

    public init(
        productIdentity: KeyProductIdentity = .stable,
        fileManager: FileManager = .default,
        homeDirectoryURL: URL? = nil
    ) {
        self.configStore = KeyConfigStore(
            productIdentity: productIdentity,
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
    let keychainMode: KeychainMode
    let vaultID: String?
}

private struct BootstrapPaths {
    let configDirectoryURL: URL
    let configFileURL: URL
    let defaultVaultURL: URL
}
