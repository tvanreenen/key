import Foundation
#if canImport(Darwin)
import Darwin
#endif

public struct KeyVersionInfo: Codable, Equatable, Sendable {
    public let marketingVersion: String
    public let buildVersion: String

    public init(marketingVersion: String, buildVersion: String) {
        self.marketingVersion = marketingVersion
        self.buildVersion = buildVersion
    }

    public init(bundle: Bundle) {
        let marketingVersion = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        let buildVersion = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        self.init(
            marketingVersion: marketingVersion ?? "0.0.0",
            buildVersion: buildVersion ?? "0"
        )
    }

    public static func currentProcess() -> KeyVersionInfo {
        KeyVersionInfo(bundle: currentProcessBundle())
    }

    public static func currentProcess(
        mainBundle: Bundle,
        executableURL: URL?
    ) -> KeyVersionInfo {
        KeyVersionInfo(
            bundle: currentProcessBundle(
                mainBundle: mainBundle,
                executableURL: executableURL
            )
        )
    }

    public static func currentProcessBundle() -> Bundle {
        currentProcessBundle(
            mainBundle: .main,
            executableURL: currentExecutableURL()
        )
    }

    static func currentProcessBundle(
        mainBundle: Bundle,
        executableURL: URL?
    ) -> Bundle {
        guard
            let executableURL,
            let bundle = bundle(containingExecutableAt: executableURL)
        else {
            return mainBundle
        }
        return bundle
    }

    public var displayString: String {
        "\(marketingVersion) (\(buildVersion))"
    }

    private static func bundle(containingExecutableAt executableURL: URL) -> Bundle? {
        var currentURL = executableURL
            .resolvingSymlinksInPath()
            .standardizedFileURL

        while currentURL.path != "/" {
            if currentURL.pathExtension == "app" {
                return Bundle(url: currentURL)
            }
            currentURL.deleteLastPathComponent()
        }

        return nil
    }

    private static func currentExecutableURL() -> URL? {
        #if canImport(Darwin)
        var size: UInt32 = 0
        _NSGetExecutablePath(nil, &size)

        var buffer = [CChar](repeating: 0, count: Int(size))
        guard _NSGetExecutablePath(&buffer, &size) == 0 else {
            return nil
        }

        let endIndex = buffer.firstIndex(of: 0) ?? buffer.endIndex
        let bytes = buffer[..<endIndex].map { UInt8(bitPattern: $0) }
        let path = String(decoding: bytes, as: UTF8.self)

        return URL(fileURLWithPath: path)
            .resolvingSymlinksInPath()
            .standardizedFileURL
        #else
        return nil
        #endif
    }
}

public struct KeyHelperStatus: Codable, Equatable, Sendable {
    public let isUnlocked: Bool
    public let sessionExpiresAt: Date?
    public let inactivityTimeoutSeconds: TimeInterval

    public init(
        isUnlocked: Bool,
        sessionExpiresAt: Date?,
        inactivityTimeoutSeconds: TimeInterval
    ) {
        self.isUnlocked = isUnlocked
        self.sessionExpiresAt = sessionExpiresAt
        self.inactivityTimeoutSeconds = inactivityTimeoutSeconds
    }

    public static func locked(inactivityTimeoutSeconds: TimeInterval) -> KeyHelperStatus {
        KeyHelperStatus(
            isUnlocked: false,
            sessionExpiresAt: nil,
            inactivityTimeoutSeconds: inactivityTimeoutSeconds
        )
    }

    public func remainingSessionTime(at date: Date = Date()) -> TimeInterval? {
        guard isUnlocked, let sessionExpiresAt else {
            return nil
        }

        let remaining = sessionExpiresAt.timeIntervalSince(date)
        guard remaining > 0 else {
            return nil
        }

        return remaining
    }
}

public protocol KeySessionStatusReporting {
    func sessionStatus(at date: Date?) -> KeyHelperStatus
}

public enum HelperRegistrationState: Equatable, Sendable {
    case registered(detail: String)
    case requiresApproval(detail: String)
    case notRegistered(detail: String)
    case unknown(detail: String)

    public var detail: String {
        switch self {
        case let .registered(detail),
             let .requiresApproval(detail),
             let .notRegistered(detail),
             let .unknown(detail):
            return detail
        }
    }
}

public enum ShellCLIMatchState: Equatable, Sendable {
    case missing
    case unreadable
    case mismatch
    case matches
}

public enum ShellCLIResolutionSource: Equatable, Sendable {
    case loginShell
    case homebrewInstall
    case homebrewPrefix

    public var displayString: String {
        switch self {
        case .loginShell:
            return "Login shell"
        case .homebrewInstall:
            return "Homebrew install path"
        case .homebrewPrefix:
            return "Homebrew prefix"
        }
    }

    fileprivate var detectionDescription: String {
        switch self {
        case .loginShell:
            return "your login shell"
        case .homebrewInstall:
            return "a standard Homebrew install path"
        case .homebrewPrefix:
            return "your Homebrew prefix"
        }
    }
}

public struct ShellCLIStatus: Equatable, Sendable {
    public let resolvedPath: String?
    public let resolutionSource: ShellCLIResolutionSource?
    public let version: KeyVersionInfo?
    public let versionErrorDescription: String?

    public init(
        resolvedPath: String?,
        version: KeyVersionInfo?,
        versionErrorDescription: String? = nil,
        resolutionSource: ShellCLIResolutionSource? = nil
    ) {
        self.resolvedPath = resolvedPath
        self.resolutionSource = resolvedPath == nil ? nil : (resolutionSource ?? .loginShell)
        self.version = version
        self.versionErrorDescription = versionErrorDescription
    }

    public func matchState(appVersion: KeyVersionInfo) -> ShellCLIMatchState {
        guard resolvedPath != nil else {
            return .missing
        }
        if versionErrorDescription != nil || version == nil {
            return .unreadable
        }
        return version == appVersion ? .matches : .mismatch
    }

    public var conciseVersionErrorDescription: String? {
        conciseVersionErrorDescription(executableName: "key")
    }

    public func conciseVersionErrorDescription(
        executableName: String
    ) -> String? {
        guard let versionErrorDescription else {
            return nil
        }

        if versionErrorDescription.contains("Unknown command 'version'.") {
            return "The detected CLI does not support `\(executableName) version` yet."
        }

        if versionErrorDescription.contains("Unknown option '--json' for version.") {
            return "The detected CLI does not support `\(executableName) version --json` yet."
        }

        if versionErrorDescription.contains("Usage:") {
            return "The detected CLI returned help text instead of structured version output."
        }

        if versionErrorDescription.hasPrefix("Command failed:") {
            return "The detected CLI version command failed."
        }

        return versionErrorDescription
    }

    public var resolutionSummary: String {
        guard let resolutionSource else {
            return "Not found via login shell or standard Homebrew paths"
        }
        return resolutionSource.displayString
    }
}

public struct KeyDashboardGuidance: Equatable, Sendable, Identifiable {
    public let title: String
    public let detail: String
    public let command: String?

    public init(title: String, detail: String, command: String?) {
        self.title = title
        self.detail = detail
        self.command = command
    }

    public var id: String {
        "\(title)|\(command ?? "")"
    }
}

public struct KeyDashboardHero: Equatable, Sendable {
    public let title: String
    public let detail: String

    public init(title: String, detail: String) {
        self.title = title
        self.detail = detail
    }
}

public struct KeyDashboardCallout: Equatable, Sendable {
    public let title: String
    public let detail: String
    public let guidance: [KeyDashboardGuidance]

    public init(title: String, detail: String, guidance: [KeyDashboardGuidance]) {
        self.title = title
        self.detail = detail
        self.guidance = guidance
    }
}

public struct KeyAppDiagnosticsContext: Equatable, Sendable {
    public let productIdentity: KeyProductIdentity
    public let appVersion: KeyVersionInfo
    public let bundledCLIPath: String
    public let helperAppPath: String
    public let helperExecutablePath: String
    public let launchAgentPlistPath: String
    public let machServiceName: String
    public let configFilePath: String
    public let vaultDirectoryPath: String
    public let vaultLocationSource: String

    public init(
        productIdentity: KeyProductIdentity = .stable,
        appVersion: KeyVersionInfo,
        bundledCLIPath: String,
        helperAppPath: String,
        helperExecutablePath: String,
        launchAgentPlistPath: String,
        machServiceName: String,
        configFilePath: String,
        vaultDirectoryPath: String,
        vaultLocationSource: String
    ) {
        self.productIdentity = productIdentity
        self.appVersion = appVersion
        self.bundledCLIPath = bundledCLIPath
        self.helperAppPath = helperAppPath
        self.helperExecutablePath = helperExecutablePath
        self.launchAgentPlistPath = launchAgentPlistPath
        self.machServiceName = machServiceName
        self.configFilePath = configFilePath
        self.vaultDirectoryPath = vaultDirectoryPath
        self.vaultLocationSource = vaultLocationSource
    }
}

public struct KeyAppDiagnosticsSnapshot: Equatable, Sendable {
    public let registration: HelperRegistrationState
    public let isHelperRunning: Bool
    public let helperStatus: KeyHelperStatus?
    public let helperStatusErrorDescription: String?
    public let shellCLIStatus: ShellCLIStatus
    public let context: KeyAppDiagnosticsContext
    public let generatedAt: Date

    public init(
        registration: HelperRegistrationState,
        isHelperRunning: Bool,
        helperStatus: KeyHelperStatus?,
        helperStatusErrorDescription: String?,
        shellCLIStatus: ShellCLIStatus,
        context: KeyAppDiagnosticsContext,
        generatedAt: Date
    ) {
        self.registration = registration
        self.isHelperRunning = isHelperRunning
        self.helperStatus = helperStatus
        self.helperStatusErrorDescription = helperStatusErrorDescription
        self.shellCLIStatus = shellCLIStatus
        self.context = context
        self.generatedAt = generatedAt
    }

    public var isHelperUnlocked: Bool {
        helperStatus?.isUnlocked == true
    }

    public var hero: KeyDashboardHero {
        let identity = context.productIdentity
        return KeyDashboardHero(
            title: "Welcome to \(identity.appName)",
            detail: "\(identity.appName) is a file-based, CLI-first secret vault for macOS. Your vault encryption key stays in Keychain, key-backed commands unlock with macOS user presence, and \(identity.helperName) briefly reuses that unlocked session in memory while it stays active."
        )
    }

    public var callout: KeyDashboardCallout? {
        switch registration {
        case let .requiresApproval(detail):
            return KeyDashboardCallout(
                title: "Approval required",
                detail: detail,
                guidance: [
                    KeyDashboardGuidance(
                        title: "Allow the helper in System Settings",
                        detail: "Approve \(context.productIdentity.appName) in Login Items & Extensions so launchd can start \(context.productIdentity.helperName) on demand.",
                        command: nil
                    )
                ]
            )
        case let .notRegistered(detail):
            return KeyDashboardCallout(
                title: "Setup is still finishing",
                detail: detail,
                guidance: [
                    KeyDashboardGuidance(
                        title: "Reopen \(context.productIdentity.appName) if setup doesn’t complete",
                        detail: "The app registers the LaunchAgent helper on open.",
                        command: nil
                    )
                ]
            )
        case let .unknown(detail):
            return KeyDashboardCallout(
                title: "Helper status is unavailable",
                detail: detail,
                guidance: []
            )
        case .registered:
            break
        }

        switch shellCLIStatus.matchState(appVersion: context.appVersion) {
        case .missing:
            let identity = context.productIdentity
            return KeyDashboardCallout(
                title: "External CLI not found",
                detail: "\(identity.appName) could not find an external `\(identity.cliExecutableName)` CLI through your login shell or standard Homebrew install locations. You can still use the bundled CLI directly from \(identity.appName).app.",
                guidance: [
                    KeyDashboardGuidance(
                        title: "Use the bundled CLI directly",
                        detail: "Run the app’s bundled CLI until an external `\(identity.cliExecutableName)` install is available again.",
                        command: bundledCLICommand("unlock")
                    )
                ]
            )
        case .unreadable:
            let identity = context.productIdentity
            let path = shellCLIStatus.resolvedPath ?? "the resolved CLI path"
            let detail = shellCLIStatus.conciseVersionErrorDescription(
                executableName: identity.cliExecutableName
            ) ?? "The CLI returned an unreadable version payload."
            let sourceDescription = shellCLIStatus.resolutionSource?.detectionDescription ?? "the detected install location"
            let guidance: [KeyDashboardGuidance]
            if detail.contains("does not support") {
                guidance = [
                    KeyDashboardGuidance(
                        title: "Use the bundled CLI directly",
                        detail: "The external `\(identity.cliExecutableName)` CLI is older than this app. Use the bundled CLI until the external CLI is updated.",
                        command: bundledCLICommand("version")
                    )
                ]
            } else {
                guidance = [
                    KeyDashboardGuidance(
                        title: "Inspect the external CLI",
                        detail: "Run the CLI version command from the same shell environment you expect to use.",
                        command: "\(identity.cliExecutableName) version"
                    )
                ]
            }

            return KeyDashboardCallout(
                title: "CLI version unavailable",
                detail: "\(path) was detected from \(sourceDescription), but version inspection failed: \(detail)",
                guidance: guidance
            )
        case .mismatch:
            let identity = context.productIdentity
            let shellVersion = shellCLIStatus.version?.displayString ?? "unknown"
            let path = shellCLIStatus.resolvedPath ?? "the resolved CLI path"
            let sourceDescription = shellCLIStatus.resolutionSource?.detectionDescription ?? "the detected install location"
            return KeyDashboardCallout(
                title: "CLI version mismatch",
                detail: "\(identity.appName) detected \(path) from \(sourceDescription) at version \(shellVersion), while this app is \(context.appVersion.displayString).",
                guidance: [
                    KeyDashboardGuidance(
                        title: "Inspect the external CLI",
                        detail: "Confirm which `\(identity.cliExecutableName)` binary your shell environment is actually using.",
                        command: "\(identity.cliExecutableName) version"
                    )
                ]
            )
        case .matches:
            break
        }

        if let helperStatusErrorDescription, isHelperRunning {
            return KeyDashboardCallout(
                title: "Helper status is temporarily unavailable",
                detail: helperStatusErrorDescription,
                guidance: [
                    KeyDashboardGuidance(
                        title: "Refresh helper status",
                        detail: "If the helper was shutting down while \(context.productIdentity.appName) checked it, refreshing should settle the dashboard.",
                        command: nil
                    )
                ]
            )
        }

        return nil
    }

    private func bundledCLICommand(_ argument: String) -> String {
        "\"\(context.bundledCLIPath)\" \(argument)"
    }
}

public struct KeyAppDiagnosticsCollector {
    public typealias RegistrationProbe = () -> HelperRegistrationState
    public typealias RunningProbe = () -> Bool
    public typealias HelperStatusProbe = () throws -> KeyHelperStatus
    public typealias ShellCLIProbe = () -> ShellCLIStatus
    public typealias Now = () -> Date

    private let context: KeyAppDiagnosticsContext
    private let registrationProbe: RegistrationProbe
    private let runningProbe: RunningProbe
    private let helperStatusProbe: HelperStatusProbe
    private let shellCLIProbe: ShellCLIProbe
    private let now: Now

    public init(
        context: KeyAppDiagnosticsContext,
        registrationProbe: @escaping RegistrationProbe,
        runningProbe: @escaping RunningProbe,
        helperStatusProbe: @escaping HelperStatusProbe,
        shellCLIProbe: @escaping ShellCLIProbe,
        now: @escaping Now = Date.init
    ) {
        self.context = context
        self.registrationProbe = registrationProbe
        self.runningProbe = runningProbe
        self.helperStatusProbe = helperStatusProbe
        self.shellCLIProbe = shellCLIProbe
        self.now = now
    }

    public func load() -> KeyAppDiagnosticsSnapshot {
        let registration = registrationProbe()
        let isHelperRunning = runningProbe()

        let helperStatus: KeyHelperStatus?
        let helperStatusErrorDescription: String?
        if isHelperRunning {
            do {
                helperStatus = try helperStatusProbe()
                helperStatusErrorDescription = nil
            } catch {
                helperStatus = nil
                helperStatusErrorDescription = error.localizedDescription
            }
        } else {
            helperStatus = nil
            helperStatusErrorDescription = nil
        }

        return KeyAppDiagnosticsSnapshot(
            registration: registration,
            isHelperRunning: isHelperRunning,
            helperStatus: helperStatus,
            helperStatusErrorDescription: helperStatusErrorDescription,
            shellCLIStatus: shellCLIProbe(),
            context: context,
            generatedAt: now()
        )
    }
}
