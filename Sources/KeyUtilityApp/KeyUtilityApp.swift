import AppKit
import Darwin
import KeyCore
import ServiceManagement
import SwiftUI

private let registeredHelperBuildDefaultsKey = "registered-helper-build-version"
private let unregisterPreviewHelperArgument = "--unregister-preview-helper"

@main
struct KeyUtilityApp: App {
    private let configuration: RuntimeConfiguration

    init() {
        let bundle = Bundle.main
        let configuration = RuntimeConfiguration.live(bundle: bundle)
        self.configuration = configuration
        Self.runPreviewMaintenanceCommandIfRequested(configuration: configuration)
        let buildVersion = KeyVersionInfo(bundle: bundle).buildVersion

        Task {
            _ = await HelperRegistrationCoordinator.shared.registrationState(
                for: configuration,
                buildVersion: buildVersion
            )
        }
    }

    private static func runPreviewMaintenanceCommandIfRequested(
        configuration: RuntimeConfiguration
    ) {
        guard Array(CommandLine.arguments.dropFirst()) == [unregisterPreviewHelperArgument] else {
            return
        }
        guard configuration.productIdentity == .preview else {
            fputs("The Preview helper maintenance command is only available in Key Preview.\n", stderr)
            Darwin.exit(EX_USAGE)
        }

        let service = SMAppService.agent(plistName: configuration.launchAgentPlistName)
        do {
            try service.unregister()
        } catch {
            let nsError = error as NSError
            guard nsError.code == kSMErrorJobNotFound else {
                fputs("Unable to unregister the Key Preview helper: \(error.localizedDescription)\n", stderr)
                Darwin.exit(EXIT_FAILURE)
            }
        }

        UserDefaults.standard.removeObject(forKey: registeredHelperBuildDefaultsKey)
        print("Unregistered the Key Preview helper.")
        Darwin.exit(EXIT_SUCCESS)
    }

    var body: some Scene {
        WindowGroup(configuration.productIdentity.appName) {
            ContentView(configuration: configuration)
                .frame(minWidth: 860, minHeight: 680)
        }
        .windowToolbarStyle(.unified(showsTitle: true))
    }
}

@MainActor
private final class DashboardModel: ObservableObject {
    @Published private(set) var snapshot: KeyAppDiagnosticsSnapshot?
    @Published private(set) var isRefreshing = false

    private let configuration: RuntimeConfiguration
    private let context: KeyAppDiagnosticsContext

    init(bundle: Bundle = .main, configuration: RuntimeConfiguration = .live(bundle: .main)) {
        self.configuration = configuration

        let bundleURL = bundle.bundleURL
        let vaultLocation: VaultLocation?
        do {
            vaultLocation = try EntryStore.defaultLocation(
                productIdentity: configuration.productIdentity
            )
        } catch {
            vaultLocation = nil
        }

        self.context = KeyAppDiagnosticsContext(
            productIdentity: configuration.productIdentity,
            appVersion: KeyVersionInfo(bundle: bundle),
            bundledCLIPath: bundleURL.appendingPathComponent(
                "Contents/MacOS/\(configuration.productIdentity.cliExecutableName)"
            ).path,
            helperAppPath: bundleURL.appendingPathComponent(
                "Contents/Helpers/\(configuration.productIdentity.helperName).app"
            ).path,
            helperExecutablePath: bundleURL.appendingPathComponent(
                "Contents/Helpers/\(configuration.productIdentity.helperName).app/Contents/MacOS/\(configuration.productIdentity.helperName)"
            ).path,
            launchAgentPlistPath: bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/\(configuration.launchAgentPlistName)").path,
            machServiceName: configuration.helperMachServiceName,
            configFilePath: vaultLocation?.configFileURL.path ?? "Unavailable",
            vaultDirectoryPath: vaultLocation?.rootURL.path ?? "Unavailable",
            vaultLocationSource: vaultLocation?.pathSource.displayString ?? "Unavailable"
        )
    }

    func refresh() {
        guard !isRefreshing else {
            return
        }

        isRefreshing = true
        let configuration = self.configuration
        let context = self.context

        Task.detached(priority: .userInitiated) {
            let registrationState = await HelperRegistrationCoordinator.shared.registrationState(
                for: configuration,
                buildVersion: context.appVersion.buildVersion
            )
            let snapshot = Self.loadSnapshot(
                configuration: configuration,
                context: context,
                registrationState: registrationState
            )
            await MainActor.run {
                self.snapshot = snapshot
                self.isRefreshing = false
            }
        }
    }

    nonisolated private static func loadSnapshot(
        configuration: RuntimeConfiguration,
        context: KeyAppDiagnosticsContext,
        registrationState: HelperRegistrationState
    ) -> KeyAppDiagnosticsSnapshot {
        let collector = KeyAppDiagnosticsCollector(
            context: context,
            registrationProbe: {
                registrationState
            },
            runningProbe: {
                helperIsRunning(agentLabel: configuration.helperMachServiceName)
            },
            helperStatusProbe: {
                try helperStatus(configuration: configuration)
            },
            shellCLIProbe: {
                shellCLIStatus(
                    executableName: configuration.productIdentity.cliExecutableName
                )
            }
        )

        return collector.load()
    }

    nonisolated private static func helperIsRunning(agentLabel: String) -> Bool {
        let process = Process()
        let stdoutPipe = Pipe()

        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", "gui/\(getuid())/\(agentLabel)"]
        process.standardOutput = stdoutPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return false
        }

        guard process.terminationStatus == 0 else {
            return false
        }

        let output = String(
            decoding: stdoutPipe.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        )

        return output.contains("state = running") || output.contains("job state = running")
    }

    nonisolated private static func helperStatus(configuration: RuntimeConfiguration) throws -> KeyHelperStatus {
        let transport = KeyXPCClientTransport(
            machServiceName: configuration.helperStatusMachServiceName,
            productIdentity: configuration.productIdentity
        )
        let response = try transport.send(.status)

        if response.exitCode != EXIT_SUCCESS {
            throw AppError.service(
                response.errorMessage
                    ?? "\(configuration.productIdentity.helperName) returned an unknown status error."
            )
        }

        guard let helperStatus = response.helperStatus else {
            throw AppError.service(
                "\(configuration.productIdentity.helperName) returned no helper status."
            )
        }

        return helperStatus
    }

    nonisolated private static func shellCLIStatus(
        executableName: String
    ) -> ShellCLIStatus {
        let runner = LoginShellCommandRunner()
        let resolvedCLI = resolvedShellCLI(
            executableName: executableName,
            using: runner
        )

        guard let resolvedCLI else {
            return ShellCLIStatus(resolvedPath: nil, version: nil)
        }

        do {
            let resolvedPath = resolvedCLI.path
            let output = try runner.run("\(shellQuote(resolvedPath)) version --json")
            let data = Data(output.utf8)
            let version = try JSONDecoder().decode(KeyVersionInfo.self, from: data)
            return ShellCLIStatus(
                resolvedPath: resolvedPath,
                version: version,
                resolutionSource: resolvedCLI.source
            )
        } catch {
            return ShellCLIStatus(
                resolvedPath: resolvedCLI.path,
                version: nil,
                versionErrorDescription: error.localizedDescription,
                resolutionSource: resolvedCLI.source
            )
        }
    }

    nonisolated private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    nonisolated private static func resolvedShellCLI(
        executableName: String,
        using runner: LoginShellCommandRunner
    ) -> (path: String, source: ShellCLIResolutionSource)? {
        if let path = resolvedPathFromLoginShell(
            executableName: executableName,
            using: runner
        ) {
            return (path, .loginShell)
        }

        // Finder-launched apps often miss Homebrew PATH setup that only lives in interactive shell init files.
        for candidate in homebrewCLIPathCandidates(
            executableName: executableName
        ) {
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return (
                    candidate,
                    source(
                        forHomebrewCandidate: candidate,
                        executableName: executableName
                    )
                )
            }
        }

        return nil
    }

    nonisolated private static func resolvedPathFromLoginShell(
        executableName: String,
        using runner: LoginShellCommandRunner
    ) -> String? {
        do {
            let output = try runner.run(
                "command -v \(shellQuote(executableName))"
            )
            return output
                .split(whereSeparator: \.isNewline)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .first(where: { $0.hasPrefix("/") && !$0.isEmpty })
        } catch {
            return nil
        }
    }

    nonisolated private static func homebrewCLIPathCandidates(
        executableName: String
    ) -> [String] {
        var candidates = [
            "/opt/homebrew/bin/\(executableName)",
            "/usr/local/bin/\(executableName)"
        ]

        for brewPath in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] {
            guard FileManager.default.isExecutableFile(atPath: brewPath) else {
                continue
            }

            let process = Process()
            let stdoutPipe = Pipe()
            process.executableURL = URL(fileURLWithPath: brewPath)
            process.arguments = ["--prefix"]
            process.standardOutput = stdoutPipe
            process.standardError = Pipe()

            do {
                try process.run()
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    continue
                }

                let output = String(
                    decoding: stdoutPipe.fileHandleForReading.readDataToEndOfFile(),
                    as: UTF8.self
                ).trimmingCharacters(in: .whitespacesAndNewlines)

                if !output.isEmpty {
                    candidates.append("\(output)/bin/\(executableName)")
                }
            } catch {
                continue
            }
        }

        var deduplicated: [String] = []
        for candidate in candidates where !deduplicated.contains(candidate) {
            deduplicated.append(candidate)
        }
        return deduplicated
    }

    nonisolated private static func source(
        forHomebrewCandidate path: String,
        executableName: String
    ) -> ShellCLIResolutionSource {
        if path == "/opt/homebrew/bin/\(executableName)"
            || path == "/usr/local/bin/\(executableName)"
        {
            return .homebrewInstall
        }
        return .homebrewPrefix
    }
}

private actor HelperRegistrationCoordinator {
    static let shared = HelperRegistrationCoordinator()

    func registrationState(
        for configuration: RuntimeConfiguration,
        buildVersion: String
    ) async -> HelperRegistrationState {
        let service = SMAppService.agent(plistName: configuration.launchAgentPlistName)
        let defaults = UserDefaults.standard
        let buildDefaultsKey = registrationBuildDefaultsKey(
            for: configuration
        )
        let registeredBuildVersion = defaults.string(forKey: buildDefaultsKey)

        do {
            switch service.status {
            case .notRegistered, .notFound:
                try service.register()
                defaults.set(buildVersion, forKey: buildDefaultsKey)
            case .enabled where registeredBuildVersion != buildVersion:
                try await unregisterForUpdate(service)
                try service.register()
                defaults.set(buildVersion, forKey: buildDefaultsKey)
            default:
                break
            }
            return helperRegistrationState(
                from: service.status,
                productIdentity: configuration.productIdentity,
                error: nil
            )
        } catch {
            return helperRegistrationState(
                from: service.status,
                productIdentity: configuration.productIdentity,
                error: error
            )
        }
    }

    private func registrationBuildDefaultsKey(
        for configuration: RuntimeConfiguration
    ) -> String {
        guard configuration.qualificationNamespace != nil else {
            return registeredHelperBuildDefaultsKey
        }
        return "\(registeredHelperBuildDefaultsKey).\(configuration.helperMachServiceName)"
    }

    private func unregisterForUpdate(_ service: SMAppService) async throws {
        try await withCheckedThrowingContinuation { continuation in
            service.unregister { error in
                if let error {
                    let nsError = error as NSError
                    if nsError.code == kSMErrorJobNotFound {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: error)
                    }
                } else {
                    continuation.resume()
                }
            }
        }
    }

    private func helperRegistrationState(
        from status: SMAppService.Status,
        productIdentity: KeyProductIdentity,
        error: Error?
    ) -> HelperRegistrationState {
        let message = error?.localizedDescription

        switch status {
        case .enabled:
            return .registered(
                detail: "\(productIdentity.helperName) is registered and can launch on demand through launchd."
            )
        case .requiresApproval:
            let detail = "Allow \(productIdentity.appName) in System Settings > Login Items & Extensions so \(productIdentity.helperName) can launch. \(message ?? "")"
                .trimmingCharacters(in: .whitespaces)
            return .requiresApproval(detail: detail)
        case .notRegistered:
            return .notRegistered(detail: message ?? "The background service has not been set up yet.")
        case .notFound:
            return .notRegistered(detail: message ?? "macOS has not finished setting up the background service.")
        @unknown default:
            return .unknown(detail: message ?? "macOS reported a background-service status Key does not recognize.")
        }
    }
}

private struct ContentView: View {
    @StateObject private var model: DashboardModel
    private let productIdentity: KeyProductIdentity
    @Namespace private var glassNamespace

    init(configuration: RuntimeConfiguration) {
        _model = StateObject(
            wrappedValue: DashboardModel(configuration: configuration)
        )
        productIdentity = configuration.productIdentity
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 28) {
                if let snapshot = model.snapshot {
                    heroSection(snapshot)
                    statusStrip(snapshot)
                    if let callout = snapshot.callout {
                        calloutSection(callout)
                    }
                    detailsSection(snapshot)
                } else {
                    ProgressView("Loading \(productIdentity.appName) status...")
                        .controlSize(.large)
                        .frame(maxWidth: .infinity, minHeight: 320)
                }
            }
            .frame(maxWidth: 960, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.refresh()
                } label: {
                    if model.isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Label("Refresh", systemImage: "arrow.clockwise")
                            .symbolRenderingMode(.monochrome)
                    }
                }
                .disabled(model.isRefreshing)
            }
        }
        .task {
            model.refresh()
        }
    }

    @ViewBuilder
    private func heroSection(_ snapshot: KeyAppDiagnosticsSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 18) {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: 72, height: 72)
                    .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))

                VStack(alignment: .leading, spacing: 10) {
                    Text(productIdentity.appName)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.secondary)

                    Text(snapshot.hero.title)
                        .font(.system(size: 34, weight: .semibold, design: .rounded))
                        .fixedSize(horizontal: false, vertical: true)

                    Text(snapshot.hero.detail)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
        .padding(26)
        .background(heroBackground, in: RoundedRectangle(cornerRadius: 30, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 30, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.06), lineWidth: 1)
        )
    }

    private var heroBackground: some ShapeStyle {
        LinearGradient(
            colors: [
                Color.accentColor.opacity(0.18),
                Color.accentColor.opacity(0.05),
                Color(nsColor: .windowBackgroundColor)
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    @ViewBuilder
    private func guidanceCard(_ item: KeyDashboardGuidance) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(item.title)
                    .font(.headline)
                Spacer()
                if let command = item.command {
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
                }
            }

            Text(item.detail)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let command = item.command {
                Text(command)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
        }
        .padding(16)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    @ViewBuilder
    private func statusStrip(_ snapshot: KeyAppDiagnosticsSnapshot) -> some View {
        let items = statusStripItems(for: snapshot)

        VStack(alignment: .leading, spacing: 14) {
            sectionHeader("Current status", detail: "The background service can be ready while idle. Vault access unlocks separately.")

            GlassEffectContainer(spacing: 12) {
                HStack(spacing: 12) {
                    ForEach(items) { item in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(item.title)
                                .font(.headline)
                                .foregroundStyle(.secondary)

                            HStack(spacing: 10) {
                                Circle()
                                    .fill(item.tint)
                                    .frame(width: 10, height: 10)

                                Text(item.value)
                                    .font(.system(size: 22, weight: .semibold, design: .rounded))
                                    .foregroundStyle(item.tint)
                            }

                            Text(item.detail)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(18)
                        .glassEffect(.regular, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
                        .glassEffectID(item.id, in: glassNamespace)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func calloutSection(_ callout: KeyDashboardCallout) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.circle.fill")
                    .symbolRenderingMode(.monochrome)
                    .foregroundStyle(.orange)
                    .font(.title3)

                VStack(alignment: .leading, spacing: 6) {
                    Text(callout.title)
                        .font(.title3.weight(.semibold))
                    Text(callout.detail)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if !callout.guidance.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(callout.guidance) { item in
                        guidanceCard(item)
                    }
                }
            }
        }
        .padding(22)
        .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .strokeBorder(Color.orange.opacity(0.18), lineWidth: 1)
        )
    }

    @ViewBuilder
    private func detailsSection(_ snapshot: KeyAppDiagnosticsSnapshot) -> some View {
        let rows = detailRows(for: snapshot)

        VStack(alignment: .leading, spacing: 14) {
            sectionHeader(
                "Details",
                detail: "Paths, versions, and runtime identifiers used by \(productIdentity.appName).app."
            )

            VStack(spacing: 0) {
                ForEach(rows) { row in
                    VStack(spacing: 0) {
                        HStack(alignment: .top, spacing: 20) {
                            Text(row.label)
                                .font(.headline)
                                .frame(width: 168, alignment: .leading)

                            VStack(alignment: .leading, spacing: 6) {
                                Text(row.value)
                                    .font(row.monospaced ? .system(.body, design: .monospaced) : .body)
                                    .textSelection(.enabled)

                                if let detail = row.detail {
                                    Text(detail)
                                        .font(.subheadline)
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }

                            Spacer(minLength: 0)
                        }
                        .padding(.horizontal, 18)
                        .padding(.vertical, 16)

                        if row.id != rows.last?.id {
                            Divider()
                                .padding(.leading, 18)
                        }
                    }
                }
            }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        }
    }

    @ViewBuilder
    private func sectionHeader(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.title3.weight(.semibold))
            Text(detail)
                .foregroundStyle(.secondary)
        }
    }

    private func statusStripItems(for snapshot: KeyAppDiagnosticsSnapshot) -> [StatusStripItem] {
        let registrationItem: StatusStripItem
        switch snapshot.registration {
        case .registered:
            registrationItem = StatusStripItem(
                id: "registered",
                title: "Background service",
                value: "Ready",
                detail: "macOS can start \(productIdentity.helperName) when needed.",
                tint: .green
            )
        case .requiresApproval:
            registrationItem = StatusStripItem(
                id: "registered",
                title: "Background service",
                value: "Approval",
                detail: "Allow the background service in System Settings.",
                tint: .orange
            )
        case .notRegistered, .unknown:
            registrationItem = StatusStripItem(
                id: "registered",
                title: "Background service",
                value: "Not ready",
                detail: "Open the app again to set up its background service.",
                tint: .red
            )
        }

        let runningItem = StatusStripItem(
            id: "running",
            title: "Service activity",
            value: snapshot.isHelperRunning ? "Running" : "Idle",
            detail: snapshot.isHelperRunning
                ? "The background service is running."
                : "The background service starts when a command needs it.",
            tint: snapshot.isHelperRunning ? .green : .secondary
        )

        let unlockedItem: StatusStripItem
            if let helperStatus = snapshot.helperStatus, helperStatus.isUnlocked {
                let detail: String
                if let remaining = helperStatus.remainingSessionTime(at: snapshot.generatedAt) {
                    let minutes = Int(ceil(remaining / 60))
                    detail = minutes == 1
                        ? "Locks in about 1 minute if unused."
                        : "Locks in about \(minutes) minutes if unused."
                } else {
                    detail = "Vault access is unlocked for this session."
                }
            unlockedItem = StatusStripItem(
                id: "unlocked",
                title: "Vault access",
                value: "Unlocked",
                detail: detail,
                tint: .green
            )
        } else if snapshot.helperStatusErrorDescription != nil {
            unlockedItem = StatusStripItem(
                id: "unlocked",
                title: "Vault access",
                value: "Unknown",
                detail: "Key could not check whether vault access is unlocked.",
                tint: .orange
            )
        } else {
            unlockedItem = StatusStripItem(
                id: "unlocked",
                title: "Vault access",
                value: "Locked",
                detail: "The next command that needs the vault key will ask you to authenticate.",
                tint: .secondary
            )
        }

        return [registrationItem, runningItem, unlockedItem]
    }

    private func detailRows(for snapshot: KeyAppDiagnosticsSnapshot) -> [DetailRow] {
        [
            DetailRow(id: "app-version", label: "App Version", value: snapshot.context.appVersion.displayString, detail: nil, monospaced: false),
            DetailRow(
                id: "external-version",
                label: "CLI Version",
                value: snapshot.shellCLIStatus.version?.displayString ?? "Not available",
                detail: "Source: \(snapshot.shellCLIStatus.resolutionSummary)",
                monospaced: false
            ),
            DetailRow(
                id: "external-path",
                label: "CLI Path",
                value: snapshot.shellCLIStatus.resolvedPath ?? "Not found",
                detail: snapshot.shellCLIStatus.resolvedPath == nil
                    ? "Checked your login shell and standard Homebrew install locations."
                    : "Source: \(snapshot.shellCLIStatus.resolutionSummary)",
                monospaced: true
            ),
            DetailRow(id: "bundled-cli", label: "Bundled CLI", value: snapshot.context.bundledCLIPath, detail: nil, monospaced: true),
            DetailRow(id: "config-file", label: "Config File", value: snapshot.context.configFilePath, detail: nil, monospaced: true),
            DetailRow(
                id: "vault-directory",
                label: "Vault Directory",
                value: snapshot.context.vaultDirectoryPath,
                detail: "Source: \(snapshot.context.vaultLocationSource)",
                monospaced: true
            ),
            DetailRow(id: "helper-app", label: "Helper App", value: snapshot.context.helperAppPath, detail: nil, monospaced: true),
            DetailRow(id: "helper-executable", label: "Helper Executable", value: snapshot.context.helperExecutablePath, detail: nil, monospaced: true),
            DetailRow(id: "launch-agent-plist", label: "LaunchAgent", value: snapshot.context.launchAgentPlistPath, detail: nil, monospaced: true),
            DetailRow(id: "mach-service", label: "Mach Service", value: snapshot.context.machServiceName, detail: nil, monospaced: true)
        ]
    }
}

private struct LoginShellCommandRunner {
    func run(_ command: String) throws -> String {
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: Self.loginShellPath())
        process.arguments = ["-lc", command]
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()
        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        let stdout = String(decoding: stdoutData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let stderr = String(decoding: stderrData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)

        guard process.terminationStatus == 0 else {
            throw AppError.service(stderr.isEmpty ? "Command failed: \(command)" : stderr)
        }

        return stdout
    }

    private static func loginShellPath() -> String {
        guard let shellPointer = getpwuid(getuid())?.pointee.pw_shell else {
            return "/bin/zsh"
        }
        return String(cString: shellPointer)
    }
}

private struct StatusStripItem: Identifiable {
    let id: String
    let title: String
    let value: String
    let detail: String
    let tint: Color
}

private struct DetailRow: Identifiable {
    let id: String
    let label: String
    let value: String
    let detail: String?
    let monospaced: Bool
}
