import KeyCore
import OSLog
import ServiceManagement
import SwiftUI

@main
struct KeyUtilityApp: App {
    var body: some Scene {
        WindowGroup("Key") {
            ContentView()
                .frame(minWidth: 520, minHeight: 320)
        }
    }
}

@MainActor
private final class HelperRegistrationModel: ObservableObject {
    @Published private(set) var statusTitle = "Checking helper registration..."
    @Published private(set) var statusDetail = "The app will register the on-demand LaunchAgent helper on first launch."

    private let configuration: RuntimeConfiguration
    private let logger = Logger(subsystem: "work.tvr.key.app", category: "helper-registration")

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func refresh() {
        let service = SMAppService.agent(plistName: configuration.launchAgentPlistName)
        logger.notice("Checking helper registration for plist \(self.configuration.launchAgentPlistName, privacy: .public); current status = \(String(describing: service.status), privacy: .public)")

        do {
            switch service.status {
            case .notRegistered, .notFound:
                logger.notice("Registering helper service for \(self.configuration.launchAgentPlistName, privacy: .public)")
                try service.register()
                logger.notice("Helper registration returned successfully")
            default:
                break
            }
            updateStatus(from: service.status, error: nil)
        } catch {
            logger.error("Helper registration failed with status \(String(describing: service.status), privacy: .public): \(error.localizedDescription, privacy: .public)")
            updateStatus(from: service.status, error: error)
        }
    }

    private func updateStatus(from status: SMAppService.Status, error: Error?) {
        logger.notice("Helper status update: \(String(describing: status), privacy: .public); error = \(error?.localizedDescription ?? "none", privacy: .public)")
        switch status {
        case .enabled:
            statusTitle = "LaunchAgent helper is registered."
            statusDetail = "The helper will launch on demand through launchd and exit after it has been idle."
        case .requiresApproval:
            statusTitle = "LaunchAgent helper needs approval."
            statusDetail = "Allow Key in System Settings > Login Items & Extensions so the helper can launch. \(error.map { $0.localizedDescription } ?? "")".trimmingCharacters(in: .whitespaces)
        case .notRegistered:
            statusTitle = "LaunchAgent helper is not registered."
            statusDetail = error?.localizedDescription ?? "Open the app again to retry registration."
        case .notFound:
            statusTitle = "LaunchAgent helper is not registered."
            statusDetail = error?.localizedDescription ?? "The system has not recorded the helper yet. Open the app again to retry registration."
        @unknown default:
            statusTitle = "LaunchAgent helper status is unknown."
            statusDetail = error?.localizedDescription ?? "ServiceManagement returned an unrecognized status."
        }
    }
}

private struct ContentView: View {
    @StateObject private var registrationModel = HelperRegistrationModel(configuration: .live(bundle: .main))

    private let configuration = RuntimeConfiguration.live(bundle: .main)
    private let cliPath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/MacOS/key")
        .path
    private let helperAppPath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Helpers/Key Agent.app")
        .path
    private let helperExecutablePath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Helpers/Key Agent.app/Contents/MacOS/Key Agent")
        .path
    private let launchAgentPlistPath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Library/LaunchAgents/work.tvr.key.agent.plist")
        .path
    private let accessGroup = Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String ?? "Not configured"
    private let service = Bundle.main.object(forInfoDictionaryKey: "VaultKeyService") as? String ?? "Not configured"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Key")
                .font(.system(size: 28, weight: .semibold))

            Text("This app registers and monitors the on-demand LaunchAgent helper used by the CLI.")
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 6) {
                Text(registrationModel.statusTitle)
                    .font(.headline)
                Text(registrationModel.statusDetail)
                    .foregroundStyle(.secondary)
            }

            Group {
                labeledValue("CLI Path", cliPath)
                labeledValue("Helper App", helperAppPath)
                labeledValue("Helper Executable", helperExecutablePath)
                labeledValue("LaunchAgent Plist", launchAgentPlistPath)
                labeledValue("Mach Service", configuration.helperMachServiceName)
                labeledValue("LaunchAgent Name", configuration.launchAgentPlistName)
                labeledValue("Shared Access Group", accessGroup)
                labeledValue("Vault Service", service)
                labeledValue("Vault Directory", "~/Library/Application Support/key/vault")
            }

            Text("The bundled `key` command talks to the helper over XPC using a Mach service managed by launchd.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Spacer()
        }
        .padding(24)
        .task {
            registrationModel.refresh()
        }
    }

    @ViewBuilder
    private func labeledValue(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.headline)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}
