import KeyCore
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

    init(configuration: RuntimeConfiguration) {
        self.configuration = configuration
    }

    func refresh() {
        let service = SMAppService.agent(plistName: configuration.launchAgentPlistName)

        do {
            if service.status == .notRegistered {
                try service.register()
            }
            updateStatus(from: service.status, error: nil)
        } catch {
            updateStatus(from: service.status, error: error)
        }
    }

    private func updateStatus(from status: SMAppService.Status, error: Error?) {
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
            statusTitle = "LaunchAgent helper assets were not found."
            statusDetail = error?.localizedDescription ?? "The bundled LaunchAgent plist or helper executable is missing."
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
    private let helperPath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/Library/Helpers/KeyLaunchAgentHelper")
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
                labeledValue("Helper Executable", helperPath)
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
