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

private struct ContentView: View {
    private let cliPath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/MacOS/key")
        .path
    private let servicePath = Bundle.main.bundleURL
        .appendingPathComponent("Contents/XPCServices/KeyXPCService.xpc")
        .path
    private let xpcIdentifier = Bundle.main.object(forInfoDictionaryKey: "XPCServiceIdentifier") as? String ?? "Not configured"
    private let accessGroup = Bundle.main.object(forInfoDictionaryKey: "KeychainAccessGroup") as? String ?? "Not configured"
    private let service = Bundle.main.object(forInfoDictionaryKey: "VaultKeyService") as? String ?? "Not configured"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Key")
                .font(.system(size: 28, weight: .semibold))

            Text("This app hosts the bundled CLI client and on-demand XPC service.")
                .foregroundStyle(.secondary)

            Group {
                labeledValue("CLI Path", cliPath)
                labeledValue("XPC Service", servicePath)
                labeledValue("XPC Identifier", xpcIdentifier)
                labeledValue("Shared Access Group", accessGroup)
                labeledValue("Vault Service", service)
                labeledValue("Vault Directory", "~/Library/Application Support/key/vault")
            }

            Text("If installed through Homebrew Cask, the `key` command should already be symlinked into your PATH and will talk to the bundled XPC service on demand.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Spacer()
        }
        .padding(24)
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
