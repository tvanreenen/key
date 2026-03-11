import Foundation
import KeyCore

let configuration = RuntimeConfiguration.live()
let transport = KeyXPCClientTransport(serviceName: configuration.xpcServiceIdentifier)
let app = KeyCLIApplication(
    transport: transport,
    io: SystemIO(),
    clipboard: SystemClipboardWriter()
)
exit(app.run(arguments: Array(CommandLine.arguments.dropFirst())))
