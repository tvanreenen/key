import Foundation
import KeyCore

let configuration = RuntimeConfiguration.live()
let transport = KeyXPCClientTransport(machServiceName: configuration.helperMachServiceName)
let app = KeyCLIApplication(
    transport: transport,
    io: SystemIO(),
    clipboard: SystemClipboardWriter()
)
exit(app.run(arguments: Array(CommandLine.arguments.dropFirst())))
