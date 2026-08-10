import Foundation
import KeyCore

let configuration = RuntimeConfiguration.live()
let transport = KeyXPCClientTransport(
    machServiceName: configuration.helperMachServiceName,
    productIdentity: configuration.productIdentity
)
let app = KeyCLIApplication(
    transport: transport,
    io: SystemIO(),
    clipboard: SystemClipboardWriter(),
    configStore: KeyConfigStore(
        productIdentity: configuration.productIdentity
    )
)
exit(app.run(arguments: Array(CommandLine.arguments.dropFirst())))
