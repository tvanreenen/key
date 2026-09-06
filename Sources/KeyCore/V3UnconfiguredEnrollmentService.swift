import Foundation

/// Joins an existing folder without composing or selecting a legacy vault.
/// The service host serializes every call against init and configured work.
struct V3UnconfiguredEnrollmentService {
    let configStore: KeyConfigStore
    let exchange: (VaultRootDirectoryHandle) -> V3EnrollmentExchangeCoordinator
    let perform: (
        VaultRootDirectoryHandle,
        KeyShareRequest,
        @escaping (String) throws -> Void
    ) throws -> KeyServiceResponse
    var now: () -> Date = Date.init

    func handle(_ request: KeyShareRequest, path: String) throws -> KeyServiceResponse {
        guard request.supportsDirectorySelection,
              path.hasPrefix("/"), !path.utf8.contains(0)
        else {
            throw AppError.operationRefused("Key needs an existing vault folder for this joining step. Use `key help share` for instructions.")
        }
        try configStore.requireUnconfigured()
        let root = try VaultRootDirectoryHandle(opening: URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL)
        if request == .invitations {
            return .success(try exchange(root).renderedInvitations())
        }

        let digest: Data
        let vaultID: String
        let create: Bool
        switch request {
        case let .join(invitationID, _):
            digest = try enrollmentDigest(invitationID)
            let invitation = try exchange(root).receiveInvitation(
                digest: digest, at: UInt64(max(0, now().timeIntervalSince1970))
            )
            vaultID = invitation.invitation.vaultID
            create = true
        case let .compare(id, invitationID, requestID):
            guard requestID == nil else {
                throw AppError.operationRefused("Compare a request ID on the Mac that created the invitation, not the joining Mac.")
            }
            digest = try enrollmentDigest(invitationID)
            vaultID = id
            create = false
        case let .accept(id, invitationID, _):
            digest = try enrollmentDigest(invitationID)
            vaultID = id
            create = false
        default:
            throw AppError.operationRefused("This command requires an existing vault configuration.")
        }
        let select = try configStore.prepareEnrollmentSelection(
            rootHandle: root, invitationDigest: digest, vaultID: vaultID, create: create
        )
        try root.requireConfiguredRootIdentity()
        let response = try perform(root, request, select)
        guard response.exitCode == EXIT_SUCCESS else { return response }
        if case .accept = request {
            let selected = try configStore.configuredVaultRuntimeSelection()
            guard selected.vaultID == vaultID,
                  selected.rootURL.standardizedFileURL == root.rootURL.standardizedFileURL
            else {
                throw AppError.operationRefused("Key could not confirm that this Mac is configured to use the approved vault. Leave this attempt intact for investigation.")
            }
            try root.requireConfiguredRootIdentity()
            return .success((response.value ?? "") + "Key will use the existing vault at '\(root.rootURL.path)'. Run `key status`.\n")
        }
        return .success((response.value ?? "") + "This Mac is not configured to use the vault yet. Continue from this folder, or pass --vault-dir with this same folder.\n")
    }

    static func live(
        configStore: KeyConfigStore,
        keyStore: any VaultKeyStoring,
        runtimeConfiguration: RuntimeConfiguration
    ) -> Self {
        Self(configStore: configStore, exchange: { root in
            V3EnrollmentExchangeCoordinator(
                mailbox: V3FilesystemEnrollmentMailbox(rootHandle: root),
                stateStore: V3EnrollmentCeremonyStateKeychainStore(configuration: runtimeConfiguration)
            )
        }, perform: { root, request, select in
            let session = V3DeviceWrappedVaultKeySessionStore()
            defer { session.invalidate() }
            let configuration = KeyConfiguration(
                configFileURL: configStore.initializationConfigFileURL,
                vaultDirectoryURL: root.rootURL,
                vaultPathSource: .appSupportConfigCustom,
                keychainMode: .local
            )
            let enrollment = try makeLiveV3EnrollmentWorkflowService(
                rootHandle: root, selectedVaultID: nil, keyStore: keyStore,
                keyConfiguration: configuration, configStore: configStore,
                runtimeConfiguration: runtimeConfiguration,
                unconfiguredSelection: select,
                deviceWrappedSession: session
            )
            // This handler is scoped to one admitted share request. It is never
            // retained as an unconfigured runtime for ordinary vault commands.
            return KeyServiceHandler(
                keyStore: keyStore, entryStore: EntryStore(rootURL: root.rootURL),
                mutationOwner: VaultTransactionMutationOwner(),
                enrollmentService: enrollment
            ).handle(.share(request))
        })
    }
}
