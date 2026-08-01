import Foundation

enum V3EnrollmentMailboxError: Error, Equatable, LocalizedError {
    case invalidDigest
    case invalidMessage
    case digestMismatch
    case invalidLimit

    var errorDescription: String? {
        switch self {
        case .invalidDigest:
            "A version 3 enrollment mailbox digest is invalid."
        case .invalidMessage:
            "A version 3 enrollment mailbox message is invalid."
        case .digestMismatch:
            "A version 3 enrollment mailbox message does not match its digest path."
        case .invalidLimit:
            "A version 3 enrollment mailbox listing limit is invalid."
        }
    }
}

enum V3EnrollmentMailboxListing: Equatable, Sendable {
    case available(digests: [Data], objectCount: Int)
    case unavailable
    case invalid
    case limitExceeded
}

protocol V3EnrollmentMailboxStoring: Sendable {
    func invitationDigests(
        maximumCount: Int
    ) throws -> V3EnrollmentMailboxListing

    func readInvitation(
        digest: Data
    ) throws -> V3RepositoryObjectRead

    func publishInvitation(_ canonicalBytes: Data) throws

    func joinRequestDigests(
        invitationDigest: Data,
        maximumCount: Int
    ) throws -> V3EnrollmentMailboxListing

    func readJoinRequest(
        invitationDigest: Data,
        joinRequestDigest: Data
    ) throws -> V3RepositoryObjectRead

    func publishJoinRequest(
        _ canonicalBytes: Data,
        invitationDigest: Data
    ) throws
}

/// Provider-neutral storage for immutable enrollment message carriers.
///
/// Paths are derived only from authenticated payload digests. File-provider
/// timestamps, versions, conflict labels, and delivery order grant no trust.
struct V3FilesystemEnrollmentMailbox:
    V3EnrollmentMailboxStoring,
    Sendable
{
    static let maximumListingCount = 4_096

    private let rootHandle: VaultRootDirectoryHandle
    private let writer: V3AtomicStagedObjectWriter

    init(rootHandle: VaultRootDirectoryHandle) {
        self.rootHandle = rootHandle
        writer = V3AtomicStagedObjectWriter(rootHandle: rootHandle)
    }

    func invitationDigests(
        maximumCount: Int
    ) throws -> V3EnrollmentMailboxListing {
        try listDigests(
            at: ".enrollment/invitations",
            maximumCount: maximumCount
        )
    }

    func readInvitation(
        digest: Data
    ) throws -> V3RepositoryObjectRead {
        guard digest.count == 32 else {
            throw V3EnrollmentMailboxError.invalidDigest
        }
        return try readMessage(
            at: invitationPath(digest: digest),
            maximumBytes: V3SignedEnrollmentInvitation.maximumBytes
        )
    }

    func publishInvitation(_ canonicalBytes: Data) throws {
        let signed: V3SignedEnrollmentInvitation
        do {
            signed = try V3SignedEnrollmentInvitation(
                canonicalBytes: canonicalBytes
            )
        } catch {
            throw V3EnrollmentMailboxError.invalidMessage
        }
        try writer.install(
            canonicalBytes,
            at: invitationPath(digest: signed.invitation.digest)
        )
    }

    func joinRequestDigests(
        invitationDigest: Data,
        maximumCount: Int
    ) throws -> V3EnrollmentMailboxListing {
        guard invitationDigest.count == 32 else {
            throw V3EnrollmentMailboxError.invalidDigest
        }
        return try listDigests(
            at: joinRequestDirectory(
                invitationDigest: invitationDigest
            ),
            maximumCount: maximumCount
        )
    }

    func readJoinRequest(
        invitationDigest: Data,
        joinRequestDigest: Data
    ) throws -> V3RepositoryObjectRead {
        guard invitationDigest.count == 32,
            joinRequestDigest.count == 32
        else {
            throw V3EnrollmentMailboxError.invalidDigest
        }
        return try readMessage(
            at: joinRequestPath(
                invitationDigest: invitationDigest,
                joinRequestDigest: joinRequestDigest
            ),
            maximumBytes: V3SignedEnrollmentJoinRequest.maximumBytes
        )
    }

    func publishJoinRequest(
        _ canonicalBytes: Data,
        invitationDigest: Data
    ) throws {
        guard invitationDigest.count == 32 else {
            throw V3EnrollmentMailboxError.invalidDigest
        }
        let signed: V3SignedEnrollmentJoinRequest
        do {
            signed = try V3SignedEnrollmentJoinRequest(
                canonicalBytes: canonicalBytes
            )
        } catch {
            throw V3EnrollmentMailboxError.invalidMessage
        }
        guard signed.joinRequest.invitationDigest == invitationDigest else {
            throw V3EnrollmentMailboxError.digestMismatch
        }
        try writer.install(
            canonicalBytes,
            at: joinRequestPath(
                invitationDigest: invitationDigest,
                joinRequestDigest: signed.joinRequest.digest
            )
        )
    }

    private func listDigests(
        at path: String,
        maximumCount: Int
    ) throws -> V3EnrollmentMailboxListing {
        guard maximumCount > 0,
            maximumCount <= Self.maximumListingCount
        else {
            throw V3EnrollmentMailboxError.invalidLimit
        }
        do {
            return try rootHandle.withResolvedDescriptor(
                at: path,
                expecting: .directory
            ) { descriptor in
                switch directoryEntryNames(
                    descriptor: descriptor.rawValue,
                    maximumCount: maximumCount
                ) {
                case .names(let names, let objectCount):
                    return .available(
                        digests: names.compactMap(
                            v3Digest(fromJSONFilename:)
                        ).sorted(by: { $0.lexicographicallyPrecedes($1) }),
                        objectCount: objectCount
                    )
                case .limitExceeded:
                    return .limitExceeded
                case .invalid:
                    return .invalid
                }
            }
        } catch let error as VaultRootDirectoryHandleError {
            throw error
        } catch VaultPathResolutionError.notFound,
            VaultPathResolutionError.providerPlaceholder
        {
            return .unavailable
        } catch {
            return .invalid
        }
    }

    private func readMessage(
        at path: String,
        maximumBytes: Int
    ) throws -> V3RepositoryObjectRead {
        do {
            return try rootHandle.withResolvedDescriptor(
                at: path,
                expecting: .regularFile
            ) { descriptor in
                readObjectData(
                    descriptor: descriptor.rawValue,
                    maximumBytes: maximumBytes
                )
            }
        } catch let error as VaultRootDirectoryHandleError {
            throw error
        } catch VaultPathResolutionError.notFound,
            VaultPathResolutionError.providerPlaceholder
        {
            return .unavailable
        } catch {
            return .invalid
        }
    }
}

private func invitationPath(digest: Data) -> String {
    ".enrollment/invitations/\(v3LowercaseHex(digest)).json"
}

private func joinRequestDirectory(invitationDigest: Data) -> String {
    ".enrollment/join-requests/\(v3LowercaseHex(invitationDigest))"
}

private func joinRequestPath(
    invitationDigest: Data,
    joinRequestDigest: Data
) -> String {
    "\(joinRequestDirectory(invitationDigest: invitationDigest))/\(v3LowercaseHex(joinRequestDigest)).json"
}
