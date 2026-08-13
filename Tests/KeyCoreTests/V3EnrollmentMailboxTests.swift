import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3EnrollmentMailboxTests {
    fileprivate static let vaultID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"

    @Test
    func publishesReadsAndListsExactImmutableMessages() throws {
        let root = try enrollmentMailboxTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try EnrollmentMailboxFixture()
        let mailbox = V3FilesystemEnrollmentMailbox(
            rootHandle: try VaultRootDirectoryHandle(opening: root)
        )

        try mailbox.publishInvitation(
            fixture.signedInvitation.canonicalBytes
        )
        try mailbox.publishInvitation(
            fixture.signedInvitation.canonicalBytes
        )
        try mailbox.publishJoinRequest(
            fixture.signedJoinRequest.canonicalBytes,
            invitationDigest: fixture.invitation.digest
        )

        guard
            case .available(let invitationBytes) = try mailbox.readInvitation(
                digest: fixture.invitation.digest
            )
        else {
            Issue.record("Published invitation was not readable.")
            return
        }
        #expect(invitationBytes == fixture.signedInvitation.canonicalBytes)

        guard
            case .available(let joinBytes) = try mailbox.readJoinRequest(
                invitationDigest: fixture.invitation.digest,
                joinRequestDigest: fixture.joinRequest.digest
            )
        else {
            Issue.record("Published join request was not readable.")
            return
        }
        #expect(joinBytes == fixture.signedJoinRequest.canonicalBytes)

        #expect(
            try mailbox.invitationDigests(maximumCount: 10)
                == .available(
                    digests: [fixture.invitation.digest],
                    objectCount: 1
                )
        )
        #expect(
            try mailbox.joinRequestDigests(
                invitationDigest: fixture.invitation.digest,
                maximumCount: 10
            )
                == .available(
                    digests: [fixture.joinRequest.digest],
                    objectCount: 1
                )
        )
    }

    @Test
    func existingDigestPathCannotBeReplacedWithDifferentBytes() throws {
        let root = try enrollmentMailboxTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try EnrollmentMailboxFixture()
        let mailbox = V3FilesystemEnrollmentMailbox(
            rootHandle: try VaultRootDirectoryHandle(opening: root)
        )
        try mailbox.publishInvitation(
            fixture.signedInvitation.canonicalBytes
        )
        let path =
            root
            .appendingPathComponent(".enrollment/invitations")
            .appendingPathComponent(
                "\(v3LowercaseHex(fixture.invitation.digest)).json"
            )
        try Data("substituted".utf8).write(to: path)

        #expect(
            throws: V3ImmutableObjectPublicationError.conflictingObject(
                path:
                    ".enrollment/invitations/\(v3LowercaseHex(fixture.invitation.digest)).json"
            )
        ) {
            try mailbox.publishInvitation(
                fixture.signedInvitation.canonicalBytes
            )
        }
        #expect(try Data(contentsOf: path) == Data("substituted".utf8))
    }

    @Test
    func listingCountsEveryProviderEntryBeforeFilteringNames() throws {
        let root = try enrollmentMailboxTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let invitations =
            root
            .appendingPathComponent(".enrollment", isDirectory: true)
            .appendingPathComponent("invitations", isDirectory: true)
        try FileManager.default.createDirectory(
            at: invitations,
            withIntermediateDirectories: true
        )
        try Data().write(
            to: invitations.appendingPathComponent("provider-metadata")
        )
        try Data().write(
            to: invitations.appendingPathComponent("another-invalid-name")
        )
        let mailbox = V3FilesystemEnrollmentMailbox(
            rootHandle: try VaultRootDirectoryHandle(opening: root)
        )

        #expect(
            try mailbox.invitationDigests(maximumCount: 1)
                == .limitExceeded
        )
        #expect(
            try mailbox.invitationDigests(maximumCount: 2)
                == .available(digests: [], objectCount: 2)
        )
    }

    @Test
    func unavailableInvalidOversizedAndChangedRootsFailSafely() throws {
        let parent = try enrollmentMailboxTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }
        let root = parent.appendingPathComponent("vault", isDirectory: true)
        let moved = parent.appendingPathComponent("moved", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        let fixture = try EnrollmentMailboxFixture()
        let rootHandle = try VaultRootDirectoryHandle(opening: root)
        let mailbox = V3FilesystemEnrollmentMailbox(rootHandle: rootHandle)

        guard
            case .unavailable = try mailbox.readInvitation(
                digest: fixture.invitation.digest
            )
        else {
            Issue.record("Missing invitation was not unavailable.")
            return
        }

        let invitationDirectory =
            root
            .appendingPathComponent(".enrollment/invitations", isDirectory: true)
        try FileManager.default.createDirectory(
            at: invitationDirectory,
            withIntermediateDirectories: true
        )
        let invitationPath = invitationDirectory.appendingPathComponent(
            "\(v3LowercaseHex(fixture.invitation.digest)).json"
        )
        try Data(
            repeating: 0x41,
            count: V3SignedEnrollmentInvitation.maximumBytes + 1
        ).write(to: invitationPath)
        guard
            case .tooLarge = try mailbox.readInvitation(
                digest: fixture.invitation.digest
            )
        else {
            Issue.record("Oversized invitation did not retain its classification.")
            return
        }

        try FileManager.default.removeItem(at: invitationPath)
        try FileManager.default.createSymbolicLink(
            at: invitationPath,
            withDestinationURL: root
        )
        guard
            case .invalid = try mailbox.readInvitation(
                digest: fixture.invitation.digest
            )
        else {
            Issue.record("Symbolic-link invitation was not invalid.")
            return
        }

        try FileManager.default.moveItem(at: root, to: moved)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        #expect(
            throws: VaultRootDirectoryHandleError.configuredRootChanged(
                path: root.path()
            )
        ) {
            try mailbox.invitationDigests(maximumCount: 10)
        }
    }

    @Test
    func publicationRejectsMalformedAndMisdirectedMessages() throws {
        let root = try enrollmentMailboxTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = try EnrollmentMailboxFixture()
        let mailbox = V3FilesystemEnrollmentMailbox(
            rootHandle: try VaultRootDirectoryHandle(opening: root)
        )

        #expect(throws: V3EnrollmentMailboxError.invalidMessage) {
            try mailbox.publishInvitation(Data("invalid".utf8))
        }
        #expect(throws: V3EnrollmentMailboxError.digestMismatch) {
            try mailbox.publishJoinRequest(
                fixture.signedJoinRequest.canonicalBytes,
                invitationDigest: Data(repeating: 0xE1, count: 32)
            )
        }
        #expect(throws: V3EnrollmentMailboxError.invalidLimit) {
            try mailbox.invitationDigests(maximumCount: 0)
        }
    }
}

private struct EnrollmentMailboxFixture {
    let invitation: V3EnrollmentInvitation
    let signedInvitation: V3SignedEnrollmentInvitation
    let joinRequest: V3EnrollmentJoinRequest
    let signedJoinRequest: V3SignedEnrollmentJoinRequest

    init() throws {
        let inviter = try EnrollmentMailboxSoftwareSigner(
            vaultID: V3EnrollmentMailboxTests.vaultID,
            displayName: "Office Mac",
            signingScalar: 1,
            wrappingScalar: 2
        )
        let joiner = try EnrollmentMailboxSoftwareSigner(
            vaultID: V3EnrollmentMailboxTests.vaultID,
            displayName: "Travel Mac",
            signingScalar: 3,
            wrappingScalar: 4
        )
        invitation = try V3EnrollmentInvitation(
            vaultID: V3EnrollmentMailboxTests.vaultID,
            parentManifestDigest: Data(repeating: 0x91, count: 32),
            invitingDevice: inviter.publicIdentity,
            nonce: Data(repeating: 0xA1, count: 32),
            expiresAt: 1_900_000_000
        )
        let authenticator = V3EnrollmentMessageAuthenticator()
        signedInvitation = try authenticator.sign(
            invitation,
            using: inviter,
            reason: "Approve invitation"
        )
        let verifiedInvitation = try authenticator.verify(signedInvitation)
        joinRequest = try V3EnrollmentJoinRequest(
            invitationDigest: invitation.digest,
            joiningDevice: joiner.publicIdentity,
            nonce: Data(repeating: 0xB1, count: 32)
        )
        signedJoinRequest = try authenticator.sign(
            joinRequest,
            answering: verifiedInvitation,
            using: joiner,
            reason: "Approve join request"
        )
    }
}

private struct EnrollmentMailboxSoftwareSigner:
    V3EnrollmentMessageSigning,
    Sendable
{
    let vaultID: String
    let publicIdentity: V3EnrollmentDeviceIdentity
    let privateKey: P256.Signing.PrivateKey

    init(
        vaultID: String,
        displayName: String,
        signingScalar: UInt8,
        wrappingScalar: UInt8
    ) throws {
        self.vaultID = vaultID
        privateKey = try P256.Signing.PrivateKey(
            rawRepresentation: enrollmentMailboxPrivateKeyBytes(
                signingScalar
            )
        )
        let wrappingKey = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: enrollmentMailboxPrivateKeyBytes(
                wrappingScalar
            )
        )
        publicIdentity = try V3EnrollmentDeviceIdentity(
            displayName: displayName,
            signingPublicKey: privateKey.publicKey.x963Representation,
            wrappingPublicKey: wrappingKey.publicKey.x963Representation
        )
    }

    func signature(for input: Data, reason _: String) throws -> Data {
        try privateKey.signature(for: input).rawRepresentation
    }
}

private func enrollmentMailboxPrivateKeyBytes(_ scalar: UInt8) -> Data {
    var bytes = Data(repeating: 0, count: 32)
    bytes[31] = scalar
    return bytes
}

private func enrollmentMailboxTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: url,
        withIntermediateDirectories: false
    )
    return url
}
