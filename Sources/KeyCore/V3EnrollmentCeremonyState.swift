import Foundation
internal import JSONCanonicalization

enum V3EnrollmentCeremonyStateError: Error, Equatable, LocalizedError {
    case invalidState
    case notFound
    case conflict
    case wrongRole
    case replayed
    case messageUnavailable
    case invalidMessage
    case messageTooLarge
    case listingInvalid
    case listingLimitExceeded
    case invalidConfiguration
    case keychainStatus(Int32)

    var errorDescription: String? {
        switch self {
        case .invalidState:
            "The device-local version 3 enrollment ceremony state is invalid."
        case .notFound:
            "No device-local version 3 enrollment ceremony state exists for this invitation."
        case .conflict:
            "The version 3 enrollment ceremony changed concurrently or conflicts with existing local state."
        case .wrongRole:
            "This device has the wrong role for the requested enrollment ceremony step."
        case .replayed:
            "This version 3 enrollment ceremony has already been consumed."
        case .messageUnavailable:
            "The version 3 enrollment message is not available from the file provider yet."
        case .invalidMessage:
            "The version 3 enrollment mailbox message is invalid."
        case .messageTooLarge:
            "The version 3 enrollment mailbox message exceeds its size limit."
        case .listingInvalid:
            "The version 3 enrollment mailbox listing is invalid."
        case .listingLimitExceeded:
            "The version 3 enrollment mailbox contains too many objects."
        case .invalidConfiguration:
            "Version 3 enrollment ceremony storage is not configured."
        case .keychainStatus(let status):
            "Version 3 enrollment ceremony Keychain operation failed (\(status))."
        }
    }
}

enum V3EnrollmentCeremonyRole: String, Equatable, Sendable {
    case inviter
    case joiner
}

enum V3EnrollmentCeremonyPhase: String, Equatable, Sendable {
    case awaitingJoinRequest
    case awaitingComparison
    case publishingApproval
    case consumed
}

/// Device-local, non-authoritative state for one exact enrollment invitation.
///
/// Exact signed carriers are retained so retries can republish identical bytes
/// instead of producing a second randomized ECDSA carrier for one payload.
struct V3EnrollmentCeremonyState: Equatable, Sendable {
    static let maximumBytes = 96 * 1_024

    let vaultID: String
    let invitationDigest: Data
    let role: V3EnrollmentCeremonyRole
    let phase: V3EnrollmentCeremonyPhase
    let signedInvitation: V3SignedEnrollmentInvitation
    let signedJoinRequest: V3SignedEnrollmentJoinRequest?
    let ownerApproval: V3EnrollmentPreparedOwnerApproval?

    init(
        vaultID: String,
        invitationDigest: Data,
        role: V3EnrollmentCeremonyRole,
        phase: V3EnrollmentCeremonyPhase,
        signedInvitation: V3SignedEnrollmentInvitation,
        signedJoinRequest: V3SignedEnrollmentJoinRequest?,
        ownerApproval: V3EnrollmentPreparedOwnerApproval? = nil
    ) throws {
        guard isValidV3UUID(vaultID),
            invitationDigest.count == 32,
            signedInvitation.invitation.vaultID == vaultID,
            signedInvitation.invitation.digest == invitationDigest
        else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }

        let validatedTranscript: V3EnrollmentTranscript?
        if let signedJoinRequest {
            guard signedJoinRequest.joinRequest.invitationDigest
                    == invitationDigest,
                  let transcript = try? V3EnrollmentTranscript(
                      invitation: signedInvitation.invitation,
                      joinRequest: signedJoinRequest.joinRequest
                  )
            else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
            validatedTranscript = transcript
        } else {
            validatedTranscript = nil
        }

        switch phase {
        case .awaitingJoinRequest:
            guard role == .inviter,
                  signedJoinRequest == nil,
                  ownerApproval == nil
            else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        case .awaitingComparison:
            guard signedJoinRequest != nil, ownerApproval == nil else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        case .publishingApproval:
            guard role == .inviter,
                  signedJoinRequest != nil,
                  let ownerApproval,
                  ownerApproval.transcriptDigest
                    == validatedTranscript?.digest
            else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        case .consumed:
            guard signedJoinRequest != nil,
                  (role == .joiner && ownerApproval == nil)
                    || (role == .inviter
                        && (ownerApproval == nil
                            || ownerApproval?.transcriptDigest
                                == validatedTranscript?.digest))
            else {
                throw V3EnrollmentCeremonyStateError.invalidState
            }
        }

        self.vaultID = vaultID
        self.invitationDigest = invitationDigest
        self.role = role
        self.phase = phase
        self.signedInvitation = signedInvitation
        self.signedJoinRequest = signedJoinRequest
        self.ownerApproval = ownerApproval
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= Self.maximumBytes else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        let value: CanonicalJSONValue
        do {
            value = try CanonicalJSON.parse(canonicalBytes)
        } catch {
            throw V3EnrollmentCeremonyStateError.invalidState
        }
        guard CanonicalJSON.encode(value) == canonicalBytes,
            let object = value.objectValue,
            Set(object.map(\.0))
                == Set([
                    "format", "invitationDigest", "phase", "role",
                    "signedInvitation", "signedJoinRequest", "ownerApproval",
                    "vaultID", "version",
                ]),
            ceremonyString("format", in: object)
                == "key-vault-enrollment-ceremony-state",
            ceremonyInteger("version", in: object) == 1,
            let vaultID = ceremonyString("vaultID", in: object),
            let invitationDigest = ceremonyData(
                "invitationDigest",
                maximumBytes: 32,
                in: object
            ),
            invitationDigest.count == 32,
            let roleValue = ceremonyString("role", in: object),
            let role = V3EnrollmentCeremonyRole(rawValue: roleValue),
            let phaseValue = ceremonyString("phase", in: object),
            let phase = V3EnrollmentCeremonyPhase(rawValue: phaseValue),
            let invitationBytes = ceremonyData(
                "signedInvitation",
                maximumBytes: V3SignedEnrollmentInvitation.maximumBytes,
                in: object
            )
        else {
            throw V3EnrollmentCeremonyStateError.invalidState
        }

        let joinRequestBytes = try decodeOptionalCeremonyData(
            "signedJoinRequest",
            maximumBytes: V3SignedEnrollmentJoinRequest.maximumBytes,
            in: object
        )
        let ownerApprovalBytes = try decodeOptionalCeremonyData(
            "ownerApproval",
            maximumBytes: V3EnrollmentPreparedOwnerApproval.maximumBytes,
            in: object
        )
        let signedInvitation: V3SignedEnrollmentInvitation
        let signedJoinRequest: V3SignedEnrollmentJoinRequest?
        let ownerApproval: V3EnrollmentPreparedOwnerApproval?
        do {
            signedInvitation = try V3SignedEnrollmentInvitation(
                canonicalBytes: invitationBytes
            )
            signedJoinRequest = try joinRequestBytes.map {
                try V3SignedEnrollmentJoinRequest(canonicalBytes: $0)
            }
            ownerApproval = try ownerApprovalBytes.map {
                try V3EnrollmentPreparedOwnerApproval(canonicalBytes: $0)
            }
        } catch {
            throw V3EnrollmentCeremonyStateError.invalidState
        }

        try self.init(
            vaultID: vaultID,
            invitationDigest: invitationDigest,
            role: role,
            phase: phase,
            signedInvitation: signedInvitation,
            signedJoinRequest: signedJoinRequest,
            ownerApproval: ownerApproval
        )
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-enrollment-ceremony-state")),
                ("version", .integer(1)),
                ("vaultID", .string(vaultID)),
                (
                    "invitationDigest",
                    .string(Base64URL.encode(invitationDigest))
                ),
                ("role", .string(role.rawValue)),
                ("phase", .string(phase.rawValue)),
                (
                    "signedInvitation",
                    .string(
                        Base64URL.encode(
                            signedInvitation.canonicalBytes
                        ))
                ),
                (
                    "signedJoinRequest",
                    signedJoinRequest.map {
                        .string(Base64URL.encode($0.canonicalBytes))
                    } ?? .null
                ),
                (
                    "ownerApproval",
                    ownerApproval.map {
                        .string(Base64URL.encode($0.canonicalBytes))
                    } ?? .null
                ),
            ])
        )
    }

    var transcript: V3EnrollmentTranscript? {
        guard let signedJoinRequest else {
            return nil
        }
        return try? V3EnrollmentTranscript(
            invitation: signedInvitation.invitation,
            joinRequest: signedJoinRequest.joinRequest
        )
    }
}

private func ceremonyMember(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> CanonicalJSONValue? {
    object.first(where: { $0.0 == name })?.1
}

private func ceremonyString(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> String? {
    ceremonyMember(name, in: object)?.stringValue
}

private func ceremonyInteger(
    _ name: String,
    in object: [(String, CanonicalJSONValue)]
) -> UInt64? {
    ceremonyMember(name, in: object)?.integerValue
}

private func ceremonyData(
    _ name: String,
    maximumBytes: Int,
    in object: [(String, CanonicalJSONValue)]
) -> Data? {
    guard let encoded = ceremonyString(name, in: object),
        let data = Base64URL.decodeCanonical(encoded),
        !data.isEmpty,
        data.count <= maximumBytes
    else {
        return nil
    }
    return data
}

private func decodeOptionalCeremonyData(
    _ name: String,
    maximumBytes: Int,
    in object: [(String, CanonicalJSONValue)]
) throws -> Data? {
    guard let value = ceremonyMember(name, in: object) else {
        throw V3EnrollmentCeremonyStateError.invalidState
    }
    if case .null = value {
        return nil
    }
    guard
        let data = ceremonyData(
            name,
            maximumBytes: maximumBytes,
            in: object
        )
    else {
        throw V3EnrollmentCeremonyStateError.invalidState
    }
    return data
}
