import Foundation

enum VaultTransactionOperationIDError: Error, Equatable, LocalizedError {
    case invalidFormat

    var errorDescription: String? {
        "A vault transaction operation ID must be a canonical lowercase UUID."
    }
}

/// A stable identity for one helper-owned mutation attempt.
///
/// The identifier is intentionally independent of a client connection. Later
/// transaction increments can persist it in staging and recovery records
/// without changing its representation.
struct VaultTransactionOperationID:
    Codable,
    CustomStringConvertible,
    Hashable,
    Sendable
{
    let rawValue: String

    init() {
        rawValue = UUID().uuidString.lowercased()
    }

    init(validating rawValue: String) throws {
        guard
            let uuid = UUID(uuidString: rawValue),
            uuid.uuidString.lowercased() == rawValue
        else {
            throw VaultTransactionOperationIDError.invalidFormat
        }
        self.rawValue = rawValue
    }

    var description: String {
        rawValue
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        do {
            try self.init(validating: rawValue)
        } catch {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: error.localizedDescription
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

enum VaultTransactionMutationKind: String, Codable, Sendable {
    case addEntry
    case editEntry
    case copyEntry
    case moveEntry
    case removeEntry
    case resolveConflict
    case mergeHeads
    case migrateToV3
    case enrollDevice
    case catchUpVault
    case recoverInterruptedTransaction
}

struct VaultTransactionMutationContext: Equatable, Sendable {
    let operationID: VaultTransactionOperationID
    let kind: VaultTransactionMutationKind
}

protocol VaultTransactionMutationOwning: Sendable {
    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result
}

/// Key Agent's serialization point for vault-content mutations.
///
/// Key Agent serves multiple XPC connections concurrently. A dedicated serial
/// queue lets reads remain concurrent while ensuring mutation attempts cannot
/// interleave. This synchronous boundary matches the existing request handler;
/// introducing an actor here would force an async bridge without improving
/// isolation.
final class VaultTransactionMutationOwner:
    VaultTransactionMutationOwning,
    Sendable
{
    private let queue: DispatchQueue
    private let makeOperationID: @Sendable () -> VaultTransactionOperationID

    init(
        queueLabel: String = "work.tvr.key.transaction-mutation-owner",
        makeOperationID: @escaping @Sendable () -> VaultTransactionOperationID = {
            VaultTransactionOperationID()
        }
    ) {
        queue = DispatchQueue(label: queueLabel)
        self.makeOperationID = makeOperationID
    }

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        try queue.sync {
            try mutation(
                VaultTransactionMutationContext(
                    operationID: makeOperationID(),
                    kind: kind
                )
            )
        }
    }
}

/// Reuses an operation identity when a higher-level helper boundary already
/// owns serialization. This prevents transaction components from nesting the
/// same serial queue while preserving one durable identifier end to end.
struct DirectVaultTransactionMutationOwner:
    VaultTransactionMutationOwning
{
    let operationID: VaultTransactionOperationID

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        try mutation(VaultTransactionMutationContext(
            operationID: operationID,
            kind: kind
        ))
    }
}
