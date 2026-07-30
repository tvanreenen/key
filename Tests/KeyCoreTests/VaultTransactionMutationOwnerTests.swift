import Foundation
import Testing
@testable import KeyCore

struct VaultTransactionMutationOwnerTests {
    @Test
    func operationIDsUseCanonicalLowercaseUUIDEncoding() throws {
        let id = VaultTransactionOperationID()
        let reparsed = try VaultTransactionOperationID(
            validating: id.rawValue
        )
        let encoded = try JSONEncoder().encode(id)
        let decoded = try JSONDecoder().decode(
            VaultTransactionOperationID.self,
            from: encoded
        )

        #expect(id.rawValue == id.rawValue.lowercased())
        #expect(id.rawValue.count == 36)
        #expect(reparsed == id)
        #expect(decoded == id)
        #expect(encoded == Data("\"\(id.rawValue)\"".utf8))
    }

    @Test
    func operationIDsRejectMalformedAndNoncanonicalValues() throws {
        #expect(throws: VaultTransactionOperationIDError.invalidFormat) {
            try VaultTransactionOperationID(validating: "not-a-uuid")
        }
        #expect(throws: VaultTransactionOperationIDError.invalidFormat) {
            try VaultTransactionOperationID(
                validating: "550E8400-E29B-41D4-A716-446655440000"
            )
        }
        #expect(
            try VaultTransactionOperationID(
                validating: "550e8400-e29b-11d4-a716-446655440000"
            ).rawValue == "550e8400-e29b-11d4-a716-446655440000"
        )
    }

    @Test
    func ownerSerializesConcurrentMutationsAndAssignsUniqueIDs() throws {
        let operationIDs = try OperationIDSequence(
            rawValues: [
                "018f4d38-7d5a-4b20-b0f1-97d6e96c44b3",
                "018f4d38-7d5a-4b20-b0f1-97d6e96c44b4"
            ]
        )
        let owner = VaultTransactionMutationOwner(
            makeOperationID: operationIDs.next
        )
        let contexts = MutationContextRecorder()
        let firstEntered = DispatchSemaphore(value: 0)
        let releaseFirst = DispatchSemaphore(value: 0)
        let secondAttempted = DispatchSemaphore(value: 0)
        let secondEntered = DispatchSemaphore(value: 0)
        let completion = DispatchGroup()

        completion.enter()
        DispatchQueue.global().async {
            try? owner.perform(.addEntry) { context in
                contexts.append(context)
                firstEntered.signal()
                releaseFirst.wait()
            }
            completion.leave()
        }

        let firstResult = firstEntered.wait(timeout: .now() + 1)
        #expect(firstResult == .success)
        guard firstResult == .success else {
            releaseFirst.signal()
            _ = completion.wait(timeout: .now() + 1)
            return
        }

        completion.enter()
        DispatchQueue.global().async {
            secondAttempted.signal()
            try? owner.perform(.removeEntry) { context in
                contexts.append(context)
                secondEntered.signal()
            }
            completion.leave()
        }

        #expect(secondAttempted.wait(timeout: .now() + 1) == .success)
        #expect(secondEntered.wait(timeout: .now() + 0.1) == .timedOut)

        releaseFirst.signal()

        #expect(secondEntered.wait(timeout: .now() + 1) == .success)
        #expect(completion.wait(timeout: .now() + 1) == .success)

        let recorded = contexts.values
        #expect(recorded.map(\.kind) == [.addEntry, .removeEntry])
        #expect(recorded.count == 2)
        guard recorded.count == 2 else {
            return
        }
        #expect(recorded[0].operationID != recorded[1].operationID)
        #expect(
            recorded.map(\.operationID.rawValue) == [
                "018f4d38-7d5a-4b20-b0f1-97d6e96c44b3",
                "018f4d38-7d5a-4b20-b0f1-97d6e96c44b4"
            ]
        )
    }

    @Test
    func failedMutationDoesNotPreventTheNextOperation() throws {
        let owner = VaultTransactionMutationOwner()

        #expect(throws: MutationOwnerTestError.expected) {
            try owner.perform(.editEntry) { _ in
                throw MutationOwnerTestError.expected
            }
        }

        let result = try owner.perform(.copyEntry) { context in
            context.kind
        }
        #expect(result == .copyEntry)
    }

    @Test
    func handlerRoutesOnlyVaultContentMutationsThroughOwner() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let owner = RecordingMutationOwner()
        let vaultUXService = RecordingVaultUXService()
        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: owner,
            vaultUXService: vaultUXService
        )

        #expect(
            handler.handle(
                .addManual(
                    name: "source",
                    secret: "one",
                    type: .secret
                )
            ) == .success()
        )
        #expect(
            handler.handle(
                .editManual(
                    name: "source",
                    secret: "two",
                    type: .secret
                )
            ) == .success()
        )
        #expect(
            handler.handle(
                .copyEntry(
                    source: "source",
                    destination: "copy",
                    force: false
                )
            ) == .success()
        )
        #expect(
            handler.handle(
                .moveEntry(
                    source: "copy",
                    destination: "moved",
                    force: false
                )
            ) == .success()
        )
        #expect(handler.handle(.removeEntry(name: "moved")) == .success())
        let resolution = VaultConflictResolution(
            conflictID: "c-123",
            versionID: "abc123"
        )
        #expect(
            handler.handle(.resolveConflicts([resolution])) == .success()
        )

        #expect(handler.handle(.get(name: "source")) == .success("two"))
        #expect(handler.handle(.list) == .success("source\n"))
        #expect(
            owner.kinds == [
                .addEntry,
                .editEntry,
                .copyEntry,
                .moveEntry,
                .removeEntry,
                .resolveConflict
            ]
        )
        #expect(vaultUXService.resolutions == [[resolution]])
    }

    @Test
    func handlerReportsOwnerFailureWithoutStartingTheMutation() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let handler = KeyServiceHandler(
            keyStore: MemoryVaultKeyStore(),
            entryStore: EntryStore(rootURL: root),
            mutationOwner: FailingMutationOwner()
        )

        let response = handler.handle(
            .addManual(name: "entry", secret: "value", type: .secret)
        )

        #expect(response.exitCode == EXIT_FAILURE)
        #expect(
            response.errorMessage?.contains(
                "Failed to prepare the vault mutation"
            ) == true
        )
        #expect(try EntryStore(rootURL: root).exists("entry") == false)
    }
}

private enum MutationOwnerTestError: Error {
    case expected
}

private final class MutationContextRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [VaultTransactionMutationContext] = []

    var values: [VaultTransactionMutationContext] {
        lock.withLock {
            storage
        }
    }

    func append(_ context: VaultTransactionMutationContext) {
        lock.withLock {
            storage.append(context)
        }
    }
}

private final class OperationIDSequence: @unchecked Sendable {
    private let lock = NSLock()
    private var operationIDs: [VaultTransactionOperationID]

    init(rawValues: [String]) throws {
        operationIDs = try rawValues.map {
            try VaultTransactionOperationID(validating: $0)
        }
    }

    func next() -> VaultTransactionOperationID {
        lock.withLock {
            precondition(!operationIDs.isEmpty)
            return operationIDs.removeFirst()
        }
    }
}

private final class RecordingMutationOwner:
    VaultTransactionMutationOwning,
    @unchecked Sendable
{
    private let lock = NSLock()
    private var storage: [VaultTransactionMutationKind] = []

    var kinds: [VaultTransactionMutationKind] {
        lock.withLock {
            storage
        }
    }

    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        lock.withLock {
            storage.append(kind)
        }
        return try mutation(
            VaultTransactionMutationContext(
                operationID: VaultTransactionOperationID(),
                kind: kind
            )
        )
    }
}

private struct FailingMutationOwner: VaultTransactionMutationOwning {
    func perform<Result>(
        _ kind: VaultTransactionMutationKind,
        _ mutation: (VaultTransactionMutationContext) throws -> Result
    ) throws -> Result {
        throw AppError.io("Failed to prepare the vault mutation.")
    }
}

private final class RecordingVaultUXService: VaultUXServicing {
    private(set) var resolutions: [[VaultConflictResolution]] = []

    func status() throws -> VaultStatus {
        VaultStatus(format: .version3, health: .ready, entryCount: 0)
    }

    func authorizeRead(name _: String, allowStale _: Bool) throws {}

    func authorizeMutation() throws {}

    func conflicts() throws -> [VaultConflictSummary] {
        []
    }

    func conflict(id _: String) throws -> VaultConflictDetail {
        throw VaultUXServiceError.conflictNotFound
    }

    func conflictValue(
        id _: String,
        versionID _: String
    ) throws -> String {
        throw VaultUXServiceError.conflictVersionNotFound
    }

    func resolve(_ resolutions: [VaultConflictResolution]) throws {
        self.resolutions.append(resolutions)
    }
}
