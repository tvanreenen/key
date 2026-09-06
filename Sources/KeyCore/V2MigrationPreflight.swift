import CryptoKit
import Foundation

struct V2MigrationPreflightReport: Equatable, Sendable {
    struct Problem: Equatable, Sendable {
        enum Kind: Int, Equatable, Sendable {
            case incompatibleName
            case unreadableFile
            case unsupportedFormat
            case invalidEncryptedPayload
            case authenticationFailed
            case invalidTOTPSeed

            var explanation: String {
                switch self {
                case .incompatibleName:
                    "the entry name is not supported by the new vault format"
                case .unreadableFile:
                    "the file is not a readable entry in the older vault format"
                case .unsupportedFormat:
                    "the file does not use the supported encryption format (v2 AES-GCM)"
                case .invalidEncryptedPayload:
                    "the file contains an invalid encrypted payload"
                case .authenticationFailed:
                    "the entry could not be verified with this vault's encryption key"
                case .invalidTOTPSeed:
                    "the authenticator setup secret is not valid Base32"
                }
            }
        }

        let entryName: String
        let kind: Kind
    }

    let entryCount: Int
    let secretCount: Int
    let totpCount: Int
    let problems: [Problem]

    var isReady: Bool {
        problems.isEmpty
    }

    var rendered: String {
        var lines: [String]
        if isReady {
            lines = [
                "Your vault is ready to migrate.",
                "Entries checked: \(entryCount) (\(count(secretCount, singular: "secret")), \(count(totpCount, singular: "TOTP entry", plural: "TOTP entries")))."
            ]
            if entryCount == 0 {
                lines.append("The original vault has no entries.")
            } else {
                lines.append(
                    "Key could read and verify every entry, and each name is supported by the new format."
                )
            }
        } else {
            lines = [
                "Your vault is not ready to migrate.",
                "Entries checked: \(entryCount).",
                "Problems:"
            ]
            lines.append(contentsOf: problems.map {
                "- \(Self.quoted($0.entryName)): \($0.kind.explanation)."
            })
        }

        lines.append("No files or Keychain items were changed. Migration has not started.")
        return lines.joined(separator: "\n")
    }

    static func blockedInspection(_ error: Error) -> String {
        [
            "Your vault is not ready to migrate.",
            "Key could not inspect the original vault: \(String(reflecting: error.localizedDescription)).",
            "No files or Keychain items were changed. Migration has not started."
        ].joined(separator: "\n")
    }

    private func count(_ value: Int, singular: String, plural: String? = nil) -> String {
        "\(value) \(value == 1 ? singular : (plural ?? singular + "s"))"
    }

    private static func quoted(_ value: String) -> String {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(value),
              let encoded = String(data: data, encoding: .utf8)
        else {
            return String(reflecting: value)
        }
        return encoded
    }
}

struct V2MigrationSourceEntry: Equatable, Sendable {
    let name: String
    let type: SecretEntryType
    let plaintext: String
    let sourceData: Data
}

struct V2MigrationInspection: Equatable, Sendable {
    let report: V2MigrationPreflightReport
    let vaultKey: Data?
    let entries: [V2MigrationSourceEntry]
}

/// Inspects the shipping version 2 vault without returning plaintext or
/// invoking any file or Keychain mutation API.
///
/// The supplied key loader must perform a read-only load with key creation and
/// repair disabled. An empty vault deliberately does not call it.
struct V2MigrationPreflight {
    private static let unsupportedPrototypeMetadataFilename = ".key-vault.json"

    private enum InspectionContent {
        case reportOnly
        case migrationSnapshot

        var retainsSource: Bool {
            switch self {
            case .reportOnly:
                false
            case .migrationSnapshot:
                true
            }
        }
    }

    let entryStore: EntryStore
    let cipher: VaultCipher

    func inspect(loadVaultKey: () throws -> Data) throws -> V2MigrationPreflightReport {
        try inspect(
            content: .reportOnly,
            loadVaultKey: loadVaultKey
        ).report
    }

    /// Performs the same complete preflight while retaining an exact,
    /// authenticated source snapshot for an immediately following migration.
    /// A blocked inspection never returns plaintext or a vault key.
    func inspectForMigration(
        loadVaultKey: () throws -> Data
    ) throws -> V2MigrationInspection {
        try inspect(
            content: .migrationSnapshot,
            loadVaultKey: loadVaultKey
        )
    }

    private func inspect(
        content: InspectionContent,
        loadVaultKey: () throws -> Data
    ) throws -> V2MigrationInspection {
        try refuseUnsupportedPrototypeMetadata()
        let entryNames = try entryStore.listEntries()
        guard !entryNames.isEmpty else {
            return V2MigrationInspection(
                report: V2MigrationPreflightReport(
                    entryCount: 0,
                    secretCount: 0,
                    totpCount: 0,
                    problems: []
                ),
                vaultKey: nil,
                entries: []
            )
        }

        let vaultKey = try loadVaultKey()
        var secretCount = 0
        var totpCount = 0
        var problems: [V2MigrationPreflightReport.Problem] = []
        var sourceEntries: [V2MigrationSourceEntry] = []
        if content.retainsSource {
            sourceEntries.reserveCapacity(entryNames.count)
        }

        for entryName in entryNames {
            let hasCompatibleName = isValidV3EntryName(entryName)
            if !hasCompatibleName {
                problems.append(.init(entryName: entryName, kind: .incompatibleName))
            }

            let stored: (file: SecretFile, data: Data)
            let file: SecretFile
            do {
                stored = try entryStore.loadStoredSecret(entryName)
                file = stored.file
            } catch {
                problems.append(.init(entryName: entryName, kind: .unreadableFile))
                continue
            }

            switch file.type {
            case .secret:
                secretCount += 1
            case .totp:
                totpCount += 1
            }

            guard file.version == 2, file.alg == "AES.GCM" else {
                problems.append(.init(entryName: entryName, kind: .unsupportedFormat))
                continue
            }

            do {
                let plaintext = try cipher.decrypt(file, keyData: vaultKey)
                let normalizedPlaintext: String
                if file.type == .totp {
                    do {
                        normalizedPlaintext = try TOTPGenerator
                            .normalizeBase32Seed(plaintext)
                    } catch {
                        problems.append(.init(entryName: entryName, kind: .invalidTOTPSeed))
                        continue
                    }
                } else {
                    normalizedPlaintext = plaintext
                }
                if content.retainsSource, hasCompatibleName {
                    sourceEntries.append(V2MigrationSourceEntry(
                        name: entryName,
                        type: file.type,
                        plaintext: normalizedPlaintext,
                        sourceData: stored.data
                    ))
                }
            } catch CryptoKitError.authenticationFailure {
                problems.append(.init(entryName: entryName, kind: .authenticationFailed))
            } catch let error as AppError {
                switch error {
                case .invalidSecretFile:
                    problems.append(.init(entryName: entryName, kind: .invalidEncryptedPayload))
                default:
                    problems.append(.init(entryName: entryName, kind: .unreadableFile))
                }
            } catch {
                problems.append(.init(entryName: entryName, kind: .invalidEncryptedPayload))
            }
        }

        problems.sort {
            let leftName = Data($0.entryName.utf8)
            let rightName = Data($1.entryName.utf8)
            return leftName.lexicographicallyPrecedes(rightName)
                || (leftName == rightName && $0.kind.rawValue < $1.kind.rawValue)
        }

        let report = V2MigrationPreflightReport(
            entryCount: entryNames.count,
            secretCount: secretCount,
            totpCount: totpCount,
            problems: problems
        )
        return V2MigrationInspection(
            report: report,
            vaultKey:
                report.isReady && content.retainsSource ? vaultKey : nil,
            entries:
                report.isReady && content.retainsSource ? sourceEntries : []
        )
    }

    private func refuseUnsupportedPrototypeMetadata(
        fileManager: FileManager = .default
    ) throws {
        let rootPath = entryStore.rootURL.path(percentEncoded: false)
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: rootPath, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            return
        }

        let children: [URL]
        do {
            children = try fileManager.contentsOfDirectory(
                at: entryStore.rootURL,
                includingPropertiesForKeys: nil,
                options: []
            )
        } catch {
            throw AppError.io(
                "Failed to inspect the version 2 vault for unsupported migration metadata: \(error.localizedDescription)"
            )
        }

        guard children.contains(where: {
            $0.lastPathComponent == Self.unsupportedPrototypeMetadataFilename
        }) else {
            return
        }

        throw AppError.operationRefused(
            "The vault contains '\(Self.unsupportedPrototypeMetadataFilename)' from the unreleased Secure Enclave sharing prototype. That prototype is not a supported migration source."
        )
    }
}
