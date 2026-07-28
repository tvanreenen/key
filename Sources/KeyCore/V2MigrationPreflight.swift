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
                    "the entry name is not compatible with the version 3 format"
                case .unreadableFile:
                    "the file is not a readable version 2 secret"
                case .unsupportedFormat:
                    "the file does not use the supported version 2 AES-GCM format"
                case .invalidEncryptedPayload:
                    "the file contains an invalid encrypted payload"
                case .authenticationFailed:
                    "the entry cannot be authenticated with the current vault key"
                case .invalidTOTPSeed:
                    "the decrypted TOTP seed is not valid Base32"
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
                "Migration preflight passed.",
                "Entries checked: \(entryCount) (\(count(secretCount, singular: "secret")), \(count(totpCount, singular: "TOTP entry", plural: "TOTP entries")))."
            ]
            if entryCount == 0 {
                lines.append("The version 2 vault is empty.")
            } else {
                lines.append(
                    "Every entry uses the supported version 2 format, has a version 3-compatible name, and decrypts with the current vault key."
                )
            }
        } else {
            lines = [
                "Migration preflight blocked.",
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
            "Migration preflight blocked.",
            "The version 2 vault could not be inspected: \(String(reflecting: error.localizedDescription)).",
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

/// Inspects the shipping version 2 vault without returning plaintext or
/// invoking any file or Keychain mutation API.
///
/// The supplied key loader must perform a read-only load with key creation and
/// repair disabled. An empty vault deliberately does not call it.
struct V2MigrationPreflight {
    private static let unsupportedPrototypeMetadataFilename = ".key-vault.json"

    let entryStore: EntryStore
    let cipher: VaultCipher

    func inspect(loadVaultKey: () throws -> Data) throws -> V2MigrationPreflightReport {
        try refuseUnsupportedPrototypeMetadata()
        let entryNames = try entryStore.listEntries()
        guard !entryNames.isEmpty else {
            return V2MigrationPreflightReport(
                entryCount: 0,
                secretCount: 0,
                totpCount: 0,
                problems: []
            )
        }

        let vaultKey = try loadVaultKey()
        var secretCount = 0
        var totpCount = 0
        var problems: [V2MigrationPreflightReport.Problem] = []

        for entryName in entryNames {
            if !isValidV3EntryName(entryName) {
                problems.append(.init(entryName: entryName, kind: .incompatibleName))
            }

            let file: SecretFile
            do {
                file = try entryStore.load(entryName)
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
                if file.type == .totp {
                    do {
                        _ = try TOTPGenerator.normalizeBase32Seed(plaintext)
                    } catch {
                        problems.append(.init(entryName: entryName, kind: .invalidTOTPSeed))
                    }
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

        return V2MigrationPreflightReport(
            entryCount: entryNames.count,
            secretCount: secretCount,
            totpCount: totpCount,
            problems: problems
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
