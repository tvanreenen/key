import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3VaultKeyHPKEError: Error, Equatable, LocalizedError {
    case invalidContext
    case invalidVaultKey
    case invalidRecipientKey
    case invalidWrappedKey
    case cryptographicFailure

    var errorDescription: String? {
        switch self {
        case .invalidContext:
            "The version 3 vault-key wrapper context is invalid."
        case .invalidVaultKey:
            "The version 3 vault key must contain exactly 32 bytes."
        case .invalidRecipientKey:
            "The version 3 recipient wrapping key is invalid."
        case .invalidWrappedKey:
            "The version 3 HPKE wrapped key is invalid."
        case .cryptographicFailure:
            "The version 3 HPKE vault-key operation failed."
        }
    }
}

/// Self-contained public context for one permanent-profile vault-key wrapper.
///
/// The random transition ID distinguishes separate authority changes without
/// pretending to be a globally ordered generation. Context is bound through
/// both HPKE `info` and authenticated data.
struct V3VaultKeyHPKEContext: Equatable, Sendable {
    static let profile = "device-wrapped"
    static let profileVersion: UInt64 = 1

    // RFC 9180 identifiers: base mode, DHKEM(P-256, HKDF-SHA256),
    // HKDF-SHA256, and AES-256-GCM.
    static let hpkeMode: UInt64 = 0
    static let hpkeKEM: UInt64 = 16
    static let hpkeKDF: UInt64 = 1
    static let hpkeAEAD: UInt64 = 2

    let vaultID: String
    let keyID: V3VaultKeyID
    let authorityTransitionID: String
    let recipientDeviceID: String

    init(
        vaultID: String,
        keyID: V3VaultKeyID,
        authorityTransitionID: String,
        recipientDeviceID: String
    ) throws {
        guard isValidV3UUID(vaultID),
              isValidV3UUID(authorityTransitionID),
              let recipientID = Base64URL.decodeCanonical(recipientDeviceID),
              recipientID.count == 32
        else {
            throw V3VaultKeyHPKEError.invalidContext
        }
        self.vaultID = vaultID
        self.keyID = keyID
        self.authorityTransitionID = authorityTransitionID
        self.recipientDeviceID = recipientDeviceID
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(.object([
            ("format", .string("key-vault-wrapped-key-context")),
            ("version", .integer(1)),
            ("profile", .string(Self.profile)),
            ("profileVersion", .integer(Self.profileVersion)),
            ("vaultID", .string(vaultID)),
            ("keyID", .string(keyID.rawValue)),
            ("authorityTransitionID", .string(authorityTransitionID)),
            ("recipientDeviceID", .string(recipientDeviceID)),
            ("hpkeSuite", .object([
                ("mode", .integer(Self.hpkeMode)),
                ("kem", .integer(Self.hpkeKEM)),
                ("kdf", .integer(Self.hpkeKDF)),
                ("aead", .integer(Self.hpkeAEAD)),
            ])),
        ]))
    }
}

/// RFC 9180 output carried by one permanent-profile device wrapper.
struct V3HPKEWrappedVaultKey: Equatable, Sendable {
    static let encapsulatedKeyByteCount = 65
    static let ciphertextByteCount = 32 + 16

    let encapsulatedKey: Data
    let ciphertext: Data

    init(encapsulatedKey: Data, ciphertext: Data) throws {
        guard encapsulatedKey.count == Self.encapsulatedKeyByteCount,
              ciphertext.count == Self.ciphertextByteCount
        else {
            throw V3VaultKeyHPKEError.invalidWrappedKey
        }
        do {
            _ = try P256.KeyAgreement.PublicKey(
                encapsulatedKey,
                kem: .P256_HKDF_SHA256
            )
        } catch {
            throw V3VaultKeyHPKEError.invalidWrappedKey
        }
        self.encapsulatedKey = encapsulatedKey
        self.ciphertext = ciphertext
    }
}

/// Permanent-profile vault-key wrapping implemented by CryptoKit's RFC 9180
/// HPKE support. The recipient private key may be a software P-256 key in tests
/// or a non-exportable Secure Enclave P-256 key in production.
struct V3VaultKeyHPKE: Sendable {
    private static let suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    private static let infoDomain = Data(
        "work.tvr.key/v3/hpke-vault-key-info/v1".utf8
    )
    private static let authenticatedDataDomain = Data(
        "work.tvr.key/v3/hpke-vault-key-aad/v1".utf8
    )

    func wrap(
        vaultKey: Data,
        recipientPublicKey: Data,
        context: V3VaultKeyHPKEContext
    ) throws -> V3HPKEWrappedVaultKey {
        guard vaultKey.count == 32 else {
            throw V3VaultKeyHPKEError.invalidVaultKey
        }

        let recipient: P256.KeyAgreement.PublicKey
        do {
            recipient = try P256.KeyAgreement.PublicKey(
                recipientPublicKey,
                kem: .P256_HKDF_SHA256
            )
        } catch {
            throw V3VaultKeyHPKEError.invalidRecipientKey
        }

        do {
            // CryptoKit HPKE and Secure Enclave P-256 HPKE conformance are
            // available beginning in macOS 14, which is Key's minimum target.
            var sender = try HPKE.Sender(
                recipientKey: recipient,
                ciphersuite: Self.suite,
                info: domainInput(Self.infoDomain, context: context)
            )
            let ciphertext = try sender.seal(
                vaultKey,
                authenticating: domainInput(
                    Self.authenticatedDataDomain,
                    context: context
                )
            )
            return try V3HPKEWrappedVaultKey(
                encapsulatedKey: sender.encapsulatedKey,
                ciphertext: ciphertext
            )
        } catch let error as V3VaultKeyHPKEError {
            throw error
        } catch {
            throw V3VaultKeyHPKEError.cryptographicFailure
        }
    }

    func unwrap<PrivateKey>(
        _ wrappedKey: V3HPKEWrappedVaultKey,
        recipientPrivateKey: PrivateKey,
        context: V3VaultKeyHPKEContext
    ) throws -> Data where
        PrivateKey: HPKEDiffieHellmanPrivateKey,
        PrivateKey.PublicKey == P256.KeyAgreement.PublicKey
    {
        do {
            var recipient = try HPKE.Recipient(
                privateKey: recipientPrivateKey,
                ciphersuite: Self.suite,
                info: domainInput(Self.infoDomain, context: context),
                encapsulatedKey: wrappedKey.encapsulatedKey
            )
            let vaultKey = try recipient.open(
                wrappedKey.ciphertext,
                authenticating: domainInput(
                    Self.authenticatedDataDomain,
                    context: context
                )
            )
            guard vaultKey.count == 32 else {
                throw V3VaultKeyHPKEError.invalidVaultKey
            }
            return vaultKey
        } catch let error as V3VaultKeyHPKEError {
            throw error
        } catch {
            throw V3VaultKeyHPKEError.cryptographicFailure
        }
    }

    private func domainInput(
        _ domain: Data,
        context: V3VaultKeyHPKEContext
    ) -> Data {
        var result = domain
        result.append(0)
        result.append(context.canonicalBytes)
        return result
    }
}
