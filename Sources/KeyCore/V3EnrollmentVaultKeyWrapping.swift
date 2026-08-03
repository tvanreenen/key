import CryptoKit
import Foundation
internal import JSONCanonicalization

enum V3EnrollmentVaultKeyWrappingError:
    Error,
    Equatable,
    LocalizedError
{
    case invalidContext
    case invalidVaultKey
    case invalidRecipientKey
    case invalidCiphertext
    case cryptographicFailure

    var errorDescription: String? {
        switch self {
        case .invalidContext:
            "The version 3 enrollment key-wrap context is invalid."
        case .invalidVaultKey:
            "The version 3 enrollment vault key must contain exactly 32 bytes."
        case .invalidRecipientKey:
            "The joining device wrapping key is invalid."
        case .invalidCiphertext:
            "The version 3 enrollment wrapped-key ciphertext is invalid."
        case .cryptographicFailure:
            "The version 3 enrollment vault-key cryptographic operation failed."
        }
    }
}

/// Public context that binds one wrapped vault key to the exact approved
/// enrollment transcript and manifest key identity.
struct V3EnrollmentVaultKeyWrapContext: Equatable, Sendable {
    let vaultID: String
    let keyID: V3VaultKeyID
    let recipientDeviceID: String
    let transcriptDigest: Data

    init(
        vaultID: String,
        keyID: V3VaultKeyID,
        recipientDeviceID: String,
        transcriptDigest: Data
    ) throws {
        guard isValidV3UUID(vaultID),
            let deviceID = Base64URL.decodeCanonical(recipientDeviceID),
            deviceID.count == 32,
            transcriptDigest.count == 32
        else {
            throw V3EnrollmentVaultKeyWrappingError.invalidContext
        }
        self.vaultID = vaultID
        self.keyID = keyID
        self.recipientDeviceID = recipientDeviceID
        self.transcriptDigest = transcriptDigest
    }

    var canonicalBytes: Data {
        CanonicalJSON.encode(
            .object([
                ("format", .string("key-vault-enrollment-wrapped-key-context")),
                ("version", .integer(1)),
                ("vaultID", .string(vaultID)),
                ("keyID", .string(keyID.rawValue)),
                ("recipientDeviceID", .string(recipientDeviceID)),
                (
                    "transcriptDigest",
                    .string(Base64URL.encode(transcriptDigest))
                ),
            ]))
    }
}

/// Fixed framing for `p256-ecies-x963-sha256-aes-gcm`.
///
/// Version byte || 65-byte ephemeral X9.63 public key || 12-byte nonce ||
/// 32-byte ciphertext || 16-byte authentication tag.
struct V3EnrollmentWrappedVaultKeyCiphertext: Equatable, Sendable {
    static let formatVersion: UInt8 = 1
    static let byteCount = 1 + 65 + 12 + 32 + 16

    let ephemeralPublicKey: Data
    let nonce: Data
    let ciphertext: Data
    let tag: Data

    init(combinedBytes: Data) throws {
        guard combinedBytes.count == Self.byteCount,
            combinedBytes.first == Self.formatVersion
        else {
            throw V3EnrollmentVaultKeyWrappingError.invalidCiphertext
        }
        let ephemeralPublicKey = combinedBytes.subdata(in: 1..<66)
        let nonce = combinedBytes.subdata(in: 66..<78)
        let ciphertext = combinedBytes.subdata(in: 78..<110)
        let tag = combinedBytes.subdata(in: 110..<126)
        do {
            _ = try P256.KeyAgreement.PublicKey(
                x963Representation: ephemeralPublicKey
            )
            _ = try AES.GCM.Nonce(data: nonce)
        } catch {
            throw V3EnrollmentVaultKeyWrappingError.invalidCiphertext
        }
        self.ephemeralPublicKey = ephemeralPublicKey
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
    }

    init(
        ephemeralPublicKey: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) throws {
        var combined = Data([Self.formatVersion])
        combined.append(ephemeralPublicKey)
        combined.append(nonce)
        combined.append(ciphertext)
        combined.append(tag)
        try self.init(combinedBytes: combined)
    }

    var combinedBytes: Data {
        var result = Data([Self.formatVersion])
        result.append(ephemeralPublicKey)
        result.append(nonce)
        result.append(ciphertext)
        result.append(tag)
        return result
    }
}

protocol V3EnrollmentVaultKeyWrapping: Sendable {
    func wrap(
        vaultKey: Data,
        recipientPublicKey: Data,
        context: V3EnrollmentVaultKeyWrapContext
    ) throws -> Data
}

protocol V3EnrollmentVaultKeyUnwrapping: Sendable {
    var vaultID: String { get }
    var publicIdentity: V3EnrollmentDeviceIdentity { get }

    func unwrapVaultKey(
        _ ciphertext: Data,
        context: V3EnrollmentVaultKeyWrapContext,
        reason: String
    ) throws -> Data
}

/// Uses an ephemeral software P-256 key only to derive a one-time wrapping
/// key. The recipient private key remains device-bound in the Secure Enclave.
struct V3EnrollmentVaultKeyWrapper: V3EnrollmentVaultKeyWrapping, Sendable {
    typealias EphemeralKeyFactory =
        @Sendable () throws ->
        P256.KeyAgreement.PrivateKey

    private static let keyDerivationDomain = Data(
        "work.tvr.key/v3/enrollment-wrapped-key-kek/v1".utf8
    )
    private static let authenticatedDataDomain = Data(
        "work.tvr.key/v3/enrollment-wrapped-key/v1".utf8
    )

    private let makeEphemeralKey: EphemeralKeyFactory

    init(
        makeEphemeralKey: @escaping EphemeralKeyFactory = {
            P256.KeyAgreement.PrivateKey()
        }
    ) {
        self.makeEphemeralKey = makeEphemeralKey
    }

    func wrap(
        vaultKey: Data,
        recipientPublicKey: Data,
        context: V3EnrollmentVaultKeyWrapContext
    ) throws -> Data {
        guard vaultKey.count == 32 else {
            throw V3EnrollmentVaultKeyWrappingError.invalidVaultKey
        }
        let recipient: P256.KeyAgreement.PublicKey
        do {
            recipient = try P256.KeyAgreement.PublicKey(
                x963Representation: recipientPublicKey
            )
        } catch {
            throw V3EnrollmentVaultKeyWrappingError.invalidRecipientKey
        }

        do {
            let ephemeral = try makeEphemeralKey()
            let sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(
                with: recipient
            )
            let wrappingKey = sharedSecret.x963DerivedSymmetricKey(
                using: SHA256.self,
                sharedInfo: domainInput(
                    Self.keyDerivationDomain,
                    context: context
                ),
                outputByteCount: 32
            )
            let sealed = try AES.GCM.seal(
                vaultKey,
                using: wrappingKey,
                authenticating: domainInput(
                    Self.authenticatedDataDomain,
                    context: context
                )
            )
            return try V3EnrollmentWrappedVaultKeyCiphertext(
                ephemeralPublicKey:
                    ephemeral.publicKey.x963Representation,
                nonce: Data(sealed.nonce),
                ciphertext: sealed.ciphertext,
                tag: sealed.tag
            ).combinedBytes
        } catch let error as V3EnrollmentVaultKeyWrappingError {
            throw error
        } catch {
            throw V3EnrollmentVaultKeyWrappingError.cryptographicFailure
        }
    }

    func unwrap(
        _ ciphertext: Data,
        context: V3EnrollmentVaultKeyWrapContext,
        sharedSecret: (P256.KeyAgreement.PublicKey) throws -> SharedSecret
    ) throws -> Data {
        let framed = try V3EnrollmentWrappedVaultKeyCiphertext(
            combinedBytes: ciphertext
        )
        do {
            let ephemeral = try P256.KeyAgreement.PublicKey(
                x963Representation: framed.ephemeralPublicKey
            )
            let wrappingKey = try sharedSecret(ephemeral)
                .x963DerivedSymmetricKey(
                    using: SHA256.self,
                    sharedInfo: domainInput(
                        Self.keyDerivationDomain,
                        context: context
                    ),
                    outputByteCount: 32
                )
            let sealed = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: framed.nonce),
                ciphertext: framed.ciphertext,
                tag: framed.tag
            )
            let vaultKey = try AES.GCM.open(
                sealed,
                using: wrappingKey,
                authenticating: domainInput(
                    Self.authenticatedDataDomain,
                    context: context
                )
            )
            guard vaultKey.count == 32 else {
                throw V3EnrollmentVaultKeyWrappingError.invalidVaultKey
            }
            return vaultKey
        } catch let error as V3EnrollmentVaultKeyWrappingError {
            throw error
        } catch {
            throw V3EnrollmentVaultKeyWrappingError.cryptographicFailure
        }
    }

    private func domainInput(
        _ domain: Data,
        context: V3EnrollmentVaultKeyWrapContext
    ) -> Data {
        var result = domain
        result.append(0)
        result.append(context.canonicalBytes)
        return result
    }
}
