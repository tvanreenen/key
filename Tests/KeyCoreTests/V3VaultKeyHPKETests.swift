import CryptoKit
import Foundation
import Testing

@testable import KeyCore

struct V3VaultKeyHPKETests {
    private static let vaultID = "018f4d38-7d5a-7b20-b0f1-97d6e96c44b3"
    private static let transitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b4"
    private static let otherTransitionID =
        "018f4d38-7d5a-7b20-b0f1-97d6e96c44b5"
    private static let vaultKey = Data((0..<32).map(UInt8.init))

    @Test
    func roundTripsWithSoftwareP256Key() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let context = try Self.makeContext(vaultKey: Self.vaultKey)

        let wrapped = try V3VaultKeyHPKE().wrap(
            vaultKey: Self.vaultKey,
            recipientPublicKey: recipient.publicKey.x963Representation,
            context: context
        )

        #expect(wrapped.encapsulatedKey.count == 65)
        #expect(wrapped.ciphertext.count == 48)
        #expect(
            try V3VaultKeyHPKE().unwrap(
                wrapped,
                recipientPrivateKey: recipient,
                context: context
            ) == Self.vaultKey
        )
    }

    @Test
    func exactContextIsRequired() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let context = try Self.makeContext(vaultKey: Self.vaultKey)
        let wrapped = try V3VaultKeyHPKE().wrap(
            vaultKey: Self.vaultKey,
            recipientPublicKey: recipient.publicKey.x963Representation,
            context: context
        )
        let wrongContexts = try [
            V3VaultKeyHPKEContext(
                vaultID: "018f4d38-7d5a-7b20-b0f1-97d6e96c44b6",
                keyID: context.keyID,
                authorityTransitionID: context.authorityTransitionID,
                recipientDeviceID: context.recipientDeviceID
            ),
            V3VaultKeyHPKEContext(
                vaultID: context.vaultID,
                keyID: V3VaultKeyID.derive(
                    vaultKey: Data(repeating: 0x99, count: 32),
                    vaultID: context.vaultID
                ),
                authorityTransitionID: context.authorityTransitionID,
                recipientDeviceID: context.recipientDeviceID
            ),
            V3VaultKeyHPKEContext(
                vaultID: context.vaultID,
                keyID: context.keyID,
                authorityTransitionID: Self.otherTransitionID,
                recipientDeviceID: context.recipientDeviceID
            ),
            V3VaultKeyHPKEContext(
                vaultID: context.vaultID,
                keyID: context.keyID,
                authorityTransitionID: context.authorityTransitionID,
                recipientDeviceID: Base64URL.encode(
                    Data(repeating: 0x77, count: 32)
                )
            ),
        ]

        for wrongContext in wrongContexts {
            #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
                try V3VaultKeyHPKE().unwrap(
                    wrapped,
                    recipientPrivateKey: recipient,
                    context: wrongContext
                )
            }
        }
    }

    @Test
    func wrongRecipientCannotOpenWrappedKey() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let otherRecipient = P256.KeyAgreement.PrivateKey()
        let context = try Self.makeContext(vaultKey: Self.vaultKey)
        let wrapped = try V3VaultKeyHPKE().wrap(
            vaultKey: Self.vaultKey,
            recipientPublicKey: recipient.publicKey.x963Representation,
            context: context
        )

        #expect(throws: V3VaultKeyHPKEError.cryptographicFailure) {
            try V3VaultKeyHPKE().unwrap(
                wrapped,
                recipientPrivateKey: otherRecipient,
                context: context
            )
        }
    }

    @Test
    func validatesKeysContextAndFramingBeforeCrypto() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let context = try Self.makeContext(vaultKey: Self.vaultKey)

        #expect(throws: V3VaultKeyHPKEError.invalidVaultKey) {
            try V3VaultKeyHPKE().wrap(
                vaultKey: Data(repeating: 0, count: 31),
                recipientPublicKey: recipient.publicKey.x963Representation,
                context: context
            )
        }
        #expect(throws: V3VaultKeyHPKEError.invalidRecipientKey) {
            try V3VaultKeyHPKE().wrap(
                vaultKey: Self.vaultKey,
                recipientPublicKey: Data(repeating: 0, count: 65),
                context: context
            )
        }
        #expect(throws: V3VaultKeyHPKEError.invalidWrappedKey) {
            try V3HPKEWrappedVaultKey(
                encapsulatedKey: Data(repeating: 0, count: 64),
                ciphertext: Data(repeating: 0, count: 48)
            )
        }
        #expect(throws: V3VaultKeyHPKEError.invalidContext) {
            try V3VaultKeyHPKEContext(
                vaultID: Self.vaultID,
                keyID: context.keyID,
                authorityTransitionID: "not-a-uuid",
                recipientDeviceID: context.recipientDeviceID
            )
        }
    }

    @Test
    func contextHasStableCanonicalEncoding() throws {
        let context = try Self.makeContext(vaultKey: Self.vaultKey)
        let encoded = String(decoding: context.canonicalBytes, as: UTF8.self)

        #expect(
            encoded ==
                "{\"authorityTransitionID\":\"018f4d38-7d5a-7b20-b0f1-97d6e96c44b4\",\"format\":\"key-vault-wrapped-key-context\",\"hpkeSuite\":{\"aead\":2,\"kdf\":1,\"kem\":16,\"mode\":0},\"keyID\":\"YWHJjbH1Mqt6bAtnVdqoT84nrfbogDs7lWSFQT8V8iA\",\"profile\":\"device-wrapped\",\"profileVersion\":1,\"recipientDeviceID\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\",\"vaultID\":\"018f4d38-7d5a-7b20-b0f1-97d6e96c44b3\",\"version\":1}"
        )
    }

    private static func makeContext(
        vaultKey: Data
    ) throws -> V3VaultKeyHPKEContext {
        try V3VaultKeyHPKEContext(
            vaultID: vaultID,
            keyID: V3VaultKeyID.derive(
                vaultKey: vaultKey,
                vaultID: vaultID
            ),
            authorityTransitionID: transitionID,
            recipientDeviceID: Base64URL.encode(Data(0..<32))
        )
    }
}
