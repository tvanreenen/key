import CryptoKit
import Foundation
import Testing

@testable import KeyCore

/// Software-only public card transport and ECDH provider; no actual smart card or authentication UI.
enum PIVRecoveryTestSupport {
  // Expired public software certificate, not the owner's hardware credential.
  static let certificate = Data(
    base64Encoded:
      "MIIBiTCCATCgAwIBAgIUMw8ODdlTgTIgtSKw44Ql3zmMG4MwCgYIKoZIzj0EAwIwKzEpMCcGA1UEAwwgRGlzcG9zYWJsZS1QdWJsaWMtUmVhZGVyLUZpeHR1cmUwHhcNMjYxMDAyMjI1NzUwWhcNMjYxMDAzMjI1NzUwWjArMSkwJwYDVQQDDCBEaXNwb3NhYmxlLVB1YmxpYy1SZWFkZXItRml4dHVyZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP6BbLGMaCO43s4BegokVD3FbytbyMSCeayyDxGJm+N+XEAO+9DcDAJf27UcWZKd0TdckqDLOu3+1ScQTREFi+6jMjAwMB0GA1UdDgQWBBTexRlA2He6kVY2UL3NTJi6MrvRTzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIB0VsnglpNS75gEdXOCCUlUC7wlzxUBBjeAbBQWWRC96AiAs0cUQFMuh68hj7v/MQWjH3JcgD4QDmUUId7Dt2Xwb3Q=="
  )!

  struct Inventory: PIVRecoveryTokenInventoryProviding {
    let card: Card
    func connections(maximumCount _: Int) throws -> [any PIVRecoveryTokenConnection] { [card] }
  }

  final class Card: PIVRecoveryTokenConnection, @unchecked Sendable {
    let tokenID = "registration-software-token"
    let readerSlotName = "registration-software-reader"
    let isValid = true
    private let lock = NSLock()
    private let certificate: Data
    private let publicKey: Data
    private var record: Data?
    private var pin: UInt8 = 3
    private var active = false
    private var sessions = 0
    var publicSessions: Int { lock.withLock { sessions } }
    var inSession: Bool { lock.withLock { active } }
    var anchor: Data? {
      get { lock.withLock { record } }
      set { lock.withLock { record = newValue } }
    }
    var pinPolicy: UInt8 {
      get { lock.withLock { pin } }
      set { lock.withLock { pin = newValue } }
    }
    init(publicKey: Data) throws {
      self.publicKey = publicKey
      // A public container fixture only. Signature/issuer trust is not claimed.
      var der = PIVRecoveryTestSupport.certificate
      let point = try PIVRecoveryTokenReader.certificatePublicKey(der)
      let range = try #require(der.range(of: point))
      der.replaceSubrange(range, with: publicKey)
      certificate = der
      #expect(try PIVRecoveryTokenReader.certificatePublicKey(der) == publicKey)
    }
    func withPublicReadSession<T>(
      lease: PIVTokenOperationLease,
      _ consume: ((PIVPublicReadCommand) throws -> PIVPublicReadReply) throws -> T
    ) throws -> T {
      lock.withLock {
        active = true
        sessions += 1
      }
      defer {
        lock.withLock { active = false }
        withExtendedLifetime(lease) {}
      }
      return try consume { command in
        switch command {
        case .selectApplication: return .init(data: nil, status: 0x9000)
        case .keyManagementCertificate:
          return .init(
            data: Self.tlv(0x53, Self.tlv(0x70, self.certificate) + Self.tlv(0x71, Data([0]))),
            status: 0x9000)
        case .keyManagementMetadata:
          return .init(
            data: Self.tlv(1, Data([0x11])) + Self.tlv(2, Data([self.pinPolicy, 2]))
              + Self.tlv(3, Data([1])) + Self.tlv(4, Self.tlv(0x86, self.publicKey)), status: 0x9000
          )
        case .recoveryAnchor:
          guard let anchor = self.anchor else { return .init(data: nil, status: 0x6a82) }
          return .init(data: Self.tlv(0x53, anchor), status: 0x9000)
        }
      }
    }
    private static func tlv(_ tag: UInt8, _ value: Data) -> Data {
      let size =
        value.count < 128
        ? [UInt8(value.count)] : [0x82, UInt8(value.count >> 8), UInt8(value.count & 255)]
      return Data([tag] + size) + value
    }
  }

  final class Provider: PIVRecoveryAgreementProviding, @unchecked Sendable {
    let token: P256.KeyAgreement.PrivateKey
    let card: Card
    private let lock = NSLock()
    private var count = 0
    var requests: Int { lock.withLock { count } }
    var cancel = false
    var onAgree: @Sendable () throws -> Void = {}
    init(token: P256.KeyAgreement.PrivateKey, card: Card) {
      self.token = token
      self.card = card
    }
    func makeSession() -> any PIVRecoveryAgreementSession { Session(provider: self) }
    func agree(_ peer: Data) throws -> Data {
      lock.withLock { count += 1 }
      #expect(!card.inSession)
      try onAgree()
      if cancel { throw PIVRecoveryAgreementError.cancelled }
      return try token.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: peer)
      ).withUnsafeBytes { Data($0) }
    }
  }

  private struct Key: PIVRecoveryAgreementKey {
    let tokenID = "registration-software-token"
    let publicKey: Data
    let isP256PrivateKey = true
    let supportsStandardECDH = true
  }

  private struct Session: PIVRecoveryAgreementSession {
    let provider: Provider
    func authenticate(key _: any PIVRecoveryAgreementKey) throws {}
    func keys(tokenID _: String, publicKey _: Data) throws -> [any PIVRecoveryAgreementKey] {
      [Key(publicKey: provider.token.publicKey.x963Representation)]
    }
    func agree(key _: any PIVRecoveryAgreementKey, peer: Data) throws -> Data {
      try provider.agree(peer)
    }
    func invalidate() {}
  }
}
