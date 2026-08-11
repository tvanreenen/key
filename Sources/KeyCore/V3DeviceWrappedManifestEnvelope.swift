import Foundation
internal import JSONCanonicalization

struct V3DeviceWrappedManifestEnvelope: Equatable, Sendable {
    let parents: [Data]
    let body: V3DeviceWrappedManifestBody
    let authenticationTag: Data
    let authorizations: [V3ManifestAuthorization]
    let canonicalBytes: Data
    let canonicalContentBytes: Data
}

/// The current outer envelope fields that remain verifiable before this
/// version of Key understands a newer manifest-body profile.
struct V3DeviceWrappedManifestEnvelopeMetadata: Equatable, Sendable {
    let parents: [Data]
    let authorizations: [V3ManifestAuthorization]
    let canonicalContentBytes: Data
}

struct V3DeviceWrappedManifestEnvelopeCodec: Sendable {
    private static let format = "key-vault-manifest-envelope"
    private static let version: UInt64 = 3
    private static let authenticationAlgorithm = "HKDF-SHA256+HMAC-SHA256"
    private static let authorizationAlgorithm = "P-256-ECDSA-SHA256"

    private struct ParsedContainer {
        let manifestValue: CanonicalJSONValue
        let authenticationTag: Data
        let metadata: V3DeviceWrappedManifestEnvelopeMetadata
    }

    func parse(_ data: Data) throws -> V3DeviceWrappedManifestEnvelope {
        let container = try parseContainer(data)
        let body: V3DeviceWrappedManifestBody
        do {
            body = try V3DeviceWrappedManifestCodec().decodeBody(
                container.manifestValue,
                path: "$.content.manifest"
            )
        } catch let error as V3DeviceWrappedManifestError {
            if case let .unsupportedProfileVersion(version) = error {
                throw V3DeviceWrappedUnlockError.unsupportedProfileVersion(
                    version
                )
            }
            throw V3DeviceWrappedUnlockError.invalidManifest
        } catch {
            throw V3DeviceWrappedUnlockError.invalidManifest
        }
        return V3DeviceWrappedManifestEnvelope(
            parents: container.metadata.parents,
            body: body,
            authenticationTag: container.authenticationTag,
            authorizations: container.metadata.authorizations,
            canonicalBytes: data,
            canonicalContentBytes: container.metadata.canonicalContentBytes
        )
    }

    /// Parses only the supported outer envelope. This lets discovery verify
    /// the direct-parent relationship and owner signature of a newer body
    /// profile without interpreting that unknown body as current state.
    func metadata(
        _ data: Data
    ) throws -> V3DeviceWrappedManifestEnvelopeMetadata {
        try parseContainer(data).metadata
    }

    private func parseContainer(_ data: Data) throws -> ParsedContainer {
        let value: CanonicalJSONValue
        do {
            value = try CanonicalJSON.parse(data)
        } catch {
            throw V3DeviceWrappedUnlockError.invalidManifest
        }
        guard CanonicalJSON.encode(value) == data,
              let root = value.objectValue,
              string("format", in: root) == Self.format,
              let version = integer("version", in: root)
        else {
            throw V3DeviceWrappedUnlockError.invalidManifest
        }
        guard version <= Self.version else {
            throw V3DeviceWrappedUnlockError.unsupportedEnvelopeVersion(
                version
            )
        }
        guard version == Self.version,
              Set(root.map(\.0)) == Set([
                  "authentication", "authorizations", "content", "format",
                  "version",
              ]),
              let contentValue = member("content", in: root),
              let content = contentValue.objectValue,
              Set(content.map(\.0)) == Set(["manifest", "parents"]),
              let parentValues = member("parents", in: content)?.arrayValue,
              let manifestValue = member("manifest", in: content),
              let authentication = member(
                  "authentication",
                  in: root
              )?.objectValue,
              Set(authentication.map(\.0)) == Set(["algorithm", "tag"]),
              string("algorithm", in: authentication)
                == Self.authenticationAlgorithm,
              let encodedTag = string("tag", in: authentication),
              let authenticationTag = Base64URL.decodeCanonical(encodedTag),
              authenticationTag.count == 32,
              let authorizationValues = member(
                  "authorizations",
                  in: root
              )?.arrayValue
        else {
            throw V3DeviceWrappedUnlockError.invalidManifest
        }

        return try ParsedContainer(
            manifestValue: manifestValue,
            authenticationTag: authenticationTag,
            metadata: V3DeviceWrappedManifestEnvelopeMetadata(
                parents: decodeParents(parentValues),
                authorizations: decodeAuthorizations(authorizationValues),
                canonicalContentBytes: CanonicalJSON.encode(contentValue)
            )
        )
    }

    private func decodeParents(
        _ values: [CanonicalJSONValue]
    ) throws -> [Data] {
        var parents: [Data] = []
        for value in values {
            guard let encoded = value.stringValue,
                  let digest = Base64URL.decodeCanonical(encoded),
                  digest.count == 32,
                  parents.last.map({ $0.lexicographicallyPrecedes(digest) })
                    ?? true
            else {
                throw V3DeviceWrappedUnlockError.invalidManifest
            }
            parents.append(digest)
        }
        return parents
    }

    private func decodeAuthorizations(
        _ values: [CanonicalJSONValue]
    ) throws -> [V3ManifestAuthorization] {
        var result: [V3ManifestAuthorization] = []
        for value in values {
            guard let authorization = value.objectValue,
                  Set(authorization.map(\.0)) == Set([
                      "algorithm", "signature", "signerDeviceID",
                  ]),
                  string("algorithm", in: authorization)
                    == Self.authorizationAlgorithm,
                  let signerDeviceID = string(
                      "signerDeviceID",
                      in: authorization
                  ),
                  let signerBytes = Base64URL.decodeCanonical(signerDeviceID),
                  signerBytes.count == 32,
                  let encodedSignature = string(
                      "signature",
                      in: authorization
                  ),
                  let signature = Base64URL.decodeCanonical(encodedSignature),
                  signature.count == 64,
                  V3P256Signature.isCanonical(signature),
                  result.last.map({
                      Data($0.signerDeviceID.utf8).lexicographicallyPrecedes(
                          Data(signerDeviceID.utf8)
                      )
                  }) ?? true
            else {
                throw V3DeviceWrappedUnlockError.invalidManifest
            }
            result.append(V3ManifestAuthorization(
                signerDeviceID: signerDeviceID,
                signature: encodedSignature
            ))
        }
        return result
    }

    private func member(
        _ name: String,
        in object: [(String, CanonicalJSONValue)]
    ) -> CanonicalJSONValue? {
        object.first(where: { $0.0 == name })?.1
    }

    private func string(
        _ name: String,
        in object: [(String, CanonicalJSONValue)]
    ) -> String? {
        member(name, in: object)?.stringValue
    }

    private func integer(
        _ name: String,
        in object: [(String, CanonicalJSONValue)]
    ) -> UInt64? {
        member(name, in: object)?.integerValue
    }
}
