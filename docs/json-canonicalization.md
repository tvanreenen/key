# Canonical JSON Module

## Status and intent

`JSONCanonicalization` is an internal SwiftPM target that owns the canonical
JSON representation used by version 3 vault authentication. Its immediate
purpose is to keep byte-level JSON parsing and serialization separate from
vault schemas, cryptography, and trust decisions.

The target is intentionally not a public package product yet. Its API uses
Swift `package` access so `KeyCore` can consume it across a real module
boundary without presenting an API that we are not ready to support.

This boundary also creates a clean path to a small, dependency-free public
package later. Extracting it is an option, not a requirement for completing
the vault.

## Standards

The implementation is guided by:

- [RFC 8785 — JSON Canonicalization Scheme
  (JCS)](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 8259 — The JavaScript Object Notation
  (JSON)](https://www.rfc-editor.org/rfc/rfc8259.html)
- [RFC 7493 — The I-JSON Message
  Format](https://www.rfc-editor.org/rfc/rfc7493.html)
- [Verified RFC 8785 errata](https://www.rfc-editor.org/errata/rfc8785)
- The [JCS reference implementations and test
  data](https://github.com/cyberphone/json-canonicalization)

RFC 8785 defines the bytes that are authenticated. RFC 8259 defines the JSON
grammar, while RFC 7493 supplies the interoperability constraints on which JCS
depends. Verified errata are part of the review surface, particularly the
guidance concerning negative zero.

## Current profile

The vault format deliberately uses a subset of the values allowed by RFC
8785. For accepted input, the target:

- requires BOM-free UTF-8;
- rejects malformed JSON and decoded duplicate object names;
- accepts strings, booleans, null, arrays, and objects;
- accepts unsigned integers from `0` through `2^53 - 1`;
- rejects negative, fractional, and exponent-form numbers;
- limits container nesting to 32 levels;
- sorts object names by UTF-16 code units;
- emits the required compact string escaping and no insignificant whitespace.

Restricting numbers keeps the vault format interoperable without implementing
the ECMAScript binary64-to-decimal algorithm. It also means the module must not
yet be described or published as a complete RFC 8785 implementation.

The input parser rejects values outside this profile. Programmatically
constructed `CanonicalJSONValue` instances are trusted package-internal input
at present; the encoder does not yet return validation errors for duplicate
members or integers above `2^53 - 1`.

## Ownership boundary

The target owns:

- the canonical JSON value representation;
- byte parsing and UTF-8 validation;
- duplicate-name rejection;
- resource limits that apply while parsing;
- deterministic serialization.

`KeyCore` continues to own:

- the version 3 envelope and manifest schemas;
- allowed, required, and unknown field decisions;
- mapping canonicalization failures to user-facing manifest errors;
- HMAC and signature inputs;
- semantic validation and trust transitions.

Keeping those responsibilities separate prevents a future general-purpose
package from knowing about vault versions, fields, keys, or security policy.

## Testing strategy

`JSONCanonicalizationTests` directly exercises canonical ordering, escaping,
duplicate-name handling, invalid encodings, nesting limits, and the restricted
number profile. `KeyCoreTests` exercises the integration boundary and verifies
that the canonical bytes are the bytes authenticated by the vault.

The RFC 8785 property-ordering vector is covered now. Full publication requires
importing and continuously running the upstream
[JCS test corpus](https://github.com/cyberphone/json-canonicalization/tree/master/testdata),
including its number-serialization vectors.

## Extraction plan

Before publishing the target as an independent package:

1. Define the intended public API and make invalid programmatic values
   unrepresentable or make encoding validate and throw.
2. Implement the complete RFC 8785 number domain and ECMAScript-compatible
   number serialization, including the verified negative-zero erratum.
3. Import the complete upstream conformance corpus and document any additional
   I-JSON policy.
4. Add fuzzing, parser differential tests, resource-exhaustion tests, and
   benchmarks.
5. Confirm supported Swift and platform versions without inheriting the vault
   application's deployment constraints.
6. Add package-level licensing, semantic-versioning, security-reporting,
   release, and compatibility policies.
7. Obtain an independent review of the parser, serializer, public API, and
   conformance claims.
8. Move `Sources/JSONCanonicalization` and
   `Tests/JSONCanonicalizationTests` into their own repository, publish a
   tagged release, and replace the local target with a pinned SwiftPM
   dependency.

Until those gates are complete, the module remains an internal implementation
detail and the version 3 vault storage format remains its only supported use.
