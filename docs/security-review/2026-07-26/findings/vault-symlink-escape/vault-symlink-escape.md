# Intermediate symlinks let entry operations escape the vault root

## Executive Summary

At revision `84e7ddb79141d8f1665f3c1bf2e4254677a988a2`, Key validates entry names
lexically but performs filesystem operations through ordinary Foundation URLs.
The validation rejects absolute paths and literal `.` or `..` components, yet
it does not reject an intermediate symbolic link already present beneath the
configured vault root.

If a vault or synchronization writer can materialize
`vault/team -> outside`, an operation on the valid logical name `team/probe`
reaches `outside/probe.secret`. Depending on the command, the helper can read,
create, replace, copy, move, or remove that path with the current user's
filesystem privileges.

The issue has **Low severity / P3 priority** and maps to **CWE-59: Improper Link
Resolution Before File Access**. The filesystem primitive is deterministic on
the local macOS filesystem, but end-to-end reach through any particular sync
provider is uncertain because providers differ in whether and how they
preserve symbolic links. A local process that can already create the link may
also possess equivalent filesystem authority, reducing incremental impact; the
more meaningful boundary is a remote collaborator or provider that can place a
link in shared storage and induce a matching entry operation.

The affected source reviewed here is revision
`84e7ddb79141d8f1665f3c1bf2e4254677a988a2`; no fixed revision was available.
I reviewed that revision directly and compiled and ran the included disposable
Foundation containment harness. I did not test a real vault, sync provider,
external account, or live service.

## Background

Key maps a logical entry name such as `github/personal` to a file beneath the
configured vault root:

```text
<vault root>/github/personal.secret
```

The vault may be local or placed in synchronized storage. Entry names cross
from the CLI/XPC request into the helper, while directory contents can be
controlled by local filesystem state or synchronization. The security
invariant is that every explicit entry operation remains beneath the vault
root even if a path component is a symbolic link.

`EntryStore` does have a useful lexical traversal control:

```swift
// Sources/KeyCore/EntryStore.swift:36-54
public func validateEntryName(_ name: String) throws {
    let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty else {
        throw AppError.invalidEntryName("Entry name must not be empty.")
    }
    guard !normalized.hasPrefix("/") else {
        throw AppError.invalidEntryName("Entry name must be relative.")
    }

    let components = normalized.split(
        separator: "/",
        omittingEmptySubsequences: false
    )
    for component in components {
        guard !component.isEmpty else {
            throw AppError.invalidEntryName(
                "Entry name must not contain empty path segments."
            )
        }
        guard component != "." && component != ".." else {
            throw AppError.invalidEntryName(
                "Entry name must not contain '.' or '..' segments."
            )
        }
    }
}
```

This correctly rejects common strings such as `../outside`. The distinction
between string traversal and filesystem traversal is the heart of this issue.
A path can be lexically beneath the vault while the kernel resolves one of its
components elsewhere.

## Vulnerability Details

After lexical validation, `url(for:)` appends components without consulting
the filesystem:

```swift
// Sources/KeyCore/EntryStore.swift:56-65
public func url(for name: String) throws -> URL {
    try validateEntryName(name)
    let components = name.split(separator: "/").map(String.init)
    let resolved = components.dropLast().reduce(rootURL) {
        partialResult,
        component in
        partialResult.appendingPathComponent(
            component,
            isDirectory: true
        )
    }
    return resolved
        .appendingPathComponent(
            components.last ?? name,
            isDirectory: false
        )
        .appendingPathExtension("secret")
}
```

Despite the local variable name `resolved`, the returned URL has not resolved
symlinks or been checked against the root's filesystem identity. For
`team/probe`, we therefore carry this lexical path into every sink:

```text
vault/team/probe.secret
```

If `vault/team` is a symlink to the sibling directory `outside`, the kernel
instead resolves:

```text
outside/probe.secret
```

### Read and write sinks

The read path follows the derived URL directly:

```swift
// Sources/KeyCore/EntryStore.swift:107-120
public func load(_ name: String) throws -> SecretFile {
    let fileURL = try url(for: name)
    guard fileManager.fileExists(
        atPath: fileURL.path(percentEncoded: false)
    ) else {
        throw AppError.entryNotFound(
            "Secret '\(name)' was not found."
        )
    }

    do {
        let data = try Data(contentsOf: fileURL)
        return try decoder.decode(SecretFile.self, from: data)
    } catch let error as AppError {
        throw error
    } catch {
        throw AppError.invalidSecretFile(
            "Secret file for '\(name)' is unreadable."
        )
    }
}
```

The write path first creates the destination directory, then creates a
temporary file in that directory and moves or replaces it:

```swift
// Sources/KeyCore/EntryStore.swift:123-144
public func save(
    _ file: SecretFile,
    as name: String,
    overwrite: Bool
) throws {
    let destination = try url(for: name)
    let directory = destination.deletingLastPathComponent()
    try fileManager.createDirectory(
        at: directory,
        withIntermediateDirectories: true
    )

    // Existing overwrite check omitted; it uses the same destination URL.
    let tempURL = directory.appendingPathComponent(
        ".\(destination.lastPathComponent).\(UUID().uuidString).tmp"
    )
    defer { try? fileManager.removeItem(at: tempURL) }

    let data = try encoder.encode(file)
    try data.write(to: tempURL, options: .completeFileProtection)
    if fileManager.fileExists(
        atPath: destination.path(percentEncoded: false)
    ) {
        _ = try fileManager.replaceItemAt(
            destination,
            withItemAt: tempURL
        )
    } else {
        try fileManager.moveItem(
            at: tempURL,
            to: destination
        )
    }
    // Existing error translation omitted.
}
```

An intermediate symlink affects both `directory` and `destination`. The
temporary encrypted envelope is created outside the root, and the final move
or replacement also occurs there.

### Copy, move, and removal sinks

The remaining explicit-name operations use the same construction:

| Operation | Source lines | Symlink-sensitive calls |
|---|---:|---|
| `exists` | 67–69 | `fileExists(atPath:)` |
| `copyEntry` | 152–183 | `createDirectory`, `copyItem`, `replaceItemAt`, `moveItem` |
| `moveEntry` | 186–220 | `createDirectory`, `moveItem`, `replaceItemAt` |
| `removeEntry` | 223–236 | `fileExists`, `removeItem` |
| directory pruning | 239–250 | `contentsOfDirectory`, `removeItem` |

We do not need a race for the basic trigger. Once the intermediate link exists,
Foundation follows it during the requested operation. A precheck added later
with `resolvingSymlinksInPath()` would detect this static case, but it would
still leave a time-of-check/time-of-use window if an attacker can swap a
directory component after the check.

`listEntries` resolves enumerated paths at lines 76 and 91. That is not a
control for these sinks: explicit-name methods call `url(for:)` independently
and perform no containment check. Enumeration behavior around directory
symlinks also varies and is not required for a caller that already knows or is
induced to use the logical name.

## Exploitability Analysis

The strongest path begins with a writer that can affect the vault directory
but should not control filesystem operations outside it:

1. create or synchronize an intermediate symlink such as
   `vault/team -> outside`;
2. induce the user or an automated workflow to add, edit, copy, rename, get, or
   remove `team/probe`;
3. let `validateEntryName` accept the ordinary two-component name;
4. let Foundation and the kernel follow `team`;
5. observe the operation at `outside/probe.secret`.

The primitive is constrained. Key always adds the `.secret` suffix to the leaf
name, so direct targets have that filename shape. `save` writes a JSON-encoded,
encrypted `SecretFile`, not arbitrary attacker-chosen bytes. `load` requires
the outside file to decode as `SecretFile`, and useful decryption additionally
requires compatibility with the current vault key. OS permissions still apply
to every target.

The deletion effect is more direct: `removeEntry` can unlink a matching
outside `.secret` file when an intermediate symlink names its directory.
Copying or moving can also affect matching files outside the root. These are
integrity and availability effects rather than unrestricted arbitrary-file
read/write primitives.

The trigger's incremental value depends on the actor:

- A same-user local process able to create the symlink may already be able to
  access the outside target directly.
- A shared-directory collaborator, synchronization service, or compromised
  remote peer may cross a meaningful boundary if the provider preserves the
  symlink and the local helper later acts on the matching logical name.
- A provider that rejects, dereferences, or serializes symlinks as ordinary
  files blocks this particular delivery route.

I did not establish which behavior iCloud synchronization or any other named
provider uses for this exact vault layout. The report therefore treats
provider delivery as uncertain while separating it from the locally reproduced
Foundation sink.

Leaf symlinks can behave differently from intermediate directory symlinks:
some replacement and removal APIs operate on the link itself. The validated
route deliberately uses an intermediate directory link, where normal path
resolution reaches the external directory before the final file operation.

There is also a raceable variant. Even if Key canonicalizes the parent once,
an attacker able to mutate the vault concurrently can replace a checked
directory with a symlink before `Data.write`, `copyItem`, `moveItem`, or
`removeItem`. That is why a string-prefix or resolve-then-use patch is helpful
diagnostically but not a complete security boundary.

## Proof of Concept

The `poc/` directory contains a defensive, disposable containment regression.
It creates two sibling directories under a fresh temporary sandbox:
`vault/` and `outside/`. It then creates `vault/team` as a symbolic link to
`outside/`, applies the relevant `EntryStore` lexical validation and URL
construction to `team/probe`, and writes a harmless marker through the derived
URL.

The harness also resolves the destination parent to show that a diagnostic
containment check would reject the static link. It does not touch a user vault
or external service, and it removes the entire temporary sandbox on exit.

From the report directory:

```sh
cd poc
make run
```

Representative output:

```text
[+] lexical validation accepted team/probe
[+] resolved parent is contained: false
[!] Foundation write landed outside lexical vault root: true
[+] defensive resolved-parent check would reject destination
[+] disposable sandbox cleanup scheduled
```

The warning line demonstrates the validated filesystem transition: although
the requested URL is lexically under `vault/`, the marker exists under
`outside/`. This is a containment regression, not an exploit against real
data.

Clean compiler output with:

```sh
make clean
```

I compiled and ran the included harness successfully on macOS and observed the
output above. I did not test a live sync path, race another process, or touch
non-disposable data.

## Remediation

The invariant to restore is:

> Every entry operation must resolve each path component relative to one
> already-open vault directory and must fail if any component is a symbolic
> link; validation and use must be one kernel-mediated operation chain.

The robust fix is a small descriptor-relative filesystem layer built on
`openat`, `mkdirat`, `renameat`, `unlinkat`, and `fstatat`:

1. open the configured vault root once as a directory with
   `O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`;
2. retain that descriptor and its `fstat` identity for the store lifetime;
3. walk every intermediate entry component with `openat` using
   `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`;
4. create missing directories with `mkdirat`, then open them with the same
   no-follow flags;
5. open read and write leaves with `O_NOFOLLOW` and verify regular-file type
   with `fstat`;
6. create temporary files and rename them relative to the verified parent
   descriptor;
7. copy and move using verified source and destination descriptors;
8. delete with `unlinkat` relative to the verified parent;
9. enumerate from the same root descriptor and skip symlink entries.

An illustrative intermediate-directory helper is:

```swift
import Darwin

private func openDirectoryComponent(
    parentFD: Int32,
    component: String
) throws -> Int32 {
    guard !component.isEmpty,
          component != ".",
          component != "..",
          !component.contains("/") else {
        throw AppError.invalidEntryName(
            "Entry path component is invalid."
        )
    }

    let fd = component.withCString {
        openat(
            parentFD,
            $0,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
    }
    guard fd >= 0 else {
        if errno == ELOOP {
            throw AppError.invalidEntryName(
                "Entry paths must not contain symbolic links."
            )
        }
        throw AppError.io(
            "Failed to open an entry directory component."
        )
    }
    return fd
}
```

The same principle must reach the leaf. For example, a save operation should
create a random temporary file with `openat(parentFD, ..., O_CREAT | O_EXCL |
O_NOFOLLOW, 0o600)`, write and synchronize it, then use a descriptor-relative
rename. Overwrite policy must be enforced atomically rather than with a
separate `fileExists` check.

Canonicalizing `rootURL` and checking that a resolved parent begins with the
root's path components is worthwhile as defense in depth and produces clearer
errors. It is not the primary fix because an attacker can change filesystem
state between that check and a later Foundation call. A string
`hasPrefix(root.path)` check is additionally unsafe at path boundaries such as
`/vault` versus `/vault-old`.

Regression tests should cover every explicit-name sink:

- save through an intermediate symlink: reject and leave outside directory
  unchanged;
- load through an intermediate symlink: reject before reading;
- copy with symlinked source and symlinked destination independently;
- move with symlinked source and symlinked destination independently;
- remove through an intermediate symlink: outside file survives;
- leaf symlink for read, overwrite, move, and remove;
- a directory swapped for a symlink between competing operations;
- configured root symlink according to an explicit allow-or-reject policy;
- symlink encountered during listing: skip or fail consistently;
- path-prefix siblings such as `vault` and `vault-old`;
- cleanup/pruning never traverses or removes outside the opened root;
- permissions and atomic overwrite behavior remain correct after the
  descriptor-relative conversion.

Provider integration tests should be separate and conditional. They can
document whether a supported synchronization backend preserves a symlink, but
local containment must remain correct regardless of provider behavior.

## Summary

Revision `84e7ddb79141d8f1665f3c1bf2e4254677a988a2` rejects literal path
traversal but joins valid components into ordinary Foundation URLs. We traced
that lexical path into all explicit-name read, write, copy, move, and remove
sinks and reproduced an intermediate directory symlink redirecting a harmless
write outside the lexical vault root.

The impact is constrained by user permissions, the forced `.secret` suffix,
envelope format, required user workflow, and uncertain sync-provider symlink
support. The durable repair is nevertheless clear: anchor every operation to
an already-open vault directory descriptor and reject symbolic links during
component-by-component traversal, eliminating both static escapes and
resolve-then-use races.
