# Vault symlink containment regression

This defensive, local-only harness creates two disposable sibling directories:
`vault/` and `outside/`. It places `vault/team` as a symbolic link to
`outside/`, applies EntryStore's lexical name validation and URL construction
to `team/probe`, and writes a harmless marker.

The harness confirms that Foundation follows the intermediate symlink and
contrasts that behavior with a resolved-parent containment check. The latter
is diagnostic only; production code should use descriptor-relative operations
that cannot be raced.

Requirements:

- macOS 13 or later
- Xcode Command Line Tools with `swiftc`

Run:

```sh
make run
```

Expected output:

```text
[+] lexical validation accepted team/probe
[+] resolved parent is contained: false
[!] Foundation write landed outside lexical vault root: true
[+] defensive resolved-parent check would reject destination
[+] disposable sandbox cleanup scheduled
```

No user vault or external service is accessed. The temporary filesystem
sandbox is removed automatically. Clean compiler output with:

```sh
make clean
```
