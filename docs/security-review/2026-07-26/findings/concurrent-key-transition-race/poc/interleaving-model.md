# Symbolic invariant

For every completed operation:

```text
all(entry.key == vault.activeKey for entry in vault.entries)
```

The repaired coordinator must make transition checkpoints `T0...T2` exclusive
with mutation checkpoints `A0...A1`. Valid execution is therefore either:

```text
A0, A1, T0, T1, T2
```

or:

```text
T0, T1, T2, A0, A1
```

No live execution is part of this model.
