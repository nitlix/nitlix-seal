# Nitlix Seal — agent instructions

Read `nitlix-seal-architecture.md` before implementing crypto or key-handling code.

## Returned key naming

When a function returns key material, **property names must match the key names from the spec** — not generic aliases like `privateKey`, `publicKey`, or `copyablePrivateKey`.

| Key   | Type        | Return when…                          |
| ----- | ----------- | ------------------------------------- |
| `GK`  | Symmetric   | Server-side helpers that expose GK    |
| `UK`  | Symmetric   | User wrap key derived from seed       |
| `PUIK`| Asymmetric  | Hybrid identity public (mailbox)      |
| `PRIK`| Asymmetric  | Hybrid identity private (client only) |
| `CK`  | Symmetric   | Content keys                          |

Examples:

```ts
// Good
{ UK: "…" }
{ PUIK: "…", PRIK: "…" }
{ seedPhrase: "…", UK: "…" }

// Bad
{ privateKey: "…", publicKey: "…" }
{ copyablePrivateKey: "…" }
{ userKey: "…" }
```

`seedPhrase` is the BIP39 root (24 words). It is not a named seal key — use `seedPhrase` for the mnemonic string only.

Encode key bytes as **base64** in JSON-returned objects unless a function explicitly documents another encoding.

## Typing conventions

- Do not use a central/shared type file for function result contracts.
- Declare return types directly on each function.
- When consuming result types in classes or wrappers, prefer `ReturnType<typeof functionName>`.

## Derivation labels (pinned `:v1`)

```
HKDF(seed, "nitlix:uk:v1")       → 32 bytes → UK
HKDF(seed, "nitlix:x25519:v1")   → 32 bytes → X25519 (PRIK_x / PUIK_x)
HKDF(seed, "nitlix:mlkem:v1")    → 64 bytes → ML-KEM-768 keygen → (PRIK_pq / PUIK_pq)
```

`PUIK = PUIK_x ‖ PUIK_pq` and `PRIK = PRIK_x ‖ PRIK_pq` (concatenated bytes, then base64 for API output).

`GK` is **not** derived from the seed. It is supplied to `SealServer` from Worker secrets.

## UK is symmetric

`UK` has no public half. Do not attach a public key to UK-returning functions.

Identity (mailbox) keys live in `deriveIKP()` / `deriveIdentityKeyPair()` → `PUIK` / `PRIK` only.
