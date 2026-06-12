# Nitlix Seal — Architecture Spec (v2)

**Purpose:** context for the agent building the open-source crypto/orchestration library behind Nitlix Seal. Defines the key hierarchy, the wrap/envelope model, the two operating modes, the sharing protocol, the post-quantum design, and the exact primitives so the library runs identically in any V8 environment (browser, Cloudflare Workers, Deno, Bun, Node). Supersedes v1. Read fully before writing code.

**What changed from v1:** Fast mode is now nested `GK(UK(CK))`, not a parallel `GK(CK)` copy (the server is no longer a standing decryption oracle). The identity keypair is renamed `PUIK`/`PRIK` and is the only asymmetric component — a "mailbox" for receiving shares. It is hardened with hybrid post-quantum crypto (X25519 + ML-KEM-768); everything symmetric is left unchanged because 256-bit symmetric is already quantum-safe. Added: scoped-CK over master-UK for AI, UK/CK transit rules, deterministic-PQ-keygen safety conditions, and crypto-agility versioning.

---

## 1. Goals and non-goals

**Goals**

- Per-user, per-content encryption with a clean wrap model.
- Fast mode: the server can decrypt for AI/agent features, but only with live user participation — never unilaterally, and never from a DB breach alone.
- Strict mode: the server genuinely cannot decrypt.
- Async sharing between users who are never online together, with no long-lived coordination objects.
- Long-term durability against quantum computers.
- Runs everywhere V8 runs. No Node-only APIs.

**Non-goals / honest boundaries (never overclaim in code, comments, or docs)**

- Fast mode is **NOT** end-to-end encryption. It is "encrypted at rest; the server can decrypt only when the user supplies a key in-session." See §5.
- The server is trusted for public-key (PUIK) distribution unless users verify fingerprints. See §6.4.
- A shared content key cannot be un-shared by deletion — only by rotation. See §7.
- Anything sent to an external model provider (e.g. Anthropic) leaves the encryption boundary entirely. Provider-side retention is solved by account config (Zero Data Retention), not by this library. Out of scope here, but on the roadmap.

---

## 2. Key hierarchy

| Key             | Name             | Where it lives                                                                                                            | Type                                                      | Role                                                                                                            |
| --------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **GK**          | Global Key       | Cloudflare Worker secret / KV. Never in the DB.                                                                           | Symmetric, 256-bit (already quantum-safe)                 | Outer layer of the Fast-mode wrap. Gates server participation — useless without the user's UK.                  |
| **UK**          | User Key         | Client only. Derived from seed. Cached client-side; moved device→device via QR + a private Durable Object (never via DB). | Symmetric, 256-bit                                        | Wraps the user's content keys. The everyday key.                                                                |
| **PUIK / PRIK** | Identity keypair | `PRIK` client only. `PUIK` published to the server at seal creation.                                                     | Asymmetric, **hybrid X25519 + ML-KEM-768** (post-quantum) | The "mailbox." Its only job: receive shared content keys. The single asymmetric component, used once per share. |
| **CK**          | Content Key      | Generated client-side. Never stored in plaintext.                                                                         | Symmetric, 256-bit                                        | Encrypts the actual content. Scope = one "sharable" (chat / folder / file).                                     |

`GK` is the server's own key and is **not** derived from the seed. Everything else derives from the user's seed phrase.

---

## 3. Derivation from the seed

Root: a BIP39 phrase, **24 words = 256 bits of entropy**, generated client-side, shown once, saved by the user. The single root of identity; the server never sees it.

```
BIP39 phrase (24 words) → seed (256-bit)
HKDF(seed, "nitlix:uk:v1")      → 32 bytes → UK
HKDF(seed, "nitlix:x25519:v1")  → 32 bytes → X25519 keypair  (PUIK_x / PRIK_x)
HKDF(seed, "nitlix:mlkem:v1")   → 64 bytes → ML-KEM-768 deterministic keygen → (PUIK_pq / PRIK_pq)

PUIK = PUIK_x ‖ PUIK_pq      (published to server)
PRIK = PRIK_x ‖ PRIK_pq      (client only)
```

All keys — symmetric and post-quantum — regenerate deterministically from the one seed. PQ keys are **derived, never stored**, so the word count never grows.

**Four safety conditions for deriving the PQ keypair from the seed (all required):**

1. **Entropy.** A derived key is only as strong as the seed. ML-KEM-768 targets ~192-bit security; the 256-bit seed clears it. **Never shrink the seed to 12 words** — 128-bit entropy would silently cap the PQ key at 128-bit effective strength. 24 words is mandatory once PQ is in play.
2. **Domain separation.** Distinct HKDF labels per key (as above) so all keys are cryptographically independent despite sharing a root. Never reuse bytes across algorithms.
3. **Deterministic keygen, random encapsulation.** Deriving the _keypair_ from the seed is fine and intended. But every _seal_ (encapsulating a CK to a PUIK) MUST use fresh randomness — never seed the encapsulation deterministically. Deterministic keys, random seals. The library does encapsulation randomness by default; do not override it.
4. **Pinned derivation path.** Because keys are derived, not stored, the derivation recipe (KDF, labels, byte order, ML-KEM parameter set) is part of the permanent format. Freeze it and version it (the `:v1` suffix). A future library change to seed-expansion would otherwise lock every user out of their own data.

---

## 4. Wrap / envelope model

Content is always encrypted with **CK**, never directly with UK/GK/PUIK. Only the small CK is wrapped. Notation `A(B)` = B wrapped (encrypted) by key A. All wraps are AEAD (authenticated).

Content encrypted **once**:

```
content = AEAD(CK, plaintext)
```

Each authorized user holds their own wrapped CK:

- **Fast mode (nested):** `GK( UK_user(CK) )` — CK wrapped by the user's UK, that wrapped by GK. Reaching CK needs **both** GK (server) **and** UK (user). Neither alone suffices. The server is never a standing oracle.
- **Strict mode:** `UK_user(CK)` — no GK layer. Only the user can reach CK; reads are fully client-side / offline-capable.

The server does **not** get its own separate copy of CK. Its ability to decrypt rides on the GK layer of each user's nested wrap, and only completes when that user supplies UK (or a scoped CK) live. This is the deliberate "middle ground."

### Storage shape for a sharable

```
content: AEAD(CK, plaintext)
sealPatterns: [
  ["user-1-id", GK(UK1(CK))],   // Fast mode  (Strict: UK1(CK))
  ["user-2-id", GK(UK2(CK))],
]
pendingGrants: [
  ["user-3-id", seal(PUIK3, CK)],  // transient, until user 3 accepts (see §6)
]
```

Each authorized user is a "recipient" with their own nested wrap. `pendingGrants` are transient PUIK-sealed deliveries, deleted once accepted.

---

## 5. Operating modes & access paths

### Read your own content

- **Fast mode:** fetch ciphertext (bulk may come direct from R2) + ask the server to peel the GK layer on the small key blob → `UK(CK)` → client peels UK → CK → decrypt locally. The Worker only ever touches the tiny key blob, never the file bytes. (Optional optimization: cache `UK(CK)` client-side after the first peel for offline reads.)
- **Strict mode:** client peels UK directly. No server round-trip. Offline and direct-from-R2 reads work.

### AI / agent call (Fast mode only)

The server needs plaintext to prompt an agent. Two ways to give it CK — **prefer the first**:

- **Scoped CK (recommended).** The user is already reading the content, so its CK is already decrypted in their client. Attach _that CK_ to the AI request. The server decrypts only that one sharable, calls the agent. **UK never transits.** Blast radius if anything leaks = one sharable.
- **Master UK (only for cross-content server ops).** Sending UK lets the server reach _every_ CK the user owns for the request's lifetime — broad exposure. Reserve for genuine whole-seal server operations (e.g. server-side search), consciously accepting the cost.

**Strict mode has no server-side AI** — the server can't decrypt, by design. AI in Strict mode is limited to client-side or device→provider-direct. State this as a deliberate limitation.

**Autonomous-agent note:** an agent acting while the user is _offline_ fundamentally needs standing decryption ability, which collides with "server can't decrypt without you." That requires a separate, explicit relaxation (e.g. a user-granted, time-boxed session key) — do not solve it by weakening the default model.

### Mode summary

|                     | Fast mode (default)                                                                | Strict mode                                          |
| ------------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Stored wrap         | `GK(UK(CK))`                                                                       | `UK(CK)`                                             |
| Server can decrypt? | Only with live UK or scoped CK from the user. Never alone, never from a DB breach. | No.                                                  |
| Own reads           | Server peels GK, client peels UK                                                   | Fully client-side / offline                          |
| AI features         | Yes (via scoped CK)                                                                | No server AI — client-side only                      |
| Honest label        | "Encrypted at rest" — NOT E2EE                                                     | "End-to-end encrypted: Nitlix cannot read your data" |

Reserve "end-to-end" for Strict mode only.

---

## 6. Sharing protocol — the PUIK mailbox

The only place the identity keypair is used. Symmetric keys cannot deliver a secret to an offline user without the server reading it; the asymmetric PUIK/PRIK pair is the primitive that can.

### 6.1 Precondition

Every user publishes their **PUIK at seal creation** (not lazily). Every user is "shareable-to" from the moment they exist.

### 6.2 Share (only user 1 online)

1. User 1 obtains CK (server peels GK → `UK1(CK)` → client peels UK1 → CK).
2. Fetch user 2's **PUIK** from the server.
3. _(Recommended)_ verify the fingerprint — §6.4.
4. **Hybrid-seal** CK to PUIK2 (fresh encapsulation randomness — §3 condition 3) → `seal(PUIK2, CK)`.
5. Upload as a `pendingGrant`. The server stores it. No Durable Object, no expiry — the sealed blob is safe at rest indefinitely because only PRIK2 opens it.

### 6.3 Accept (user 2, any time later)

1. Fetch the grant `seal(PUIK2, CK)`.
2. Open with PRIK2 → CK. (Plaintext CK exists only in user 2's client, for the instant of re-wrapping.)
3. Wrap with own UK2 → `UK2(CK)`. Upload it.
4. **The server applies the outer GK layer** (GK is the server's key) → stores `GK(UK2(CK))` in `sealPatterns`. For a Strict-mode sharable, no GK layer — store `UK2(CK)` as-is.
5. Delete the `pendingGrant` — it's spent.

After accept, user 2 reads via symmetric UK2 like everyone else. The PQ operation happened once.

### 6.4 Trust boundary (document precisely)

The server distributes PUIKs. A malicious server could substitute its own key and intercept a _share_. In Fast mode this is moot (server can decrypt with user cooperation anyway). In **Strict mode** it is the one residual point where a malicious server could insert itself into a share. Mitigation: fingerprint/safety-number verification (compare out-of-band), trust-on-first-use by default. Honest copy: _"Strict-mode sharing trusts Nitlix for public-key distribution unless you verify your contact's fingerprint."_

### 6.5 Invite a non-user (separate flow)

PUIK sharing needs an existing published keypair. For someone not yet on Nitlix: wrap CK under a random invite secret, put the secret in the URL **fragment** (`#…`, never sent to the server), store only the wrapped blob. The recipient opens the link, unwraps CK, re-wraps to their new UK on signup. The link **is** the capability — scope to single-use / short-lived. Keep distinct from the PUIK path.

---

## 7. Revocation = rotation (not deletion)

Once a user has received CK they can cache it forever; deleting their `sealPatterns` row does not revoke access. To truly revoke: generate **CK′**, re-encrypt the content, re-distribute CK′ to the remaining authorized users only. Treat "unshare" as "rotate content key." Build the rotation path from day one.

---

## 8. Post-quantum design

**Principle: only the asymmetric component is quantum-vulnerable.** Quantum breaks asymmetric crypto via Shor (exponential — total break of X25519). It only dents symmetric crypto via Grover (quadratic — 256-bit → ~128-bit floor, still unbreakable, and Grover barely parallelizes). So:

- `GK`, `UK`, `CK`, content encryption — symmetric, 256-bit → **already quantum-safe. No change.**
- Identity keypair — asymmetric → **the only thing to harden.**

### Hybrid KEM for the seal

Do not replace X25519 with ML-KEM — **combine** them, so you're safe if _either_ holds (X25519 against a future ML-KEM weakness; ML-KEM against quantum). Standard pairing: **X25519 + ML-KEM-768**.

Seal construction (`seal(PUIK, CK)`):

1. X25519 ECDH to the recipient's X25519 public key → `ss_classical`.
2. ML-KEM-768 encapsulate to the recipient's ML-KEM public key → `ss_pq` + KEM ciphertext. (Fresh randomness.)
3. `key = HKDF(ss_classical ‖ ss_pq ‖ context)` — KDF **both** secrets together, never one.
4. `wrapped = AEAD(key, CK)` (XChaCha20-Poly1305, random 192-bit nonce).
5. Output = `eph_x25519_pub ‖ mlkem_ciphertext ‖ nonce ‖ wrapped`.

Opening reverses with PRIK.

### Size implication → coarse CK granularity for shared content

ML-KEM-768: public key ~1184 B, ciphertext ~1088 B, so each seal carries ~1.2 KB. Used once per share, so negligible at the right granularity — **use per-chat / per-folder CK for shared content**, not per-message, so the ~1 KB is amortized. Self-access wraps stay tiny (symmetric) and can be any granularity.

---

## 9. Cryptographic primitives — web/V8 stack

WebCrypto for universal, hardware-accelerated bulk work; the audited `@noble`/`@scure` suite (pure TypeScript, zero native deps, no WASM, identical everywhere) for modern primitives WebCrypto lacks consistently.

| Operation                               | Primitive                                | Library                                                                                   |
| --------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------- |
| Seed phrase gen/validate                | BIP39 (24-word)                          | `@scure/bip39` (import English wordlist only — ~5 KB gzipped)                             |
| Key derivation from seed                | HKDF-SHA-256                             | `WebCrypto` (or `@noble/hashes`)                                                          |
| **Content encryption (CK → data)**      | **AES-256-GCM**                          | `WebCrypto` (hardware AES; chunk large files — 96-bit random nonce safe to ~2³² msgs/key) |
| Key wrapping (CK under UK; UK under GK) | AES-256-GCM or AES-KW                    | `WebCrypto`                                                                               |
| Hybrid PQ seal (share)                  | X25519 + ML-KEM-768 + XChaCha20-Poly1305 | `@noble/curves` + `@noble/post-quantum` + `@noble/ciphers`                                |
| Optional PQ fingerprint signatures      | ML-DSA                                   | `@noble/post-quantum`                                                                     |

Hard rules: never roll your own ciphers/curves — orchestrate the listed primitives only. All wraps AEAD. GK lives only in Worker secrets/KV, never the DB.

---

## 10. Transit & operational rules

- **UK and CK are radioactive in transit.** Never logged, never in an error payload (scrub from Sentry et al.), never cached. Send them in a header your logging explicitly redacts — not in a JSON body that gets captured wholesale. This hygiene _is_ the Fast-mode security boundary; the crypto is sound, the leak surface is the transit path.
- **Prefer scoped CK over master UK for AI** (§5). UK's blast radius is the user's entire seal; a single CK's is one sharable.
- **The server never sees** the seed, any UK, any PRIK, or a long-lived plaintext CK. (Fast-mode AI legitimately yields transient plaintext content + a scoped CK for the agent call — never UK, never PRIK, never the seed.)
- **Provider retention:** anything sent to an external model leaves the boundary. Require Zero Data Retention (or equivalent) at the account level for AI features. Separate from this library, but on the roadmap.

---

## 11. Crypto-agility / versioning

The highest-leverage long-term protection — not a bigger key (256-bit symmetric is already the ceiling and is quantum-safe), but the ability to swap primitives later.

- **Version-tag every wrapped blob** with algorithm identifiers (content cipher, KDF, KEM, AEAD) and the derivation-label version.
- **Pin the derivation path** (the `:v1` labels) so keys regenerate identically across library upgrades, forever.
- **Migration:** to adopt a new primitive, re-wrap blobs under the new algorithm and bump the version tag. The format must tolerate mixed-version blobs during migration.

---

## 12. Suggested library surface

Keep primitives and orchestration separate. Indicative (names flexible):

```
// identity (all client-side)
generateSeed(): string                         // BIP39, 24 words
deriveIdentity(seed): { uk, x25519, mlkem }    // UK + hybrid keypair
publicIdentity(identity): PUIK                  // published at seal creation

// content keys
createContentKey(): CK
encryptContent(CK, plaintext): bytes
decryptContent(CK, ciphertext): plaintext

// wraps
wrap(key, wrappingKey): blob                    // AEAD, version-tagged
unwrap(blob, wrappingKey): key
buildFastWrap(CK, UK): blob                     // UK(CK); server adds GK
peelGK(blob, GK): blob                          // server-side → UK(CK)
buildStrictWrap(CK, UK): blob                   // UK(CK), no GK

// sharing (hybrid PQ)
sealToIdentity(CK, recipientPUIK): sealed       // fresh encapsulation randomness
openSealed(sealed, myPRIK): CK
fingerprint(PUIK): string                       // §6.4 verification

// lifecycle
rotateContentKey(oldCK, content, recipients): { newCK, reEncrypted, regrants }
```

Server-side helpers (Worker) only ever touch: GK, `peelGK`, applying the GK layer on accept, storing `pendingGrants` and `sealPatterns`, distributing PUIKs. No server function produces a plaintext seed, UK, PRIK, or long-lived CK.

---

## 13. Build order

1. Seed → identity derivation (`@scure/bip39` + HKDF; deterministic X25519 + ML-KEM keypairs with the four safety conditions) and PUIK publication at seal creation.
2. CK + content encryption (AES-256-GCM) and the `GK(UK(CK))` / `UK(CK)` wraps with version tags.
3. Fast/Strict toggle (presence of the GK layer) and the read paths (§5).
4. AI path: scoped-CK request flow + UK-transit redaction rules.
5. Sharing: hybrid PQ seal + `pendingGrants` + accept/re-wrap (server applies GK; delete grant).
6. Rotation (unshare = rotate).
7. Fingerprint verification (§6.4) and the non-user invite-link flow (§6.5).
8. Device→device UK transfer via QR + Durable Object (orthogonal; parallelizable).

```

```
