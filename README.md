# SigTXT

**Post-quantum signed and encrypted message container.**

SigTXT is a command-line tool that wraps a message in a self-contained file (`.sigtxt`) that can be safely sent over any untrusted channel — email, messengers, USB sticks, public file hosting. Only the intended recipient, holding the matching private key, can read it. Any tampering — with either the open header or the encrypted body — is cryptographically detectable.

```bash
sigtxt keygen alice_sign.json --type sign --owner alice@example.com
sigtxt keygen bob_kem.json   --type kem  --owner bob@example.com
sigtxt export-pub alice_sign.json alice_sign.pub.json
sigtxt sign  msg.txt out.sigtxt --sign-key alice_sign.json --to-key bob_kem.pub.json \
             --sender alice@example.com --recipient bob@example.com --subject "Hi"
sigtxt open  out.sigtxt --my-key bob_kem.json --from-key alice_sign.pub.json
```

---

## Table of contents

- [What it is](#what-it-is)
- [What it is not](#what-it-is-not)
- [Design](#design)
- [Cryptographic primitives](#cryptographic-primitives)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [File format](#file-format)
- [Key files](#key-files)
- [Environment variables](#environment-variables)
- [Security model](#security-model)
- [Threat model](#threat-model)
- [Known limitations](#known-limitations)
- [Operational discipline](#operational-discipline)
- [Recovery and rotation](#recovery-and-rotation)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

---

## What it is

A single-purpose tool that takes a text message, signs it with the sender's private key, encrypts it to the recipient's public key, and packages the result into one file. The file has two parts:

- an **open, signed header** (visible without any key) — sender ID, recipient ID, subject, creation time, expiry, algorithm identifiers, key fingerprints;
- an **encrypted, signed body** — the message text plus a copy of the metadata, tied to the header via `SHA3-256(header) || body`.

The header is visible to anyone. The body is readable only by the recipient. Both are cryptographically bound: changing any byte in either part breaks signature verification.

## What it is not

- **Not a transport.** SigTXT does not send anything. It produces a file. How it reaches the recipient is out of scope.
- **Not an email client.** It does not speak SMTP, IMAP, or any messaging protocol. It is not a replacement for PGP/MIME.
- **Not a file encryption tool.** Designed for text messages. Large binary files will work but are loaded entirely into memory.
- **Not a replacement for Signal.** No forward secrecy, no ratcheting, no disappearing messages.
- **Not FIPS 140-3 certified.** See [Limitations](#known-limitations).
- **Not anonymous.** The `sender_id` is in the open header.

## Design

Three principles:

1. **Sign-then-encrypt, always.** The sender signs first, then the entire signed package is encrypted to the recipient. The reversed order is known to be unsafe.
2. **Bind header to body.** The body's signature covers `SHA3-256(header) || body`, so an attacker cannot swap a valid header onto a different body, nor vice versa.
3. **Hybrid by default.** Every cryptographic operation combines a classical algorithm (believed secure today, broken by quantum computers eventually) and a post-quantum algorithm (believed secure against quantum computers, less battle-tested). An attacker must break **both** to succeed.

## Cryptographic primitives

| Function | Default profile | CNSA 2.0 profile |
|---|---|---|
| Signature | Ed25519 + ML-DSA-65 | ML-DSA-87 (pure PQC) |
| Key encapsulation | X25519 + ML-KEM-768 | ML-KEM-1024 (pure PQC) |
| Symmetric AEAD | ChaCha20-Poly1305 | ChaCha20-Poly1305 |
| Hash | SHA3-256 | SHA3-256 |
| KDF (for key file password) | Argon2id (2 GiB, t=1, p=4) | Argon2id (2 GiB, t=1, p=4) |
| Key file AEAD | ChaCha20-Poly1305 | ChaCha20-Poly1305 |

Two profiles, chosen at key generation:

- **`default`** — `Ed25519 + ML-DSA-65` signatures, `X25519 + ML-KEM-768` KEM. Suitable for most civilian use.
- **`cnsa2`** — `ML-DSA-87` and `ML-KEM-1024`, pure post-quantum. Recommended when required by policy (US CNSA 2.0, some government contexts). Larger keys, slower operations, no classical fallback.

Both peers must be on the same profile. `sign` refuses to produce a message if `--sign-key` and `--to-key` are on different profiles.

CNSA 2.0 profile support depends on the installed version of `quantum-safe-py`. If your version does not expose `quantum_safe.compliance.cnsa2`, the `--cnsa` flag will fail with `ImportError`.

## Installation

Requires Python 3.10+.

```bash
pip install argon2-cffi cryptography click "quantum-safe-py[pyca]"
pip uninstall -y liboqs-python   # optional; not used with pyca backend
```

`liboqs-python` is not required. If it is installed on a system without a matching `liboqs` C library, it will attempt to download and compile `liboqs` from GitHub on first import, which is slow and network-dependent. Uninstalling it avoids this.

Argon2id with the high-memory profile allocates ~2 GiB per key operation. On systems with less than 8 GiB free RAM, use `--kdf-profile 2` (256 MiB). Old keys remain readable after choosing either profile at generation time; the KDF parameters are stored in the key file as a version number.

## Quick start

Full one-time setup between two parties:

**Alice:**

```bash
sigtxt keygen alice_sign.json --type sign --owner alice@example.com
sigtxt keygen alice_kem.json  --type kem  --owner alice@example.com
sigtxt export-pub alice_sign.json alice_sign.pub.json
sigtxt export-pub alice_kem.json  alice_kem.pub.json
```

**Bob:**

```bash
sigtxt keygen bob_sign.json --type sign --owner bob@example.com
sigtxt keygen bob_kem.json  --type kem  --owner bob@example.com
sigtxt export-pub bob_sign.json bob_sign.pub.json
sigtxt export-pub bob_kem.json  bob_kem.pub.json
```

**Exchange public keys.** Alice sends `alice_sign.pub.json` and `alice_kem.pub.json` to Bob. Bob sends `bob_sign.pub.json` and `bob_kem.pub.json` to Alice. Public keys are not secret.

**Verify fingerprints.** Read the fingerprints from `sigtxt export-pub` output aloud over a voice call, or compare them in person. This is not optional if you care about MITM. See [Operational discipline](#operational-discipline).

**Alice sends a message:**

```bash
echo "Meeting moved to Thursday." > msg.txt
sigtxt sign msg.txt msg.sigtxt \
  --sign-key alice_sign.json \
  --to-key   bob_kem.pub.json \
  --sender    alice@example.com \
  --recipient bob@example.com \
  --subject   "Meeting"
```

**Bob reads it:**

```bash
sigtxt open msg.sigtxt \
  --my-key   bob_kem.json \
  --from-key alice_sign.pub.json
```

**Bob peeks at the header without decrypting:**

```bash
sigtxt open msg.sigtxt \
  --my-key   bob_kem.json \
  --from-key alice_sign.pub.json \
  --header-only
```

## Command reference

### `keygen`

```
sigtxt keygen OUTPUT --type {sign,kem} --owner ID [OPTIONS]
```

Generates a keypair. `--type sign` produces a signing keypair (used by the sender). `--type kem` produces a KEM keypair (used by the recipient).

| Option | Default | Description |
|---|---|---|
| `--type` | `sign` | `sign` for signature keys, `kem` for encryption keys. |
| `--owner` | — | Owner ID, canonicalized and stored. Required unless `--allow-no-owner`. |
| `--password` | `$SIGTXT_PASSWORD` | Password protecting the private key. |
| `--password-file` | — | Read password from file. Mutually exclusive with `--password`. |
| `--no-password` | — | Store private key unencrypted. Insecure. |
| `--kdf-profile` | `1` | `1` = 2 GiB Argon2id, `2` = 256 MiB. |
| `--cnsa` | — | Use CNSA 2.0 profile. |
| `--allow-no-owner` | — | Skip owner binding. Not recommended. |
| `--force` | — | Overwrite existing file. |

If neither `--password`, `--password-file`, nor `$SIGTXT_PASSWORD` is set and `--no-password` is not passed, the tool prompts interactively. In a non-interactive context, it errors instead of silently producing an unencrypted key.

### `export-pub`

```
sigtxt export-pub KEY_FILE OUTPUT [--force]
```

Extracts only the public part of a keypair into a separate file. Never touches the private part.

### `change-password`

```
sigtxt change-password KEY_FILE [OPTIONS]
```

Re-encrypts the private key under a new password. The keypair itself does not change, so the fingerprint is unchanged and no correspondent needs to update anything.

Options: `--old-password`, `--old-password-file`, `--new-password`, `--new-password-file`, `--kdf-profile`. Falls back to `$SIGTXT_PASSWORD` for the old password, and to interactive prompt if a terminal is available.

The write is atomic (temp file + `fsync` + `rename`) — an interrupted `change-password` leaves the old key intact.

### `sign`

```
sigtxt sign MESSAGE_FILE OUTPUT --sign-key KEY --to-key KEY \
       --sender ID --recipient ID --subject TEXT [OPTIONS]
```

Produces a `.sigtxt` file. `--sign-key` must be a private signing key (unlocked with `--password` or `$SIGTXT_PASSWORD`). `--to-key` must be the recipient's **public** KEM key (from `export-pub`).

| Option | Default | Description |
|---|---|---|
| `--encoding` | `utf-8` | Encoding of the input text file. |
| `--content-type` | `text/plain` | Stored in header and body, not interpreted. |
| `--cnsa` | — | Require CNSA 2.0. Errors if the sign key is `default`. |
| `--ttl-days` | `30` | Expiry in days. Set to `0` for immediate expiry (mostly useful for testing). |
| `--force` | — | Overwrite existing output file. |

Refuses if `--sign-key` and `--to-key` are on different profiles. Refuses if the header exceeds `MAX_HEADER_BYTES` (64 KiB). Refuses if the container exceeds `MAX_TOTAL_BYTES` (1 GiB).

### `open`

```
sigtxt open SIGTXT_FILE --my-key KEY --from-key KEY [OPTIONS]
```

Verifies the header, decrypts the body, verifies the body signature, and prints the message.

| Option | Description |
|---|---|
| `--password`, `--password-file` | Password for the recipient's private key. |
| `--out FILE` | Save the plaintext to a file. |
| `--header-only` | Verify and print the open header only. Does not decrypt, does not touch the private key. |
| `--cnsa` | Require CNSA 2.0 profile. Errors if the file is `default`. |
| `--allow-no-owner` | Skip `sender_id` / `recipient_id` verification. Not recommended. |

Prints `WARNING: this message has been read before` to stderr if the same `unique_stamp` was seen by this machine. See [Limitations](#known-limitations).

## File format

Version 2, all integers big-endian:

```
offset  size        field
0       8           MAGIC       = b"SIGTXT\x02"
8       1           VERSION     = 2
9       4           L_header    (uint32)
13      L_header    header_json (UTF-8 JSON, canonical)
13+L    2           L_hsig      (uint16)
15+L    L_hsig      header_sig  (CBOR of SignedMessage)
15+L+S  …           ciphertext  (Envelope: KEM-sealed AEAD)
```

Inside `ciphertext`, after decryption, the plaintext is:

```
offset  size        field
0       2           L_psig      (uint16)
2       L_psig      payload_sig (CBOR of SignedMessage over SHA3-256(header) || body)
2+L      …           body        (UTF-8 JSON)
```

`header_json` fields:

| Field | Purpose |
|---|---|
| `subject` | Visible subject line. |
| `sender_id`, `recipient_id` | Canonicalized IDs. |
| `created_at`, `not_after` | ISO 8601, UTC, `Z` suffix. |
| `unique_stamp` | `SHA3-256(sender \| recipient \| created_at \| nonce \| prefix_hash)`. |
| `size_bytes` | Length of the body text in bytes, after encoding. |
| `encoding`, `content_encoding`, `content_type` | Text encoding and MIME info. |
| `signature_algorithm`, `kem_algorithm` | Algorithm identifiers. Must match a whitelisted pair. |
| `signer_fingerprint`, `recipient_fingerprint` | `sha3:<128-bit-hex>` fingerprints of the sender's and recipient's public keys. |

`body` JSON contains `meta` (a copy of the header fields, plus `nonce`) and `text`.

## Key files

Keypairs are stored as JSON:

```json
{
  "type": "sign",
  "owner": "alice@example.com",
  "profile": "default",
  "fingerprint": "sha3:abc…",
  "secret_enc": "password",
  "kdf_version": 1,
  "secret": { "salt": "…", "nonce": "…", "ct": "…" },
  "public": { "enc": "b64", "data": "…" }
}
```

- `secret_enc = "password"` means the private key is encrypted with Argon2id + ChaCha20-Poly1305.
- `secret_enc = null` means the private key is stored as CBOR, unencrypted. This is only produced by `--no-password`.
- `fingerprint` is recomputed on every load and compared against the stored value. A mismatch aborts the load.
- `owner` is canonicalized: lowercase, `[a-z0-9@._+-]{1,128}`. Stored as `null` if not set.

Files created by `keygen` have mode `0600` (POSIX) or the equivalent ACL on Windows. This is a courtesy, not a security boundary — see [Operational discipline](#operational-discipline).

## Environment variables

| Variable | Purpose |
|---|---|
| `SIGTXT_PASSWORD` | Default password for `--password`. |
| `SIGTXT_OLD_PASSWORD` | Default for `change-password --old-password`. |
| `SIGTXT_NEW_PASSWORD` | Default for `change-password --new-password`. |
| `SIGTXT_HOME` | Directory for `replay.db`. Defaults to `~/.sigtxt`. |

## Security model

What SigTXT **guarantees**, assuming the implementation and its dependencies are correct:

- **Confidentiality of the body.** Only someone holding the private key corresponding to `recipient_fingerprint` can decrypt the body. This requires breaking the KEM, which is a hybrid of X25519 and ML-KEM (or pure ML-KEM-1024 under CNSA 2.0).
- **Authenticity of the header and body.** Only someone holding the private key corresponding to `signer_fingerprint` can produce a header or body that passes verification. This requires breaking the signature scheme.
- **Integrity and binding.** Any single-bit change to the header, the body, the header signature, the body signature, or the ciphertext is detected.
- **Header/body binding.** An attacker cannot take a valid header and attach it to a different body, or vice versa, because the body signature covers `SHA3-256(header) || body`.
- **Metadata consistency.** After decryption, `unique_stamp`, `subject`, and `size_bytes` are compared between header and body. A mismatch aborts.
- **Expiry and clock-skew checks.** `created_at` more than 5 minutes in the future, or past `not_after`, aborts.
- **Key pinning.** If fingerprints are present in the header, they are compared to the fingerprints of the keys actually used to decrypt and verify. A mismatch aborts.

What SigTXT **does not guarantee**:

- **Anonymity.** `sender_id`, `recipient_id`, `subject`, `created_at`, `not_after`, both fingerprints, and approximate message size are visible to anyone who obtains the file.
- **Metadata privacy.** Same as above.
- **Delivery.** Nothing prevents an attacker from deleting, delaying, or substituting the file.
- **Forward secrecy.** Compromising a recipient's private key compromises all past messages sent to that key.
- **Deniability.** Signatures prove authorship to anyone who trusts the sender's public key.

## Threat model

**In scope:**

- Passive eavesdropper with the file.
- Active attacker with the file, who can modify any byte.
- Attacker with access to the sender's or recipient's **public** keys.
- Attacker with a quantum computer (assuming ML-KEM and ML-DSA are not broken; the hybrid provides a classical fallback if they are).
- Replay to the same machine, detected with a warning (see [Limitations](#known-limitations)).
- MITM on public key exchange, detected if the operator follows [Operational discipline](#operational-discipline).

**Out of scope:**

- Compromised endpoint. If the attacker has code execution on the sender's or recipient's machine while the private key is in memory, they can read everything. No cryptographic tool can prevent this.
- Compromised private key. If the private key is stolen, all past and future messages to that key are readable.
- Compromised dependencies. If `quantum-safe-py`, `cryptography`, `argon2-cffi`, or `click` are backdoored, the tool is compromised. Supply-chain attacks on Python packages are not prevented.
- Traffic analysis beyond file size. If you send 40 kB every day at 14:00 to the same recipient, an observer learns the pattern even if they cannot read content.
- Coercion or legal compulsion. If you are forced to reveal a key, SigTXT cannot help.

## Known limitations

- **Argon2id parameters are tied to the key file.** A key generated with `--kdf-profile 1` will always use 2 GiB when unlocked. If you need to move a key to a memory-constrained environment, regenerate with `--kdf-profile 2`.
- **`quantum-safe-py` has not been audited.** It passes ACVP test vectors, which is evidence of correct implementation, not independent validation. For high-assurance deployments, consider Rust with `ml-kem` and `ml-dsa` and independent review.
- **No FIPS 140-3 certification.** Neither `quantum-safe-py` nor the Python `cryptography` stack used here is FIPS-validated. Use a certified HSM if this matters.
- **Replay warning is local.** `~/.sigtxt/replay.db` is per-machine. Reading the same message on a different machine will not trigger the warning. The stamp is informational, not a security control.
- **No forward secrecy.** Compromising the recipient's private key compromises the entire history.
- **No padding.** File size reveals approximate message length. An attacker can distinguish short notes from long documents.
- **No multi-recipient.** One message per recipient. N recipients require N files.
- **No detached signatures.** `sign` always produces a combined signed-and-encrypted file.
- **Legacy files without fingerprints.** Files created by earlier versions of SigTXT (before the fingerprint feature) are readable, with a warning on stderr. New files always include fingerprints.
- **Windows and `fsync`.** Atomic replace relies on `os.replace`. Directory fsync is not available on Windows; durability relies on NTFS journaling.
- **No memory wiping guarantee.** Sensitive buffers are wiped where practical (`bytearray` + `_wipe` for derived keys and decrypted key material). Python's garbage collector does not guarantee that intermediate `bytes` objects are zeroed before they leave memory.

## Operational discipline

Cryptography protects against mathematics. It does not protect against people. The following are not optional if the security claims above are to hold in practice.

**1. Verify fingerprints.** Every time you receive a new public key from someone, read their fingerprint aloud on a voice call or compare it in person. Store the verified key. If the fingerprint ever changes without notice, treat it as a compromise.

**2. Use strong passwords.** Argon2id makes guessing expensive, not impossible. A 12-character random passphrase is reasonable. `admin!123` is not.

**3. Never share a private key.** Not with support, not with a colleague, not "just for a minute". A private key is never needed by anyone but its owner. Any request for one is either a misunderstanding or an attack.

**4. Treat urgency as a red flag.** "Update immediately", "urgent security patch", "we need to rotate your key now" — these are the standard mechanisms of supply-chain and social-engineering attacks. Pause, verify the source, then act.

**5. Run `sigtxt` on a trusted machine.** A signed, encrypted file is only as safe as the environment that decrypts it. If the machine is compromised while the key is in memory, no cryptography will help.

**6. Keep private keys off shared storage.** No Dropbox, no Git, no shared network drives. Local disk with a password, or a hardware-backed keystore if you need it.

**7. Read the header before decrypting.** `--header-only` verifies the sender's signature without touching your private key. If the header looks wrong, do not decrypt.

**8. Keep dependencies up to date, but not blindly.** Watch `quantum-safe-py` and `cryptography` for security advisories. Do not apply urgent updates from unverified channels.

## Recovery and rotation

**Lost password.** If the private key file is encrypted and the password is lost, the private key is lost. There is no recovery. The keypair must be regenerated, and all correspondents must be given the new public key and fingerprint.

**Lost private key file.** Same as above. There is no recovery.

**Compromised private key.** There is currently no revocation mechanism in SigTXT. In practice:

1. Generate a new keypair.
2. Notify every correspondent, in a signed message under the new key, that the old key is retired.
3. Correspondents must manually remove the old public key from their trusted set.

Signed key bundles with revocation are on the roadmap but not implemented. Until then, treat any compromise as "replace everywhere, verify fingerprints again".

**Rotating by policy.** Generate a new keypair, notify correspondents, keep the old one only for reading old messages. There is no automatic grace period.

## Testing

```bash
# Fresh start
rm -f alice_sign.json bob_kem.json alice_sign.pub.json bob_kem.pub.json msg.txt msg.sigtxt
rm -f ~/.sigtxt/replay.db

# Keypairs (password from env)
export SIGTXT_PASSWORD="correct horse battery staple"
sigtxt keygen alice_sign.json --type sign --owner alice@example.com
sigtxt keygen bob_kem.json   --type kem  --owner bob@example.com

# Public keys
sigtxt export-pub alice_sign.json alice_sign.pub.json
sigtxt export-pub bob_kem.json   bob_kem.pub.json

# Message
printf 'Hello, Bob!' > msg.txt
sigtxt sign msg.txt msg.sigtxt \
  --sign-key alice_sign.json --to-key bob_kem.pub.json \
  --sender alice@example.com --recipient bob@example.com --subject "Hi"

# Header without decryption
sigtxt open msg.sigtxt --my-key bob_kem.json --from-key alice_sign.pub.json --header-only

# Decryption, first read
sigtxt open msg.sigtxt --my-key bob_kem.json --from-key alice_sign.pub.json

# Decryption, second read — expect a replay warning
sigtxt open msg.sigtxt --my-key bob_kem.json --from-key alice_sign.pub.json

# Wrong password — expect "key unlock failed (InvalidTag)"
SIGTXT_PASSWORD="wrong" sigtxt open msg.sigtxt --my-key bob_kem.json --from-key alice_sign.pub.json

# Empty password file — expect an error and no key file
: > empty.txt
SIGTXT_PASSWORD="" sigtxt keygen test.json --type sign --owner t@x --password-file empty.txt

# Profile mismatch — expect "both must match"
sigtxt keygen bob_cnsa.json --type kem --owner bob@example.com --cnsa
sigtxt sign msg.txt msg2.sigtxt --sign-key alice_sign.json --to-key bob_cnsa.json \
  --sender alice@example.com --recipient bob@example.com --subject "Test"
```

Expected outcomes are described in the comments.

## Dependencies

| Package | Purpose |
|---|---|
| `quantum-safe-py` | Hybrid PQC KEM and signatures, envelope format. |
| `cryptography` | ChaCha20-Poly1305 for key-file encryption. |
| `argon2-cffi` | Argon2id KDF. |
| `click` | CLI framework. |

`quantum-safe-py[pyca]` is the recommended extra. Do not install `quantum-safe-py[liboqs]` unless you have a working `liboqs` C library on your system; on Windows it will attempt to build `liboqs` from source on first import.

## Contributing

- **Bug reports:** include the full traceback, the command, the Python version, and the `quantum-safe-py` version.
- **Pull requests:** keep changes small and focused. Any change to the file format or cryptographic operations requires a corresponding test vector.
- **Do not add new cryptographic primitives** without a discussion. The design principle is "hybrid, audited, boring".
- **Do not add features** that expand the surface area without a threat model justifying them.

## License

Copyright (C) 2026 SigTXT contributors.

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version**.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of **MERCHANTABILITY** or **FITNESS FOR A PARTICULAR PURPOSE**. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

The full text of GPLv3 is in [`LICENSE`](LICENSE).

---

**SigTXT is not a substitute for operational discipline.** It is a tool that makes certain attacks detectable and others infeasible. It does not make you safe. It makes you safer, if you use it correctly. Read [Operational discipline](#operational-discipline) and [Known limitations](#known-limitations) before relying on it for anything that matters.