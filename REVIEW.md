# Review packet

For an independent security review of the suite. It says how to build and test it, where every cryptographic construction
lives, and which areas are riskiest, in the order we would look at them. `SECURITY.md` has the threat model; `HANDOFF.md`
has the reasoning behind each milestone (M0 to M8) and every departure from the original design.

## Building and testing

- Dependencies: OpenSSL 3, liboqs (ML-KEM-768, ML-DSA-65), SQLite 3, Qt 6 (app only).
- Tests: `cmake -B build -DPQ_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build --output-on-failure` (about 2,110
  checks; the group suite takes about 12 minutes; the integration suites start real relays on local ports, run them one at a time).
- Sanitizers: add `-DPQ_SANITIZE=ON` (GCC or Clang); build with few parallel jobs, as it needs a lot of memory.
- Fuzzing: `pq-fuzz --seconds N` (any compiler; build with `PQ_SANITIZE`), or `-DPQ_FUZZ=ON` with clang for `pq-libfuzzer`
  (coverage-guided; the stronger tool). `fuzz/fuzz_targets.h` explains the one input format.
- The development sandbox had no clang, CMake or Qt: libFuzzer and the CMake options were not run there, and the GUI was only
  type-checked against a stand-in. They have since been built on real Qt by the maintainer.

## Map of the code

| Area | Files |
|---|---|
| Primitives (ML-KEM, ML-DSA, X25519, AES-256-GCM, HKDF-SHA256, scrypt, random, wiping) | `client/crypto_engine.{h,cpp}` |
| Keys at rest, passphrase, local key derivation | `client/key_store.{h,cpp}`, `client/keychain.{h,cpp}` |
| Identity bundles, contact cards, invites | `client/identity_bundle.{h,cpp}`, `client/sharing.{h,cpp}` |
| Signed records (every message and control record) | `client/message_record.{h,cpp}` |
| Envelopes (v1 long-term only; v2 with a one-time prekey and X25519) | `client/envelope.{h,cpp}` |
| Prekeys and their private store | `client/prekey.{h,cpp}`, `client/prekey_vault.{h,cpp}` |
| Encrypted relay connection (handshake, frames) and its wiring | `client/secure_channel.{h,cpp}`, `protocol/protocol.{h,cpp}` (frame cipher registry), `protocol/platform.h` |
| Relay protocol (formats) | `protocol/relay_protocol.{h,cpp}`, `protocol/messages.h` |
| Relay (sessions, auth, storage, limits) | `server/relay_service.{h,cpp}`, `server/relay_store.{h,cpp}`, `server/main.cpp` |
| The app's rules: who may send what, in which chat, when | `client/messaging_engine.{h,cpp}` (large) |
| History at rest | `client/history_store.{h,cpp}` |
| Archives (hash chain, checkpoints, deletion by agreement) | `client/archive.{h,cpp}`, plus the engine |
| Keyring (backup of per-chat keys on the relay) | `client/keyring.{h,cpp}` |
| Attachments (chunk encryption, streaming, file names) | `client/attachment.{h,cpp}` |
| Private chats store | `client/private_store.{h,cpp}` |
| Older transfer-ID file transfer (v2 protocol) | `client/transfer_engine.{h,cpp}`, `server/main.cpp` |

## The cryptographic constructions

| # | Construction | How | Where |
|---|---|---|---|
| 1 | **Relay connection** (M8) | Client: one-connection X25519 key + nonce. Relay: identity key (ML-DSA-65; its SHA-256 is the pinned relay ID), one-connection ML-KEM-768 and X25519 keys, nonce, ML-DSA signature over the client's hello and all of this. Client: ML-KEM encapsulation. Keys: HKDF-SHA256 over the ML-KEM and X25519 secrets, salted with the hash of the whole exchange, one per direction. Frames: AES-256-GCM, nonce = per-direction counter, direction in the AAD; any failure kills the channel. | `secure_channel.cpp` |
| 2 | **Envelope v1** | ML-KEM-768 to the recipient's long-term key; HKDF; AES-256-GCM; header as AAD; padded to size buckets. | `envelope.cpp` |
| 3 | **Envelope v2** (M6) | As v1, plus an ML-KEM encapsulation to a one-time prekey and X25519 with the prekey's X25519 key; HKDF over all three secrets salted with the header's hash. The sender wipes its ephemeral key. | `envelope.cpp` |
| 4 | **Prekeys** | ML-KEM-768 + X25519 public keys, a last-resort flag and a date, signed by the owner's identity key; senders verify. Private halves: own SQLite store, each sealed under a derived key, deleted (overwrite, then `secure_delete`) once the envelope is stored. | `prekey.cpp`, `prekey_vault.cpp`, engine |
| 5 | **Records** | Every message and control record is a canonical encoding signed with ML-DSA-65; transcript records link to the sender's previous one and to what they had seen. | `message_record.cpp` |
| 6 | **Identity bundles** | Signing and encryption public keys, name, address, date; self-signed. | `identity_bundle.cpp` |
| 7 | **Archives** | Each chat's history on the relay: entries sealed under a per-chat archive key (random nonce per entry), a hash chain computed by the relay and checked by members, signed checkpoints to detect forks, deletion only with every member's signature. | `archive.cpp`, relay, engine |
| 8 | **Keyring** | Per-chat keys and small tables, AES-256-GCM under a key derived from the user's private key, mailbox ID as AAD. | `keyring.cpp` |
| 9 | **Attachments** | Random per-file key; 48 KiB chunks, AES-256-GCM, nonce = chunk number (safe: one key per file), file ID / chunk number / count in the AAD; SHA-256 of the whole file signed in the record; one-time download tokens (relay keeps hashes). | `attachment.cpp`, engine |
| 10 | **Data at rest** | History, prekey store and private store keys: HKDF-SHA256 from the private ML-KEM key with a label each. Private keys: optionally passphrase-protected with scrypt, optionally in the OS keychain. Private chat messages: each under its own random key, erased at expiry. | `key_store.cpp`, `history_store.cpp`, `private_store.cpp` |

## Riskiest areas first

1. **The relay connection** (#1; new in M8). The handshake transcript and what the signature covers; key separation by direction; the counter nonces; that the X25519 secret really feeds the keys (**no test can show this**, as both sides would agree either way); the per-socket cipher registry in `protocol.cpp` (keyed by socket number: closing must always go through `close_socket`; any path that closes a relay socket some other way could leave a stale cipher for a reused number); trust on first use for the Files tab.
2. **The engine's acceptance rules** (`messaging_engine.cpp`): who may write into which conversation (contacts, group members, introduced members, Private chats), recipients-hash checks, replay and duplicate handling, the Private chats' clock windows, retractions and deletions. This file is large and is where a logic error would most likely let a hostile member or relay do something they shouldn't.
3. **Envelope v2 and prekeys** (#3, #4): the key derivation; prekey signature verification on the sender's side; deleting a used one-time key only after the message is stored (ordering against crashes); the fallback to v1 (a hostile relay can force it; the sender is warned only for contacts that have had prekeys before).
4. **Groups**: membership changes, introductions of members who can't reach each other directly (relayed by the creator; these grants stay v1), send tokens per member.
5. **Archives** (#7): chain verification across tombstones, checkpoint comparison, the relay computing the chain, deletion by agreement (every member's signature over the exact order).
6. **Attachments** (#9): the nonce-from-chunk-number argument, the hash check before saving, file name sanitizing (`sanitize_filename`, `unique_path`; the free-name check and the rename are not atomic), that a file's relay must be the sender's own.
7. **Keys at rest** (#10): scrypt parameters, the local-key labels, what a stolen device without the passphrase yields.
8. **The relay**: sign-in, send tokens, rate limits and quotas (denial of service), the hourly prekey allowance, revocation of waiting envelopes.
9. **Secure deletion assumptions**: SQLite `secure_delete` with an in-memory journal for the prekey and private stores; the limits of this on SSDs.
10. **Parsers**: all are fuzzed and strict (canonical round trips), but a reviewer's eye on the length handling is still welcome.

## Decisions a reviewer may want to challenge

- No deniable authentication (records are signed).
- Archives are deliberately not forward-secret (every member holds the archive key).
- Read receipts are always on in Private chats (the sender can't know the recipient's setting; reading starts the timer).
- Over its hourly prekey allowance, a contact gets the last-resort prekey instead of a refusal (so chats aren't held up).
- No plaintext fallback for relay connections; the Files tab trusts on first use when no relay ID is pinned.
- One-to-one Private chats only; no files in Private chats yet.
- liboqs's ML-KEM / ML-DSA are used as provided; side-channel resistance of the primitives is inherited from liboqs and OpenSSL.

## Specific questions

1. Is the relay handshake (#1) sound as a signed-ephemeral key exchange, and is binding the signature to the client's hello enough to prevent replay and unknown-key-share issues?
2. Is HKDF with the transcript hash as salt (rather than as info) appropriate in #1 and #3?
3. Is anything lost by the relay computing the archive hash chain itself, given members check it?
4. Are there acceptance-rule gaps in `messaging_engine.cpp` for introduced group members?
5. Are the scrypt parameters adequate for passphrase-protected keys?
