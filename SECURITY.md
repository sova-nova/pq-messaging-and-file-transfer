# Security

This is a post-quantum secure messaging and file transfer suite: an app (C++17, Qt 6) and a relay (`pq-server`).
This file says what it protects against, what it does not, how to run a relay safely, and how to report a problem.

**Status: not yet independently reviewed.** The design and code have been tested extensively (see *Testing* below), but
no outside cryptographer has reviewed them. `REVIEW.md` is the packet prepared for that review. Until it has happened,
treat the suite as promising but unaudited.

## Who it defends against

| Adversary | What they can do | What they get |
|---|---|---|
| **Someone watching the network** | See and record every connection to a relay | Encrypted traffic only (since M8): not the invites, send tokens, mailboxes, messages or files. They do see that you talk to the relay, when, and roughly how much. |
| **The relay's operator** (or whoever controls the relay) | See everything that reaches the relay; drop, delay, replay or reorder; lie | Encrypted envelopes, files and archives they can't open. They see which mailbox receives how much and when, and the IP addresses of connections. Tampering is detected (signatures, chains, fingerprints); dropping and delaying can't be prevented, but archives detect a withheld or altered history. A relay can make a sender fall back to envelopes without forward secrecy by claiming a recipient has no one-time keys; the sender is warned when that looks suspicious. |
| **A contact or group member** | Everything a member legitimately sees | They can of course keep, copy or forward what you send them. They can't impersonate another member, write into a chat they aren't in, change a Private chat's rule, retract someone else's message, or point you at a relay that isn't theirs for an attachment. |
| **Someone who steals a device later** | The app's files | With the passphrase (or an unlocked OS keychain): the saved history and archives. Without it: nothing readable. Either way, **not** envelopes captured earlier from the network or relay (forward secrecy, M6), and not Private messages that have already expired. |
| **Someone who sends you a file** | A file with any name and contents | A safe, non-overwriting file name in the folder you choose, saved only after it matches what the sender signed. Files are never opened automatically. The contents can still be harmful if you open them. |

## What is protected

- **Message and file contents**, end to end: only the intended recipients can read them, and every message is signed by its sender.
- **Post-quantum by default:** ML-KEM-768 for encryption, ML-DSA-65 for signatures; X25519 is combined with ML-KEM wherever forward secrecy applies, so it doesn't rest on one algorithm.
- **Forward secrecy for envelopes** (M6): an envelope can't be opened once the recipient has used and deleted its one-time key, even with every long-term key.
- **The connection to a relay** (M8): encrypted and authenticated, with the relay's identity pinned.
- **Archives and keyrings on the relay**: encrypted; the relay keeps ciphertext only. Archive history is a hash chain with signed checkpoints, so a relay that alters, truncates or forks it is detected.
- **Private chats** (M7): messages expire on a fixed timer and are then erased from both devices and the relay; never archived, backed up or restored.
- **Data at rest**: history, the prekey store and the private store are encrypted under keys derived from the user's private key; private keys can be protected with a passphrase (scrypt), optionally kept in the OS keychain.

## What is not protected

- **Metadata**: the relay sees mailboxes, sizes, timing and IP addresses; a network observer sees sizes and timing.
- **Availability**: a relay (or the network) can drop or delay anything.
- **Archives are not forward-secret**: a chat's archive is encrypted under a key every member holds; someone who later steals one member's device and passphrase can read that chat's archive from the relay.
- **What people do with what they receive**: copies, screenshots, exports, or a modified app. Private chats can't prevent these.
- **A device compromised while in use** (malware, an unlocked machine).
- **Deniability**: messages are signed, so a recipient can prove you sent them.
- **Deleted data on solid-state disks**: the app overwrites and securely deletes keys and expired messages, but an SSD may keep old copies of its own that no software can reach.
- **Envelopes sealed while a device is being restored** can't be opened afterwards (their one-time keys are gone).

## For relay operators

- **Back up `<storage>/v3`**: it holds the relay's identity key, its database and stored files. If the identity key is lost or changes, every app that pinned it will refuse the relay (as they should), and invites and contact cards naming it stop working.
- **Protect that folder**: whoever has the identity key can impersonate the relay to anyone who trusts it (they still couldn't read messages).
- **Keep the relay and the apps on the same version.** Since M8, older apps can't connect to a newer relay and vice versa.
- **Use the limits** (`--rate-limit`, mailbox and attachment quotas, `--max-prekeys`, `--prekey-takes-per-hour`, `--member-invites`): see `pq-server --help`.
- **Invites are single-use secrets**: send them over a channel you trust, and cancel unused ones.
- **Logs** contain connecting IP addresses and short mailbox IDs; treat them as sensitive and rotate them.
- A VPN (such as WireGuard) in front of the relay is no longer needed for confidentiality, but still hides who connects to it.

## For users

- **Compare fingerprints** (Verify…) with each contact over another channel once. Until you do, you trust the contact card as given.
- **Use a passphrase** for your keys, and **back up your keys folder**: without it and its passphrase there is nothing to restore from.
- **Private chats** disappear for honest apps; anyone can still photograph a screen.

## Reporting a problem

**Please report security problems privately**, not in a public issue: <!-- MAINTAINER: add a contact address or private reporting channel here -->
*(contact to be added by the maintainer)*. Include what you found, how to reproduce it, and what you think the impact is.
We will acknowledge the report, work on a fix, and credit you if you wish.

## Testing

About 2,110 automated checks across twelve suites, including hostile relays, hostile group members, tampered and replayed
data, forged keys and lost devices; all of them also pass under AddressSanitizer and UndefinedBehaviorSanitizer with leak
detection (`-DPQ_SANITIZE=ON`). Every parser of someone else's data is fuzzed (`fuzz/`; `pq-fuzz`, or `pq-libfuzzer` with
clang via `-DPQ_FUZZ=ON`). See `HANDOFF.md` for the details of each milestone.
