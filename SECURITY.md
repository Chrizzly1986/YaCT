# Security

## Status

YaCT 1.0 has **not had an independent security review**. The design uses
standard, well-studied building blocks and the implementation is tested
against official test vectors, but mistakes are possible until experts have
looked at it.

## What YaCT protects against

Someone who has a copy of the container file, but neither a password nor a
private key that opens it. For example: a lost or stolen device, a seized USB
stick, a cloud or backup provider.

Such a person learns:

- that the file is a YaCT container, its size, the chosen cipher and chunk size;
- how many password and public-key entries it has (not whose keys they are);
- nothing about the number, names, sizes or content of the stored files.

Any change to the container is detected when the affected data is read.

## What YaCT does not protect against

- **The computer itself:** malware, keyloggers or anyone with access to the
  computer while the container is open.
- **Weak passwords:** Argon2id slows down guessing, but cannot make a short
  or common password strong. Use a long passphrase.
- **Copies elsewhere:** old versions in backups, cloud sync histories,
  file system snapshots or SSD wear levelling. They stay encrypted, but anyone
  who has a key can open them, including with entries you have since removed.
- **Revoking access:** removing a password or key does not lock out someone
  who has already opened the container; they may have kept the internal key.
- **Rollback:** someone with write access can replace a container with an
  older copy of itself.
- **Fake keys:** YaCT cannot tell who a public key belongs to. Compare the
  fingerprint with its owner over a second channel.

## Cryptography

| Purpose | Algorithm |
|---|---|
| Data | AES-256-GCM or ChaCha20-Poly1305, per 64 KiB chunk (STREAM construction) |
| Passwords | Argon2id v1.3 |
| Key derivation, header MAC | HKDF and HMAC over SHA3-256 |
| Public-key entries | ML-KEM-1024 or -768 (FIPS 203) + X25519, hybrid combiner |
| Random data | `SecureRandom`; free space: AES-256-CTR keystream |

Details and the reasoning behind them: [docs/container-format.md](docs/container-format.md).

## Reporting a vulnerability

Please report security problems privately via GitHub's *Security → Report a
vulnerability* on this repository, not in public issues. Include what you
found, how to reproduce it and which version you used.
