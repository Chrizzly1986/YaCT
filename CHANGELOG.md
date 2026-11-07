# Changelog

## 1.0.0 – unreleased

Complete rewrite. Version 0.x never encrypted any data; its files cannot be
opened by 1.0 and there is nothing to migrate.

- Encrypted file vault with a documented, versioned file format.
- AES-256-GCM (hardware-accelerated) or ChaCha20-Poly1305, authenticated per
  64 KiB chunk.
- Password entries with Argon2id; post-quantum public-key entries with
  ML-KEM-1024/-768 + X25519; up to 16 entries per container.
- Fixed-size containers filled with random data; enlarging; wiping of deleted
  data; crash-safe updates.
- Key pairs with password-protected private key files and fingerprints.
- JavaFX desktop application in German, English (British), French, Spanish
  and Portuguese.
- Self-contained builds with their own Java runtime for Linux, Windows and
  macOS; `--self-test` for packaged builds.
