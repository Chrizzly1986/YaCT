# Changelog

## 1.0.0 – unreleased

Complete rewrite. Version 0.x never encrypted any data; its files cannot be
opened by 1.0 and there is nothing to migrate.

- Encrypted file vault with a documented, versioned file format.
- AES-256-GCM (hardware-accelerated) or ChaCha20-Poly1305, authenticated per
  64 KiB chunk.
- Password entries with Argon2id (128 MiB by default, at least 12 characters);
  post-quantum public-key entries with
  ML-KEM-1024/-768 + X25519; up to 16 entries per container.
- Fixed-size containers filled with random data; enlarging; wiping of deleted
  data; crash-safe updates.
- Key pairs with password-protected private key files and fingerprints.
- JavaFX desktop application in German, English (British), French, Spanish
  and Portuguese.
- Re-encryption with a new master key, so removed access stops working also
  for anyone who kept the old key.
- Security check (*Help → Security check*): installation and open container,
  every file authenticated, with explanations and fixes where possible.
- Protection against compromised dependencies and code injection: passwords
  and master keys are handled only by the JDK and YaCT's own Argon2id and
  BLAKE2b; BouncyCastle only for ML-KEM, always combined with X25519; JDK
  providers verified; known-answer tests before every use; Java modules with
  strong encapsulation; refusal to start with Java agents, `--add-opens` and
  similar options.
- Supply chain: Maven wrapper with a pinned checksum, SHA-256 checksums for
  every build artifact, fixed plugin versions, GitHub Actions pinned to commit
  hashes.
- Self-contained builds with their own Java runtime for Linux, Windows and
  macOS – one linked runtime image without a class path, without support for
  Java agents or debuggers, with JavaFX's native libraries inside;
  `--self-test` for packaged builds.
