# Security

## Status

YaCT 1.0 has **not had an independent security review**. The design uses
standard, well-studied building blocks, the implementation is tested against
official test vectors and independent implementations, and every protection
below is covered by a test that fails when the protection is removed. Still,
mistakes are possible until experts have looked at it.

## Goal

A container must not open without a matching credential – a current password
or private key – also when other software on the computer, or one of YaCT's
own dependencies, is malicious or compromised, as far as an application can
ensure that at all.

## What YaCT protects against

**Someone who has the container file, but no password or key**: a lost or
stolen device, a cloud or backup provider, someone with access to a shared
folder.

- They learn the container size, the chosen cipher and how many password and
  public-key entries it has (not whose keys). Free space is random data, so the
  file does not reveal how much it holds.
- Any change to the container is detected when the affected data is read;
  damaging the newest state cannot bring back an older one.
- A manipulated file cannot crash YaCT, make it allocate unbounded memory, or
  write files outside the target folder on extraction (also not through
  symbolic links or Windows device names and alternate data streams).

**People whose access was removed**: after *Re-encrypt* the container has a new
master key; old passwords and keys no longer open it, even for someone who
kept the old master key.

**Compromised dependencies and code injection** – see the next section.

## Compromised dependencies and code injection

A Java application runs third-party code in the same process: here JavaFX (the
user interface) and BouncyCastle (ML-KEM). If such code were malicious, or if
other software could inject code into YaCT, it could try to weaken the
encryption or read keys. YaCT defends in layers:

| Layer | Protection |
|---|---|
| **Build** | Maven itself is fixed by the wrapper (`./mvnw`), which refuses a distribution with a different SHA-256. Every Maven artifact – dependencies, plugins and their dependencies – is checked against pinned SHA-256 checksums (`.mvn/checksums`) before use; all plugin versions are fixed. A changed or unknown artifact stops the build before its code runs. GitHub Actions are pinned to commit hashes. |
| **Who sees secrets** | Passwords, master keys and random numbers are handled only by the Java runtime and YaCT's own code: Argon2id and BLAKE2b are YaCT's implementations; AES-GCM, ChaCha20-Poly1305, X25519, HMAC/SHA3 and the random generator come from the JDK. BouncyCastle is used only for ML-KEM, never sees a password, master key or YaCT's random generator, and its result is always combined with JDK X25519 – so a compromised ML-KEM alone cannot open a container. |
| **JDK providers** | JDK cryptography is obtained only from providers verified to be part of the Java runtime image (module and class loader). A provider registered under the same name by other code is ignored. |
| **Known answers** | Before any container or key file is created or opened, every primitive must reproduce official test vectors (NIST, RFC). A tampered or broken implementation stops YaCT instead of producing weak containers. |
| **Encapsulation** | YaCT's code is a set of Java modules. No package is open to reflection, and the core is exported only to the YaCT user interface: other code in the process can neither read private fields such as the master key nor call the core. |
| **Packaged runtime** | Everything is linked into one runtime image without a class path. The image contains no support for Java agents, the debugger or attaching; the JVM refuses attach requests and writes no core dumps. JavaFX's native libraries live inside the runtime instead of a user-writable cache folder. Installers install into protected locations (Program Files, /opt, /Applications). |
| **Start-up check** | YaCT refuses to start if Java agents, `--add-opens` and similar options, a custom system class loader or security configuration, a class path or unexpected modules are present – e.g. injected through `JAVA_TOOL_OPTIONS`. |

## What YaCT cannot protect against

- **Malware already running as you, or as administrator.** It can log
  keystrokes, read the screen, or inject native code into any process at the
  operating-system level (`LD_PRELOAD`, DLL injection, native JVM agents –
  YaCT then refuses to continue, but the native code has already run). No
  application can prevent this; keep the computer clean.
- **The user interface toolkit.** JavaFX necessarily sees what you type,
  including passwords. It is pinned by checksum, but a version that was
  already malicious when it was pinned would not be detected.
- **Trust on first use.** The pinned checksums were recorded from Maven Central.
  Verify them once against the projects' published signatures before a release
  (BouncyCastle signs with key `84E913A8E3A748C0`; check the full fingerprint on
  bouncycastle.org).
- **Weak passwords.** Argon2id slows guessing down, but cannot make a short or
  common password strong. YaCT requires 12 characters; use a long passphrase.
- **Old copies.** Backups, sync histories, snapshots and SSD wear levelling may
  keep old versions of the container. They stay encrypted, but open with the
  credentials that were valid then – also with access you removed or replaced
  by re-encrypting. Deleted data may remain in such copies.
- **Activity patterns.** Someone who sees several versions of the container
  (e.g. a cloud provider keeping history) can tell which regions changed, and
  so roughly how much was added or deleted.
- **Rollback.** Someone with write access can replace the container with an
  older copy of itself.
- **Keys in memory.** While a container is open, its keys are in memory and may
  reach the swap file or a hibernation image. Passwords typed into the user
  interface are held by JavaFX as strings that cannot be wiped.
- **Fake public keys.** YaCT cannot tell who a public key belongs to. Compare
  the fingerprint with its owner over a second channel.
- **Unsigned downloads.** The builds are not code-signed yet; check them against
  `SHA256SUMS` from the same build.

## Cryptography

| Purpose | Algorithm | Implementation |
|---|---|---|
| Data | AES-256-GCM or ChaCha20-Poly1305, per 64 KiB chunk (STREAM construction) | JDK |
| Passwords | Argon2id v1.3, 128 MiB / 3 passes (strong: 512 MiB / 4) | YaCT |
| Key derivation, header MAC | HKDF and HMAC over SHA3-256 | YaCT on JDK HMAC |
| Public-key entries | ML-KEM-1024 or -768 (FIPS 203) + X25519, hybrid combiner | BouncyCastle + JDK |
| Random data | Hash_DRBG, 256-bit; free space: AES-256-CTR keystream | JDK |

Details: [docs/container-format.md](docs/container-format.md).

## Reporting a vulnerability

Please report security problems privately via GitHub's *Security → Report a
vulnerability* on this repository, not in public issues. Include what you
found, how to reproduce it and which version you used.
