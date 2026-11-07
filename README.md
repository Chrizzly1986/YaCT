# YaCT – Yet another Crypto Tool

Encrypted file vault with post-quantum key slots.

> **Status: under reconstruction.** The legacy Eclipse code in `src/` does not
> encrypt anything and must not be used. It stays in the repository only until its
> UI parts are migrated. The new code lives in the Maven modules below.

## Modules

| Module      | Contents                                                     |
|-------------|--------------------------------------------------------------|
| `yact-core` | UI-independent crypto and container engine (BouncyCastle)    |
| `yact-ui`   | JavaFX desktop client                                        |

## Requirements

- JDK 21 or newer
- Maven 3.9+

## Build and test

```sh
mvn verify
```

## Run

```sh
mvn -q install -DskipTests
mvn -q -pl yact-ui javafx:run
```

The client follows the system language: German, French, Spanish or European
Portuguese. Every other language, including US English, gets British English
with British date and number formats. It can
create containers (fixed size, protected by a password or a public key), open
them, add files and folders (also by drag and drop), extract, rename and delete
them (deleted data is overwritten), enlarge the container, manage passwords
and keys, and create post-quantum key pairs. *Help → Crypto self-test* checks
that every algorithm works in the current runtime.

### Screenshots of all screens

Renders every window and dialog to PNG files and runs an import through the UI
logic. Needs a display, e.g. a virtual one:

```sh
mvn -q install -DskipTests
LC_ALL=C.UTF-8 xvfb-run mvn -pl yact-ui test -Dtest=UiScreenshots \
    -Dyact.screenshots=/tmp/yact-shots -Dsurefire.failIfNoSpecifiedTests=false
```

Add `-Dyact.locale=fr` (or `es`, `pt`, `en-US`, …) to render another language;
the default is German.

## Planned cryptography

| Purpose                  | Algorithm                                       |
|--------------------------|-------------------------------------------------|
| Data encryption          | AES-256-GCM (default), ChaCha20-Poly1305        |
| Password → key           | Argon2id                                        |
| Combining secrets        | HKDF over SHA3-256                              |
| Public-key key slot      | Hybrid ML-KEM-1024 (default) or -768 (FIPS 203) + X25519 |
| Signatures (optional)    | ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205)        |

AES-256-GCM uses the JDK's own implementation, which uses the processor's AES
instructions; all other primitives come from BouncyCastle (`bcprov-jdk18on`).
YaCT implements no cryptographic algorithms itself. The file format is specified in
[docs/container-format.md](docs/container-format.md).

## Progress

| Milestone | Content | Status |
|---|---|---|
| 1 | Maven build, crypto self-test | done |
| 2 | Container header, password key slots, chunked data encryption | done |
| 3 | Hybrid post-quantum key slot (ML-KEM + X25519), key files | done |
| 4 | Container operations: fixed-size container (growable), add/extract/delete files, wipe on delete | done |
| 5 | JavaFX client (German, British English, French, Spanish, Portuguese) | done |
| 6 | Remove legacy code, documentation | open |

## License

MIT, see `Licence.txt`.
