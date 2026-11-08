<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/yact-wordmark-dark.png">
    <img src="docs/logo/yact-wordmark-light.png" alt="YaCT – Yet another Crypto Tool" width="460">
  </picture>
</p>

# YaCT – Yet another Crypto Tool

YaCT is an encrypted file vault for the desktop. A vault ("container") is a
single file of fixed size that holds your files encrypted. You open it with a
password or with a **post-quantum key pair**, add and extract files, and close
it again.

> **Status:** version 1.0 in development. The cryptography follows current
> standards and is thoroughly tested, but it has **not been reviewed by
> independent security experts**. Do not rely on YaCT as your only protection
> for critical data until it has been. See [SECURITY.md](SECURITY.md).

## Features

- **Strong encryption:** AES-256-GCM (default) or ChaCha20-Poly1305; every
  64 KiB block is authenticated, so tampering and damage are detected.
- **Passwords:** Argon2id (128 MiB, or 512 MiB in the "strong" profile);
  at least 12 characters.
- **Post-quantum keys:** share a container with someone's public key.
  ML-KEM-1024 (FIPS 203) combined with X25519: an attacker has to break both.
- **Several ways in:** a container can have up to 16 entries – passwords and
  public keys – each of which opens it.
- **Fixed size, no leaks:** free space is filled with random data, so the
  file does not reveal how much it holds. Containers can be enlarged.
- **Deleting means deleting:** deleted files and older states of the
  container are overwritten with random data.
- **Revoking access:** *Re-encrypt* gives the container a new internal key;
  old passwords and keys stop working, also for anyone who kept the old key.
- **Security check:** *Help → Security check* checks the installation and the
  open container – every file is read and authenticated – and explains what
  to do about each finding.
- **Crash-safe:** a crash or power cut leaves the container in its previous or
  its new state, never broken.
- **Languages:** German, English (British), French, Spanish, Portuguese.

## Getting YaCT

**Ready-made builds** for Linux, Windows and macOS are attached as artifacts to
every run of the [build workflow](.github/workflows/build.yml) (GitHub, tab
*Actions*). They contain their own Java runtime; nothing else needs to be
installed. The builds are not signed, so Windows SmartScreen and macOS
Gatekeeper will warn on first start.

**From source:** see [Building](#building).

## Using YaCT

1. **Create a container:** *Create new container…*, choose where to save it,
   its size and a password (or a public key). The container is filled with
   random data, which takes a moment for large sizes.
2. **Add files:** drag files or folders into the window, or use *Add files…*
   and *Add folder…*. Select a folder first to add into it.
3. **Get files out:** select files or folders and choose *Extract…*.
4. **Share a container:** the other person creates a key pair (*Keys → New
   key pair…*) and sends you the `.yactpub` file. In *Access…* choose *Add
   key…* and compare the fingerprint with them by phone or in person.
5. **Remove access:** in *Access…* remove the entry, then choose
   *Re-encrypt…* – only that locks out someone who opened the container
   before.
6. **Check security:** *Help → Security check* now and then, and whenever
   something seems odd.
7. **Close** the container (*File → Close container*) when you are done; this
   also happens when you quit.

Keep your private key file (`.yactkey`) and passwords safe: **without them,
nobody can open the container – including you.** There is no recovery.

## Security in brief

YaCT protects your files against anyone who gets hold of the container file
but not a password or key: a lost laptop, a stolen USB stick, a cloud
provider. Any change to the container is detected. YaCT also defends against
compromised dependencies and code injected into the program: passwords and keys
are handled only by the Java runtime and YaCT's own code, every primitive is
checked against official test vectors before use, and the packaged application
refuses to start when foreign code could be injected.

It cannot protect against malware on the computer while the container is open,
against weak passwords, or against copies of the container kept elsewhere
(backups, cloud versions). Details: [SECURITY.md](SECURITY.md); the file
format: [docs/container-format.md](docs/container-format.md).

## Building

Requirements: JDK 21 or newer. Maven comes with the project: `./mvnw`
(`mvnw.cmd` on Windows) downloads exactly the Maven version in
`.mvn/wrapper` and refuses it if its checksum differs.

```sh
./mvnw verify                       # build and run all tests
./mvnw -q install -DskipTests       # build only
./mvnw -q -pl yact-ui javafx:run    # start the application (from the build, for development)
```

Every artifact Maven downloads – dependencies, plugins and theirs – is
checked against the SHA-256 checksums in `.mvn/checksums` before it is used;
an unknown or changed artifact stops the build.

The build also produces a jar with its libraries in `lib/`
(`java -jar yact-ui/target/yact-ui-1.0.0-SNAPSHOT.jar`). Started that way,
YaCT runs without its module protection; use it for development only.

### Updating dependencies

A new version of a dependency or plugin (e.g. proposed by Dependabot) fails
the build until its checksums are recorded – on purpose. After deciding to
trust the new version:

```sh
packaging/record-checksums.sh       # records everything from an empty repository, then checks
git diff .mvn/checksums             # every change must belong to the update
```

Check new artifacts against their publishers' signatures before committing
(see [SECURITY.md](SECURITY.md), "Trust on first use").

### Self-contained application

`jpackage` (part of the JDK) builds an application with its own Java runtime,
for the operating system it runs on:

```sh
packaging/package.sh             # Linux, macOS: app image in target/dist/
packaging/package.sh deb         # Linux installer (needs dpkg-deb and fakeroot)
packaging/package.sh dmg         # macOS installer
powershell -File packaging\package.ps1            # Windows app image
powershell -File packaging\package.ps1 -Type msi  # Windows installer (needs WiX)
```

Installers register `.yact` files, so a double-click opens them in YaCT.

### Checks

```sh
target/dist/YaCT/bin/YaCT --self-test   # crypto, locale data and installation check of a packaged build
```

*Help → Security check* shows the same in the application, and checks the
open container as well.

Screenshots of every screen, rendered on a virtual display (also runs an
import through the UI end to end):

```sh
./mvnw -q install -DskipTests
LC_ALL=C.UTF-8 xvfb-run ./mvnw -pl yact-ui test -Dtest=UiScreenshots \
    -Dyact.screenshots=/tmp/yact-shots -Dyact.locale=de -Dsurefire.failIfNoSpecifiedTests=false
```

## Project structure

| Path | Contents |
|---|---|
| `yact-core` | Cryptography and container engine, no UI |
| `yact-ui` | JavaFX desktop application |
| `docs/container-format.md` | Specification of the file formats |
| `packaging/` | Scripts for self-contained builds and installers, recording checksums; application icons |
| `.mvn/` | Maven wrapper and the pinned checksums of every build artifact |
| `docs/logo/` | Logo sources (SVG) and renderings |

Everything that sees a password or master key comes from the Java runtime
(AES-256-GCM with the processor's AES instructions, ChaCha20-Poly1305, X25519,
SHA-3, HMAC, the random generator) or is YaCT's own, tested code (Argon2id,
BLAKE2b). BouncyCastle is used only for ML-KEM, and its result is always
combined with X25519 from the Java runtime.

## Licence

MIT, see [Licence.txt](Licence.txt).
