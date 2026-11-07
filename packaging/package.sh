#!/usr/bin/env bash
#-------------------------------------------------------------------------------
# YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
#-------------------------------------------------------------------------------
# Builds a self-contained YaCT application for this operating system.
#
# Usage: packaging/package.sh [TYPE]
#   TYPE: app-image (default, a runnable folder, also archived), or an
#         installer: deb, rpm (Linux; need dpkg-deb/fakeroot or rpmbuild),
#         dmg, pkg (macOS)
# Result: target/dist/, with SHA256SUMS for every file produced.
#
# Hardening:
# - Everything - YaCT, JavaFX, BouncyCastle - is linked into one Java runtime
#   image. There is no class path and no loose jar to swap or add.
# - JavaFX's native libraries are placed inside the runtime, where JavaFX
#   loads them first. Otherwise it would extract them to ~/.openjfx/cache, a
#   folder any program of the user can write to.
# - BouncyCastle's jar is signed; linking drops the signature. YaCT does not use
#   it through the JCE (which would check it); its integrity is verified by the
#   pinned SHA-256 checksums of the build (.mvn/checksums).
# - The JVM refuses attach requests from other processes and writes no core
#   dumps (which could contain keys); the launcher checks for injected agents.
#
# jpackage can only build for the system it runs on; build each platform there
# (the CI workflow does this for Linux, Windows and macOS).
set -euo pipefail

TYPE="${1:-app-image}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Modules the application module graph does not pull in by itself:
# locale data (formats for the five languages), charsets, and the SunEC provider (X25519).
EXTRA_MODULES="jdk.localedata,jdk.charsets,jdk.crypto.ec"
JAVA_OPTIONS="-Dyact.packaged=true -XX:+DisableAttachMechanism -XX:-CreateCoredumpOnCrash -XX:MaxRAMPercentage=50"

VERSION="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' pom.xml | head -1)"
APP_VERSION="${VERSION%-SNAPSHOT}"   # jpackage needs a plain number such as 1.0.0

case "$(uname -s)" in
  Darwin) OS=mac;   ICON=packaging/icons/yact.icns ;;
  *)      OS=linux; ICON=packaging/icons/yact.png ;;
esac

echo "Building YaCT $VERSION ..."
mvn -B -q -DskipTests package

TARGET="yact-ui/target"
MODS="$TARGET/jpackage-modules"
rm -rf "$MODS" target/dist
mkdir -p "$MODS" target/dist

# Module path: YaCT, BouncyCastle and the platform jars of JavaFX (the plain ones are empty).
cp "$TARGET/yact-ui-$VERSION.jar" "$MODS/"
for jar in "$TARGET"/lib/*.jar; do
  case "$(basename "$jar")" in
    javafx-*-"$OS"*.jar|javafx-*-mac*.jar) cp "$jar" "$MODS/" ;;
    javafx-*) ;;
    *) cp "$jar" "$MODS/" ;;
  esac
done

jpackage --type app-image \
  --name YaCT \
  --app-version "$APP_VERSION" \
  --vendor "Christian Hoppe" \
  --copyright "(c) 2015-2026 Christian Hoppe" \
  --description "Encrypted file vault with post-quantum keys" \
  --icon "$ICON" \
  --module-path "$MODS" \
  --module yact.ui/yact.ui.Launcher \
  --add-modules "$EXTRA_MODULES" \
  --jlink-options "--strip-debug --no-header-files --no-man-pages --strip-native-commands --include-locales=en,de,fr,es,pt --compress=zip-6 --ignore-signing-information" \
  --java-options "$JAVA_OPTIONS" \
  --dest target/dist

# JavaFX native libraries into the runtime's library folder.
if [ "$OS" = mac ]; then
  APP=target/dist/YaCT.app; RTLIB="$APP/Contents/runtime/Contents/Home/lib"; EXT=dylib
else
  APP=target/dist/YaCT; RTLIB="$APP/lib/runtime/lib"; EXT=so
fi
for jar in "$MODS"/javafx-graphics-*.jar; do
  unzip -q -o "$jar" "*.$EXT" -d "$RTLIB"
done

if [ "$TYPE" = app-image ]; then
  (cd target/dist && tar czf "YaCT-$APP_VERSION-$OS.tar.gz" "$(basename "$APP")")
else
  EXTRA=()
  case "$TYPE" in
    deb|rpm) EXTRA=(--linux-shortcut --linux-menu-group Utility --linux-app-category utils) ;;
  esac
  jpackage --type "$TYPE" --app-image "$APP" --name YaCT --app-version "$APP_VERSION" \
    --vendor "Christian Hoppe" --license-file Licence.txt \
    --file-associations packaging/yact-file.properties ${EXTRA[@]+"${EXTRA[@]}"} --dest target/dist
fi

(cd target/dist && find . -maxdepth 1 -type f ! -name SHA256SUMS -exec sha256sum {} + | sed 's# \./# #' > SHA256SUMS)
echo "Done:"; ls -1 target/dist
