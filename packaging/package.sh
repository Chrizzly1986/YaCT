#!/usr/bin/env bash
#-------------------------------------------------------------------------------
# YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
#-------------------------------------------------------------------------------
# Builds a self-contained YaCT application for this operating system: a Java
# runtime with JavaFX built in, so users do not need to install Java.
#
# Usage: packaging/package.sh [TYPE]
#   TYPE: app-image (default, a runnable folder), or an installer type:
#         deb, rpm (Linux; need dpkg-deb/fakeroot or rpmbuild), dmg, pkg (macOS)
# Result: target/dist/
#
# jpackage can only build for the system it runs on; build each platform there
# (the CI workflow does this for Linux, Windows and macOS).
set -euo pipefail

TYPE="${1:-app-image}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# JDK modules the application needs (determined with jdeps); jdk.localedata
# provides date and number formats for the translated languages (reduced to
# those languages by --include-locales below).
MODULES="java.base,java.naming,java.sql,jdk.localedata,jdk.charsets,javafx.controls"

VERSION="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' pom.xml | head -1)"
APP_VERSION="${VERSION%-SNAPSHOT}"   # jpackage needs a plain number such as 1.0.0

echo "Building YaCT $VERSION ..."
mvn -B -q -DskipTests package

TARGET="yact-ui/target"
STAGE="$TARGET/jpackage-input"
FXMODS="$TARGET/javafx-modules"
rm -rf "$STAGE" "$FXMODS"
mkdir -p "$STAGE/lib" "$FXMODS" target/dist

cp "$TARGET/yact-ui-$VERSION.jar" "$STAGE/"
for jar in "$TARGET"/lib/*.jar; do
  name="$(basename "$jar")"
  case "$name" in
    # JavaFX goes into the runtime as modules. Only the platform jars
    # (javafx-*-linux.jar etc.) hold classes; the plain ones are empty.
    javafx-*-*.jar) cp "$jar" "$FXMODS/" ;;
    javafx-*) ;;
    *) cp "$jar" "$STAGE/lib/" ;;
  esac
done

# Application icon in the format of this operating system.
case "$(uname -s)" in
  Darwin) ICON=packaging/icons/yact.icns ;;
  *)      ICON=packaging/icons/yact.png ;;
esac

ARGS=(
  --type "$TYPE"
  --icon "$ICON"
  --name YaCT
  --app-version "$APP_VERSION"
  --vendor "Christian Hoppe"
  --copyright "(c) 2015-2026 Christian Hoppe"
  --description "Encrypted file vault with post-quantum keys"
  --input "$STAGE"
  --main-jar "yact-ui-$VERSION.jar"
  --main-class yact.ui.Launcher
  --module-path "$FXMODS"
  --add-modules "$MODULES"
  --jlink-options "--strip-debug --no-header-files --no-man-pages --strip-native-commands --include-locales=en,de,fr,es,pt --compress=zip-6"
  --java-options "-Dfile.encoding=UTF-8"
  --dest target/dist
)
if [ "$TYPE" != "app-image" ]; then
  ARGS+=(--license-file Licence.txt --file-associations packaging/yact-file.properties)
fi
case "$TYPE" in
  deb|rpm) ARGS+=(--linux-shortcut --linux-menu-group Utility --linux-app-category utils) ;;
esac

rm -rf "target/dist/YaCT" "target/dist/YaCT.app"
jpackage "${ARGS[@]}"
echo "Done: $(ls -d target/dist/*)"
