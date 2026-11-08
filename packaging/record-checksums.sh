#!/usr/bin/env bash
#-------------------------------------------------------------------------------
# YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
#-------------------------------------------------------------------------------
# Records the SHA-256 checksum of every Maven artifact the build uses in
# .mvn/checksums/checksums-central.sha256 - after a dependency or plugin update.
#
# Starts from an empty local repository, so nothing is taken from a cache and
# nothing is missed, then builds once more from a second empty repository with
# the checksums enforced, as CI does.
#
# Run it only once you trust the new artifacts. Afterwards review
#   git diff .mvn/checksums
# Every change must belong to the intended update; check new artifacts against
# their publishers' signatures (e.g. the .asc files on Maven Central).
#
# Usage: packaging/record-checksums.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FILE=.mvn/checksums/checksums-central.sha256
JAVAFX="$(sed -n 's:.*<javafx.version>\(.*\)</javafx.version>.*:\1:p' pom.xml | head -1)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
RECORD=(-B -q "-Dmaven.repo.local=$WORK/record" -Daether.artifactResolver.postProcessor.trustedChecksums.record=true)

rm -f "$FILE"
echo "Recording: build and tests ..."
./mvnw "${RECORD[@]}" clean install
echo "Recording: javafx:run ..."
# Starts YaCT from the build with --version, which prints and exits without a window.
./mvnw "${RECORD[@]}" -pl yact-ui javafx:run -Djavafx.args=--version
echo "Recording: JavaFX $JAVAFX for every platform ..."
for m in javafx-base javafx-graphics javafx-controls; do
  for c in win mac mac-aarch64 linux linux-aarch64; do
    ./mvnw "${RECORD[@]}" dependency:get "-Dartifact=org.openjfx:$m:$JAVAFX:jar:$c" -Dtransitive=false
  done
done
sort -o "$FILE" "$FILE"
rm -f "$FILE.bak" # Maven's backup of the previous file
echo "Recorded $(wc -l < "$FILE") checksums."

echo "Checking: build from an empty repository with the checksums enforced ..."
./mvnw -B -q "-Dmaven.repo.local=$WORK/verify" clean verify
echo "Done. Review: git diff $FILE"
