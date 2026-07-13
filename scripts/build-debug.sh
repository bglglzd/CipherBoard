#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/_common.sh"

cd "$ROOT_DIR"
version=$(project_property cipherboard.versionName)
artifact=$(project_property cipherboard.artifactName)

./gradlew --no-daemon :app:lintDebug :app:testDebugUnitTest :app:assembleDebug

source_apk=$(find_single_apk "$ROOT_DIR/app/build/outputs/apk/debug" "$artifact-$version-debug.apk")
mkdir -p "$ROOT_DIR/dist"
destination="$ROOT_DIR/dist/$artifact-$version-debug.apk"
cp -- "$source_apk" "$destination"
"$SCRIPT_DIR/verify-apk.sh" --debug "$destination"
printf 'Debug APK: %s\n' "$destination"
