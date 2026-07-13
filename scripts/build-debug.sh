#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/_common.sh"

cd "$ROOT_DIR"
version=$(project_property cipherboard.versionName)
artifact=$(project_property cipherboard.artifactName)

if command -v python3 >/dev/null 2>&1; then python=python3; else python=python; fi
"$python" "$SCRIPT_DIR/security_source_scan.py" "$ROOT_DIR"
"$python" "$SCRIPT_DIR/kotlin_style_check.py" "$ROOT_DIR"
./gradlew --no-daemon :app:lintDebug :app:testDebugUnitTest \
    :crypto-core:testDebugUnitTest :pairing:testDebugUnitTest \
    :secure-storage:testDebugUnitTest :app:assembleDebug

source_apk=$(find_single_apk "$ROOT_DIR/app/build/outputs/apk/debug" "$artifact-$version-debug.apk")
"$SCRIPT_DIR/verify-apk.sh" --debug "$source_apk"
mkdir -p "$ROOT_DIR/dist"
destination="$ROOT_DIR/dist/$artifact-$version-debug.apk"
cp -- "$source_apk" "$destination"
printf 'Debug APK: %s\n' "$destination"
