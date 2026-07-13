#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/_common.sh"

cd "$ROOT_DIR"
version=$(project_property cipherboard.versionName)
artifact=$(project_property cipherboard.artifactName)
signing_properties=${CIPHERBOARD_SIGNING_PROPERTIES:-"$HOME/.config/cipherboard/signing.properties"}
[ -f "$signing_properties" ] || die "external signing properties not found: $signing_properties"
check_private_mode_posix "$signing_properties"

store_file=$(signing_property "$signing_properties" storeFile)
store_password=$(signing_property "$signing_properties" storePassword)
key_alias=$(signing_property "$signing_properties" keyAlias)
key_password=$(signing_property "$signing_properties" keyPassword)
case "$store_file" in
    '~/'*) store_file=$HOME/${store_file#\~/} ;;
esac
[ -f "$store_file" ] || die "release keystore does not exist: $store_file"
check_private_mode_posix "$store_file"

sdk=$(sdk_root)
build_tools=$(latest_build_tools_dir)
apksigner=$(sdk_executable "$build_tools/apksigner") || die "apksigner not found in $build_tools"
zipalign=$(sdk_executable "$build_tools/zipalign") || die "zipalign not found in $build_tools"
apkanalyzer=$(sdk_executable "$sdk/cmdline-tools/latest/bin/apkanalyzer" \
    "$sdk/tools/bin/apkanalyzer" "$sdk/tools/bin/apkanalyzer.bat") || die "apkanalyzer not found"
if command -v python3 >/dev/null 2>&1; then
    python=python3
elif command -v python >/dev/null 2>&1; then
    python=python
else
    die "Python 3 is required for release metadata"
fi

temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t cipherboard-release) || die "cannot create temporary directory"
cleanup() {
    unset store_password key_password
    rm -rf -- "$temp_dir"
}
trap cleanup EXIT HUP INT TERM
chmod 700 "$temp_dir" 2>/dev/null || true
printf '%s\n' "$store_password" >"$temp_dir/store.pass"
printf '%s\n' "$key_password" >"$temp_dir/key.pass"
chmod 600 "$temp_dir/store.pass" "$temp_dir/key.pass" 2>/dev/null || true
unset store_password key_password

cargo fmt --all --manifest-path crypto-core/native/Cargo.toml -- --check
cargo clippy --manifest-path crypto-core/native/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path crypto-core/native/Cargo.toml
cargo audit --file crypto-core/native/Cargo.lock
cargo fmt --all --manifest-path crypto-core/jni/Cargo.toml -- --check
cargo clippy --manifest-path crypto-core/jni/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path crypto-core/jni/Cargo.toml
cargo audit --file crypto-core/jni/Cargo.lock
./gradlew --no-daemon :app:lintRelease :app:testReleaseUnitTest :app:assembleRelease

unsigned_apk=$(find_single_apk "$ROOT_DIR/app/build/outputs/apk/release" '*.apk')
mkdir -p "$ROOT_DIR/dist"
aligned_apk="$temp_dir/aligned.apk"
destination="$ROOT_DIR/dist/$artifact-$version-release.apk"
"$zipalign" -f -P 16 4 "$unsigned_apk" "$aligned_apk"
"$apksigner" sign \
    --ks "$store_file" \
    --ks-key-alias "$key_alias" \
    --ks-pass "file:$temp_dir/store.pass" \
    --key-pass "file:$temp_dir/key.pass" \
    --min-sdk-version 23 \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --out "$destination" \
    "$aligned_apk"

"$SCRIPT_DIR/verify-apk.sh" "$destination"
sha256_file "$destination" >"$destination.sha256"
cp -- "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$ROOT_DIR/dist/THIRD_PARTY_NOTICES.txt"
"$python" "$SCRIPT_DIR/release_metadata.py" \
    --root "$ROOT_DIR" \
    --apk "$destination" \
    --output-dir "$ROOT_DIR/dist" \
    --apksigner "$apksigner" \
    --apkanalyzer "$apkanalyzer"
printf 'Release APK: %s\nSHA-256: %s\n' "$destination" "$(cut -d ' ' -f 1 "$destination.sha256")"
