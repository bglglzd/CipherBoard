#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/_common.sh"

cd "$ROOT_DIR"
git_status=$(git status --porcelain=v1 --untracked-files=all) || die "cannot inspect Git worktree"
[ -z "$git_status" ] || die "release builds require a clean Git worktree"
unset git_status
source_commit=$(git rev-parse HEAD) || die "cannot determine source commit"
version=$(project_property cipherboard.versionName)
artifact=$(project_property cipherboard.artifactName)
signing_properties=${CIPHERBOARD_SIGNING_PROPERTIES:-"$HOME/.config/cipherboard/signing.properties"}
[ -f "$signing_properties" ] || die "external signing properties not found: $signing_properties"
check_private_mode_posix "$signing_properties"
signing_properties_dir=$(CDPATH= cd -- "$(dirname -- "$signing_properties")" && pwd -P) || \
    die "cannot resolve signing properties directory"
signing_properties=$signing_properties_dir/$(basename -- "$signing_properties")
case "$signing_properties" in
    "$ROOT_DIR"|"$ROOT_DIR"/*) die "signing properties must be outside the repository" ;;
esac

store_file=$(signing_property "$signing_properties" storeFile)
store_password=$(signing_property "$signing_properties" storePassword)
key_alias=$(signing_property "$signing_properties" keyAlias)
key_password=$(signing_property "$signing_properties" keyPassword)
case "$store_file" in
    '~/'*) store_file=$HOME/${store_file#\~/} ;;
    /*) ;;
    *) store_file=$signing_properties_dir/$store_file ;;
esac
[ -f "$store_file" ] || die "release keystore does not exist: $store_file"
check_private_mode_posix "$store_file"
store_file_dir=$(CDPATH= cd -- "$(dirname -- "$store_file")" && pwd -P) || die "cannot resolve keystore directory"
store_file=$store_file_dir/$(basename -- "$store_file")
case "$store_file" in
    "$ROOT_DIR"|"$ROOT_DIR"/*) die "release keystore must be outside the repository" ;;
esac

sdk=$(sdk_root)
build_tools=$(configured_build_tools_dir)
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
osv_scanner=${CIPHERBOARD_OSV_SCANNER:-}
if [ -z "$osv_scanner" ]; then
    osv_scanner=$(command -v osv-scanner 2>/dev/null || true)
fi
[ -n "$osv_scanner" ] && [ -f "$osv_scanner" ] || \
    die "pinned OSV-Scanner is required; set CIPHERBOARD_OSV_SCANNER"
osv_scanner_dir=$(CDPATH= cd -- "$(dirname -- "$osv_scanner")" && pwd -P) || die "cannot resolve OSV-Scanner"
osv_scanner=$osv_scanner_dir/$(basename -- "$osv_scanner")
case "$osv_scanner" in
    "$ROOT_DIR"|"$ROOT_DIR"/*) die "OSV-Scanner must be installed outside the repository" ;;
esac
case "$(uname -s 2>/dev/null || true)" in
    Darwin*) osv_database_root="$HOME/Library/Caches/osv-scanner" ;;
    *) osv_database_root="${XDG_CACHE_HOME:-$HOME/.cache}/osv-scanner" ;;
esac
[ -d "$osv_database_root" ] || die "offline OSV databases are missing from $osv_database_root"
osv_database_root=$(CDPATH= cd -- "$osv_database_root" && pwd -P) || die "cannot resolve offline OSV databases"
case "$osv_database_root" in
    "$ROOT_DIR"|"$ROOT_DIR"/*) die "offline OSV databases must be outside the repository" ;;
esac

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
cargo clippy --locked --manifest-path crypto-core/native/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path crypto-core/native/Cargo.toml
cargo audit --file crypto-core/native/Cargo.lock
cargo fmt --all --manifest-path crypto-core/native/fuzz/Cargo.toml -- --check
cargo clippy --locked --manifest-path crypto-core/native/fuzz/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path crypto-core/native/fuzz/Cargo.toml
cargo audit --file crypto-core/native/fuzz/Cargo.lock
cargo fmt --all --manifest-path crypto-core/jni/Cargo.toml -- --check
cargo clippy --locked --manifest-path crypto-core/jni/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --locked --manifest-path crypto-core/jni/Cargo.toml
cargo audit --file crypto-core/jni/Cargo.lock
"$python" "$SCRIPT_DIR/security_source_scan.py" "$ROOT_DIR"
"$python" "$SCRIPT_DIR/kotlin_style_check.py" "$ROOT_DIR"
"$python" -m unittest discover -s "$SCRIPT_DIR/tests" -p 'test_*.py'
./gradlew --no-daemon \
    :app:lintRelease :crypto-core:lintRelease :pairing:lintRelease :secure-storage:lintRelease \
    :app:testDebugUnitTest :crypto-core:testDebugUnitTest \
    :pairing:testDebugUnitTest :secure-storage:testDebugUnitTest \
    :crypto-core:connectedDebugAndroidTest :app:connectedDebugAndroidTest \
    :app:assembleRelease
assert_clean_git_state "$source_commit"

unsigned_apk=$(find_single_apk "$ROOT_DIR/app/build/outputs/apk/release" '*.apk')
aligned_apk="$temp_dir/aligned.apk"
staging_dir="$temp_dir/dist"
mkdir -p "$staging_dir"
staged_apk="$staging_dir/$artifact-$version-release.apk"
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
    --out "$staged_apk" \
    "$aligned_apk"

"$SCRIPT_DIR/verify-apk.sh" "$staged_apk"
hash_line=$(sha256_file "$staged_apk")
hash=${hash_line%% *}
printf '%s  %s\n' "$hash" "$(basename "$staged_apk")" >"$staged_apk.sha256"
cp -- "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$staging_dir/THIRD_PARTY_NOTICES.txt"
for license_file in \
    LICENSE \
    LICENSE-Apache-2.0 \
    LICENSE-BSD-3-Clause-NOTICES \
    LICENSE-BlueOak-1.0.0 \
    LICENSE-CC-BY-SA-4.0 \
    LICENSE-MIT \
    LICENSES.md; do
    cp -- "$ROOT_DIR/$license_file" "$staging_dir/$license_file"
done
git -C "$ROOT_DIR" archive --format=tar.gz \
    --prefix="$artifact-$version-source/" \
    --output="$staging_dir/$artifact-$version-source.tar.gz" \
    "$source_commit"
"$python" "$SCRIPT_DIR/release_metadata.py" \
    --root "$ROOT_DIR" \
    --apk "$staged_apk" \
    --output-dir "$staging_dir" \
    --apksigner "$apksigner" \
    --apkanalyzer "$apkanalyzer"
"$python" "$SCRIPT_DIR/osv_offline_scan.py" \
    --scanner "$osv_scanner" \
    --database-root "$osv_database_root" \
    --sbom "$staging_dir/SBOM.json" \
    --output "$staging_dir/VULNERABILITY_SCAN.json"
public_dir="$temp_dir/public"
mkdir -p "$public_dir"
cp -- "$staged_apk" "$staged_apk.sha256" "$public_dir/"
bundle="$public_dir/$artifact-$version-verification.zip"
"$python" "$SCRIPT_DIR/release_bundle.py" create \
    --staging-dir "$staging_dir" \
    --output "$bundle" \
    --artifact "$artifact" \
    --version "$version"
assert_clean_git_state "$source_commit"
rm -rf -- "$ROOT_DIR/dist"
mkdir -p "$ROOT_DIR/dist"
cp -- "$public_dir"/* "$ROOT_DIR/dist/"
"$python" "$SCRIPT_DIR/release_bundle.py" extract \
    --assets-dir "$ROOT_DIR/dist" \
    --output-dir "$temp_dir/published-evidence" \
    --artifact "$artifact" \
    --version "$version"
published_hash_line=$(sha256_file "$destination")
published_hash=${published_hash_line%% *}
[ "$published_hash" = "$hash" ] || die "published release APK hash differs from verified staging APK"
printf 'Release APK: %s\nSHA-256: %s\nVerification bundle: %s\n' \
    "$destination" "$hash" "$ROOT_DIR/dist/$(basename -- "$bundle")"
