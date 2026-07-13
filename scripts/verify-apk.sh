#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/_common.sh"

usage() {
    printf 'Usage: %s [--debug] APK\n' "$0" >&2
    exit 2
}

mode=release
if [ "${1:-}" = "--debug" ]; then
    mode=debug
    shift
fi
[ "$#" -eq 1 ] || usage
apk=$1
[ -f "$apk" ] || die "APK not found: $apk"

require_command awk
require_command find
require_command sort

sdk=$(sdk_root)
build_tools=$(latest_build_tools_dir)
aapt=$(sdk_executable "$build_tools/aapt") || die "aapt not found in $build_tools"
apksigner=$(sdk_executable "$build_tools/apksigner") || die "apksigner not found in $build_tools"
zipalign=$(sdk_executable "$build_tools/zipalign") || die "zipalign not found in $build_tools"
apkanalyzer=$(sdk_executable "$sdk/cmdline-tools/latest/bin/apkanalyzer" \
    "$sdk/tools/bin/apkanalyzer" "$sdk/tools/bin/apkanalyzer.bat") || die "apkanalyzer not found"

if command -v python3 >/dev/null 2>&1; then
    python=python3
elif command -v python >/dev/null 2>&1; then
    python=python
else
    die "Python 3 is required for manifest and DEX policy checks"
fi

temp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t cipherboard-verify) || die "cannot create temporary directory"
cleanup() {
    rm -rf -- "$temp_dir"
}
trap cleanup EXIT HUP INT TERM

"$aapt" dump permissions "$apk" >"$temp_dir/aapt-permissions.txt" || die "aapt permission dump failed"
"$apkanalyzer" manifest permissions "$apk" >"$temp_dir/apkanalyzer-permissions.txt" || die "apkanalyzer permission dump failed"
"$apkanalyzer" manifest print "$apk" >"$temp_dir/manifest.xml" || die "apkanalyzer manifest print failed"
"$apkanalyzer" dex packages "$apk" >"$temp_dir/dex-packages.txt" || die "apkanalyzer DEX package scan failed"

for permission in \
    android.permission.INTERNET \
    android.permission.ACCESS_NETWORK_STATE \
    android.permission.READ_CONTACTS \
    android.permission.WRITE_CONTACTS \
    android.permission.READ_SMS \
    android.permission.RECEIVE_SMS \
    android.permission.SEND_SMS \
    android.permission.QUERY_ALL_PACKAGES \
    android.permission.SYSTEM_ALERT_WINDOW \
    android.permission.BIND_ACCESSIBILITY_SERVICE; do
    if grep -F "$permission" "$temp_dir/aapt-permissions.txt" >/dev/null 2>&1 || \
       grep -F "$permission" "$temp_dir/apkanalyzer-permissions.txt" >/dev/null 2>&1; then
        die "forbidden permission found: $permission"
    fi
done

"$python" "$SCRIPT_DIR/apk_policy.py" --mode "$mode" --manifest "$temp_dir/manifest.xml" --apk "$apk"
"$zipalign" -c -P 16 -v 4 "$apk" >"$temp_dir/zipalign.txt" || die "APK zip alignment check failed"
"$apksigner" verify --verbose --print-certs "$apk" >"$temp_dir/signature.txt" || die "APK signature verification failed"
grep -F 'Verified using v2 scheme (APK Signature Scheme v2): true' "$temp_dir/signature.txt" >/dev/null 2>&1 || \
    die "APK Signature Scheme v2 is required"

if [ "$mode" = release ] && grep -i 'Android Debug' "$temp_dir/signature.txt" >/dev/null 2>&1; then
    die "release APK is signed with an Android debug certificate"
fi

printf 'APK verification passed: %s\n' "$apk"
sha256_file "$apk"
grep -E '(Signer #1|V[0-9]+ Signer): certificate (SHA-256 digest|DN):' "$temp_dir/signature.txt" || true
