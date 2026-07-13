#!/usr/bin/env sh

set -eu

die() {
    printf '%s\n' "error: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

project_property() {
    key=$1
    value=$(awk -F= -v wanted="$key" '
        { sub(/\r$/, "", $0) }
        $0 !~ /^[[:space:]]*#/ && $1 == wanted { count++; print substr($0, index($0, "=") + 1) }
        END { if (count != 1) exit 2 }
    ' "$ROOT_DIR/gradle.properties") || die "missing or duplicate Gradle property: $key"
    [ -n "$value" ] || die "empty Gradle property: $key"
    printf '%s' "$value"
}

signing_property() {
    file=$1
    key=$2
    value=$(awk -F= -v wanted="$key" '
        { sub(/\r$/, "", $0) }
        $0 !~ /^[[:space:]]*[#!]/ && $1 == wanted { count++; print substr($0, index($0, "=") + 1) }
        END { if (count != 1) exit 2 }
    ' "$file") || die "missing or duplicate signing property: $key"
    [ -n "$value" ] || die "empty signing property: $key"
    printf '%s' "$value"
}

sdk_root() {
    value=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
    [ -n "$value" ] || die "ANDROID_SDK_ROOT or ANDROID_HOME must point to the Android SDK"
    [ -d "$value" ] || die "Android SDK directory does not exist: $value"
    printf '%s' "$value"
}

latest_build_tools_dir() {
    sdk=$(sdk_root)
    directory=$(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -V | tail -n 1)
    [ -n "$directory" ] || die "Android SDK build-tools are not installed"
    printf '%s' "$directory"
}

sdk_executable() {
    base=$1
    shift
    for candidate in "$base" "$base.exe" "$base.bat"; do
        if [ -f "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    for candidate in "$@"; do
        if [ -f "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

sha256_file() {
    file=$1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file"
    else
        die "sha256sum or shasum is required"
    fi
}

find_single_apk() {
    directory=$1
    pattern=$2
    set -- "$directory"/$pattern
    [ "$#" -eq 1 ] && [ -f "$1" ] || die "expected exactly one APK matching $directory/$pattern"
    printf '%s' "$1"
}

check_private_mode_posix() {
    path=$1
    case "$(uname -s 2>/dev/null || true)" in
        MINGW*|MSYS*|CYGWIN*) return 0 ;;
    esac
    if mode=$(stat -c '%a' "$path" 2>/dev/null); then
        case "$mode" in
            *[1-7][0-7]|*[0-7][1-7]) die "permissions must deny group/other access: $path ($mode)" ;;
        esac
    elif mode=$(stat -f '%Lp' "$path" 2>/dev/null); then
        group_other=$((mode % 100))
        [ "$group_other" -eq 0 ] || die "permissions must deny group/other access: $path ($mode)"
    else
        die "unable to verify file permissions: $path"
    fi
}
