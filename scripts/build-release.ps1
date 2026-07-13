. (Join-Path $PSScriptRoot "_Common.ps1")

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Version = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.versionName"
$Artifact = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.artifactName"
$SigningProperties = if ($env:CIPHERBOARD_SIGNING_PROPERTIES) {
    $env:CIPHERBOARD_SIGNING_PROPERTIES
} else {
    Join-Path $HOME ".config/cipherboard/signing.properties"
}
Assert-PrivateFile $SigningProperties
$StoreFile = Get-PropertyValue $SigningProperties "storeFile"
$StorePassword = Get-PropertyValue $SigningProperties "storePassword"
$KeyAlias = Get-PropertyValue $SigningProperties "keyAlias"
$KeyPassword = Get-PropertyValue $SigningProperties "keyPassword"
if ($StoreFile.StartsWith("~/")) { $StoreFile = Join-Path $HOME $StoreFile.Substring(2) }
Assert-PrivateFile $StoreFile

$Sdk = Get-SdkRoot
$BuildTools = Get-LatestBuildTools $Sdk
$ApkSigner = Get-SdkTool (Join-Path $BuildTools "apksigner")
$ZipAlign = Get-SdkTool (Join-Path $BuildTools "zipalign")
$ApkAnalyzer = Get-SdkTool (Join-Path $Sdk "cmdline-tools/latest/bin/apkanalyzer")
$Python = (Get-Command python3 -ErrorAction SilentlyContinue)?.Source
if (-not $Python) { $Python = (Get-Command python -ErrorAction SilentlyContinue)?.Source }
if (-not $Python) { Fail "Python 3 is required for release metadata" }
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("cipherboard-release-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Temp | Out-Null
if ($IsWindows) {
    & icacls.exe $Temp /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "cannot restrict release temporary directory ACL" }
}
try {
    $Utf8NoBom = [Text.UTF8Encoding]::new($false)
    $StorePassFile = Join-Path $Temp "store.pass"
    $KeyPassFile = Join-Path $Temp "key.pass"
    [IO.File]::WriteAllText($StorePassFile, $StorePassword + [Environment]::NewLine, $Utf8NoBom)
    [IO.File]::WriteAllText($KeyPassFile, $KeyPassword + [Environment]::NewLine, $Utf8NoBom)
    $StorePassword = $null
    $KeyPassword = $null

    Push-Location $Root
    try {
        Invoke-Checked "cargo" @("fmt", "--all", "--manifest-path", "crypto-core/native/Cargo.toml", "--", "--check")
        Invoke-Checked "cargo" @("clippy", "--manifest-path", "crypto-core/native/Cargo.toml", "--all-targets", "--all-features", "--", "-D", "warnings")
        Invoke-Checked "cargo" @("test", "--manifest-path", "crypto-core/native/Cargo.toml")
        Invoke-Checked "cargo" @("audit", "--file", "crypto-core/native/Cargo.lock")
        Invoke-Checked "cargo" @("fmt", "--all", "--manifest-path", "crypto-core/jni/Cargo.toml", "--", "--check")
        Invoke-Checked "cargo" @("clippy", "--manifest-path", "crypto-core/jni/Cargo.toml", "--all-targets", "--all-features", "--", "-D", "warnings")
        Invoke-Checked "cargo" @("test", "--manifest-path", "crypto-core/jni/Cargo.toml")
        Invoke-Checked "cargo" @("audit", "--file", "crypto-core/jni/Cargo.lock")
        Invoke-Checked (Join-Path $Root "gradlew.bat") @("--no-daemon", ":app:lintRelease", ":app:testReleaseUnitTest", ":app:assembleRelease")

        $Unsigned = Get-SingleApk (Join-Path $Root "app/build/outputs/apk/release") "*.apk"
        $Aligned = Join-Path $Temp "aligned.apk"
        $Dist = Join-Path $Root "dist"
        New-Item -ItemType Directory -Force -Path $Dist | Out-Null
        $Destination = Join-Path $Dist "$Artifact-$Version-release.apk"
        Invoke-Checked $ZipAlign @("-f", "-P", "16", "4", $Unsigned, $Aligned)
        Invoke-Checked $ApkSigner @(
            "sign", "--ks", $StoreFile, "--ks-key-alias", $KeyAlias,
            "--ks-pass", "file:$StorePassFile", "--key-pass", "file:$KeyPassFile",
            "--min-sdk-version", "23", "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
            "--out", $Destination, $Aligned
        )
        & (Join-Path $PSScriptRoot "verify-apk.ps1") -Apk $Destination
        if (-not $?) { Fail "release APK verification failed" }
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$Destination.sha256", "$Hash  $([IO.Path]::GetFileName($Destination))`n", $Utf8NoBom)
        Copy-Item -LiteralPath (Join-Path $Root "THIRD_PARTY_NOTICES.md") -Destination (Join-Path $Dist "THIRD_PARTY_NOTICES.txt") -Force
        Invoke-Checked $Python @(
            (Join-Path $PSScriptRoot "release_metadata.py"),
            "--root", $Root, "--apk", $Destination, "--output-dir", $Dist,
            "--apksigner", $ApkSigner, "--apkanalyzer", $ApkAnalyzer
        )
        Write-Output "Release APK: $Destination"
        Write-Output "SHA-256: $Hash"
    } finally {
        Pop-Location
    }
} finally {
    $StorePassword = $null
    $KeyPassword = $null
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
