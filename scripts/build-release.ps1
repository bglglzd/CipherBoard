. (Join-Path $PSScriptRoot "_Common.ps1")

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$GitStatus = & git -C $Root status --porcelain=v1 --untracked-files=all
if ($LASTEXITCODE -ne 0) { Fail "cannot inspect Git worktree" }
if ($GitStatus) { Fail "release builds require a clean Git worktree" }
$SourceCommit = (& git -C $Root rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or -not $SourceCommit) { Fail "cannot determine source commit" }
$Version = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.versionName"
$Artifact = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.artifactName"
$SigningProperties = if ($env:CIPHERBOARD_SIGNING_PROPERTIES) {
    $env:CIPHERBOARD_SIGNING_PROPERTIES
} else {
    Join-Path $HOME ".config/cipherboard/signing.properties"
}
Assert-PrivateFile $SigningProperties
$SigningProperties = (Resolve-Path -LiteralPath $SigningProperties).Path
Assert-OutsideDirectory $SigningProperties $Root
$StoreFile = Get-PropertyValue $SigningProperties "storeFile"
$StorePassword = Get-PropertyValue $SigningProperties "storePassword"
$KeyAlias = Get-PropertyValue $SigningProperties "keyAlias"
$KeyPassword = Get-PropertyValue $SigningProperties "keyPassword"
if ($StoreFile.StartsWith("~/")) { $StoreFile = Join-Path $HOME $StoreFile.Substring(2) }
if (-not [IO.Path]::IsPathRooted($StoreFile)) {
    $StoreFile = Join-Path (Split-Path -Parent $SigningProperties) $StoreFile
}
Assert-PrivateFile $StoreFile
$StoreFile = (Resolve-Path -LiteralPath $StoreFile).Path
Assert-OutsideDirectory $StoreFile $Root

$Sdk = Get-SdkRoot
$BuildTools = Get-ConfiguredBuildTools $Sdk $Root
$ApkSigner = Get-SdkTool (Join-Path $BuildTools "apksigner")
$ZipAlign = Get-SdkTool (Join-Path $BuildTools "zipalign")
$ApkAnalyzer = Get-SdkTool (Join-Path $Sdk "cmdline-tools/latest/bin/apkanalyzer")
$Python = (Get-Command python3 -ErrorAction SilentlyContinue)?.Source
if (-not $Python) { $Python = (Get-Command python -ErrorAction SilentlyContinue)?.Source }
if (-not $Python) { Fail "Python 3 is required for release metadata" }
$OsvScanner = if ($env:CIPHERBOARD_OSV_SCANNER) {
    $env:CIPHERBOARD_OSV_SCANNER
} else {
    (Get-Command osv-scanner -ErrorAction SilentlyContinue)?.Source
}
if (-not $OsvScanner -or -not (Test-Path -LiteralPath $OsvScanner -PathType Leaf)) {
    Fail "pinned OSV-Scanner is required; set CIPHERBOARD_OSV_SCANNER"
}
$OsvScanner = (Resolve-Path -LiteralPath $OsvScanner).Path
Assert-OutsideDirectory $OsvScanner $Root
$OsvCacheRoot = if ($IsWindows) {
    $env:LOCALAPPDATA
} elseif ($IsMacOS) {
    Join-Path $HOME "Library/Caches"
} elseif ($env:XDG_CACHE_HOME) {
    $env:XDG_CACHE_HOME
} else {
    Join-Path $HOME ".cache"
}
$OsvDatabaseRoot = Join-Path $OsvCacheRoot "osv-scanner"
if (-not (Test-Path -LiteralPath $OsvDatabaseRoot -PathType Container)) {
    Fail "offline OSV databases are missing from $OsvDatabaseRoot"
}
$OsvDatabaseRoot = (Resolve-Path -LiteralPath $OsvDatabaseRoot).Path
Assert-OutsideDirectory $OsvDatabaseRoot $Root
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
        Invoke-Checked "cargo" @("clippy", "--locked", "--manifest-path", "crypto-core/native/Cargo.toml", "--all-targets", "--all-features", "--", "-D", "warnings")
        Invoke-Checked "cargo" @("test", "--locked", "--manifest-path", "crypto-core/native/Cargo.toml")
        Invoke-Checked "cargo" @("audit", "--file", "crypto-core/native/Cargo.lock")
        Invoke-Checked "cargo" @("fmt", "--all", "--manifest-path", "crypto-core/native/fuzz/Cargo.toml", "--", "--check")
        Invoke-Checked "cargo" @("clippy", "--locked", "--manifest-path", "crypto-core/native/fuzz/Cargo.toml", "--all-targets", "--", "-D", "warnings")
        Invoke-Checked "cargo" @("test", "--locked", "--manifest-path", "crypto-core/native/fuzz/Cargo.toml")
        Invoke-Checked "cargo" @("audit", "--file", "crypto-core/native/fuzz/Cargo.lock")
        Invoke-Checked "cargo" @("fmt", "--all", "--manifest-path", "crypto-core/jni/Cargo.toml", "--", "--check")
        Invoke-Checked "cargo" @("clippy", "--locked", "--manifest-path", "crypto-core/jni/Cargo.toml", "--all-targets", "--all-features", "--", "-D", "warnings")
        Invoke-Checked "cargo" @("test", "--locked", "--manifest-path", "crypto-core/jni/Cargo.toml")
        Invoke-Checked "cargo" @("audit", "--file", "crypto-core/jni/Cargo.lock")
        Invoke-Checked $Python @((Join-Path $PSScriptRoot "security_source_scan.py"), $Root)
        Invoke-Checked $Python @((Join-Path $PSScriptRoot "kotlin_style_check.py"), $Root)
        Invoke-Checked $Python @("-m", "unittest", "discover", "-s", (Join-Path $PSScriptRoot "tests"), "-p", "test_*.py")
        Invoke-Checked (Join-Path $Root "gradlew.bat") @(
            "--no-daemon",
            ":app:lintRelease", ":crypto-core:lintRelease", ":pairing:lintRelease", ":secure-storage:lintRelease",
            ":app:testDebugUnitTest", ":crypto-core:testDebugUnitTest",
            ":pairing:testDebugUnitTest", ":secure-storage:testDebugUnitTest",
            ":crypto-core:connectedDebugAndroidTest", ":app:connectedDebugAndroidTest",
            ":app:assembleRelease"
        )
        Assert-CleanGitState $Root $SourceCommit

        $Unsigned = Get-SingleApk (Join-Path $Root "app/build/outputs/apk/release") "*.apk"
        $Aligned = Join-Path $Temp "aligned.apk"
        $Staging = Join-Path $Temp "dist"
        New-Item -ItemType Directory -Path $Staging | Out-Null
        $StagedApk = Join-Path $Staging "$Artifact-$Version-release.apk"
        $Dist = Join-Path $Root "dist"
        $Destination = Join-Path $Dist "$Artifact-$Version-release.apk"
        Invoke-Checked $ZipAlign @("-f", "-P", "16", "4", $Unsigned, $Aligned)
        Invoke-Checked $ApkSigner @(
            "sign", "--ks", $StoreFile, "--ks-key-alias", $KeyAlias,
            "--ks-pass", "file:$StorePassFile", "--key-pass", "file:$KeyPassFile",
            "--min-sdk-version", "23", "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
            "--out", $StagedApk, $Aligned
        )
        & (Join-Path $PSScriptRoot "verify-apk.ps1") -Apk $StagedApk
        if (-not $?) { Fail "release APK verification failed" }
        $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $StagedApk).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$StagedApk.sha256", "$Hash  $([IO.Path]::GetFileName($StagedApk))`n", $Utf8NoBom)
        Copy-Item -LiteralPath (Join-Path $Root "THIRD_PARTY_NOTICES.md") -Destination (Join-Path $Staging "THIRD_PARTY_NOTICES.txt")
        $LicenseFiles = @(
            "LICENSE",
            "LICENSE-Apache-2.0",
            "LICENSE-BSD-3-Clause-NOTICES",
            "LICENSE-BlueOak-1.0.0",
            "LICENSE-CC-BY-SA-4.0",
            "LICENSE-MIT",
            "LICENSES.md"
        )
        foreach ($LicenseFile in $LicenseFiles) {
            Copy-Item -LiteralPath (Join-Path $Root $LicenseFile) -Destination (Join-Path $Staging $LicenseFile)
        }
        $SourceArchive = Join-Path $Staging "$Artifact-$Version-source.tar.gz"
        Invoke-Checked "git" @(
            "-C", $Root, "archive", "--format=tar.gz",
            "--prefix=$Artifact-$Version-source/", "--output=$SourceArchive", $SourceCommit
        )
        Invoke-Checked $Python @(
            (Join-Path $PSScriptRoot "release_metadata.py"),
            "--root", $Root, "--apk", $StagedApk, "--output-dir", $Staging,
            "--apksigner", $ApkSigner, "--apkanalyzer", $ApkAnalyzer
        )
        Invoke-Checked $Python @(
            (Join-Path $PSScriptRoot "osv_offline_scan.py"),
            "--scanner", $OsvScanner, "--database-root", $OsvDatabaseRoot,
            "--sbom", (Join-Path $Staging "SBOM.json"),
            "--output", (Join-Path $Staging "VULNERABILITY_SCAN.json")
        )
        $Public = Join-Path $Temp "public"
        New-Item -ItemType Directory -Path $Public | Out-Null
        Copy-Item -LiteralPath $StagedApk, "$StagedApk.sha256" -Destination $Public
        $BundleName = "$Artifact-$Version-verification.zip"
        $Bundle = Join-Path $Public $BundleName
        Invoke-Checked $Python @(
            (Join-Path $PSScriptRoot "release_bundle.py"), "create",
            "--staging-dir", $Staging, "--output", $Bundle,
            "--artifact", $Artifact, "--version", $Version
        )
        Assert-CleanGitState $Root $SourceCommit
        Remove-Item -LiteralPath $Dist -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $Dist | Out-Null
        Copy-Item -LiteralPath $StagedApk, "$StagedApk.sha256", $Bundle -Destination $Dist
        Invoke-Checked $Python @(
            (Join-Path $PSScriptRoot "release_bundle.py"), "extract",
            "--assets-dir", $Dist, "--output-dir", (Join-Path $Temp "published-evidence"),
            "--artifact", $Artifact, "--version", $Version
        )
        $PublishedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
        if ($PublishedHash -ne $Hash) { Fail "published release APK hash differs from verified staging APK" }
        Write-Output "Release APK: $Destination"
        Write-Output "SHA-256: $Hash"
        Write-Output "Verification bundle: $(Join-Path $Dist $BundleName)"
    } finally {
        Pop-Location
    }
} finally {
    $StorePassword = $null
    $KeyPassword = $null
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
