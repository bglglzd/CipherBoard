param(
    [Parameter(Mandatory = $true, Position = 0)] [string]$Apk,
    [switch]$DebugBuild
)

. (Join-Path $PSScriptRoot "_Common.ps1")

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Apk = (Resolve-Path -LiteralPath $Apk).Path
$Sdk = Get-SdkRoot
$BuildTools = Get-ConfiguredBuildTools $Sdk $Root
$Aapt = Get-SdkTool (Join-Path $BuildTools "aapt")
$ApkSigner = Get-SdkTool (Join-Path $BuildTools "apksigner")
$ZipAlign = Get-SdkTool (Join-Path $BuildTools "zipalign")
$ApkAnalyzer = Get-SdkTool (Join-Path $Sdk "cmdline-tools/latest/bin/apkanalyzer")
$Python = (Get-Command python3 -ErrorAction SilentlyContinue)?.Source
if (-not $Python) { $Python = (Get-Command python -ErrorAction SilentlyContinue)?.Source }
if (-not $Python) { Fail "Python 3 is required for manifest and DEX policy checks" }

$Temp = Join-Path ([IO.Path]::GetTempPath()) ("cipherboard-verify-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    $AaptPermissions = Join-Path $Temp "aapt-permissions.txt"
    $AnalyzerPermissions = Join-Path $Temp "apkanalyzer-permissions.txt"
    $Manifest = Join-Path $Temp "manifest.xml"
    $Resources = Join-Path $Temp "aapt-resources.txt"
    $Signature = Join-Path $Temp "signature.txt"

    & $Aapt dump permissions $Apk 2>&1 | Set-Content -LiteralPath $AaptPermissions
    if ($LASTEXITCODE -ne 0) { Fail "aapt permission dump failed" }
    & $ApkAnalyzer manifest permissions $Apk 2>&1 | Set-Content -LiteralPath $AnalyzerPermissions
    if ($LASTEXITCODE -ne 0) { Fail "apkanalyzer permission dump failed" }
    & $ApkAnalyzer manifest print $Apk 2>&1 | Set-Content -LiteralPath $Manifest -Encoding utf8
    if ($LASTEXITCODE -ne 0) { Fail "apkanalyzer manifest print failed" }
    & $Aapt dump resources $Apk 2>&1 | Set-Content -LiteralPath $Resources -Encoding utf8
    if ($LASTEXITCODE -ne 0) { Fail "aapt resource dump failed" }
    $DexPackages = Join-Path $Temp "dex-packages.txt"
    & $ApkAnalyzer dex packages $Apk 2>&1 | Set-Content -LiteralPath $DexPackages
    if ($LASTEXITCODE -ne 0) { Fail "apkanalyzer DEX package scan failed" }
    if (Select-String -LiteralPath $DexPackages -SimpleMatch "java.lang.System void load(java.lang.String)" -Quiet) {
        Fail "arbitrary-path native code loading reference found in DEX"
    }

    $Forbidden = @(
        "android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
        "android.permission.QUERY_ALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION"
    )
    $PermissionText = (Get-Content -Raw -LiteralPath $AaptPermissions) + (Get-Content -Raw -LiteralPath $AnalyzerPermissions)
    foreach ($Permission in $Forbidden) {
        if ($PermissionText.Contains($Permission)) { Fail "forbidden permission found: $Permission" }
    }

    $Mode = if ($DebugBuild) { "debug" } else { "release" }
    $BasePackage = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.applicationId"
    $ExpectedPackage = if ($DebugBuild) { "$BasePackage.debug" } else { $BasePackage }
    $ExpectedVersionName = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.versionName"
    $ExpectedVersionCode = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.versionCode"
    $PolicyArgs = @(
        (Join-Path $PSScriptRoot "apk_policy.py"), "--mode", $Mode,
        "--manifest", $Manifest, "--apk", $Apk,
        "--expected-package", $ExpectedPackage,
        "--expected-version-name", $ExpectedVersionName,
        "--expected-version-code", $ExpectedVersionCode,
        "--aapt-resources", $Resources,
        "--expected-abi", "arm64-v8a"
    )
    if ($DebugBuild) { $PolicyArgs += @("--expected-abi", "x86_64") }
    Invoke-Checked $Python $PolicyArgs
    & $ZipAlign -c -P 16 -v 4 $Apk 2>&1 | Set-Content -LiteralPath (Join-Path $Temp "zipalign.txt")
    if ($LASTEXITCODE -ne 0) { Fail "APK zip alignment check failed" }
    & $ApkSigner verify --verbose --print-certs $Apk 2>&1 | Set-Content -LiteralPath $Signature
    if ($LASTEXITCODE -ne 0) { Fail "APK signature verification failed" }
    $SignatureText = Get-Content -Raw -LiteralPath $Signature
    if (-not $SignatureText.Contains("Verified using v2 scheme (APK Signature Scheme v2): true")) {
        Fail "APK Signature Scheme v2 is required"
    }
    if ($SignatureText -notmatch "(?m)^Number of signers: 1\r?$") {
        Fail "APK must have exactly one signer"
    }
    if (-not $DebugBuild -and -not $SignatureText.Contains("Verified using v3 scheme (APK Signature Scheme v3): true")) {
        Fail "release APK Signature Scheme v3 is required"
    }
    if (-not $DebugBuild -and $SignatureText -match "(?i)Android Debug") {
        Fail "release APK is signed with an Android debug certificate"
    }
    if (-not $DebugBuild) {
        $ExpectedSigner = (Get-Content -Raw -LiteralPath (Join-Path $Root "SIGNING_CERTIFICATE_SHA256")).Trim().ToLowerInvariant()
        if ($ExpectedSigner -notmatch '^[0-9a-f]{64}$') { Fail "invalid pinned signing certificate fingerprint" }
        $SignerMatch = [Regex]::Match(
            $SignatureText,
            '(?im)(?:Signer #1|V[0-9]+ Signer):? certificate SHA-256 digest: ([0-9a-f:]+)'
        )
        if (-not $SignerMatch.Success) { Fail "release signer SHA-256 fingerprint is missing" }
        $ActualSigner = $SignerMatch.Groups[1].Value.Replace(":", "").ToLowerInvariant()
        if ($ActualSigner -ne $ExpectedSigner) { Fail "release signer does not match the pinned update certificate" }
    }

    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Apk).Hash.ToLowerInvariant()
    Write-Output "APK verification passed: $Apk"
    Write-Output "$Hash  $Apk"
    Get-Content -LiteralPath $Signature | Where-Object { $_ -match '(Signer #1|V[0-9]+ Signer):? certificate (SHA-256 digest|DN):' }
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
