. (Join-Path $PSScriptRoot "_Common.ps1")

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Version = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.versionName"
$Artifact = Get-PropertyValue (Join-Path $Root "gradle.properties") "cipherboard.artifactName"
Push-Location $Root
try {
    $Python = Get-Python3
    Invoke-Checked $Python @((Join-Path $PSScriptRoot "security_source_scan.py"), $Root)
    Invoke-Checked $Python @((Join-Path $PSScriptRoot "kotlin_style_check.py"), $Root)
    Invoke-Checked (Join-Path $Root "gradlew.bat") @(
        "--no-daemon", ":app:lintDebug", ":app:testDebugUnitTest",
        ":crypto-core:testDebugUnitTest", ":pairing:testDebugUnitTest",
        ":secure-storage:testDebugUnitTest", ":app:assembleDebug"
    )
    $Source = Get-SingleApk (Join-Path $Root "app/build/outputs/apk/debug") "$Artifact-$Version-debug.apk"
    & (Join-Path $PSScriptRoot "verify-apk.ps1") -Apk $Source -DebugBuild
    if (-not $?) { Fail "debug APK verification failed" }
    $Dist = Join-Path $Root "dist"
    New-Item -ItemType Directory -Force -Path $Dist | Out-Null
    $Destination = Join-Path $Dist "$Artifact-$Version-debug.apk"
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    Write-Output "Debug APK: $Destination"
} finally {
    Pop-Location
}
