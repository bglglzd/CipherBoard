Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    throw "error: $Message"
}

function Get-PropertyValue([string]$Path, [string]$Name) {
    $pattern = "^" + [Regex]::Escape($Name) + "=(.*)$"
    $matches = @(Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch '^[\s]*[#!]' } | ForEach-Object {
        if ($_ -match $pattern) { $Matches[1] }
    })
    if ($matches.Count -ne 1 -or [string]::IsNullOrEmpty($matches[0])) {
        Fail "missing, duplicate, or empty property $Name in $Path"
    }
    return $matches[0]
}

function Get-SdkRoot {
    $sdk = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { $env:ANDROID_HOME }
    if (-not $sdk -or -not (Test-Path -LiteralPath $sdk -PathType Container)) {
        Fail "ANDROID_SDK_ROOT or ANDROID_HOME must point to the Android SDK"
    }
    return (Resolve-Path -LiteralPath $sdk).Path
}

function Get-LatestBuildTools([string]$Sdk) {
    $directories = @(Get-ChildItem -LiteralPath (Join-Path $Sdk "build-tools") -Directory | Sort-Object {
        try { [Version]$_.Name } catch { [Version]"0.0" }
    })
    if ($directories.Count -eq 0) { Fail "Android SDK build-tools are not installed" }
    return $directories[-1].FullName
}

function Get-SdkTool([string]$Base) {
    foreach ($candidate in @($Base, "$Base.exe", "$Base.bat")) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    Fail "Android SDK tool not found: $Base"
}

function Invoke-Checked([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "command failed ($LASTEXITCODE): $Command" }
}

function Get-SingleApk([string]$Directory, [string]$Filter) {
    $matches = @(Get-ChildItem -LiteralPath $Directory -Filter $Filter -File)
    if ($matches.Count -ne 1) { Fail "expected exactly one APK matching $Directory/$Filter" }
    return $matches[0].FullName
}

function Assert-PrivateFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "file does not exist: $Path" }
    if (-not $IsWindows) { return }
    $allowed = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        "S-1-5-18",
        "S-1-5-32-544"
    )
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            Fail "cannot resolve ACL identity for $Path"
        }
        if ($sid -notin $allowed) { Fail "file ACL grants access to ${sid}: $Path" }
    }
}
