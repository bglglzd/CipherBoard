$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$commit = "525f9b560de45753a5ea01069454e72e9aa541c6"
$sources = @(
    @{
        Language = "en"
        Name = "en_50k.txt"
        Sha256 = "5351ff405b1126ef555791dd4d9798a48e3e9a501a9fc481a9da957752cfb458"
    },
    @{
        Language = "ru"
        Name = "ru_50k.txt"
        Sha256 = "6095f507cc167488ec66ada5a85ac50433503a08ad24a07c6eabdf54352c4e7f"
    }
)

$sourceDirectory = Join-Path ([IO.Path]::GetTempPath()) "cipherboard-frequencywords-$commit"
New-Item -ItemType Directory -Force $sourceDirectory | Out-Null

foreach ($source in $sources) {
    $path = Join-Path $sourceDirectory $source.Name
    $url = "https://raw.githubusercontent.com/hermitdave/FrequencyWords/$commit/content/2018/$($source.Language)/$($source.Name)"
    Invoke-WebRequest -UseBasicParsing $url -OutFile $path
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $source.Sha256) {
        throw "Unexpected source hash for $($source.Name): $actual"
    }
}

$englishExact = @(
    "anal", "ass", "asses", "asshole", "assholes", "bastard", "bastards", "boob", "boobs",
    "breast", "breasts", "condom", "cum", "damn", "damned", "dick", "dicks", "erotic", "erection",
    "cocaine", "dead", "deadlier", "deadliest", "deadly", "death", "deaths", "faggot", "gay", "gays",
    "hell", "heroin", "hitler", "idiot", "idiots", "incest", "jerk", "jerks", "kill",
    "killed", "killer", "killers", "killing", "killings", "kills", "lesbian", "moron", "morons", "murder",
    "murdered", "murderer", "murderers", "murdering", "murders", "naked", "nazi", "nazis", "nude", "nudes",
    "orgasm", "orgasms", "rape", "raped", "rapes", "raping", "rapist", "rapists", "retard", "retarded",
    "semen", "sex", "sexual", "sexually", "sexy", "slut", "sluts", "sperm", "suicide", "suicides", "tits",
    "titty", "whore", "whores"
)
$englishFragments = @(
    "bitch", "blood", "blowjob", "bomb", "bullshit", "cock", "corpse", "cunt", "dick", "dildo", "fuck",
    "hentai", "hostage", "masturbat", "motherfuck", "nigga", "nigger", "nipple", "penis", "porn",
    "prostitut", "pussy", "shit", "shoot", "terror", "vagina", "weapon"
)

$russianExact = @(
    "войн", "война", "войне", "войной", "войною", "войну", "войны", "войнах", "войнами", "голая",
    "голого", "голой", "голые", "голый", "голым", "голую", "дебил", "дебилы", "дерьмо", "дурак",
    "дураки", "жопа", "жопе", "жопой", "жопу", "жопы", "идиот", "идиоты", "кретин", "минет", "сперма",
    "кровь", "крови", "кровью", "сука", "суки", "убил", "убила", "убили", "убило", "убит", "убита",
    "убиты", "убить", "убью", "убьют", "убьет", "урод", "уроды", "хрен", "черт", "член", "члены"
)
$russianFragments = @(
    "бляд", "блят", "бомб", "выстрел", "гандон", "гитлер", "дроч", "ебан", "ебат", "ебл", "жоп",
    "заложник", "кровав", "кровопролит", "кровотеч", "мертв", "насил", "наркот", "ниггер", "оргаз",
    "оруж", "педик", "пизд", "порно", "секс", "сись", "смерт", "солдат", "сперм", "стреля", "суицид",
    "сукин", "террор", "трах", "труп", "убив", "убий", "фашист", "хуев", "хуе", "хуй", "хуя", "член",
    "мудак"
)

function Select-Words {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Pattern,
        [Parameter(Mandatory = $true)][string[]] $ExactDenyList,
        [Parameter(Mandatory = $true)][string[]] $FragmentDenyList
    )

    $exact = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $ExactDenyList | ForEach-Object { [void] $exact.Add($_) }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $selected = [Collections.Generic.List[string]]::new()

    foreach ($line in [IO.File]::ReadLines($Path, [Text.Encoding]::UTF8)) {
        $word = ($line -split " ", 2)[0]
        if ($word -cnotmatch $Pattern -or $exact.Contains($word)) {
            continue
        }
        $blocked = $false
        foreach ($fragment in $FragmentDenyList) {
            if ($word.Contains($fragment, [StringComparison]::Ordinal)) {
                $blocked = $true
                break
            }
        }
        if (-not $blocked -and $seen.Add($word)) {
            $selected.Add($word)
            if ($selected.Count -eq 4096) {
                break
            }
        }
    }
    if ($selected.Count -ne 4096) {
        throw "Expected 4096 words, selected $($selected.Count) from $Path"
    }
    return $selected
}

$english = Select-Words `
    -Path (Join-Path $sourceDirectory "en_50k.txt") `
    -Pattern "^[a-z]{4,10}$" `
    -ExactDenyList $englishExact `
    -FragmentDenyList $englishFragments
$russian = Select-Words `
    -Path (Join-Path $sourceDirectory "ru_50k.txt") `
    -Pattern "^[а-я]{4,10}$" `
    -ExactDenyList $russianExact `
    -FragmentDenyList $russianFragments

$utf8WithoutBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot "words_en_v1.txt"), (($english -join "`n") + "`n"), $utf8WithoutBom)
[IO.File]::WriteAllText((Join-Path $PSScriptRoot "words_ru_v1.txt"), (($russian -join "`n") + "`n"), $utf8WithoutBom)

Write-Output "Generated immutable v1 word lists. Review and update pinned output hashes deliberately."
