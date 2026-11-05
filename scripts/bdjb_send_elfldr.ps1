param(
    [string]$Ps4Ip = "192.168.31.11",
    [switch]$Send,
    [switch]$AcceptRisk,
    [switch]$AllowCustomLoader
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root
$Bin = Join-Path $Root 'dist\elfldr.bin'
$HashFile = Join-Path $Root 'dist\elfldr.bin.sha256'
if (-not (Test-Path -LiteralPath $Bin -PathType Leaf)) {
    throw "Manca dist\elfldr.bin. In WSL: bash scripts/setup_elfldr.sh ; bash scripts/stage_elfldr_bin.sh"
}
if (-not (Test-Path -LiteralPath $HashFile -PathType Leaf)) {
    throw 'Manca dist\elfldr.bin.sha256. Esegui: bash scripts/stage_elfldr_bin.sh'
}
$BinInfo = Get-Item -LiteralPath $Bin
if ($BinInfo.Length -lt 128) { throw 'elfldr.bin troppo piccolo: impossibile inviarlo' }
$ExpectedHash = ((Get-Content -LiteralPath $HashFile -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
if ($ExpectedHash -notmatch '^[0-9a-f]{64}$') {
    throw 'File SHA-256 non valido: esegui nuovamente stage_elfldr_bin.sh'
}
$ActualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Bin).Hash.ToLowerInvariant()
if ($ActualHash -ne $ExpectedHash) {
    throw 'SHA-256 mismatch: elfldr.bin differisce dal file preparato. NON INVIARE.'
}
# A sidecar only checks that the file did not change after staging. It does
# NOT authenticate the loader. Prefer the official v0.7 SHA-256 pinned in
# scripts/fetch_official_elfldr.py; custom local binaries require an explicit
# acknowledgement before a live send.
$OfficialHash = '9525dc95393ab943758db69a1f49fea6e82f36f2821bf5f41bc00bfc4d6f75df'
$IsOfficialBin = ($ActualHash -eq $OfficialHash)
if (-not $IsOfficialBin) {
    Write-Warning 'Loader non identico alla release ufficiale v0.7: checksum locale NON ne autentica provenienza e correttezza.'
    if ($Send -and -not $AllowCustomLoader) {
        throw 'Invio di un BIN non ufficiale bloccato. Usa il downloader con SHA pinned oppure -AllowCustomLoader (solo dopo verifica sorgenti e build).'
    }
} else {
    Write-Host 'Loader ufficiale elfldr.bin v0.7: SHA-256 pinned verificato.'
}

$Stream = [System.IO.File]::OpenRead($Bin)
try {
    $Magic = New-Object byte[] 4
    if ($Stream.Read($Magic, 0, 4) -ne 4) { throw 'Payload BIN vuoto o troppo piccolo' }
    if ($Magic[0] -eq 127 -and $Magic[1] -eq 69 -and $Magic[2] -eq 76 -and $Magic[3] -eq 70) {
        throw 'Questo e un ELF, NON un BIN flat. Non rinominare il file!'
    }
} finally { $Stream.Dispose() }
Write-Host '=== BD-JB / Poops -> GoldHEN 9090 -> elfldr.bin ==='
Get-FileHash -Algorithm SHA256 -LiteralPath $Bin | Format-List Hash,Path
if ($Send -and -not $AcceptRisk) {
    throw 'Per inviare davvero servono entrambi -Send -AcceptRisk (rischio di instabilita PS4).'
}
$ArgsList = @('-m','host.ps4_sender.cli','--host',$Ps4Ip,'--loader','goldhen',
              '--file',$Bin,'--expected-sha256',$ExpectedHash)
if ($Send) {
    $ArgsList += @('--send','--accept-bootstrap-risk')
    if (-not $IsOfficialBin) { $ArgsList += '--allow-custom-bin' }
}
& python @ArgsList
if ($LASTEXITCODE -ne 0) { throw "Errore sender Python: exit $LASTEXITCODE" }
if ($Send) {
    Write-Host 'Trasferimento effettuato; NON e prova di esecuzione.'
    Write-Host "Verifica 9021: python -m host.ps4_sender.diagnostics --host $Ps4Ip --port 9021 --require-open"
} else {
    Write-Host 'DRY RUN: nessuna connessione alla PS4. Invio ufficiale: .\scripts\bdjb_send_elfldr.ps1 -Send -AcceptRisk'
    if (-not $IsOfficialBin) { Write-Host 'BIN locale non ufficiale: serve anche -AllowCustomLoader prima di un invio.' }
}
