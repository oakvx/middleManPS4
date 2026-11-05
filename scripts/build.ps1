param(
    [string]$SdkPath = "/home/gabri/ps4-payload-sdk-1252"
)
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$WslRoot = (& wsl.exe --exec wslpath -a -u $RepoRoot).Trim()
if ($LASTEXITCODE -ne 0 -or !$WslRoot) { throw "Impossibile convertire il path per WSL" }
& wsl.exe --cd $WslRoot --exec env "PS4_PAYLOAD_SDK=$SdkPath" bash scripts/build.sh
if ($LASTEXITCODE -ne 0) { throw "Build non riuscita: controlla SDK e compiler nel terminale WSL" }
Write-Host "ELF compilati nella directory dist/"
