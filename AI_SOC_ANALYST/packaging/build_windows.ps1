<#
  Construit AI SOC ANALYST pour Windows 10/11 x64 :
    1. environnement virtuel + dépendances verrouillées
    2. tests (pytest, Qt offscreen)
    3. exécutables PyInstaller (dist\AI_SOC_ANALYST\AI_SOC_ANALYST.exe et AI_SOC_ANALYST_cli.exe)
    4. autotest de l'exécutable gelé
    5. version portable (zip) et programme d'installation Inno Setup
  Usage (PowerShell, depuis le dossier AI_SOC_ANALYST) :  powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#>
param([switch]$SkipTests, [string]$Python = "py -3.13")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$root = Get-Location

if (-not (Test-Path .venv)) { Invoke-Expression "$Python -m venv .venv" }
$py = Join-Path $root ".venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements-dev.txt -c requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw "Installation des dépendances en échec" }

if (-not $SkipTests) {
  $env:QT_QPA_PLATFORM = "offscreen"
  & $py -m pytest tests -q --junitxml=dist\test-results.xml
  if ($LASTEXITCODE -ne 0) { throw "Tests en échec" }
  Remove-Item Env:QT_QPA_PLATFORM
}

& $py -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging\AI_SOC_ANALYST.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller en échec" }

$exeDir = Join-Path $root "dist\AI_SOC_ANALYST"
$p = Start-Process -FilePath "$exeDir\AI_SOC_ANALYST_cli.exe" -ArgumentList "--selftest","--selftest-out","$root\dist\selftest.json" -Wait -PassThru -NoNewWindow
if ($p.ExitCode -ne 0) { Get-Content dist\selftest.json; throw "Autotest de l'exécutable en échec" }

# version portable : les données sont stockées dans .\data à côté de l'exécutable
$portable = Join-Path $root "dist\portable\AI_SOC_ANALYST"
if (Test-Path (Join-Path $root "dist\portable")) { Remove-Item -Recurse -Force (Join-Path $root "dist\portable") }
New-Item -ItemType Directory -Force $portable | Out-Null
Copy-Item -Recurse "$exeDir\*" $portable
Set-Content -Path "$portable\portable.ini" -Value "[portable]`r`n; Présence de ce fichier = données stockées dans .\data" -Encoding UTF8
Copy-Item docs\*.md $portable
Compress-Archive -Path $portable -DestinationPath "dist\AI_SOC_ANALYST_1.0.0_portable_win64.zip" -Force

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
  & $iscc packaging\AI_SOC_ANALYST.iss
  if ($LASTEXITCODE -ne 0) { throw "Inno Setup en échec" }
} else {
  Write-Warning "Inno Setup 6 introuvable : programme d'installation non généré (choco install innosetup)."
}
Write-Host "Terminé. Exécutable : $exeDir\AI_SOC_ANALYST.exe"
