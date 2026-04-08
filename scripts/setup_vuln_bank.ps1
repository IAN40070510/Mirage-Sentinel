param(
    [string]$RepoUrl = "https://github.com/Commando-X/vuln-bank.git",
    [string]$TargetPath = "external/vuln-bank",
    [string]$Branch = "main",
    [switch]$InstallDeps
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$fullTarget = Join-Path $repoRoot $TargetPath

Write-Host "[setup-vuln-bank] repo root: $repoRoot"
Write-Host "[setup-vuln-bank] target path: $fullTarget"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required but not found in PATH."
}

if (Test-Path (Join-Path $fullTarget ".git")) {
    Write-Host "[setup-vuln-bank] existing clone found, pulling latest..."
    Push-Location $fullTarget
    git fetch --all --prune
    git checkout $Branch
    git pull --ff-only origin $Branch
    Pop-Location
}
else {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $fullTarget) | Out-Null
    Write-Host "[setup-vuln-bank] cloning..."
    git clone --depth 1 --branch $Branch $RepoUrl $fullTarget
}

if ($InstallDeps) {
    if (-not (Test-Path (Join-Path $fullTarget "requirements.txt"))) {
        throw "requirements.txt not found under $fullTarget"
    }
    Write-Host "[setup-vuln-bank] installing dependencies in current Python environment..."
    pip install -r (Join-Path $fullTarget "requirements.txt")
}

Write-Host "[setup-vuln-bank] done."
Write-Host "[next] start vuln-bank:"
Write-Host "       cd $fullTarget"
Write-Host "       python app.py"
Write-Host "[next] set Mirage env:"
Write-Host "       VULN_BANK_BASE_URL=http://127.0.0.1:5000"
