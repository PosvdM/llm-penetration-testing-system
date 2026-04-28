Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[1/2] Preparing backend environment..." -ForegroundColor Cyan
Push-Location "$PSScriptRoot\..\..\backend"
try {
    uv venv --python 3.12
    .\.venv\Scripts\activate
    uv sync
} finally {
    Pop-Location
}

Write-Host "[2/2] Installing frontend dependencies..." -ForegroundColor Cyan
Push-Location "$PSScriptRoot\..\..\frontend"
try {
    pnpm install
} finally {
    Pop-Location
}

Write-Host "Development environment setup complete." -ForegroundColor Green
