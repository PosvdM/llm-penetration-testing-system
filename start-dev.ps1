Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-DotEnvValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match "^\s*$Key=(.*)$") {
            return $Matches[1].Trim()
        }
    }

    return $null
}

function New-EncodedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandText
    )

    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($CommandText))
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $projectRoot ".env"
$backendDir = Join-Path $projectRoot "backend"
$frontendDir = Join-Path $projectRoot "frontend"

$apiHost = Get-DotEnvValue -Path $envFile -Key "API_HOST"
if (-not $apiHost) {
    $apiHost = "127.0.0.1"
}

$apiPort = Get-DotEnvValue -Path $envFile -Key "API_PORT"
if (-not $apiPort) {
    $apiPort = "8000"
}

$frontendPort = Get-DotEnvValue -Path $envFile -Key "FRONTEND_PORT"
if (-not $frontendPort) {
    $frontendPort = "5173"
}

$viteApiBaseUrl = Get-DotEnvValue -Path $envFile -Key "VITE_API_BASE_URL"
if (-not $viteApiBaseUrl) {
    $viteApiBaseUrl = "http://$apiHost`:$apiPort"
}

foreach ($tool in @("uv", "pnpm")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required command '$tool' was not found in PATH."
    }
}

$backendCommand = @"
`$Host.UI.RawUI.WindowTitle = 'LLM Pentest Backend'
Set-Location -LiteralPath '$backendDir'
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    uv venv --python 3.12
}
uv sync
uv run uvicorn app.main:app --host $apiHost --port $apiPort --reload
"@

$frontendCommand = @"
`$Host.UI.RawUI.WindowTitle = 'LLM Pentest Frontend'
Set-Location -LiteralPath '$frontendDir'
if (-not (Test-Path -LiteralPath 'node_modules')) {
    pnpm install
}
`$env:VITE_API_BASE_URL = '$viteApiBaseUrl'
pnpm dev -- --host 127.0.0.1 --port $frontendPort
"@

$backendProcess = Start-Process powershell `
    -ArgumentList @(
        "-NoExit",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", (New-EncodedCommand -CommandText $backendCommand)
    ) `
    -WorkingDirectory $backendDir `
    -PassThru

$frontendProcess = Start-Process powershell `
    -ArgumentList @(
        "-NoExit",
        "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", (New-EncodedCommand -CommandText $frontendCommand)
    ) `
    -WorkingDirectory $frontendDir `
    -PassThru

Write-Host "Backend started in a new window (PID: $($backendProcess.Id)) at http://$apiHost`:$apiPort" -ForegroundColor Green
Write-Host "Frontend started in a new window (PID: $($frontendProcess.Id)) at http://127.0.0.1:$frontendPort" -ForegroundColor Green
