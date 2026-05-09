param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("core", "analytics", "graph", "search", "full")]
    [string]$Profile = "core",

    [Parameter(Mandatory=$false)]
    [switch]$Build
)

$cmd = "docker compose --profile $Profile up -d"
if ($Build) {
    $cmd += " --build"
}

Write-Host "🚀 Iniciando SENTINELA Profile: [$($Profile.ToUpper())]..." -ForegroundColor Cyan
Invoke-Expression $cmd
Write-Host "✅ Comando enviado. Verifique o status com 'docker compose --profile $Profile ps'" -ForegroundColor Green
