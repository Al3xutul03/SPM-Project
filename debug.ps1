<#
.SYNOPSIS
    Rebuilds and (re)starts the SPM Project container
    so you can run or attach the Visual Studio debugger to it.

.DESCRIPTION
    1. Builds Application/Dockerfile (Debug configuration by default).
    2. Removes any previous container and starts a fresh one.
    3. Waits until the app is answering HTTP requests.
    4. Follows the container logs (Ctrl+C stops following, the container keeps running).

    Then in Visual Studio: Debug > Attach to Process > Connection type "Docker (Linux Container)"
    > pick the "spm-project" container > attach to the "dotnet" process.

.EXAMPLE
    .\debug.ps1                  # build + run + follow logs
    .\debug.ps1 -NoLogs          # build + run, return to the prompt
    .\debug.ps1 -Port 5000       # publish on localhost:5000 instead of 8080
    .\debug.ps1 -Stop            # stop and remove the container
#>
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [int]$Port = 8080,
    [switch]$NoLogs,
    [switch]$Stop
)

$Name  = 'spm-project'
$Image = "spm-project:$($Configuration.ToLower())"

# Always run from the solution root (the Docker build context).
Set-Location $PSScriptRoot

function Remove-OldContainer {
    if (docker ps -aq --filter "name=^$Name$") {
        Write-Host "Removing existing '$Name' container..." -ForegroundColor DarkGray
        docker rm -f $Name *> $null
    }
}

if ($Stop) {
    Remove-OldContainer
    Write-Host "Stopped." -ForegroundColor Green
    return
}

docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error "Docker isn't running. Start Docker Desktop first."; exit 1 }

Write-Host "Building $Image..." -ForegroundColor Cyan
docker build -f Application/Dockerfile --build-arg "BUILD_CONFIGURATION=$Configuration" -t $Image .
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed."; exit 1 }

Remove-OldContainer

# Fail early with a readable message if the host port is already taken.
$owner = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($owner) {
    $proc = (Get-Process -Id $owner.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Error "Port $Port is already in use by '$proc' (PID $($owner.OwningProcess)). Pick another with -Port."
    exit 1
}

$runArgs = @('run', '-d', '--name', $Name, '-p', "${Port}:8080", '-e', 'ASPNETCORE_ENVIRONMENT=Development', $Image)

Write-Host "Starting container..." -ForegroundColor Cyan
docker @runArgs | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to start the container."; exit 1 }

# Wait for the app to answer HTTP requests.
$url = "http://localhost:$Port"
$deadline = (Get-Date).AddSeconds(60)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $state = docker inspect -f '{{.State.Running}}' $Name 2> $null
    if ($state -ne 'true') { break }
    try {
        Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 3 | Out-Null
        $ready = $true; break
    } catch {
        # A non-2xx response still means the app is up.
        if ($_.Exception.Response) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
}

if (-not $ready) {
    Write-Host "`nThe app didn't come up. Last log lines:" -ForegroundColor Red
    docker logs --tail 40 $Name
    exit 1
}

Write-Host ""
Write-Host "Ready:  $url" -ForegroundColor Green
Write-Host "Attach: Debug > Attach to Process > Docker (Linux Container) > '$Name' > dotnet" -ForegroundColor Yellow
Write-Host "Stop:   .\debug.ps1 -Stop" -ForegroundColor DarkGray

if (-not $NoLogs) {
    Write-Host "`nFollowing logs (Ctrl+C to stop following; the container keeps running)...`n" -ForegroundColor DarkGray
    docker logs -f --since 1s $Name
}
