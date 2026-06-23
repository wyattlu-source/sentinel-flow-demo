# ============================================================
#  SentinelFlow - One-Click Startup Script
#  Usage:
#    .\start-all.ps1           # Start all services
#    .\start-all.ps1 -Stop     # Stop all services
#    .\start-all.ps1 -Status   # Check current status
# ============================================================
param(
    [switch]$Stop,
    [switch]$Status
)

$ROOT   = $PSScriptRoot
$NGROK  = "C:\ngrok\ngrok.exe"
$DOMAIN = "arborescent-actorly-carroll.ngrok-free.dev"

# Service list (startup order matters)
$SERVICES = @(
    @{ name = "blackduck-service";  port = 8006; desc = "SCA / Black Duck"      },
    @{ name = "sast-service";       port = 8011; desc = "SAST / Coverity"        },
    @{ name = "dast-service";       port = 8012; desc = "DAST / Nuclei (stub)"   },
    @{ name = "normalizer-service"; port = 8014; desc = "Normalizer"             },
    @{ name = "compare-service";    port = 8015; desc = "Compare before/after"   },
    @{ name = "report-service";     port = 8016; desc = "Report Generator"       },
    @{ name = "scan-coordinator";   port = 8010; desc = "Orchestrate Entry Point" }
)

# ── Helper functions ──────────────────────────────────────────────────────────
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [!!] $msg" -ForegroundColor Red   }
function Write-Info($msg) { Write-Host "  [..] $msg" -ForegroundColor Cyan  }
function Write-Skip($msg) { Write-Host "  [--] $msg" -ForegroundColor Gray  }
function Write-Head($msg) { Write-Host $msg -ForegroundColor Yellow          }

function Kill-Port($port) {
    $pids = netstat -ano | Select-String ":$port\s" |
            ForEach-Object { ($_ -split '\s+')[-1] } | Select-Object -Unique
    foreach ($p in $pids) {
        if ($p -match '^\d+$' -and [int]$p -gt 0) {
            Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-Health($port) {
    try {
        $r = Invoke-WebRequest "http://localhost:$port/health" -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
        $body = $r.Content | ConvertFrom-Json
        return ($body.status -eq "ok")
    } catch {
        return $false
    }
}

function Wait-Service($port, $timeout = 60) {
    $deadline = (Get-Date).AddSeconds($timeout)
    while ((Get-Date) -lt $deadline) {
        if (Test-Health $port) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Start-Svc($svc) {
    Kill-Port $svc.port
    $svcPath = Join-Path $ROOT $svc.name
    $cmd = "cd '$svcPath'; uvicorn app.main:app --host 0.0.0.0 --port $($svc.port)"
    Start-Process powershell -WindowStyle Minimized `
        -ArgumentList "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", $cmd
}

# ══════════════════════════════════════════════════════════════
#  -Status mode
# ══════════════════════════════════════════════════════════════
if ($Status) {
    Write-Head ""
    Write-Head "  SentinelFlow - Service Status"
    Write-Head "  ----------------------------------------"

    foreach ($svc in $SERVICES) {
        $label = ":$($svc.port)  $($svc.name)  [$($svc.desc)]"
        if (Test-Health $svc.port) {
            Write-Ok $label
        } else {
            Write-Fail $label
        }
    }

    Write-Head "  ----------------------------------------"

    # auto-fix watcher
    $watcher = Get-WmiObject Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
               Where-Object { $_.CommandLine -like "*claude_auto_fix*" }
    if ($watcher) {
        Write-Ok "claude_auto_fix.py watch  (running)"
    } else {
        Write-Fail "claude_auto_fix.py watch  (not running)"
    }

    # ngrok
    try {
        $tunnels = Invoke-RestMethod "http://127.0.0.1:4040/api/tunnels" -TimeoutSec 2
        $url = $tunnels.tunnels[0].public_url
        Write-Ok "ngrok  $url -> :8010"
    } catch {
        Write-Fail "ngrok  (not running)"
    }

    Write-Head ""
    exit
}

# ══════════════════════════════════════════════════════════════
#  -Stop mode
# ══════════════════════════════════════════════════════════════
if ($Stop) {
    Write-Head ""
    Write-Head "  SentinelFlow - Stopping All Services"
    Write-Head "  ----------------------------------------"

    foreach ($svc in $SERVICES) {
        Kill-Port $svc.port
        Write-Ok "Stopped :$($svc.port)  $($svc.name)"
    }

    Get-Process | Where-Object { $_.Name -like "*ngrok*" } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Ok "Stopped ngrok"

    Get-WmiObject Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*claude_auto_fix*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Ok "Stopped claude_auto_fix.py watch"

    Write-Head ""
    exit
}

# ══════════════════════════════════════════════════════════════
#  Start mode (default)
# ══════════════════════════════════════════════════════════════
Write-Head ""
Write-Head "  ============================================"
Write-Head "    SentinelFlow - Starting All Services"
Write-Head "  ============================================"
Write-Head ""

# ── Step 1: Start microservices ───────────────────────────────────────────────
Write-Head "  [1/4] Starting microservices..."
Write-Head ""

foreach ($svc in $SERVICES) {
    Write-Info "Starting $($svc.name) on :$($svc.port)..."
    Start-Svc $svc
    Start-Sleep -Milliseconds 400
}

# ── Step 2: Health checks ─────────────────────────────────────────────────────
Write-Head ""
Write-Head "  [2/4] Waiting for services to be ready..."
Write-Head ""
Start-Sleep -Seconds 10

$allOk = $true
foreach ($svc in $SERVICES) {
    # sast-service 啟動較慢（載入 Coverity），給更多時間
    $timeout = if ($svc.name -eq "sast-service") { 90 } else { 60 }
    $ok = Wait-Service $svc.port $timeout
    if ($ok) {
        Write-Ok ":$($svc.port)  $($svc.name)"
    } else {
        Write-Fail ":$($svc.port)  $($svc.name)  - not responding after 60s"
        $allOk = $false
    }
}

# ── Step 3: Auto-Fix Watcher ──────────────────────────────────────────────────
Write-Head ""
Write-Head "  [3/4] Starting Auto-Fix Watcher..."
Write-Head ""

# Kill old watcher if running
Get-WmiObject Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*claude_auto_fix*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$watchCmd = "cd '$ROOT'; python claude_auto_fix.py watch"
Start-Process powershell -WindowStyle Minimized `
    -ArgumentList "-ExecutionPolicy", "Bypass", "-NoExit", "-Command", $watchCmd

Start-Sleep -Seconds 2

# Read CLI setting from .env
$cliSetting = "claude"
$envFile = Join-Path $ROOT ".env"
if (Test-Path $envFile) {
    $match = Select-String "AUTO_FIX_CLI=(\w+)" $envFile
    if ($match) { $cliSetting = $match.Matches[0].Groups[1].Value }
}
Write-Ok "claude_auto_fix.py watch  (CLI: $cliSetting)"

# ── Step 4: ngrok ─────────────────────────────────────────────────────────────
Write-Head ""
Write-Head "  [4/4] Starting ngrok tunnel..."
Write-Head ""

Get-Process | Where-Object { $_.Name -like "*ngrok*" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

if (Test-Path $NGROK) {
    Start-Process $NGROK -ArgumentList "http", "--domain=$DOMAIN", "8010" -WindowStyle Minimized
    Start-Sleep -Seconds 3
    try {
        $tunnels = Invoke-RestMethod "http://127.0.0.1:4040/api/tunnels" -TimeoutSec 5
        $url = $tunnels.tunnels[0].public_url
        Write-Ok "ngrok  $url  ->  :8010"
    } catch {
        Write-Fail "ngrok started but tunnel URL not verified"
    }
} else {
    Write-Skip "ngrok not found at $NGROK  (skipped)"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Head ""
Write-Head "  ============================================"
if ($allOk) {
    Write-Head "  [OK] All systems ready!"
} else {
    Write-Head "  [!!] Some services failed - check above"
}
Write-Head "  ============================================"
Write-Head ""
Write-Head "  Orchestrate entry:"
Write-Host "    https://$DOMAIN" -ForegroundColor Cyan
Write-Head ""
Write-Head "  Local endpoints:"
Write-Host "    :8010  scan-coordinator   http://localhost:8010/docs" -ForegroundColor White
Write-Host "    :8006  blackduck-service  http://localhost:8006/docs" -ForegroundColor White
Write-Host "    :8011  sast-service       http://localhost:8011/docs" -ForegroundColor White
Write-Host "    :8012  dast-service       http://localhost:8012/docs" -ForegroundColor White
Write-Host "    :8014  normalizer         http://localhost:8014/docs" -ForegroundColor White
Write-Host "    :8015  compare-service    http://localhost:8015/docs" -ForegroundColor White
Write-Host "    :8016  report-service     http://localhost:8016/docs" -ForegroundColor White
Write-Head ""
Write-Head "  Other commands:"
Write-Host "    .\start-all.ps1 -Status   # Check service status" -ForegroundColor Gray
Write-Host "    .\start-all.ps1 -Stop     # Stop all services"    -ForegroundColor Gray
Write-Head ""
