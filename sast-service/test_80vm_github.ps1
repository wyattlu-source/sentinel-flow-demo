$RemoteHost     = "10.107.85.80"
$RemoteUser     = "Administrator"
$RemotePassword = "P@ssw0rd"

$secpwd  = ConvertTo-SecureString $RemotePassword -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential($RemoteUser, $secpwd)
$session = New-PSSession -ComputerName $RemoteHost -Credential $cred

Write-Host ""
Write-Host "====== Testing 80 VM GitHub connectivity ======" -ForegroundColor Cyan

Invoke-Command -Session $session -ScriptBlock {

    Write-Host ""
    Write-Host "[1] Checking git installation..." -ForegroundColor Yellow
    $gitPath = (Get-Command git -ErrorAction SilentlyContinue).Source
    if ($gitPath) {
        $gitVer = git --version
        Write-Host "    OK: git found - $gitVer" -ForegroundColor Green
    } else {
        Write-Host "    FAIL: git not installed" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[2] Testing TCP connection to github.com:443..." -ForegroundColor Yellow
    $tcp = Test-NetConnection -ComputerName "github.com" -Port 443 -WarningAction SilentlyContinue
    if ($tcp.TcpTestSucceeded) {
        Write-Host "    OK: TCP 443 reachable" -ForegroundColor Green
    } else {
        Write-Host "    FAIL: Cannot reach github.com:443" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[3] Trying git clone (public test repo)..." -ForegroundColor Yellow
    $testDir = "C:\coverity-workspace\_github_test"
    if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force }

    git clone --depth 1 https://github.com/octocat/Hello-World.git $testDir 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    OK: git clone succeeded - GitHub HTTPS works!" -ForegroundColor Green
        Remove-Item $testDir -Recurse -Force
    } else {
        Write-Host "    FAIL: git clone failed" -ForegroundColor Red
    }
}

Remove-PSSession $session
Write-Host ""
Write-Host "====== Test complete ======" -ForegroundColor Cyan
