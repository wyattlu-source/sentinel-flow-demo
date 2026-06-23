# schedule_claude_fix.ps1
# 用 Windows 工作排程器每 5 分鐘執行一次 claude_auto_fix.py
# 不需要任何 API Key，使用你已登入的 Claude Code 帳號
#
# 使用方式（以系統管理員身分執行 PowerShell）：
#   .\schedule_claude_fix.ps1 -Register     # 安裝排程
#   .\schedule_claude_fix.ps1 -Unregister   # 移除排程
#   .\schedule_claude_fix.ps1 -Status       # 查看狀態
#   .\schedule_claude_fix.ps1 -RunNow       # 立即執行一次（測試用）

param(
    [switch]$Register,
    [switch]$Unregister,
    [switch]$Status,
    [switch]$RunNow
)

$TaskName   = "SentinelFlow-ClaudeAutoFix"
$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptsDir   # scripts/ 的上一層 = 專案根目錄
$Script     = Join-Path $ProjectDir "claude_auto_fix.py"

function Get-PythonExe {
    foreach ($c in @("python", "python3", "py")) {
        try {
            $out = & $c --version 2>&1
            if ($out -match "Python") { return (Get-Command $c).Source }
        } catch {}
    }
    return $null
}

if ($Register) {
    $python = Get-PythonExe
    if (-not $python) { Write-Error "找不到 Python"; exit 1 }

    $action  = New-ScheduledTaskAction `
        -Execute $python `
        -Argument "`"$Script`" run" `
        -WorkingDirectory $ProjectDir

    $trigger = New-ScheduledTaskTrigger `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -Once -At (Get-Date)

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 4) `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action   $action `
        -Trigger  $trigger `
        -Settings $settings `
        -RunLevel Highest `
        -Force | Out-Null

    Write-Host ""
    Write-Host "✅ 排程已安裝：$TaskName" -ForegroundColor Green
    Write-Host "   每 5 分鐘自動執行 claude_auto_fix.py run"
    Write-Host "   Log：$ProjectDir\.claude-auto-fix.log"
    Write-Host ""
    Write-Host "即時查看 log："
    Write-Host "   Get-Content '$ProjectDir\.claude-auto-fix.log' -Wait"
}
elseif ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "⚠️  排程已移除：$TaskName" -ForegroundColor Yellow
}
elseif ($Status) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host ""
        Write-Host "工作名稱 : $TaskName"
        Write-Host "狀態     : $($task.State)"
        Write-Host "上次執行 : $($info.LastRunTime)  結果=$($info.LastTaskResult)"
        Write-Host "下次執行 : $($info.NextRunTime)"
        Write-Host ""
    } else {
        Write-Host "排程尚未安裝。執行 -Register 來安裝。" -ForegroundColor Yellow
    }
}
elseif ($RunNow) {
    $python = Get-PythonExe
    if (-not $python) { Write-Error "找不到 Python"; exit 1 }
    Write-Host "執行 claude_auto_fix.py run ..." -ForegroundColor Cyan
    & $python $Script run
}
else {
    Write-Host @"

schedule_claude_fix.ps1 — Claude Code CLI 自動修復排程

使用方式（PowerShell，建議以系統管理員執行）：
  .\schedule_claude_fix.ps1 -Register     安裝排程工作（每 5 分鐘）
  .\schedule_claude_fix.ps1 -Unregister   移除排程工作
  .\schedule_claude_fix.ps1 -Status       查看排程狀態
  .\schedule_claude_fix.ps1 -RunNow       立即執行一次（測試）

自動化流程：
  1. Orchestrate 送分析訊息 → 儲存到 .analysis-messages/
  2. 排程每 5 分鐘觸發 claude_auto_fix.py run
  3. claude -p 讀取訊息，分析漏洞，直接修改程式碼
  4. 標記訊息為已處理，寫入 .claude-auto-fix.log

不需要 API Key — 使用你已登入的 Claude Code 帳號
"@
}
