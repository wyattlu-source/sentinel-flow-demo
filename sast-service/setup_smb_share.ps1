<#
.SYNOPSIS
    建立 SAST 掃描用的 SMB 共享。只需執行一次。
    遠端 Coverity VM 透過此共享直接讀取專案，取代慢速的 WinRM Copy-Item。

.PARAMETER SharePath
    要共享的本機目錄（專案根目錄），例如 C:\Users\Administrator\Desktop\Projects

.PARAMETER ShareName
    SMB 共享名稱，預設 sast-scan

.PARAMETER AllowUser
    允許存取的 Windows 使用者帳號，預設 Administrator

.EXAMPLE
    .\setup_smb_share.ps1 -SharePath "C:\Users\Administrator\Desktop\Projects"
    .\setup_smb_share.ps1 -SharePath "C:\Projects" -ShareName "sast-scan" -AllowUser "Administrator"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$SharePath,

    [string]$ShareName  = "sast-scan",
    [string]$AllowUser  = "Administrator"
)

# ── 確認目錄存在 ──────────────────────────────────────────────────────────────
if (-not (Test-Path $SharePath)) {
    New-Item -ItemType Directory -Path $SharePath -Force | Out-Null
    Write-Host "已建立目錄：$SharePath"
}

# ── 移除舊的同名共享（若存在）────────────────────────────────────────────────
$existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if ($existing) {
    Remove-SmbShare -Name $ShareName -Force
    Write-Host "已移除舊共享：$ShareName"
}

# ── 建立 SMB 共享 ─────────────────────────────────────────────────────────────
New-SmbShare -Name $ShareName -Path $SharePath -FullAccess $AllowUser -ErrorAction Stop

# ── 取得本機 IP（排除 Loopback / vEthernet） ──────────────────────────────────
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet|Teredo|isatap' } |
       Sort-Object PrefixLength |
       Select-Object -First 1).IPAddress

# ── 顯示結果與 .env 設定指示 ──────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host "  SMB 共享建立成功！"
Write-Host "======================================================"
Write-Host "  共享名稱  : $ShareName"
Write-Host "  本機路徑  : $SharePath"
Write-Host "  存取帳號  : $AllowUser"
Write-Host "  本機 IP   : $ip"
Write-Host "  UNC 路徑  : \\$ip\$ShareName"
Write-Host ""
Write-Host "------------------------------------------------------"
Write-Host "  請在 .env 加入以下設定："
Write-Host "------------------------------------------------------"
Write-Host ""
Write-Host "  LOCAL_HOST_IP=$ip"
Write-Host "  SMB_SHARE_NAME=$ShareName"
Write-Host "  SMB_SHARE_ROOT=$SharePath"
Write-Host "  SMB_USER=$AllowUser"
Write-Host "  SMB_PASSWORD=<您的 Windows 密碼>"
Write-Host ""
Write-Host "======================================================"
Write-Host ""

# ── 驗證：確認共享可以被列出 ──────────────────────────────────────────────────
$share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if ($share) {
    Write-Host "驗證通過：Get-SmbShare 確認共享已存在。"
} else {
    Write-Host "警告：建立後無法驗證共享，請手動確認。"
}
