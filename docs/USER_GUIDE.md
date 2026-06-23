# Sentinel Flow - 安全掃描平台使用說明

## 📚 目錄

1. [專案簡介](#專案簡介)
2. [系統架構](#系統架構)
3. [服務說明](#服務說明)
4. [安裝與啟動](#安裝與啟動)
5. [使用流程](#使用流程)
6. [API 使用範例](#api-使用範例)
7. [常見問題](#常見問題)

---

## 專案簡介

Sentinel Flow 是一個自動化安全掃描平台，可以掃描任意專案的安全漏洞並提供 AI 輔助修復功能。

### 核心功能

- **SAST（白箱掃描）**：使用 Coverity 分析原始碼
- **SCA（套件掃描）**：使用 Black Duck 檢查開源套件漏洞
- **自動修復**：AI 輔助修復高風險漏洞
- **報告產生**：統一格式的 JSON 報告
- **Kafka 整合**：支援事件發布

### 適用場景

- 定期安全掃描
- CI/CD 整合
- 修復後驗證
- 合規檢查

---

## 系統架構

### 整體架構圖

```
┌─────────────────────────────────────────────────────────────────┐
│                         使用者/Orchestrate                        │
│                      (專案掃描請求)                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Scan Coordinator (8010)                       │
│                         統一入口服務                              │
│                                                                  │
│  • 掃描協調：並行觸發 SAST + SCA                                 │
│  • 專案管理：支援多專案註冊                                       │
│  • 修復過濾：篩選高風險漏洞                                       │
│  • BlackDuck Proxy：轉發 API 請求                               │
│                                                                  │
│  註：每次掃描一個專案，但可同時處理多個掃描請求                   │
└─────────────────────────────────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
        ┌──────────────┐          ┌──────────────┐
        │ SAST Service │          │ SCA Service  │
        │   (8011)     │          │   (8006)     │
        │              │          │              │
        │  Coverity    │          │ Black Duck   │
        │  白箱掃描    │          │  套件掃描    │
        │              │          │              │
        │ • WinRM 遠端 │          │ • Detect CLI │
        │ • 完整/增量  │          │ • BOM 分析   │
        └──────────────┘          └──────────────┘
                │                         │
                └────────────┬────────────┘
                             ▼
                    ┌──────────────────┐
                    │ Normalizer (8014)│
                    │   結果正規化      │
                    │                  │
                    │ • SAST Parser    │
                    │ • SCA Parser     │
                    │ • 統一格式       │
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  Report (8016)   │
                    │   報告產生        │
                    │                  │
                    │ • JSON 報告      │
                    │ • Kafka 發布     │
                    │ • 檔案儲存       │
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Fix Filter     │
                    │  高風險過濾       │
                    │                  │
                    │ • HIGH/CRITICAL  │
                    │ • 修復計畫       │
                    │ • PyPI 查詢      │
                    └──────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Code Mod (8006)  │
                    │  程式碼修復請求   │
                    │                  │
                    │ • Bob AI 整合    │
                    │ • 自動修復       │
                    └──────────────────┘
```

---

## 服務說明

### 安全掃描服務

| 服務 | Port | 功能 | 狀態 |
|------|------|------|------|
| **Scan Coordinator** | **8010** | **統一入口、掃描協調** | ✅ 完整 |
| SAST Service | 8011 | Coverity 白箱掃描 | ✅ 完整 |
| SCA Service (BlackDuck) | 8006 | Black Duck 套件掃描 | ✅ 完整 |
| Normalizer Service | 8014 | 結果正規化 | ✅ 完整 |
| Report Service | 8016 | 報告產生與發布 | ✅ 完整 |

---

## 安裝與啟動

### 1. 環境需求

- **Python 3.8+**
- **PowerShell**
- **Coverity** (安裝在遠端 VM 10.107.85.80)
- **Black Duck Detect** (本地或遠端)
- **Kafka** (選用): 10.107.85.239:9092

### 2. 環境變數設定

```powershell
# 複製範本
copy .env.example .env

# 編輯設定
notepad .env
```

**必要設定**：
```env
# ── Black Duck ────────────────────────────────────────────────
BLACKDUCK_URL=https://your-blackduck-server
BLACKDUCK_API_TOKEN=your-api-token
BLACKDUCK_DEFAULT_PROJECT=your-org/your-project
BLACKDUCK_DEFAULT_VERSION=main

# ── Coverity (SAST) ───────────────────────────────────────────
COVERITY_REMOTE_HOST=10.107.85.80
COVERITY_REMOTE_USER=Administrator
COVERITY_REMOTE_PASSWORD=your-password
COVERITY_REMOTE_WORKSPACE=C:\coverity-workspace
COVERITY_YAML_PATH=C:\path\to\coverity.yaml

# ── 專案路徑 ──────────────────────────────────────────────────
DEFAULT_REPO_PATH=C:\path\to\your\project
PROJECTS_ROOT=C:\path\to\projects\directory

# ── Kafka (選用) ──────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS=10.107.85.239:9092
KAFKA_TOPIC=blackduck-log
```

### 3. 安裝依賴

```powershell
pip install -r requirements.txt
pip install -r scan-coordinator/requirements.txt
pip install -r sast-service/requirements.txt
pip install -r blackduck-service/requirements.txt
pip install -r normalizer-service/requirements.txt
pip install -r report-service/requirements.txt
```

### 4. 啟動服務

```powershell
# 使用啟動腳本（推薦）
.\start-all.ps1

# 或手動啟動各服務
cd scan-coordinator && uvicorn app.main:app --host 0.0.0.0 --port 8010
cd sast-service && uvicorn app.main:app --host 0.0.0.0 --port 8011
cd blackduck-service && uvicorn app.main:app --host 0.0.0.0 --port 8006
cd normalizer-service && uvicorn app.main:app --host 0.0.0.0 --port 8014
cd report-service && uvicorn app.main:app --host 0.0.0.0 --port 8016
```

### 5. 驗證服務

```powershell
curl http://localhost:8010/health  # Scan Coordinator
curl http://localhost:8011/health  # SAST
curl http://localhost:8006/health  # BlackDuck
curl http://localhost:8014/health  # Normalizer
curl http://localhost:8016/health  # Report
```

---

## 使用流程

### 流程 1：單一專案完整掃描

```
┌──────────────────────────────────────────────────────────────┐
│ 步驟 1：使用者發起掃描請求                                    │
│ POST /scan/start {"project": "my-web-app"}                   │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 步驟 2：Scan Coordinator 產生 scan_id                        │
│ scan_id = "scan_20260611_103000_abc123"                      │
└────────────────────────┬─────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌─────────────────────┐         ┌─────────────────────┐
│ 步驟 3a：觸發 SAST  │         │ 步驟 3b：觸發 SCA   │
│ POST /sast/scan     │         │ POST /scan/trigger  │
│                     │         │                     │
│ ↓ WinRM 連線        │         │ ↓ 執行 Detect       │
│ ↓ 遠端 VM 執行      │         │ ↓ 上傳到 BD Server  │
│ ↓ Coverity 掃描     │         │ ↓ 取得漏洞清單      │
│ ↓ 5-20 分鐘         │         │ ↓ 3-10 分鐘         │
│                     │         │                     │
│ job_id: sast_xxx    │         │ job_id: bd_xxx      │
└─────────┬───────────┘         └─────────┬───────────┘
          │                               │
          │ 步驟 4：輪詢狀態（每 30 秒）  │
          │ GET /sast/status/{job_id}    │
          │ GET /scan/status/{job_id}    │
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 5：兩個掃描都完成         │
          │ sast_status = "completed"     │
          │ bd_status = "completed"       │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 6：正規化結果             │
          │ POST /normalize/sast          │
          │ POST /normalize/sca           │
          │                               │
          │ 轉換為統一格式                 │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 7：產生報告               │
          │ POST /report/generate         │
          │                               │
          │ • 彙整 SAST + SCA 結果        │
          │ • 計算嚴重程度統計             │
          │ • 產生 JSON 報告              │
          └───────────────┬───────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
┌────────────┐  ┌────────────────┐  ┌────────────┐
│ Kafka 發布 │  │ 檔案儲存       │  │ 回傳報告   │
│ (選用)     │  │ reports/       │  │ 給使用者   │
│            │  │ xxx.json       │  │            │
└────────────┘  └────────────────┘  └────────────┘
```

**時間軸**：
```
T+0s    : 使用者發起掃描
T+1s    : Coordinator 同時觸發 SAST 和 SCA
T+30s   : 第一次輪詢狀態（running）
T+60s   : 第二次輪詢狀態（running）
...
T+10min : SCA 完成
T+15min : SAST 完成
T+15min : 開始正規化
T+16min : 產生報告
T+16min : 回傳結果給使用者
```

---

### 流程 2：自動修復流程

```
┌──────────────────────────────────────────────────────────────┐
│ 步驟 1：使用者觸發修復                                        │
│ POST /fix/submit {"scan_id": "scan_xxx", "project": "..."}  │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 步驟 2：Fix Filter 讀取掃描報告                              │
│ 從 reports/ 目錄讀取 scan_xxx 的報告                         │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ 步驟 3：過濾高風險漏洞                                        │
│ • 只保留 HIGH 和 CRITICAL                                    │
│ • SCA: 45 個漏洞 → 17 個高風險                               │
│ • SAST: 30 個問題 → 7 個高風險                               │
└────────────────────────┬─────────────────────────────────────┘
                         │
         ┌───────────────┴───────────────┐
         │                               │
         ▼                               ▼
┌─────────────────────┐         ┌─────────────────────┐
│ 步驟 4a：SCA 分組   │         │ 步驟 4b：SAST 分組  │
│                     │         │                     │
│ 依套件名稱分組：     │         │ 依問題類型分組：     │
│ • urllib3 1.26.5    │         │ • CORS 配置錯誤 (3) │
│   CVE-2023-45803    │         │ • 硬編碼密碼 (2)    │
│   CVE-2023-43804    │         │ • NULL 解引用 (2)   │
│ • PyJWT 1.7.2       │         │                     │
│   CVE-2022-29217    │         │ 收集受影響檔案：     │
│ • lxml 4.6.3        │         │ • main.py:15        │
│   CVE-2021-43818    │         │ • config.py:42      │
└─────────┬───────────┘         └─────────┬───────────┘
          │                               │
          │ 步驟 5：查詢 PyPI 最新版本    │
          │ urllib3 → 2.2.1               │
          │ PyJWT → 2.12.0                │
          │ lxml → 6.1.0                  │
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 6：產生修復計畫           │
          │                               │
          │ SCA 修復：                    │
          │ • fix_packages:               │
          │   - urllib3>=2.2.1            │
          │   - PyJWT>=2.12.0             │
          │   - lxml>=6.1.0               │
          │                               │
          │ SAST 修復：                   │
          │ • sast_fixes:                 │
          │   - type: CORS 配置錯誤       │
          │     files: [main.py:15, ...]  │
          │     fix_guide: "修改 CORS..." │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 7：送出修復請求           │
          │ POST /code-modification/request│
          │                               │
          │ request_id = "req_abc123"     │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 8：儲存到檔案系統         │
          │ .code-requests/pending/       │
          │ req_abc123.json               │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 9：自動處理               │
          │ claude_auto_fix.py 監控目錄    │
          │ 偵測到新請求                   │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 10：呼叫 Bob AI           │
          │ bob -p "修復漏洞..."          │
          │                               │
          │ Bob 執行：                    │
          │ 1. 讀取 requirements.txt      │
          │ 2. 修改套件版本               │
          │ 3. 讀取 main.py               │
          │ 4. 修復 CORS 配置             │
          │ 5. 儲存檔案                   │
          └───────────────┬───────────────┘
                          │
                          ▼
          ┌───────────────────────────────┐
          │ 步驟 11：更新狀態              │
          │ status = "completed"          │
          │                               │
          │ 移動檔案：                     │
          │ pending/ → completed/         │
          └───────────────────────────────┘
```

**時間軸**：
```
T+0s    : 使用者觸發修復
T+1s    : 讀取報告並過濾
T+2s    : 查詢 PyPI 最新版本
T+3s    : 產生修復計畫
T+4s    : 送出修復請求
T+5s    : claude_auto_fix.py 偵測到請求
T+10s   : Bob AI 開始執行
T+30s   : Bob 完成修復
T+31s   : 更新狀態為 completed
```

---

### 流程 3：多專案掃描（依序執行）

```
使用者想掃描 3 個專案：project-a, project-b, project-c

┌─────────────────────────────────────────────────────────────┐
│ 步驟 1：依序發起掃描請求                                     │
└─────────────────────────────────────────────────────────────┘

POST /scan/start {"project": "project-a"}
  → scan_id_a = "scan_20260611_100000_aaa"
  → 背景執行（SAST + SCA）

POST /scan/start {"project": "project-b"}
  → scan_id_b = "scan_20260611_100005_bbb"
  → 背景執行（SAST + SCA）

POST /scan/start {"project": "project-c"}
  → scan_id_c = "scan_20260611_100010_ccc"
  → 背景執行（SAST + SCA）

┌─────────────────────────────────────────────────────────────┐
│ 步驟 2：三個掃描並行執行                                     │
└─────────────────────────────────────────────────────────────┘

時間軸：
T+0min  : 三個掃描都在執行
T+5min  : project-b 的 SCA 完成
T+8min  : project-a 的 SCA 完成
T+10min : project-c 的 SCA 完成
T+12min : project-b 的 SAST 完成 → project-b 掃描完成
T+15min : project-a 的 SAST 完成 → project-a 掃描完成
T+18min : project-c 的 SAST 完成 → project-c 掃描完成

┌─────────────────────────────────────────────────────────────┐
│ 步驟 3：查詢各自的狀態和報告                                 │
└─────────────────────────────────────────────────────────────┘

GET /scan/status/scan_20260611_100000_aaa
  → status: "completed", step: "done"

GET /scan/report/scan_20260611_100000_aaa
  → 取得 project-a 的完整報告

GET /scan/report/scan_20260611_100005_bbb
  → 取得 project-b 的完整報告

GET /scan/report/scan_20260611_100010_ccc
  → 取得 project-c 的完整報告
```

**重要說明**：
- 每個掃描有獨立的 `scan_id`
- 掃描在背景並行執行，互不影響
- 可以隨時查詢任一掃描的狀態
- 報告獨立儲存，不會互相覆蓋

---

## API 使用範例

### 範例 1：掃描單一專案（完整流程）

```powershell
# ========================================
# 步驟 1：註冊專案（首次掃描時）
# ========================================
Write-Host "步驟 1：註冊專案"
curl -X POST http://localhost:8010/projects/register `
  -H "Content-Type: application/json" `
  -Body '{
    "name": "my-web-app",
    "path": "C:\\Projects\\my-web-app",
    "bd_project": "my-org/my-web-app"
  }'

# ========================================
# 步驟 2：啟動掃描
# ========================================
Write-Host "`n步驟 2：啟動掃描"
$response = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8010/scan/start" `
  -ContentType "application/json" `
  -Body '{"project": "my-web-app"}'

$scanId = $response.scan_id
Write-Host "掃描已啟動: $scanId"
Write-Host "預計需要 10-30 分鐘"

# ========================================
# 步驟 3：輪詢狀態（每 30 秒）
# ========================================
Write-Host "`n步驟 3：等待掃描完成"
$startTime = Get-Date
do {
  Start-Sleep -Seconds 30
  $status = Invoke-RestMethod -Uri "http://localhost:8010/scan/status/$scanId"
  $elapsed = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)
  
  Write-Host "[$elapsed min] 步驟: $($status.step)"
  Write-Host "  SAST: $($status.sast_status)"
  Write-Host "  SCA: $($status.bd_status)"
  
} while ($status.status -ne "completed")

# ========================================
# 步驟 4：取得報告
# ========================================
Write-Host "`n步驟 4：取得掃描報告"
$report = Invoke-RestMethod -Uri "http://localhost:8010/scan/report/$scanId"

Write-Host "`n=== 掃描結果 ==="
Write-Host "專案: $($report.project_name)"
Write-Host "掃描時間: $($report.generated_at)"
Write-Host "總漏洞數: $($report.summary.total_vulnerabilities)"
Write-Host ""
Write-Host "依嚴重程度："
Write-Host "  CRITICAL: $($report.summary.by_severity.critical)"
Write-Host "  HIGH: $($report.summary.by_severity.high)"
Write-Host "  MEDIUM: $($report.summary.by_severity.medium)"
Write-Host "  LOW: $($report.summary.by_severity.low)"
Write-Host ""
Write-Host "依來源："
Write-Host "  SAST: $($report.summary.sast.total)"
Write-Host "  SCA: $($report.summary.sca.total)"
Write-Host ""
Write-Host "報告路徑: $($report.report_path)"
```

### 範例 2：依序掃描多個專案

```powershell
# 定義要掃描的專案清單
$projects = @("project-a", "project-b", "project-c")
$scanIds = @{}

Write-Host "=== 開始掃描 $($projects.Count) 個專案 ==="

# ========================================
# 步驟 1：依序發起掃描請求
# ========================================
foreach ($proj in $projects) {
  Write-Host "`n啟動 $proj 的掃描..."
  $response = Invoke-RestMethod -Method Post `
    -Uri "http://localhost:8010/scan/start" `
    -ContentType "application/json" `
    -Body "{`"project`": `"$proj`"}"
  
  $scanIds[$proj] = $response.scan_id
  Write-Host "  scan_id: $($response.scan_id)"
  Start-Sleep -Seconds 2  # 避免同時發起太多請求
}

# ========================================
# 步驟 2：等待所有掃描完成
# ========================================
Write-Host "`n=== 等待所有掃描完成 ==="
$allCompleted = $false
$iteration = 0

while (-not $allCompleted) {
  Start-Sleep -Seconds 30
  $iteration++
  $allCompleted = $true
  
  Write-Host "`n[檢查 #$iteration]"
  foreach ($proj in $projects) {
    $scanId = $scanIds[$proj]
    $status = Invoke-RestMethod -Uri "http://localhost:8010/scan/status/$scanId"
    
    Write-Host "  [$proj] $($status.step) - SAST:$($status.sast_status) SCA:$($status.bd_status)"
    
    if ($status.status -ne "completed") {
      $allCompleted = $false
    }
  }
}

# ========================================
# 步驟 3：取得所有報告
# ========================================
Write-Host "`n=== 掃描結果摘要 ==="
foreach ($proj in $projects) {
  $scanId = $scanIds[$proj]
  $report = Invoke-RestMethod -Uri "http://localhost:8010/scan/report/$scanId"
  
  Write-Host "`n[$proj]"
  Write-Host "  總漏洞數: $($report.summary.total_vulnerabilities)"
  Write-Host "  CRITICAL: $($report.summary.by_severity.critical)"
  Write-Host "  HIGH: $($report.summary.by_severity.high)"
  Write-Host "  SAST: $($report.summary.sast.total)"
  Write-Host "  SCA: $($report.summary.sca.total)"
}
```

### 範例 3：過濾高風險漏洞並修復

```powershell
# ========================================
# 步驟 1：取得最新掃描的高風險漏洞
# ========================================
Write-Host "步驟 1：分析高風險漏洞"
$fixPlan = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8010/fix/prepare" `
  -ContentType "application/json" `
  -Body '{"scan_id": "latest", "project": "my-web-app"}'

Write-Host "`n=== 高風險漏洞摘要 ==="
Write-Host "總數: $($fixPlan.high_risk_summary.total)"
Write-Host "  SCA 套件漏洞: $($fixPlan.high_risk_summary.sca)"
Write-Host "  SAST 程式碼問題: $($fixPlan.high_risk_summary.sast)"

# ========================================
# 步驟 2：顯示 SCA 修復計畫
# ========================================
Write-Host "`n=== SCA 套件升級計畫 ==="
foreach ($pkg in $fixPlan.sca_fixes) {
  Write-Host "`n套件: $($pkg.package) $($pkg.current_version)"
  Write-Host "  嚴重程度: $($pkg.severity)"
  Write-Host "  CVEs: $($pkg.cves -join ', ')"
  Write-Host "  建議: 升級到最新版本"
}

# ========================================
# 步驟 3：顯示 SAST 修復計畫
# ========================================
Write-Host "`n=== SAST 程式碼修復計畫 ==="
foreach ($issue in $fixPlan.sast_fixes) {
  Write-Host "`n問題類型: $($issue.type)"
  Write-Host "  嚴重程度: $($issue.severity)"
  Write-Host "  發現數量: $($issue.count) 處"
  Write-Host "  可自動修復: $(if ($issue.auto_fixable) {'是'} else {'否'})"
  Write-Host "  修復方式: $($issue.fix_guide)"
  
  if ($issue.files.Count -gt 0) {
    Write-Host "  受影響檔案:"
    foreach ($f in $issue.files) {
      Write-Host "    - $($f.file):$($f.line)"
    }
  }
}

# ========================================
# 步驟 4：確認並自動修復
# ========================================
Write-Host "`n是否要自動修復這些漏洞？"
$confirm = Read-Host "輸入 'yes' 確認"

if ($confirm -eq "yes") {
  Write-Host "`n步驟 4：送出修復請求"
  $fixResult = Invoke-RestMethod -Method Post `
    -Uri "http://localhost:8010/fix/submit" `
    -ContentType "application/json" `
    -Body '{"scan_id": "latest", "project": "my-web-app"}'
  
  Write-Host "修復請求已送出"
  Write-Host "  request_id: $($fixResult.submission_result.request_id)"
  Write-Host "  狀態: $($fixResult.submission_result.status)"
  Write-Host "`nBob AI 將自動處理修復，請稍候..."
}
```

### 範例 4：修復後重新掃描並比對

```powershell
# ========================================
# 步驟 1：原始掃描
# ========================================
Write-Host "步驟 1：執行原始掃描"
$scan1 = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8010/scan/start" `
  -ContentType "application/json" `
  -Body '{"project": "my-web-app"}'

Write-Host "原始掃描 ID: $($scan1.scan_id)"

# 等待完成（省略輪詢代碼）
# ...

$report1 = Invoke-RestMethod -Uri "http://localhost:8010/scan/report/$($scan1.scan_id)"
Write-Host "原始掃描完成"
Write-Host "  總漏洞數: $($report1.summary.total_vulnerabilities)"
Write-Host "  HIGH+CRITICAL: $(($report1.summary.by_severity.critical + $report1.summary.by_severity.high))"

# ========================================
# 步驟 2：自動修復
# ========================================
Write-Host "`n步驟 2：自動修復高風險漏洞"
$fixResult = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8010/fix/submit" `
  -ContentType "application/json" `
  -Body "{`"scan_id`": `"$($scan1.scan_id)`", `"project`": `"my-web-app`"}"

Write-Host "修復請求已送出: $($fixResult.submission_result.request_id)"

# 等待修復完成
Read-Host "`n修復完成後按 Enter 繼續"

# ========================================
# 步驟 3：重新掃描
# ========================================
Write-Host "`n步驟 3：執行修復後掃描"
$scan2 = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8010/scan/start" `
  -ContentType "application/json" `
  -Body "{`"project`": `"my-web-app`", `"trigger_reason`": `"post_fix:$($scan1.scan_id)`"}"

Write-Host "修復後掃描 ID: $($scan2.scan_id)"

# 等待完成（省略輪詢代碼）
# ...

$report2 = Invoke-RestMethod -Uri "http://localhost:8010/scan/report/$($scan2.scan_id)"

# ========================================
# 步驟 4：比對結果
# ========================================
Write-Host "`n=== 修復效果比對 ==="
Write-Host "修復前："
Write-Host "  總漏洞數: $($report1.summary.total_vulnerabilities)"
Write-Host "  CRITICAL: $($report1.summary.by_severity.critical)"
Write-Host "  HIGH: $($report1.summary.by_severity.high)"

Write-Host "`n修復後："
Write-Host "  總漏洞數: $($report2.summary.total_vulnerabilities)"
Write-Host "  CRITICAL: $($report2.summary.by_severity.critical)"
Write-Host "  HIGH: $($report2.summary.by_severity.high)"

$totalBefore = $report1.summary.total_vulnerabilities
$totalAfter = $report2.summary.total_vulnerabilities
$fixed = $totalBefore - $totalAfter
$fixRate = if ($totalBefore -gt 0) { [math]::Round(($fixed / $totalBefore) * 100, 1) } else { 0 }

Write-Host "`n修復成效："
Write-Host "  已修復: $fixed 個漏洞"
Write-Host "  修復率: $fixRate%"
```

---

## 常見問題

### Q1: 可以同時掃描多個專案嗎？

**答**：
可以。每次呼叫 `/scan/start` 掃描一個專案，但可以連續發起多個掃描請求。每個掃描有獨立的 `scan_id`，在背景並行執行。

範例：
```powershell
# 發起專案 A 的掃描
$scanA = POST /scan/start {"project": "project-a"}

# 發起專案 B 的掃描（不需要等 A 完成）
$scanB = POST /scan/start {"project": "project-b"}

# 分別查詢狀態
GET /scan/status/{scanA.scan_id}
GET /scan/status/{scanB.scan_id}
```

### Q2: 掃描需要多久時間？

**答**：
- SAST (Coverity): 5-20 分鐘（視專案大小）
- SCA (Black Duck): 3-10 分鐘
- 總計約 10-30 分鐘

### Q3: 報告儲存在哪裡？

**答**：
- 路徑：`report-service/reports/`
- 檔名格式：`{timestamp}_full_{scan_id}.json`
- 範例：`20260611_1045_full_scan_202.json`

### Q4: 如何查看掃描歷史？

**答**：
```powershell
GET /scan/list
```
會列出所有掃描工作及其狀態。

### Q5: 支援哪些程式語言？

**答**：
- **SAST (Coverity)**：C/C++, Java, C#, Python, JavaScript, Go 等
- **SCA (Black Duck)**：所有使用套件管理工具的語言（npm, pip, maven, gradle 等）

### Q6: 如何掃描新專案？

**答**：
1. 先註冊專案：
```powershell
POST /projects/register
{
  "name": "project-name",
  "path": "C:\\path\\to\\project",
  "bd_project": "org/project"
}
```

2. 然後掃描：
```powershell
POST /scan/start
{
  "project": "project-name"
}
```

### Q7: SAST 掃描失敗怎麼辦？

**答**：
1. 檢查 WinRM 連線：
```powershell
Test-WSMan 10.107.85.80
```

2. 確認環境變數設定
3. 查看錯誤訊息：
```powershell
GET /sast/status/{job_id}
```

### Q8: SCA 掃描失敗怎麼辦？

**答**：
1. 檢查 Black Duck 服務：
```powershell
GET /blackduck/scan/status/{job_id}
```

2. 確認 API Token 有效
3. 檢查專案路徑是否包含套件管理檔案（requirements.txt, package.json 等）

### Q9: 修復失敗怎麼辦？

**答**：
1. 查詢修復狀態：
```powershell
GET /code-modification/status/{request_id}
```

2. 檢查 `.code-requests/` 目錄
3. 確認 `claude_auto_fix.py` 正在運作
4. 查看錯誤訊息

### Q10: 如何整合到 CI/CD？

**答**：
在 CI/CD pipeline 中加入：
```yaml
# 範例：GitHub Actions
- name: Security Scan
  run: |
    $response = Invoke-RestMethod -Method Post `
      -Uri "http://scan-server:8010/scan/start" `
      -Body '{"project": "${{ github.repository }}"}'
    
    $scanId = $response.scan_id
    
    # 等待完成
    do {
      Start-Sleep -Seconds 30
      $status = Invoke-RestMethod -Uri "http://scan-server:8010/scan/status/$scanId"
    } while ($status.status -ne "completed")
    
    # 檢查結果
    $report = Invoke-RestMethod -Uri "http://scan-server:8010/scan/report/$scanId"
    if ($report.summary.by_severity.critical -gt 0) {
      exit 1
    }
```

---

## API 文件連結

所有服務都提供 Swagger UI 介面：

- **Scan Coordinator**: http://localhost:8010/docs
- **SAST Service**: http://localhost:8011/docs
- **BlackDuck Service**: http://localhost:8006/docs
- **Normalizer Service**: http://localhost:8014/docs
- **Report Service**: http://localhost:8016/docs

---

## 附錄

### A. 支援的漏洞類型

#### SAST (Coverity)
- CORS 配置錯誤 (CWE-942)
- 硬編碼密碼 (CWE-798)
- NULL 指標解引用
- URL 操作漏洞
- LocalStorage 敏感資料儲存
- SQL Injection
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)

#### SCA (Black Duck)
- CVE 漏洞
- 授權風險
- 套件版本過舊
- 已知安全問題
- 依賴衝突

### B. Kafka Topic

- `blackduck-log`: 掃描報告發布
- `security-scan-results`: 掃描結果（修復前）
- `security-rescan-results`: 重掃結果（修復後）

### C. 環境變數完整清單

```env
# ── Black Duck ────────────────────────────────────────────────
BLACKDUCK_URL=https://your-server
BLACKDUCK_API_TOKEN=your-token
BLACKDUCK_DEFAULT_PROJECT=your-org/your-project
BLACKDUCK_DEFAULT_VERSION=main

# ── Coverity (SAST) ───────────────────────────────────────────
COVERITY_REMOTE_HOST=10.107.85.80
COVERITY_REMOTE_USER=Administrator
COVERITY_REMOTE_PASSWORD=your-password
COVERITY_REMOTE_WORKSPACE=C:\coverity-workspace

# ── Kafka ─────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS=10.107.85.239:9092
KAFKA_TOPIC=blackduck-log

# ── 專案路徑 ──────────────────────────────────────────────────
DEFAULT_REPO_PATH=C:\path\to\your\project
PROJECTS_ROOT=C:\path\to\projects
```

---

**文件版本**: 1.0.0  
**最後更新**: 2026-06-11  
**維護者**: Sentinel Flow Team