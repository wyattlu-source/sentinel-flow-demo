# 程式碼自動修改 POC 文件

## 概述

這個 POC (Proof of Concept) 實作了一個系統，讓 watsonx Orchestrate 可以請求程式碼修改，然後由 Bob (Roo Cline) 來執行實際的程式碼修改工作。

## 架構

```
Orchestrate (分析弱點報告)
    ↓
    發送修改請求到 API
    ↓
BlackDuck Service (/code-modification/request)
    ↓
    儲存請求到 .code-requests/pending/
    ↓
    使用者通知 Bob
    ↓
Bob (Roo Cline) 讀取請求
    ↓
    分析並修改程式碼
    ↓
    更新狀態到 completed
    ↓
Orchestrate 查詢結果
```

## 目錄結構

```
sentinel-flow-demo/
├── .code-requests/              # 程式碼修改請求目錄
│   ├── pending/                # 待處理的請求
│   ├── processing/             # 處理中的請求
│   ├── completed/              # 已完成的請求
│   └── failed/                 # 失敗的請求
├── blackduck-service/
│   └── app/
│       ├── main.py            # 主要 API (包含新的端點)
│       └── code_modification.py  # 程式碼修改邏輯
└── test_*.py                   # 測試腳本
```

## API 端點

### 1. 建立程式碼修改請求

**POST** `/code-modification/request`

請求範例:
```json
{
  "source": "orchestrate",
  "type": "vulnerability_fix",
  "vulnerability_info": {
    "project_name": "sentinel-flow-demo",
    "version": "1.0.0",
    "severity": "HIGH",
    "vulnerability_type": "SQL_INJECTION",
    "affected_files": ["account-service/app/main.py"],
    "description": "SQL injection vulnerability detected"
  },
  "modification_request": {
    "action": "fix_vulnerability",
    "details": "修復 SQL injection 漏洞，使用參數化查詢",
    "priority": "high"
  }
}
```

回應範例:
```json
{
  "request_id": "req_20260511_150000_abc123",
  "status": "pending",
  "timestamp": "2026-05-11T15:00:00.000000",
  "message": "Code modification request created..."
}
```

### 2. 查詢請求狀態

**GET** `/code-modification/status/{request_id}`

回應範例:
```json
{
  "request_id": "req_20260511_150000_abc123",
  "status": "pending",
  "timestamp": "2026-05-11T15:00:00.000000",
  "vulnerability_info": {...},
  "modification_request": {...},
  "result": null,
  "completed_at": null
}
```

### 3. 列出所有請求

**GET** `/code-modification/list?status=pending`

回應範例:
```json
{
  "total": 5,
  "requests": [...]
}
```

### 4. 更新請求狀態

**POST** `/code-modification/update-status/{request_id}?new_status=completed&result=Fixed successfully`

回應範例:
```json
{
  "request_id": "req_20260511_150000_abc123",
  "old_status": "pending",
  "new_status": "completed",
  "message": "Status updated from 'pending' to 'completed'"
}
```

## 使用流程

### 步驟 1: Orchestrate 發送請求

在 watsonx Orchestrate 中，當分析完弱點報告後，可以說：
- "幫我改程式"
- "修復程式碼中的漏洞"
- "fix the vulnerability in my code"

Orchestrate 會呼叫 `/code-modification/request` API。

### 步驟 2: 檢查請求檔案

請求會被儲存到 `.code-requests/pending/` 目錄：

```bash
# 列出待處理的請求
ls .code-requests/pending/

# 查看請求內容
cat .code-requests/pending/req_20260511_150000_abc123.json
```

### 步驟 3: 通知 Bob 處理請求

在 VS Code 中告訴 Bob (Roo Cline):

```
請讀取 .code-requests/pending/ 目錄中的請求，
並根據請求內容修改程式碼來修復漏洞。
```

### 步驟 4: Bob 處理請求

Bob 會：
1. 讀取請求檔案
2. 分析漏洞資訊和受影響的檔案
3. 使用工具 (read_file, apply_diff 等) 修改程式碼
4. 更新請求狀態為 completed

### 步驟 5: Orchestrate 查詢結果

Orchestrate 可以查詢請求狀態：
- "查詢程式碼修改狀態"
- "修改完成了嗎"
- "check code modification status"

## 測試

### 測試 1: 檔案系統測試

```bash
python test_simple.py
```

這會建立一個測試請求並驗證檔案系統功能。

### 測試 2: API 測試 (需要啟動服務)

```bash
# 終端 1: 啟動服務
cd blackduck-service
python -m uvicorn app.main:app --port 8006 --reload

# 終端 2: 執行測試
python test_code_modification.py
```

### 測試 3: 手動測試

1. 查看示例請求:
```bash
cat .code-requests/pending/req_example_001.json
```

2. 在 VS Code 中告訴 Bob:
```
請讀取 .code-requests/pending/req_example_001.json 
這個程式碼修改請求，並根據內容修改 account-service/app/main.py 
來修復 SQL injection 漏洞。
```

3. Bob 會處理請求並修改程式碼

## 請求 JSON 格式

```json
{
  "request_id": "唯一識別碼",
  "timestamp": "建立時間 (ISO 8601)",
  "source": "請求來源 (orchestrate)",
  "type": "請求類型 (vulnerability_fix)",
  "status": "狀態 (pending/processing/completed/failed)",
  "vulnerability_info": {
    "project_name": "專案名稱",
    "version": "版本",
    "severity": "嚴重性 (CRITICAL/HIGH/MEDIUM/LOW)",
    "vulnerability_type": "漏洞類型",
    "affected_files": ["受影響的檔案列表"],
    "description": "漏洞描述"
  },
  "modification_request": {
    "action": "動作類型",
    "details": "詳細說明",
    "priority": "優先級 (high/medium/low)"
  },
  "result": "處理結果 (完成後填寫)",
  "completed_at": "完成時間 (完成後填寫)"
}
```

## Orchestrate 自然語言觸發

在 watsonx Orchestrate 中，可以使用以下自然語言來觸發功能：

### 建立修改請求
- "fix the vulnerability in my code"
- "修復程式碼中的漏洞"
- "幫我改程式"
- "自動修復安全問題"
- "請修改程式碼來解決漏洞"

### 查詢狀態
- "check code modification status"
- "查詢程式碼修改狀態"
- "修改完成了嗎"
- "is the code fix done"

### 列出請求
- "list all code modification requests"
- "列出所有程式碼修改請求"
- "show pending code fixes"
- "顯示待處理的修改"

## 下一步改進

### 短期 (POC 驗證後)
1. ✅ 完成基本的檔案系統功能
2. ✅ 實作 API 端點
3. ⏳ 測試完整流程
4. ⏳ 建立 Bob 的自動處理腳本

### 中期 (功能增強)
1. 建立 MCP Server 讓 Bob 可以自動接收通知
2. 實作程式碼修改的驗證機制
3. 加入修改歷史和版本控制
4. 支援更多類型的程式碼修改

### 長期 (生產環境)
1. 整合 CI/CD 流程
2. 加入自動測試驗證
3. 實作回滾機制
4. 建立監控和告警系統

## 注意事項

1. **安全性**: 目前是 POC，沒有身份驗證和授權機制
2. **備份**: 修改程式碼前建議先備份
3. **測試**: 修改後需要執行測試確保功能正常
4. **人工審查**: 重要的修改建議人工審查後再部署

## 支援

如有問題，請聯繫開發團隊或查看：
- API 文件: http://localhost:8006/docs
- 專案 README: README.md