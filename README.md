# Sentinel Flow Demo

金融業微服務示範專案，使用 Python FastAPI 架構，包含完整的金融業務邏輯與 Bloomberg 風格前端介面。

## Architecture

```
sentinel-flow-demo/
├── api-gateway/          # Port 8000 — 統一入口、路由、限流
├── auth-service/         # Port 8001 — JWT 登入、OTP、Token 刷新
├── account-service/      # Port 8002 — 帳戶管理、餘額查詢
├── transaction-service/  # Port 8003 — 轉帳、交易記錄、PDF 對帳單
├── risk-service/         # Port 8004 — AML 規則引擎、信用評分、異常偵測
├── notification-service/ # Port 8005 — 通知管理
├── frontend/             # Port 3000 — Bloomberg 風格 SPA
├── seed_data.py          # 初始化測試資料
├── start_all.bat         # 一鍵啟動所有服務 (Windows)
└── .env.example          # 環境變數範本
```

## Quick Start

### 1. 安裝依賴

```powershell
# 建議為每個服務建立獨立虛擬環境，或使用全域安裝
pip install -r auth-service/requirements.txt
pip install -r account-service/requirements.txt
pip install -r transaction-service/requirements.txt
pip install -r risk-service/requirements.txt
pip install -r notification-service/requirements.txt
pip install -r api-gateway/requirements.txt
```

### 2. 設定環境變數

```powershell
copy .env.example .env
# 編輯 .env，填入 MongoDB Atlas 連線字串
notepad .env
```

### 3. 初始化測試資料

```powershell
python seed_data.py
```

### 4. 啟動所有服務

```powershell
.\start_all.bat
```

瀏覽器會自動開啟 `http://localhost:3000`

## Test Accounts

| Username       | Role        | Password   | OTP    | Status |
|----------------|-------------|------------|--------|--------|
| admin          | admin       | Test1234!  | —      | active |
| john.doe       | user        | Test1234!  | —      | active |
| jane.smith     | user        | Test1234!  | 234567 | active |
| michael.chen   | user (VIP)  | Test1234!  | 345678 | active |
| sarah.wong     | user (VIP)  | Test1234!  | —      | active |
| risk.user1     | user        | Test1234!  | —      | active |
| risk.user2     | user        | Test1234!  | —      | locked |
| risk_officer   | risk_officer| Test1234!  | 567890 | active |

## API Documentation

啟動後，每個服務的 Swagger UI 可於以下位址存取：
- Gateway: http://localhost:8000/docs
- Auth: http://localhost:8001/docs
- Account: http://localhost:8002/docs
- Transaction: http://localhost:8003/docs
- Risk: http://localhost:8004/docs
- Notification: http://localhost:8005/docs

## Security Notice

本專案使用舊版套件（PyJWT 1.7.2、cryptography 3.3.1 等）供安全掃描測試用途。
**請勿將此專案直接用於生產環境。**
