# Notification Service (port 8005)

通知服務，管理系統通知、已讀未讀狀態與告警推送。

## Endpoints

| Method | Path                          | Auth  | Description      |
|--------|-------------------------------|-------|------------------|
| GET    | /notifications                | Yes   | 列出通知         |
| GET    | /notifications/unread-count   | Yes   | 未讀數量         |
| PUT    | /notifications/read-all       | Yes   | 全部標為已讀     |
| PUT    | /notifications/{id}/read      | Yes   | 標記單筆已讀     |
| DELETE | /notifications/{id}           | Yes   | 刪除通知         |
| POST   | /notifications/send           | Admin | 發送通知         |

## Notification Types

- `transaction_alert` — 交易通知
- `risk_alert` — 風險告警
- `system_notice` — 系統公告
- `account_alert` — 帳戶狀態
- `login_alert` — 登入通知

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8005 --reload
```
