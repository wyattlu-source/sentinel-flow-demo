# Account Service (port 8002)

帳戶管理服務，提供帳戶查詢、開戶與管理功能。

## Endpoints

| Method | Path                          | Auth  | Description    |
|--------|-------------------------------|-------|----------------|
| GET    | /accounts                     | Yes   | 列出帳戶       |
| GET    | /accounts/summary             | Yes   | 帳戶總覽含統計 |
| GET    | /accounts/{id}                | Yes   | 查詢單一帳戶   |
| GET    | /accounts/{id}/balance        | Yes   | 查詢餘額       |
| POST   | /accounts/open                | Yes   | 申請開戶       |
| PUT    | /accounts/{id}                | Yes   | 更新帳戶別名   |
| PUT    | /accounts/{id}/freeze         | Admin | 凍結帳戶       |
| PUT    | /accounts/{id}/activate       | Admin | 解凍帳戶       |

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```
