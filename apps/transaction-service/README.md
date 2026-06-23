# Transaction Service (port 8003)

交易服務，提供轉帳、交易查詢與 PDF 對帳單生成。

## Endpoints

| Method | Path                               | Auth  | Description        |
|--------|------------------------------------|-------|--------------------|
| POST   | /transactions/transfer             | Yes   | 發起轉帳           |
| GET    | /transactions                      | Yes   | 查詢交易記錄       |
| GET    | /transactions/{tx_id}              | Yes   | 查詢單筆交易       |
| GET    | /transactions/statement/{acc_id}   | Yes   | 下載 PDF 對帳單    |
| GET    | /transactions/stats/summary        | Admin | 交易統計摘要       |

## Query Parameters

- `GET /transactions?account_id=T...&tx_type=transfer&status=completed&limit=50`
- `GET /transactions/statement/{id}?days=30`

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8003 --reload
```
