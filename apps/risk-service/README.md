# Risk Service (port 8004)

風控服務，提供 AML 規則引擎、信用評分與異常偵測。

## Endpoints

| Method | Path                          | Auth        | Description          |
|--------|-------------------------------|-------------|----------------------|
| GET    | /risk/events                  | Yes         | 列出風險事件         |
| GET    | /risk/score/{username}        | Yes         | 取得信用評分         |
| POST   | /risk/analyze                 | Yes         | 對交易執行 AML 分析  |
| GET    | /risk/anomalies               | Admin/Risk  | 查詢異常交易         |
| PUT    | /risk/events/{id}/review      | Admin/Risk  | 審查風險事件         |
| POST   | /risk/events                  | Admin/Risk  | 手動建立風險事件     |
| GET    | /risk/dashboard               | Admin/Risk  | 風險儀表板統計       |

## Credit Score Grades

| Score   | Grade | Rating    |
|---------|-------|-----------|
| 750–850 | A     | Excellent |
| 680–749 | B     | Good      |
| 580–679 | C     | Fair      |
| 480–579 | D     | Poor      |
| 300–479 | F     | Very Poor |

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8004 --reload
```
