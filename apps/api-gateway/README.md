# API Gateway (port 8000)

統一入口，負責路由代理、JWT 驗證與速率限制。

## Route Mapping

| Path prefix    | Routes to           |
|----------------|---------------------|
| /auth/*        | auth-service :8001  |
| /accounts/*    | account-service :8002 |
| /transactions/*| transaction-service :8003 |
| /risk/*        | risk-service :8004  |
| /notifications/*| notification-service :8005 |

## Public Endpoints (no auth required)

- `POST /auth/login`
- `POST /auth/otp/verify`
- `POST /auth/token/refresh`
- `GET /health`

## Rate Limiting

Default: 100 requests/minute per IP. Configurable via `RATE_LIMIT_PER_MINUTE` env var.

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
