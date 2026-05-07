# Auth Service (port 8001)

JWT 認證服務，提供登入、OTP 驗證與 Token 管理。

## Endpoints

| Method | Path                    | Auth | Description          |
|--------|-------------------------|------|----------------------|
| POST   | /auth/login             | No   | Username/password 登入 |
| POST   | /auth/otp/verify        | No   | OTP 驗證             |
| POST   | /auth/token/refresh     | No   | Refresh token        |
| GET    | /auth/me                | Yes  | 取得當前用戶資訊     |
| PUT    | /auth/me/password       | Yes  | 修改密碼             |
| GET    | /auth/users             | Admin| 列出所有用戶         |
| PUT    | /auth/users/{u}/lock    | Admin| 鎖定帳號             |
| PUT    | /auth/users/{u}/unlock  | Admin| 解鎖帳號             |

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```
