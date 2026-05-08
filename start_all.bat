@echo off
chcp 65001 > nul
title Sentinel Flow Demo - Service Manager
SET "PYBIN=C:\Users\WyattLu-盧羿樺-產品代理技術處D\AppData\Local\Python\bin"
SET "PATH=%PYBIN%;%PATH%"

echo.
echo ====================================================
echo   SENTINEL FLOW DEMO ? Starting All Services
echo ====================================================
echo.

REM Check .env exists
if not exist ".env" (
    echo [ERROR] .env file not found!
    echo         Copy .env.example to .env and fill in your values.
    echo.
    pause
    exit /b 1
)

REM Copy .env to each service directory
echo [SETUP] Copying .env to service directories...
for %%d in (api-gateway auth-service account-service transaction-service risk-service notification-service) do (
    copy /y ".env" "%%d\.env" > nul 2>&1
)
echo [SETUP] Done.
echo.

REM Start services in separate windows (slight stagger so gateway starts last)
echo [START] Auth Service         (port 8001)...
start "SF: Auth Service :8001" cmd /k "cd auth-service && python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload"
timeout /t 1 /nobreak > nul

echo [START] Account Service      (port 8002)...
start "SF: Account Service :8002" cmd /k "cd account-service && python -m uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload"
timeout /t 1 /nobreak > nul

echo [START] Transaction Service  (port 8003)...
start "SF: Transaction Service :8003" cmd /k "cd transaction-service && python -m uvicorn app.main:app --host 0.0.0.0 --port 8003 --reload"
timeout /t 1 /nobreak > nul

echo [START] Risk Service         (port 8004)...
start "SF: Risk Service :8004" cmd /k "cd risk-service && python -m uvicorn app.main:app --host 0.0.0.0 --port 8004 --reload"
timeout /t 1 /nobreak > nul

echo [START] Notification Service (port 8005)...
start "SF: Notification Service :8005" cmd /k "cd notification-service && python -m uvicorn app.main:app --host 0.0.0.0 --port 8005 --reload"
timeout /t 2 /nobreak > nul

echo [START] BlackDuck API Service (port 8006)...
start "SF: BlackDuck API :8006" cmd /k "cd blackduck-service && python -m uvicorn app.main:app --host 0.0.0.0 --port 8006 --reload"
timeout /t 1 /nobreak > nul

echo [START] API Gateway          (port 8000)...
start "SF: API Gateway :8000" cmd /k "cd api-gateway && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
timeout /t 2 /nobreak > nul

echo [START] Frontend             (port 3000)...
start "SF: Frontend :3000" cmd /k "cd frontend && python -m http.server 3000"
timeout /t 1 /nobreak > nul

echo.
echo ====================================================
echo   All services started!
echo ====================================================
echo.
echo   Frontend       :  http://localhost:3000
echo   API Gateway    :  http://localhost:8000
echo   API Docs       :  http://localhost:8000/docs
echo   Auth           :  http://localhost:8001/docs
echo   Account        :  http://localhost:8002/docs
echo   Transaction    :  http://localhost:8003/docs
echo   Risk           :  http://localhost:8004/docs
echo   Notification   :  http://localhost:8005/docs
echo   BlackDuck API  :  http://localhost:8006/docs
echo.
echo   Default login  :  admin / Test1234!
echo.
echo   Press any key to open the frontend in browser...
pause > nul
start http://localhost:3000
