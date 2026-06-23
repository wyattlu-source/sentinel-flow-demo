@echo off
chcp 65001 > nul
title Sentinel Flow Demo - Service Manager
SET "ROOT=%~dp0.."
REM 使用系統 PATH 中的 Python（自動偵測）

echo.
echo ====================================================
echo   SENTINEL FLOW DEMO - Starting All Services
echo ====================================================
echo.

cd /d "%ROOT%"

if not exist ".env" (
    echo [ERROR] .env file not found!
    pause
    exit /b 1
)

echo [SETUP] Copying .env to service directories...
for %%d in (apps\api-gateway apps\auth-service apps\account-service apps\transaction-service apps\risk-service apps\notification-service blackduck-service) do (
    copy /y ".env" "%%d\.env" > nul 2>&1
)
echo [SETUP] Done.
echo.

echo [START] Auth Service         (port 8001)...
start "SF: Auth :8001" cmd /k "cd /d "%ROOT%\apps\auth-service" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload"
timeout /t 1 /nobreak > nul

echo [START] Account Service      (port 8002)...
start "SF: Account :8002" cmd /k "cd /d "%ROOT%\apps\account-service" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload"
timeout /t 1 /nobreak > nul

echo [START] Transaction Service  (port 8003)...
start "SF: Transaction :8003" cmd /k "cd /d "%ROOT%\apps\transaction-service" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8003 --reload"
timeout /t 1 /nobreak > nul

echo [START] Risk Service         (port 8004)...
start "SF: Risk :8004" cmd /k "cd /d "%ROOT%\apps\risk-service" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8004 --reload"
timeout /t 1 /nobreak > nul

echo [START] Notification Service (port 8005)...
start "SF: Notification :8005" cmd /k "cd /d "%ROOT%\apps\notification-service" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8005 --reload"
timeout /t 2 /nobreak > nul

echo [START] BlackDuck Service    (port 8006)...
start "SF: BlackDuck :8006" cmd /k "cd /d "%ROOT%\blackduck-service" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8006 --reload"
timeout /t 1 /nobreak > nul

echo [START] API Gateway          (port 8000)...
start "SF: Gateway :8000" cmd /k "cd /d "%ROOT%\apps\api-gateway" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
timeout /t 2 /nobreak > nul

echo [START] Frontend             (port 3000)...
start "SF: Frontend :3000" cmd /k "cd /d "%ROOT%\apps\frontend" && python -m http.server 3000"
timeout /t 1 /nobreak > nul

echo.
echo ====================================================
echo   All services started!
echo ====================================================
echo.
echo   Frontend       :  http://localhost:3000
echo   API Gateway    :  http://localhost:8000/docs
echo   Auth           :  http://localhost:8001/docs
echo   Account        :  http://localhost:8002/docs
echo   Transaction    :  http://localhost:8003/docs
echo   Risk           :  http://localhost:8004/docs
echo   Notification   :  http://localhost:8005/docs
echo   BlackDuck API  :  http://localhost:8006/docs
echo.
echo   Default login  :  admin / Test1234!
echo.
pause > nul
start http://localhost:3000
