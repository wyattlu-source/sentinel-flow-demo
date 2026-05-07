from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from dotenv import load_dotenv, find_dotenv
import requests
import asyncio
import jwt
import os
import time
from collections import defaultdict

load_dotenv(find_dotenv())

app = FastAPI(title="API Gateway", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SERVICES = {
    "auth":         os.getenv("AUTH_SERVICE_URL",         "http://localhost:8001"),
    "account":      os.getenv("ACCOUNT_SERVICE_URL",      "http://localhost:8002"),
    "transaction":  os.getenv("TRANSACTION_SERVICE_URL",  "http://localhost:8003"),
    "risk":         os.getenv("RISK_SERVICE_URL",         "http://localhost:8004"),
    "notification": os.getenv("NOTIFICATION_SERVICE_URL", "http://localhost:8005"),
}

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-secret-key")
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))

_rate_store: dict = defaultdict(list)

PUBLIC_PATHS = {
    "/auth/login",
    "/auth/otp/verify",
    "/auth/token/refresh",
    "/health",
}


def check_rate_limit(client_ip: str):
    now = time.time()
    window_start = now - 60
    calls = [t for t in _rate_store[client_ip] if t > window_start]
    if len(calls) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {RATE_LIMIT} requests/minute",
            headers={"Retry-After": "60"},
        )
    calls.append(now)
    _rate_store[client_ip] = calls


def route_request(path: str):
    if path.startswith("/auth"):
        return "auth", path
    if path.startswith("/accounts"):
        return "account", path
    if path.startswith("/transactions"):
        return "transaction", path
    if path.startswith("/risk"):
        return "risk", path
    if path.startswith("/notifications"):
        return "notification", path
    return None, None


def _proxy(method: str, url: str, headers: dict, params: dict, body: bytes) -> requests.Response:
    safe_headers = {k: v for k, v in headers.items() if k.lower() not in ("host", "content-length", "transfer-encoding")}
    return requests.request(
        method=method,
        url=url,
        headers=safe_headers,
        params=params,
        data=body,
        timeout=30,
        stream=True,
    )


@app.get("/health")
def health():
    results = {}
    for name, base_url in SERVICES.items():
        try:
            r = requests.get(f"{base_url}/health", timeout=3)
            results[name] = "ok" if r.status_code == 200 else "degraded"
        except Exception:
            results[name] = "unavailable"
    overall = "ok" if all(v == "ok" for v in results.values()) else "degraded"
    return {"status": overall, "service": "api-gateway", "port": 8000, "services": results}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway(path: str, request: Request):
    full_path = f"/{path}"
    client_ip = request.client.host if request.client else "0.0.0.0"

    check_rate_limit(client_ip)

    service_name, service_path = route_request(full_path)
    if not service_name:
        raise HTTPException(status_code=404, detail=f"No route for path: {full_path}")

    service_url = SERVICES.get(service_name)
    if not service_url:
        raise HTTPException(status_code=503, detail=f"Service '{service_name}' not configured")

    # JWT auth check for protected endpoints
    is_public = full_path in PUBLIC_PATHS
    if not is_public:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Authorization header required")
        try:
            jwt.decode(auth_header[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.body()
    headers = dict(request.headers)
    params = dict(request.query_params)
    target_url = f"{service_url}{service_path}"

    try:
        resp = await asyncio.to_thread(
            _proxy, request.method, target_url, headers, params, body
        )
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail=f"Service '{service_name}' is unavailable")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Gateway timeout — upstream service did not respond")

    content_type = resp.headers.get("content-type", "")

    if "application/pdf" in content_type:
        return StreamingResponse(
            iter([resp.content]),
            media_type="application/pdf",
            headers={"Content-Disposition": resp.headers.get("Content-Disposition", "attachment")},
        )

    try:
        json_body = resp.json()
        return JSONResponse(content=json_body, status_code=resp.status_code)
    except Exception:
        return JSONResponse(
            content={"detail": resp.text or "Upstream error"},
            status_code=resp.status_code,
        )
