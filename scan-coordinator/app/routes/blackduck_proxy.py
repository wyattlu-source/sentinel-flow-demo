"""
Proxy routes: 將 blackduck-service 的所有 endpoint 透過 scan-coordinator 轉發。
這樣 Orchestrate 只需要一個 ngrok URL 就能存取全部功能。
"""
import requests
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

router = APIRouter()
BD_URL = "http://localhost:8006"


async def _proxy(path: str, request: Request) -> Response:
    url = f"{BD_URL}/{path}"
    params = dict(request.query_params)
    body = await request.body()
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }
    try:
        r = requests.request(
            method=request.method,
            url=url,
            params=params,
            data=body if body else None,
            headers=headers,
            timeout=120,
            verify=False,
        )
        return Response(
            content=r.content,
            status_code=r.status_code,
            media_type=r.headers.get("content-type", "application/json"),
        )
    except requests.exceptions.ConnectionError:
        return JSONResponse(
            {"error": "blackduck-service (port 8006) is not running"},
            status_code=503,
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)


# ── Proxy: /blackduck/* ───────────────────────────────────────────────────────

@router.api_route(
    "/blackduck/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
async def proxy_blackduck(path: str, request: Request):
    return await _proxy(f"blackduck/{path}", request)


# ── Proxy: /code-modification/* ───────────────────────────────────────────────

@router.api_route(
    "/code-modification/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
async def proxy_code_modification(path: str, request: Request):
    return await _proxy(f"code-modification/{path}", request)


# ── Proxy: /analysis/* ────────────────────────────────────────────────────────

@router.api_route(
    "/analysis/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
async def proxy_analysis(path: str, request: Request):
    return await _proxy(f"analysis/{path}", request)


# ── Proxy: /webhook/* ────────────────────────────────────────────────────────

@router.api_route(
    "/webhook/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
async def proxy_webhook(path: str, request: Request):
    return await _proxy(f"webhook/{path}", request)
