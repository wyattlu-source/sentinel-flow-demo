import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from dotenv import load_dotenv, find_dotenv
from .routes.scan import router
from .routes.blackduck_proxy import router as bd_proxy_router
from .routes.fix_filter import router as fix_router
from .routes.projects import router as projects_router

load_dotenv(find_dotenv())

# Orchestrate 用來呼叫此服務的公開 URL（ngrok）
SERVICE_URL = os.getenv("SCAN_COORDINATOR_URL", "http://localhost:8010")

# ── 自然語言觸發範例（Orchestrate x-ibm-nl-intent-examples）────────────────
NL_INTENTS = {
    "startScan": [
        "幫我掃描專案",
        "執行安全掃描",
        "掃描 sentinel-flow-demo",
        "開始做白箱和套件掃描",
        "run a full security scan",
        "scan the project for vulnerabilities",
        "start SAST and SCA scan",
        "trigger security scan",
    ],
    "getScanStatus": [
        "掃描進度如何",
        "掃描完成了嗎",
        "查詢掃描狀態",
        "check scan status",
        "is the scan done",
        "what is the scan progress",
    ],
    "getScanReport": [
        "給我掃描報告",
        "顯示掃描結果",
        "有幾個漏洞",
        "安全掃描結果",
        "show security scan report",
        "get the vulnerability report",
        "what vulnerabilities were found",
    ],
}

app = FastAPI(
    title="Scan Coordinator",
    description=(
        "安全掃描協調器：一次觸發 SAST（白箱）和 SCA（Black Duck 套件）兩種掃描，"
        "並產生彙整報告。可用自然語言說「幫我掃描專案」來觸發。"
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/scan")
app.include_router(bd_proxy_router)   # proxy: /blackduck/* /code-modification/* /analysis/* /webhook/*
app.include_router(fix_router)        # /fix/prepare  /fix/submit
app.include_router(projects_router)   # /projects/list  /projects/register  /projects/resolve/{name}


@app.get("/health")
def health():
    return {
        "status":      "ok",
        "service":     "scan-coordinator",
        "version":     "1.0.0",
        "port":        8010,
        "service_url": SERVICE_URL,
    }


# ── Orchestrate 相容的 OpenAPI（3.0.3 + x-ibm-nl-intent-examples）──────────
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema["openapi"] = "3.0.3"
    schema["servers"] = [{"url": SERVICE_URL, "description": "Scan Coordinator"}]

    for path_item in schema.get("paths", {}).values():
        for operation in path_item.values():
            op_id = operation.get("operationId", "")
            if op_id in NL_INTENTS:
                operation["x-ibm-nl-intent-examples"] = NL_INTENTS[op_id]

    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi
