"""
Claude Code CLI 自動修復代理人

從 .analysis-messages/ 讀取 Orchestrate 的分析訊息，
用 claude -p 自動修改程式碼，不需要任何 API Key，
使用你已登入的 Claude Code 帳號。

使用方式:
  python claude_auto_fix.py run      # 處理所有待處理訊息（一次）
  python claude_auto_fix.py watch    # 持續監控，有新訊息就自動處理
  python claude_auto_fix.py list     # 列出待處理的訊息

需求:
  - 已安裝並登入 Claude Code CLI (claude --version)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ── 路徑 ─────────────────────────────────────────────────────────────────────
PROJECT_DIR  = Path(__file__).parent
ANALYSIS_DIR = PROJECT_DIR / ".analysis-messages"
CODE_REQ_DIR = PROJECT_DIR / ".code-requests"
LOG_FILE     = PROJECT_DIR / ".claude-auto-fix.log"

POLL_INTERVAL = int(os.getenv("AUTO_FIX_INTERVAL", "30"))  # 秒

# claude CLI 的 permission mode：
#   bypassPermissions = 完全無人值守（自動接受所有操作）
PERMISSION_MODE = os.getenv("AUTO_FIX_PERMISSION_MODE", "bypassPermissions")


# ── log ───────────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ── claude CLI 呼叫 ───────────────────────────────────────────────────────────

def run_claude(prompt: str, label: str = "") -> tuple[bool, str]:
    """
    呼叫 claude -p "{prompt}" --permission-mode bypassPermissions
    回傳 (成功與否, 輸出文字)
    """
    cmd = [
        "claude",
        "-p", prompt,
        "--permission-mode", PERMISSION_MODE,
        "--output-format", "text",
    ]

    log(f"  執行 claude CLI{' (' + label + ')' if label else ''}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=str(PROJECT_DIR),
            timeout=300,  # 5 分鐘上限
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            err = result.stderr.strip()
            log(f"  claude 結束碼 {result.returncode}: {err[:200]}")
            return False, err
        log(f"  claude 完成（{len(output)} 字元輸出）")
        return True, output
    except subprocess.TimeoutExpired:
        log("  claude 超時（5 分鐘）")
        return False, "timeout"
    except FileNotFoundError:
        log("  找不到 claude 指令，請確認已安裝 Claude Code CLI")
        sys.exit(1)


# ── analysis message 處理 ─────────────────────────────────────────────────────

def load_analysis_messages() -> list[dict]:
    if not ANALYSIS_DIR.exists():
        return []
    msgs: list[dict] = []
    for f in ANALYSIS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if not data.get("processed"):
                msgs.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    msgs.sort(key=lambda x: x.get("received_at", ""))
    return msgs


def mark_analysis_processed(message_id: str, result: str) -> None:
    msg_file = ANALYSIS_DIR / f"{message_id}.json"
    if not msg_file.exists():
        return
    try:
        data = json.loads(msg_file.read_text(encoding="utf-8"))
        data["processed"]         = True
        data["processed_at"]      = datetime.now().isoformat()
        data["processing_result"] = result
        msg_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        log(f"  警告：無法標記 {message_id} 為已處理：{e}")


def build_analysis_prompt(msg: dict) -> str:
    mid      = msg.get("message_id", "unknown")
    mtype    = msg.get("message_type", "unknown")
    content  = msg.get("content", "")
    project  = msg.get("project_name", "")
    version  = msg.get("version", "")
    severity = msg.get("severity", "")
    meta     = json.dumps(msg.get("metadata") or {}, indent=2, ensure_ascii=False)

    affected_files_hint = ""
    af = (msg.get("metadata") or {}).get("affected_files", [])
    if af:
        affected_files_hint = (
            f"\n受影響的檔案（請先讀取）：\n" + "\n".join(f"  - {f}" for f in af)
        )

    return f"""你是一個自動化安全修復代理人，正在處理來自 IBM watsonx Orchestrate 的漏洞分析報告。

訊息 ID  : {mid}
訊息類型 : {mtype}
專案     : {project}  版本：{version}
嚴重性   : {severity}
{affected_files_hint}

── 報告內容 ──────────────────────────────────────────
{content}

── 額外資訊 ──────────────────────────────────────────
{meta}

請執行以下步驟：
1. 讀取上方提到的相關檔案（如果沒有指定，搜尋專案中可能受影響的檔案）
2. 分析漏洞並進行最小範圍的修復
3. 直接修改檔案（不需要詢問確認）
4. 完成後說明修改了哪些檔案以及修改原因

如果不需要修改程式碼（例如純資訊性通知），請說明原因。
"""


def process_analysis_message(msg: dict) -> bool:
    mid = msg.get("message_id", "unknown")
    log(f"處理 analysis 訊息：{mid}  [{msg.get('message_type')}]")

    prompt = build_analysis_prompt(msg)
    ok, output = run_claude(prompt, label=mid)

    mark_analysis_processed(mid, "success" if ok else f"error: {output[:100]}")
    return ok


# ── code-modification request 處理 ───────────────────────────────────────────

def load_pending_requests() -> list[tuple[Path, dict]]:
    pending_dir = CODE_REQ_DIR / "pending"
    if not pending_dir.exists():
        return []
    items: list[tuple[Path, dict]] = []
    for f in pending_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            items.append((f, data))
        except (json.JSONDecodeError, OSError):
            continue
    return items


def move_request(src: Path, status: str, result: str) -> None:
    dest_dir = CODE_REQ_DIR / status
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
        data["status"]       = status
        data["completed_at"] = datetime.now().isoformat()
        data["result"]       = result
        dest = dest_dir / src.name
        dest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        src.unlink(missing_ok=True)
    except OSError as e:
        log(f"  警告：移動請求失敗：{e}")


def build_request_prompt(req: dict) -> str:
    rid   = req.get("request_id", "unknown")
    vinfo = req.get("vulnerability_info", {})
    vtype = vinfo.get("vulnerability_type", "unknown")
    sev   = vinfo.get("severity", "unknown")
    desc  = vinfo.get("description", "")
    fix   = vinfo.get("fix_recommendation", "")
    files = vinfo.get("affected_files", [])
    deps  = vinfo.get("affected_dependencies", [])

    files_hint = ""
    if files:
        files_hint = "\n受影響的檔案：\n" + "\n".join(f"  - {f}" for f in files)
    deps_hint = ""
    if deps:
        deps_hint = "\n受影響的依賴套件：\n" + "\n".join(f"  - {d}" for d in deps)

    return f"""你是一個自動化安全修復代理人，正在處理程式碼修改請求。

請求 ID  : {rid}
漏洞類型 : {vtype}
嚴重性   : {sev}
{files_hint}{deps_hint}

── 問題描述 ──────────────────────────────────────────
{desc}

── 修復建議 ──────────────────────────────────────────
{fix}

請執行以下步驟：
1. 讀取上方列出的相關檔案
2. 套用修復建議（最小範圍修改）
3. 如果是版本升級，同時更新 requirements.txt 或相關設定檔
4. 直接修改檔案（不需要詢問確認）
5. 完成後說明修改了哪些地方

如果不需要修改程式碼，請說明原因。
"""


def process_code_request(req_file: Path, req: dict) -> bool:
    rid = req.get("request_id", req_file.stem)
    log(f"處理 code request：{rid}  [{req.get('vulnerability_info', {}).get('vulnerability_type')}]")

    prompt = build_request_prompt(req)
    ok, output = run_claude(prompt, label=rid)

    move_request(req_file, "completed" if ok else "failed", "success" if ok else f"error: {output[:100]}")
    return ok


# ── 主循環 ────────────────────────────────────────────────────────────────────

def run_once() -> tuple[int, int]:
    """處理所有待處理項目一次，回傳 (成功數, 失敗數)"""
    done = 0
    fail = 0

    msgs = load_analysis_messages()
    if msgs:
        log(f"發現 {len(msgs)} 個未處理的 analysis 訊息")
        for msg in msgs:
            if process_analysis_message(msg):
                done += 1
            else:
                fail += 1

    reqs = load_pending_requests()
    if reqs:
        log(f"發現 {len(reqs)} 個待處理的 code-modification 請求")
        for req_file, req in reqs:
            if process_code_request(req_file, req):
                done += 1
            else:
                fail += 1

    if not msgs and not reqs:
        log("沒有待處理項目")

    return done, fail


def watch() -> None:
    log(f"自動修復代理人啟動（間隔={POLL_INTERVAL}s，permission={PERMISSION_MODE}）")
    log(f"專案目錄：{PROJECT_DIR}")
    log("按 Ctrl+C 停止")
    try:
        while True:
            try:
                done, fail = run_once()
                if done or fail:
                    log(f"本輪完成：成功={done} 失敗={fail}")
            except Exception as e:
                log(f"迴圈錯誤：{e}")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        log("代理人已停止")


def show_list() -> None:
    msgs = load_analysis_messages()
    reqs = load_pending_requests()
    print(f"\n未處理 analysis 訊息：{len(msgs)}")
    for m in msgs:
        print(f"  {m.get('message_id')}  [{m.get('message_type')}]  嚴重性={m.get('severity', '-')}")
    print(f"\n待處理 code-mod 請求：{len(reqs)}")
    for _, r in reqs:
        v = r.get("vulnerability_info", {})
        print(f"  {r.get('request_id')}  [{v.get('vulnerability_type')}]  嚴重性={v.get('severity', '-')}")
    print()


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "run":
        done, fail = run_once()
        print(f"\n完成 — 成功={done} 失敗={fail}")
    elif cmd == "watch":
        watch()
    elif cmd == "list":
        show_list()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
