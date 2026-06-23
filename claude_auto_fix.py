"""
自動修復代理人（支援 Claude Code CLI 與 Bob CLI）

從 .analysis-messages/ 讀取 Orchestrate 的分析訊息，
自動修改程式碼，不需要任何 API Key。

使用方式:
  python claude_auto_fix.py run      # 處理所有待處理訊息（一次）
  python claude_auto_fix.py watch    # 持續監控，有新訊息就自動處理
  python claude_auto_fix.py list     # 列出待處理的訊息

環境變數:
  AUTO_FIX_CLI=claude   使用 Claude Code CLI（預設）
  AUTO_FIX_CLI=bob      使用 Bob CLI（bobshell）

需求（擇一）:
  - Claude Code CLI：已安裝並登入 (claude --version)
  - Bob CLI：npm install -g bobshell，已登入 (bob --version)
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# ── 路徑 ─────────────────────────────────────────────────────────────────────
PROJECT_DIR  = Path(__file__).parent
ANALYSIS_DIR = PROJECT_DIR / ".analysis-messages"
CODE_REQ_DIR = PROJECT_DIR / ".code-requests"
LOG_FILE     = PROJECT_DIR / ".claude-auto-fix.log"

POLL_INTERVAL = int(os.getenv("AUTO_FIX_INTERVAL", "30"))  # 秒

# 選擇使用哪個 CLI：claude（預設）或 bob
AUTO_FIX_CLI = os.getenv("AUTO_FIX_CLI", "claude").lower()

# claude CLI 的 permission mode：bypassPermissions = 完全無人值守
PERMISSION_MODE = os.getenv("AUTO_FIX_PERMISSION_MODE", "bypassPermissions")

# 修復完成後自動重新掃描的目標服務
SCAN_COORDINATOR_URL = os.getenv("SCAN_COORDINATOR_URL", "http://localhost:8010")


# ── log ───────────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# ── claude CLI 呼叫 ───────────────────────────────────────────────────────────

def run_claude(prompt: str, label: str = "", cwd: str = None) -> tuple[bool, str]:
    """
    把 prompt 寫入暫存檔，用 claude -p 或 bob 讀取並執行。
    避免 Windows shell 對長字串的截斷與跳脫問題。
    AUTO_FIX_CLI=claude（預設）或 bob 來切換。
    cwd: 執行目錄（None = PROJECT_DIR，可指定其他專案路徑）
    """
    import shutil, platform

    work_dir  = Path(cwd) if cwd else PROJECT_DIR
    # 把完整 prompt 寫到暫存檔，讓 AI 去讀，避免 shell 參數長度限制
    # 這個檔名被列在 .gitignore，bobshell 的 read_file 工具會遵守 .gitignore，
    # 所以讀不到它，只能繞道用 PowerShell Get-Content 讀取。Get-Content 在沒有
    # BOM 標記時會用系統預設編碼（這台機器是 cp950）解碼，把中文整份讀成亂碼，
    # 只有 ASCII 套件名稱/版本號能倖存。寫成帶 BOM 的 UTF-8，讓 Get-Content
    # 不論系統編碼為何都能正確判斷成 UTF-8。
    task_file = work_dir / "auto-fix-task.md"
    task_file.write_text(prompt, encoding="utf-8-sig")

    short_prompt = (
        "Please read the file auto-fix-task.md and execute the "
        "security fix instructions in it. Make the actual code changes directly to the files."
    )

    if AUTO_FIX_CLI == "bob":
        exe = shutil.which("bob") or shutil.which("bob.ps1") or shutil.which("bob.cmd")
        if not exe:
            log("  找不到 bob 指令，請確認已安裝 bobshell（npm install -g bobshell）")
            sys.exit(1)
        cmd = [
            exe,
            short_prompt,              # positional prompt（非互動一次性執行）
            "--approval-mode", "yolo", # 自動接受所有操作（等同 bypassPermissions）
            "--chat-mode", "code",     # 使用 code 模式
            "-o", "text",
        ]
        if os.getenv("BOBSHELL_API_KEY"):
            cmd += ["--auth-method", "api-key"]
        cli_name = "bob"
    else:
        exe = shutil.which("claude") or shutil.which("claude.cmd")
        if not exe:
            log("  找不到 claude 指令，請確認已安裝 Claude Code CLI")
            sys.exit(1)
        cmd = [
            exe,
            "-p", short_prompt,
            "--permission-mode", PERMISSION_MODE,
            "--output-format", "text",
        ]
        cli_name = "claude"

    log(f"  執行 {cli_name} CLI{' (' + label + ')' if label else ''}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(work_dir),
            timeout=900,
            shell=(platform.system() == "Windows"),
        )
        # 清理暫存檔
        try:
            task_file.unlink()
        except OSError:
            pass

        output = result.stdout.strip()
        if result.returncode != 0:
            err = result.stderr.strip()
            log(f"  {cli_name} 結束碼 {result.returncode}: {err[:200]}")
            return False, err
        log(f"  {cli_name} 完成（{len(output)} 字元輸出）")
        return True, output
    except subprocess.TimeoutExpired as e:
        log(f"  {cli_name} 超時（15 分鐘）")
        partial = (e.stdout or "") if isinstance(e.stdout, str) else ""
        return False, partial or "timeout"


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


def _parse_upgrades(mreq: dict) -> list[tuple[str, str]]:
    """從 modification_request 解析 (套件名稱, 目標版本) 清單。

    優先使用結構化的 fix_packages 欄位（格式：["urllib3>=2.6.3"]），
    若無則從 details 字串中用 regex 提取。
    """
    import re
    upgrades: list[tuple[str, str]] = []
    seen: set[str] = set()

    # 優先：fix_packages 欄位（結構化，最可靠）
    fix_packages = mreq.get("fix_packages") or []
    for item in fix_packages:
        if ">=" in item:
            pkg, ver = item.split(">=", 1)
            pkg, ver = pkg.strip(), ver.strip()
            if pkg and ver and pkg not in seen:
                upgrades.append((pkg, ver))
                seen.add(pkg)
    if upgrades:
        return upgrades

    # 備用：從 details 字串解析
    details = mreq.get("details", "")

    # 格式 1：urllib3>=2.6.3 / PyJWT>=2.12.0
    for m in re.finditer(r"([A-Za-z][A-Za-z0-9_\-\.]+)>=?([\d]+\.[\d.]+)", details):
        pkg, ver = m.group(1), m.group(2)
        if pkg not in seen:
            upgrades.append((pkg, ver))
            seen.add(pkg)

    # 格式 2：upgrade/update X to Y.Y.Y 或 upgrade X from A to B
    for m in re.finditer(
        r"(?:upgrade|update)\s+([A-Za-z][A-Za-z0-9_\-\.]+)"
        r"(?:\s+from\s+[\S]+)?\s+to\s+([\d]+\.[\d.]+)",
        details, re.IGNORECASE
    ):
        pkg, ver = m.group(1), m.group(2)
        if pkg not in seen:
            upgrades.append((pkg, ver))
            seen.add(pkg)

    return upgrades


def build_request_prompt(req: dict, project_root: str = None) -> str:
    rid     = req.get("request_id", "unknown")
    vinfo   = req.get("vulnerability_info", {})
    mreq    = req.get("modification_request", {})
    vtype   = vinfo.get("vulnerability_type", "unknown")
    sev     = vinfo.get("severity", "unknown")
    desc    = vinfo.get("description", "")
    details = mreq.get("details", "")
    files   = [f for f in vinfo.get("affected_files", []) if not f.endswith(".xml")]

    # ── SCA 部分：套件升級指令 ───────────────────────────────────────────────
    upgrades = _parse_upgrades(mreq)
    source_files = [f for f in files if not f.endswith("requirements.txt")]

    # 不信任呼叫方傳來的 requirements.txt 路徑（Orchestrate 的 LLM 組 JSON 時，
    # Windows 路徑的反斜線常常被吃掉，例如 "C:\Users\..." 變成 "C: Users ..."）。
    # 自己在 project_root 底下重新搜尋，確保 bob 拿到的是真實可用的絕對路徑。
    root = project_root or str(PROJECT_DIR)
    req_files = [
        os.path.abspath(f)
        for f in glob.glob(os.path.join(root, "**", "requirements.txt"), recursive=True)
    ]

    if upgrades:
        sca_instructions = "\n".join(
            f"  • 找到開頭為 '{pkg}' 的行 → 整行替換為：{pkg}>={ver}"
            for pkg, ver in upgrades
        )
    elif req_files:
        sca_instructions = f"  （請根據以下說明判斷）\n  {details}"
    else:
        sca_instructions = "  （無 SCA 套件需升級）"

    req_files_list = "\n".join(f"  - {f}" for f in req_files) if req_files else "  （無）"

    # 具體、可直接逐行執行的安裝指令清單（不要留任何待代入的佔位符，
    # 不然容易被當成說明文字而被跳過，不會真的執行）
    pip_install_lines = (
        "\n".join(f'  python -m pip install --upgrade -r "{f}"' for f in req_files)
        if req_files else "  （無）"
    )

    # ── SAST 部分：原始碼修復指令 ────────────────────────────────────────────
    sast_fixes = mreq.get("sast_fixes", [])
    sast_section = ""
    if sast_fixes:
        sast_lines = []
        for item in sast_fixes:
            vt        = item.get("type", "")
            guide     = item.get("fix_guide", "")
            cwe       = item.get("cwe", "")
            file_list = item.get("files", [])
            file_lines = "\n".join(
                f"    • {fe['file']}" + (f"  行 {fe['line']}" if fe.get("line") else "")
                for fe in file_list
            )
            sast_lines.append(
                f"  [{vt}] {cwe}\n"
                f"  修復方式：{guide}\n"
                f"  受影響檔案：\n{file_lines}"
            )
        sast_section = (
            "\n── SAST 程式碼修復（照修復方式修改每個受影響檔案） ──\n"
            + "\n\n".join(sast_lines)
        )
    elif source_files:
        # 舊格式 fallback：source_files 有但沒有 sast_fixes 結構
        sast_section = (
            "\n── SAST 程式碼修復 ──\n"
            + "\n".join(f"  - {f}" for f in source_files)
            + f"\n  修復說明：{details}"
        )

    return f"""你是一個自動化安全修復代理人，正在處理 Python 專案的漏洞修復。
本次同時包含 SCA（套件升級）和 SAST（程式碼修復）兩種任務，請依序完成。

請求 ID  : {rid}
漏洞類型 : {vtype}  嚴重性：{sev}

══ 任務一：SCA 套件升級 ══════════════════════════════

需要修改的 requirements.txt：
{req_files_list}

明確替換指令（直接執行）：
{sca_instructions}

執行規則：
  1. 逐一讀取每個 requirements.txt
  2. 找到對應套件行 → 整行替換（不論現有版本號）
  3. ⚠️ 數字必須改，>=2.3.0 不代表已修復，Black Duck 看的是最低版本號
  4. 不可移除或新增其他套件行
  5. 不可讓多個 requirements.txt 變成相同內容（各服務版本可能不同）
  6. ⚠️ 全部 requirements.txt 改完後，逐行實際執行以下安裝指令（不可省略、不可只改版本號文字）：
{pip_install_lines}
     缺這一步等於沒修，下次掃描會偵測到環境裡仍是舊版套件。
{sast_section}
══ 完成後輸出 ══════════════════════════════════════════

每個修改一行，格式：
  檔案路徑 | 修改前 | 修改後 | pip install 執行結果（成功/失敗）
"""


def _trigger_post_fix_scan(req_id: str) -> None:
    """
    修復完成後自動觸發重新掃描。
    在背景執行，不阻塞主流程。
    掃描完成後 report-service 會自動：
      1. 存 JSON 報告到 report-service/reports/
      2. 發布到 Kafka blackduck-log
      3. [PLACEHOLDER] 寄 email 通知
    """
    import requests as _req
    try:
        log(f"  [post-fix] 觸發重新掃描（修復請求：{req_id}）")
        r = _req.post(
            f"{SCAN_COORDINATOR_URL}/scan/start",
            json={"trigger_reason": f"post_fix:{req_id}"},
            timeout=30,
        )
        r.raise_for_status()
        scan_id = r.json().get("scan_id")
        log(f"  [post-fix] 掃描已啟動 scan_id={scan_id}，輪詢中（每 30 秒）...")

        deadline = time.time() + 3600  # 最多等 1 小時
        while time.time() < deadline:
            time.sleep(30)
            try:
                sr = _req.get(
                    f"{SCAN_COORDINATOR_URL}/scan/status/{scan_id}",
                    timeout=10,
                )
                if sr.ok:
                    data = sr.json()
                    step   = data.get("step", "?")
                    status = data.get("status", "?")
                    log(f"  [post-fix] scan_id={scan_id} status={status} step={step}")
                    if status == "completed":
                        log(f"  [post-fix] ✅ 掃描完成，報告已產生 scan_id={scan_id}")
                        return
            except Exception as e:
                log(f"  [post-fix] 輪詢錯誤：{e}")

        log(f"  [post-fix] ⚠️ 掃描等待超時（1小時），scan_id={scan_id}")
    except Exception as e:
        log(f"  [post-fix] ❌ 觸發掃描失敗：{e}")


def process_code_request(req_file: Path, req: dict) -> bool:
    rid = req.get("request_id", req_file.stem)
    log(f"處理 code request：{rid}  [{req.get('vulnerability_info', {}).get('vulnerability_type')}]")

    # 支援其他專案：從請求取得 project_root，作為 Claude 工作目錄
    project_root = req.get("vulnerability_info", {}).get("project_root") or str(PROJECT_DIR)
    if project_root != str(PROJECT_DIR):
        log(f"  目標專案：{project_root}")

    prompt = build_request_prompt(req, project_root=project_root)
    ok, output = run_claude(prompt, label=rid, cwd=project_root)

    log_dir = CODE_REQ_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"{rid}.log").write_text(output, encoding="utf-8", errors="replace")

    move_request(req_file, "completed" if ok else "failed", "success" if ok else f"error: {output[:100]}")

    # 修復成功 → 背景觸發重新掃描（不阻塞監控迴圈）
    if ok:
        threading.Thread(
            target=_trigger_post_fix_scan,
            args=(rid,),
            daemon=True,
        ).start()

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
    log(f"自動修復代理人啟動（CLI={AUTO_FIX_CLI}，間隔={POLL_INTERVAL}s，permission={PERMISSION_MODE}）")
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
