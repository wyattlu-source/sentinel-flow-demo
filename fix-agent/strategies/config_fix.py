"""
設定修正策略（CORS、JWT、環境變數等）。
TODO: 實作
"""


def build_prompt(req: dict) -> str:
    details = req.get("modification_request", {}).get("details", "")
    files = req.get("vulnerability_info", {}).get("affected_files", [])
    files_list = "\n".join(f"  - {f}" for f in files)
    return f"""你是一個自動化安全修復代理人，請修正以下設定問題。

需要修改的檔案：
{files_list}

修正說明：
{details}

請直接修改設定值，不需要詢問確認。完成後說明修改了哪些內容。
"""
