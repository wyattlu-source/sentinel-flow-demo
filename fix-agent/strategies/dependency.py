"""
依賴升級策略 — 對應 claude_auto_fix.py 的 _parse_upgrades + build_request_prompt。
目前為薄包裝，直接引用 claude_auto_fix 的邏輯。
"""
import sys
from pathlib import Path

# 指向專案根目錄，讓 import claude_auto_fix 可以找到
_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT))


def parse_upgrades(mreq: dict) -> list[tuple[str, str]]:
    from claude_auto_fix import _parse_upgrades
    return _parse_upgrades(mreq)


def build_prompt(req: dict) -> str:
    from claude_auto_fix import build_request_prompt
    return build_request_prompt(req)
