"""
Fix Agent — 修復代理人主程式。

目前架構：
  claude_auto_fix.py  ← 完整可用，直接執行
  fix-agent/          ← 新架構骨架，逐步遷移中

使用方式（目前）：
  python claude_auto_fix.py watch

未來使用方式：
  python fix-agent/agent.py watch   ← 完成遷移後
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""

    if cmd in ("watch", "run", "list"):
        import claude_auto_fix
        claude_auto_fix.main()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
