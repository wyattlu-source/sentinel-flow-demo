"""
Kafka consumer — 訂閱 security-scan-results topic，觸發修復流程。
無 KAFKA_BROKER 時改用檔案輪詢（與現有 claude_auto_fix.py watch 相同效果）。
TODO: 整合
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))


def start():
    """
    TODO: 從 shared.kafka.consumer 訂閱 topic，
    對每個 VulnerabilityItem 呼叫對應 strategy，
    修復完成後呼叫 git_helper.commit_and_pr()，
    再觸發 rescan。

    目前請使用 claude_auto_fix.py watch 替代。
    """
    print("[fix-agent] kafka_consumer 尚未實作，請使用 claude_auto_fix.py watch")
