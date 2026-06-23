"""
Kafka consumer — 有 KAFKA_BROKER 就訂閱真實 Kafka，否則輪詢本地檔案。
"""
import json
import os
from pathlib import Path
from typing import Callable

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "")
_EVENTS_DIR = Path(__file__).parent.parent.parent / ".events"


def consume(topic: str, handler: Callable[[dict], None], poll_interval: int = 10) -> None:
    if KAFKA_BROKER:
        _consume_kafka(topic, handler)
    else:
        _consume_file(topic, handler, poll_interval)


def _consume_kafka(topic: str, handler: Callable[[dict], None]) -> None:
    try:
        from kafka import KafkaConsumer
        consumer = KafkaConsumer(
            topic,
            bootstrap_servers=KAFKA_BROKER,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
        )
        for msg in consumer:
            handler(msg.value)
    except ImportError:
        raise RuntimeError("kafka-python not installed. pip install kafka-python")


def _consume_file(topic: str, handler: Callable[[dict], None], poll_interval: int) -> None:
    import time
    topic_dir = _EVENTS_DIR / topic
    processed_dir = topic_dir / ".processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    while True:
        for f in sorted(topic_dir.glob("*.json")):
            try:
                payload = json.loads(f.read_text(encoding="utf-8"))
                handler(payload)
                f.rename(processed_dir / f.name)
            except Exception as e:
                print(f"[consumer] error processing {f.name}: {e}")
        time.sleep(poll_interval)
