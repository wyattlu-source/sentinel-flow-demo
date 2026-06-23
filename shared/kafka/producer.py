"""
Kafka producer — 有 KAFKA_BROKER 就用真實 Kafka，否則寫檔案模擬。
"""
import json
import os
from pathlib import Path
from datetime import datetime
from uuid import uuid4

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "")
_EVENTS_DIR = Path(__file__).parent.parent.parent / ".events"


def publish(topic: str, payload: dict) -> None:
    if KAFKA_BROKER:
        _publish_kafka(topic, payload)
    else:
        _publish_file(topic, payload)


def _publish_kafka(topic: str, payload: dict) -> None:
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        producer.send(topic, payload)
        producer.flush()
    except ImportError:
        raise RuntimeError("kafka-python not installed. pip install kafka-python")


def _publish_file(topic: str, payload: dict) -> None:
    topic_dir = _EVENTS_DIR / topic
    topic_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}.json"
    (topic_dir / filename).write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
