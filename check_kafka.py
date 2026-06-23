from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    "blackduck-log",
    bootstrap_servers="10.107.85.239:9092",
    auto_offset_reset="earliest",
    consumer_timeout_ms=8000,
    value_deserializer=lambda v: json.loads(v.decode("utf-8")),
)

count = 0
for msg in consumer:
    count += 1
    v = msg.value
    scan_id = v.get("scan_id", "?")
    project = v.get("project_name", "?")
    total   = v.get("summary", {}).get("total_vulnerabilities", "?")
    ts      = v.get("generated_at", "?")
    print(f"[msg {count}] scan_id={scan_id}  project={project}  total_vulns={total}  at={ts}")

consumer.close()
print(f"\nTotal messages in blackduck-log: {count}")
