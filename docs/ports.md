# Port 對照表

## 現有服務（維持不變）
| 服務 | Port | 狀態 |
|---|---|---|
| api-gateway | 8000 | 運作中 |
| auth-service | 8001 | 運作中 |
| account-service | 8002 | 運作中 |
| transaction-service | 8003 | 運作中 |
| risk-service | 8004 | 運作中 |
| notification-service | 8005 | 運作中 |
| blackduck-service (sca-service) | 8006 | 運作中 |

## 新增服務（骨架已建立，待實作）
| 服務 | Port | 狀態 |
|---|---|---|
| scan-coordinator | 8010 | stub |
| sast-service | 8011 | stub |
| dast-service | 8012 | stub |
| sca-service | 8013 | 預留（目前用 8006）|
| normalizer-service | 8014 | stub |
| compare-service | 8015 | stub |
| report-service | 8016 | stub |

## fix-agent
- 不占用 port，為背景執行程式
- 目前入口：`python claude_auto_fix.py watch`
- 未來入口：`python fix-agent/agent.py watch`

## Kafka（對方 VM）
| 環境變數 | 說明 |
|---|---|
| KAFKA_BROKER | broker URL，未設定時用本地檔案模擬 |
| KAFKA_TOPIC_SCAN | 掃描結果 topic（預設 security-scan-results）|
| KAFKA_TOPIC_RESCAN | 重掃結果 topic（預設 security-rescan-results）|
