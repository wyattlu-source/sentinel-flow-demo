# sca-service

SCA（Software Composition Analysis）套件掃描服務。

## 目前狀態

現有功能在 `../blackduck-service/`（port 8006），與 Orchestrate 整合已完整。

此目錄為未來重構預留位置：
- blackduck-service 的邏輯將逐步遷移至此
- 新增統一輸出格式（VulnerabilityItem）
- 新增 Kafka 發布功能

## 計畫 Port：8013
