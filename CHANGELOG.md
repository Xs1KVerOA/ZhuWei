# 变更日志 / Changelog

本文件记录烛微 ZhuWei 的重要变更。

All notable changes to ZhuWei are recorded in this file.

## [v0.1.0] - 2026-04-28

### 新增 / Added

- 发布烛微 ZhuWei 初始版本：一套可私有化部署的本地化漏洞情报与产品风险研判平台。
- Initial release of ZhuWei, a self-hosted vulnerability intelligence and product-risk analysis workspace.
- 接入多源漏洞情报采集，包括 CISA KEV、NVD、GitHub Security Advisories、长亭 VulDB、OSCS、微步、Seebug、AVD、CNVD、启明星辰、Apache Struts2 官方公告、Doonsec WeChat RSS、biu.life 等。
- Added multi-source vulnerability ingestion for CISA KEV, NVD, GitHub Security Advisories, Chaitin VulDB, OSCS, ThreatBook, Seebug, AVD, CNVD, Venustech, Apache Struts2 bulletins, Doonsec WeChat RSS, biu.life, and more.
- 新增 GitHub Security Lab Advisories、GobyVuls GitHub 漏洞文档、Sploitus RSS、CXSecurity WLB RSS 等稳定证据源。
- Added stable evidence sources for GitHub Security Lab Advisories, GobyVuls GitHub vulnerability documents, Sploitus RSS, and CXSecurity WLB RSS.
- 新增数据源健康中心、手动运行、定时采集分组、运行状态与 warning 记录。
- Added source health tracking, manual source runs, scheduled source groups, and source warning/status reporting.
- 新增告警研判、产品归属、产品库对齐、源码证据管理、模型辅助漏洞分析和 Neo4j 图谱同步能力。
- Added alert triage, product attribution, product catalog alignment, source archive management, model-assisted vulnerability analysis, and Neo4j graph synchronization.
- 新增 CVE/GHSA 的 GitHub POC/EXP 证据增强，支持仓库/代码证据评分和 POC/EXP Tab 展示。
- Added GitHub POC/EXP evidence enrichment for CVE/GHSA records, including repository/code evidence scoring and POC/EXP tab display.
- 新增 Docker Compose 部署、SQLite/PostgreSQL 支持、Redis 队列、MinIO 对象存储，以及面向 Cookie/Session 类站点的浏览器代理能力。
- Added Docker Compose deployment, local SQLite/PostgreSQL support, Redis queue support, MinIO artifact storage, and browser proxy support for cookie/session-based sources.

### 变更 / Changed

- GitHub Advisory 和外部证据源默认作为证据源入库，不自动触发高危告警。
- GitHub advisory and external evidence sources are ingested as evidence-only sources and do not automatically create high-risk alerts.
- GitHub Search API 限流提示不再把无关数据源采集状态标记为部分失败。
- GitHub Search API rate-limit warnings no longer mark unrelated source ingestion runs as partial failures.
- 优化产品匹配逻辑，支持结构化产品字段、CPE 标签提取和更多噪声标签过滤。
- Improved product matching with structured product fields, CPE-derived labels, and additional noisy-label filtering.

### 文档 / Documentation

- 新增 README、部署指南、产品概览、用户指南、Docker 部署说明和热更新文档。
- Added README, deployment guide, product overview, user guide, Docker deployment notes, and hot-update documentation.
- 补充 GitHub 证据配置项，以及可选证据源的默认行为说明。
- Documented GitHub evidence settings and default behavior for optional evidence sources.
