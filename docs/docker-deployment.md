# Docker 部署文档

本文档用于服务器或干净测试机上的 Docker 部署。本地开发环境可以继续使用 `./start.sh`，不需要切换到 Docker Compose。

## 部署内容

完整 Docker 部署会启动以下服务：

- `zhuwei-app`：FastAPI 后端与内置前端。
- `zhuwei-postgres`：PostgreSQL 16，保存漏洞、告警、产品和任务数据。
- `zhuwei-redis`：分析队列与运行态队列。
- `zhuwei-minio`：源码归档对象存储。
- `zhuwei-neo4j`：产品、漏洞、告警和源码证据图谱。

相关文件：

- [docker-compose.yml](../docker-compose.yml)：完整部署。
- [docker-compose.infra.yml](../docker-compose.infra.yml)：只启动 PostgreSQL、Redis、MinIO、Neo4j，适合应用仍在宿主机运行的场景。
- [.env.docker.example](../.env.docker.example)：Docker 部署环境变量模板。
- [scripts/docker_start.sh](../scripts/docker_start.sh)：推荐启动脚本。
- [deploy/docker/daemon.json.example](../deploy/docker/daemon.json.example)：可选 Docker Hub 镜像加速配置。

## 前置条件

服务器需要安装：

- Docker Engine
- Docker Compose Plugin，或兼容的 `docker-compose` v1
- `curl`

检查命令：

```bash
docker --version
docker compose version
```

如果 `docker compose` 不存在，可以安装 Docker Compose Plugin，或安装 `docker-compose` v1。启动脚本会自动优先使用 `docker compose`，再回退到 `docker-compose`。

建议资源：

- 最低：2 CPU / 2 GB RAM / 20 GB 磁盘。
- 推荐：2 CPU / 4 GB RAM 或更高。
- 如果 Neo4j 图谱数据量持续增长，建议把 Docker 可用内存提升到 4 GB 以上，并同步调大 `.env.docker` 中的 `NEO4J_HEAP_*` 与 `NEO4J_PAGECACHE`。

## 快速部署

在项目根目录执行：

```bash
./scripts/docker_start.sh init-env
```

脚本会生成 `.env.docker` 并退出。编辑配置：

```bash
vim .env.docker
```

至少修改：

- `SESSION_SECRET`：随机长字符串。
- `POSTGRES_PASSWORD`：PostgreSQL 强密码。
- `MINIO_ROOT_PASSWORD`：MinIO 强密码。
- `NEO4J_PASSWORD`：Neo4j 强密码。
- `DEEPSEEK_API_KEY` 或 `ANTHROPIC_AUTH_TOKEN`：模型 API Key。
- `APP_BIND`：公网直连可用 `0.0.0.0`；仅反向代理或本机访问建议用 `127.0.0.1`。
- `APP_PORT`：默认 `8010`。

启动：

```bash
./scripts/docker_start.sh up
```

查看容器：

```bash
./scripts/docker_start.sh ps
```

查看登录 token：

```bash
./scripts/docker_start.sh token
```

查看应用日志：

```bash
./scripts/docker_start.sh logs
```

默认访问：

```text
http://服务器IP:8010
```

登录 token 每次应用容器启动都会重新生成，脚本会从 app 日志中打印最近 token 行。

## 数据源自动调度

应用启动后会自动注册并启动调度器，不需要人工点“运行”才能周期采集：

- `regular` 数据源：默认每 30 分钟自动运行一次。
- `slow` 数据源：默认按 `Asia/Shanghai` 时区每天 `10:00` 和 `18:00` 自动运行。
- 页面上的“运行”按钮只是立即补跑一次，不会关闭自动调度。

`biu.life 产品库` 会按慢速策略分页采集，默认每页间隔 8 秒，并额外加入 0-4 秒随机抖动；遇到 429 会从 30 秒开始指数退避重试。线上部署建议保持默认值或调得更慢：

```env
BIU_PRODUCT_PAGE_DELAY_MS=8000
BIU_PRODUCT_PAGE_JITTER_MS=4000
BIU_PRODUCT_RETRY_COUNT=8
BIU_PRODUCT_RETRY_BASE_SECONDS=30
```

AVD、CNVD 等浏览器型数据源依赖 Playwright Chromium 和站点会话。Docker 镜像会在构建时预装 Chromium；如果是旧镜像升级，执行一次重建：

```bash
./scripts/docker_start.sh up
```

如果页面仍显示 `BrowserType.launch: Executable doesn't exist`，说明当前运行的还是旧镜像或构建时浏览器下载失败。重新构建后查看 app 日志确认镜像构建阶段执行了 Playwright 安装。

部分站点还可能要求 Cookie 或验证码态。此时调度会照常自动触发，但该源会记录 `failed` 或 `partial`，需要先在“站点会话”里刷新 Cookie，再等待下一次调度或手动点一次“运行”验证。

## 热更新

前端“更新”页可以上传 `.update` 文件。应用会把更新包保存到 `backend/data/updates`，由后端按 manifest 声明确定性应用 patch/replace/add 变更，同时生成报告和机器可读结果：

- `report.md`：中文更新报告。
- `result.json`：状态、摘要、变更文件、校验结果、是否需要重启。
- `stdout.log` / `stderr.log`：确定性更新执行和校验输出。

默认上传限制为 200 MB，可通过 `UPDATE_UPLOAD_MAX_MB` 调整。更新包必须为结构化 `.update`，每个操作都需要声明 `before_sha256` 和 `after_sha256`，patch 还需要 `patch_sha256`，replace/add 还需要 `source_sha256`。后端会在应用前校验目标文件哈希，应用后校验结果哈希；基础版本不一致会拒绝更新并回滚，避免同一个 update 包在不同部署上产生不一致代码。

为了避免泄露生产凭据，更新任务会把 `.update` 当作不可信输入，禁止读取/输出 `.env`、API key、secret 等敏感信息，也禁止执行更新包内脚本、删除/重置、网络访问、容器操作和服务重启命令。若更新结果标记 `needs_restart=true`，请在维护窗口执行：

```bash
./scripts/docker_start.sh restart
```

## 启动脚本命令

```bash
./scripts/docker_start.sh up          # 构建并启动完整部署
./scripts/docker_start.sh up --no-build
./scripts/docker_start.sh infra       # 只启动 Postgres/Redis/MinIO/Neo4j
./scripts/docker_start.sh build
./scripts/docker_start.sh pull
./scripts/docker_start.sh restart
./scripts/docker_start.sh down
./scripts/docker_start.sh ps
./scripts/docker_start.sh logs
./scripts/docker_start.sh token
./scripts/docker_start.sh doctor
```

可用环境变量：

```bash
ENV_FILE=.env.docker ./scripts/docker_start.sh up
COMPOSE_FILE=docker-compose.infra.yml ./scripts/docker_start.sh infra
COMPOSE_PROJECT_NAME=zhuwei ./scripts/docker_start.sh up
```

脚本默认会拒绝使用模板里的弱密码启动。如果只是一次性本地测试，可以显式允许：

```bash
ALLOW_INSECURE_DEFAULTS=1 ./scripts/docker_start.sh up
```

生产环境不要使用这个选项。

## 端口与网络

完整部署中：

- 应用端口由 `APP_BIND` / `APP_PORT` 控制。
- PostgreSQL、Redis、MinIO、Neo4j 的宿主机端口默认只绑定 `127.0.0.1`。
- 应用容器通过 Docker 网络 `zhuwei-net` 访问中间件。

默认端口：

| 服务 | 宿主机端口 | 容器端口 | 用途 |
| --- | --- | --- | --- |
| app | `8010` | `8010` | Web 后台与 API |
| PostgreSQL | `5432` | `5432` | 数据库 |
| Redis | `6379` | `6379` | 队列 |
| MinIO API | `9000` | `9000` | 对象存储 API |
| MinIO Console | `9001` | `9001` | MinIO 控制台 |
| Neo4j Browser | `7474` | `7474` | Neo4j Web UI |
| Neo4j Bolt | `7687` | `7687` | 图数据库连接 |

公网部署建议只暴露应用入口，并在前面放 Nginx/Caddy：

- 对外开放 `80/443`。
- 反向代理到 `127.0.0.1:8010`。
- 配置 HTTPS。
- 不要把 `5432/6379/9000/9001/7474/7687` 暴露到公网。

## Neo4j 内存配置

`neo4j:5-community` 使用新版 `server.memory.*` 配置。Compose 文件已使用：

```text
NEO4J_server_memory_heap_initial__size
NEO4J_server_memory_heap_max__size
NEO4J_server_memory_pagecache_size
```

`.env.docker.example` 的默认值偏保守，适合 2 GB 左右的小机器：

```dotenv
NEO4J_HEAP_INITIAL=384m
NEO4J_HEAP_MAX=384m
NEO4J_PAGECACHE=256m
```

如果服务器有 4 GB 以上内存，可以调整为：

```dotenv
NEO4J_HEAP_INITIAL=768m
NEO4J_HEAP_MAX=768m
NEO4J_PAGECACHE=512m
```

如果 Neo4j 被系统杀掉，通常会看到 exit code `137` 或 Docker events 里的 `oom`。处理方式：

1. 提高 Docker / VPS 可用内存。
2. 降低 `NEO4J_HEAP_MAX` 与 `NEO4J_PAGECACHE`。
3. 重启：

```bash
./scripts/docker_start.sh restart neo4j
./scripts/docker_start.sh restart app
```

## 数据持久化

Compose 使用 Docker named volumes：

- `zhuwei_app_data`
- `zhuwei_postgres_data`
- `zhuwei_redis_data`
- `zhuwei_minio_data`
- `zhuwei_neo4j_data`
- `zhuwei_neo4j_logs`

停止服务不会删除数据：

```bash
./scripts/docker_start.sh down
```

只有显式删除 volumes 才会清空数据：

```bash
docker volume rm zhuwei_postgres_data zhuwei_minio_data zhuwei_neo4j_data
```

执行删除前务必先备份。

## 旧 SQLite 数据迁移

新部署可跳过本节。若需要把已有 `backend/data/zhuwei.sqlite3` 迁移到 Docker PostgreSQL：

```bash
./scripts/docker_start.sh infra

docker compose --env-file .env.docker -f docker-compose.yml run --rm \
  -v "$PWD/backend/data:/host-data:ro" \
  app python scripts/migrate_sqlite_to_postgres.py \
  --sqlite /host-data/zhuwei.sqlite3 \
  --drop-target

./scripts/docker_start.sh up
```

如果服务器只有 `docker-compose` v1，把 `docker compose` 替换为 `docker-compose`。

## 常见问题

### Docker Compose 不存在

现象：

```text
Docker Compose is not installed
```

处理：安装 Docker Compose Plugin，或安装 `docker-compose` v1。安装后运行：

```bash
./scripts/docker_start.sh doctor
```

### 使用模板密码被拒绝启动

启动脚本会阻止模板弱密码。编辑 `.env.docker`，替换：

- `SESSION_SECRET`
- `POSTGRES_PASSWORD`
- `MINIO_ROOT_PASSWORD`
- `NEO4J_PASSWORD`

### 图谱不可用

先看 Neo4j 是否运行：

```bash
./scripts/docker_start.sh ps
./scripts/docker_start.sh logs neo4j
```

再进入系统前端的“图谱”页，点击“同步图谱”。也可以调用 API：

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"limit":5000}' \
  http://127.0.0.1:8010/api/graph/sync
```

### 模型分析不可用

确认 `.env.docker` 中至少配置了一个：

```dotenv
DEEPSEEK_API_KEY=...
ANTHROPIC_AUTH_TOKEN=...
```

然后重启 app：

```bash
./scripts/docker_start.sh restart app
```

### 容器化浏览器代理

部分数据源需要浏览器态。完整 Docker 部署默认挂载 `/var/run/docker.sock`，应用容器可临时拉起 Selenium/Chromium 容器。

这会给应用容器较高的 Docker 管理权限，生产环境建议：

- 只在可信服务器部署。
- 后台入口加 HTTPS 和访问控制。
- 防火墙不要开放中间件端口。
- 必要时把 `BROWSER_PROXY_PULL_IMAGE=0` 改成固定私有镜像。

## 国内源部署

如果服务器拉取 Docker Hub、PyPI 或 npm 慢，可以参考 [Docker Compose 国内源部署指南](docker-compose-cn.md)。核心启动命令仍推荐使用：

```bash
./scripts/docker_start.sh up
```
