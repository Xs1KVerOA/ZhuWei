# 烛微 ZhuWei：部署文档

## 1. 环境要求

推荐环境：

- Python 3.11+
- Node.js 18+ 和 npm
- macOS 或 Linux
- 可访问外部漏洞情报源的网络
- 可选：Google Chrome，用于刷新 AVD/CNVD 浏览器 Cookie

核心 Python 依赖写在 `requirements.txt` 中，主要包括 FastAPI、Uvicorn、APScheduler、HTTPX、BeautifulSoup、Playwright 和 python-dotenv。

## 2. 获取代码

```bash
cd /path/to/ZhuWei
```

如果是新机器部署，请先把项目目录复制到目标机器，再进入项目根目录。

Linux 云服务器也可以直接使用 Docker Compose 部署完整环境，包含应用、PostgreSQL、Redis、MinIO、Neo4j 和容器化浏览器代理；详见 [Docker Compose 国内源部署指南](docker-compose-cn.md)。

## 3. 创建虚拟环境

如果使用项目自带启动脚本，可以跳过手动创建虚拟环境，直接运行：

```bash
./start.sh
```

脚本会自动创建 `.venv` 并安装依赖。手动方式如下：

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

如果需要使用浏览器刷新 AVD/CNVD 会话，还需要安装 Playwright 浏览器依赖：

```bash
python -m playwright install chromium
```

## 4. 配置环境变量

复制示例配置：

```bash
cp .env.example .env
```

当前登录 token 由服务在每次启动时随机生成，并打印到控制台，不需要在 `.env` 中配置 `APP_TOKEN`。

建议至少检查以下配置：

```bash
SESSION_SECRET=change-me-to-a-long-random-secret
SCHEDULER_TIMEZONE=Asia/Shanghai
DATABASE_PATH=backend/data/zhuwei.sqlite3

CLAUDE_CODE_INSTALL_ON_STARTUP=1
CLAUDE_CODE_REQUIRED=0
CLAUDE_CODE_COMMAND=claude

ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic
DEEPSEEK_API_KEY=
ANTHROPIC_MODEL=deepseek-v4-pro[1m]
ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash

AVD_BROWSER_HEADLESS=0
AVD_BROWSER_TIMEOUT_SECONDS=60
CNVD_PAGE_SIZE=10
CNVD_MAX_PAGES=5
```

说明：

- `SESSION_SECRET` 用于签发浏览器 session cookie，建议生产环境固定。
- `DATABASE_PATH` 是 SQLite 数据文件路径，部署时需要持久化。
- `DEEPSEEK_API_KEY` 可以放在 `.env`，也可以在前端 DeepSeek 区域保存。
- `ANTHROPIC_MODEL` 用于深度漏洞分析；`ANTHROPIC_DEFAULT_HAIKU_MODEL` 用于产品归属识别等轻量任务，默认 DeepSeek Flash。
- `CLAUDE_CODE_INSTALL_ON_STARTUP=1` 时，服务启动会检查 `claude` 命令，不存在则执行安装命令。
- `CLAUDE_CODE_REQUIRED=1` 会在 Claude Code 不可用时阻止服务启动，默认不阻止。

## 5. 启动服务

开发或本机运行：

```bash
./start.sh
```

启动成功后会输出：

```text
[烛微] login: http://127.0.0.1:8010/login
[烛微] random token: <本次启动随机 token>
```

打开登录地址，输入随机 token。

如果需要局域网访问：

```bash
HOST=0.0.0.0 PORT=8010 ./start.sh
```

建议只在可信网络或反向代理后暴露服务。

脚本参数：

- `HOST`：监听地址，默认 `127.0.0.1`。
- `PORT`：监听端口，默认 `8010`。
- `RELOAD=1`：启用 Uvicorn 热重载，适合开发调试。
- `INSTALL_PLAYWRIGHT=1`：额外安装 Playwright Chromium。
- `SKIP_DEPENDENCY_INSTALL=1`：跳过依赖检查和安装。
- `PYTHON_BIN=/path/to/python3`：指定创建虚拟环境使用的 Python。

macOS 可双击根目录 `start.command` 启动。

## 6. PostgreSQL / Redis 预迁移

当前默认仍使用 SQLite。可以先启用 PostgreSQL 和 Redis 做迁移演练，但不切换应用数据源：

```bash
DATABASE_BACKEND=sqlite
DATABASE_PATH=backend/data/zhuwei.sqlite3
DATABASE_URL=postgresql://zhuwei:zhuwei_change_me@127.0.0.1:5432/zhuwei
REDIS_URL=redis://127.0.0.1:6379/0
```

启动基础设施：

```bash
./scripts/infra_postgres_redis.sh start
```

脚本优先复用正在运行的 Docker/Podman。如果本机已准备 Colima 工具，脚本会在 `start` 时自动启动 Colima Docker 运行时；也可以手动指定：

```bash
LOCAL_TOOL_DIR=$HOME/.local/share/zhuwei-tools/bin ./scripts/infra_postgres_redis.sh start
```

如果使用 Podman：

```bash
podman machine init
podman machine start
CONTAINER_ENGINE=podman ./scripts/infra_postgres_redis.sh start
```

从 SQLite 全量迁移到 PostgreSQL 副本：

```bash
.venv/bin/python scripts/migrate_sqlite_to_postgres.py --drop-target
```

迁移报告会写入：

```text
backend/data/postgres_migration_report.json
```

确认服务当前数据源：

```bash
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/infra/status
```

只要 `active_database_backend` 仍为 `sqlite`，应用就还在读写 SQLite，PostgreSQL 只是迁移副本。

## 7. GitHub 证据源配置

GitHub Security Advisories 不需要 Token 即可拉取公开数据。GitHub Code Search 建议配置 `GITHUB_TOKEN`，否则系统只执行 Advisory 和仓库搜索，代码搜索会跳过。

```bash
GITHUB_TOKEN=<github-token>
GITHUB_EVIDENCE_AUTO_SEARCH_PER_RUN=5
GITHUB_EVIDENCE_REFRESH_HOURS=24
```

GitHub 证据只写入漏洞的证据层和 POC/EXP Tab，不会单独触发高危告警。生产环境建议按 API 配额调小 `GITHUB_EVIDENCE_AUTO_SEARCH_PER_RUN`，或在批量历史回填时临时调大。

## 8. systemd 部署示例

Linux 生产环境可以使用 systemd 托管。创建 `/etc/systemd/system/zhuwei.service`：

```ini
[Unit]
Description=烛微
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/zhuwei
EnvironmentFile=/opt/zhuwei/.env
ExecStart=/opt/zhuwei/.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8010
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zhuwei
sudo journalctl -u zhuwei -f
```

随机 token 会输出在 journal 日志中。

## 9. Nginx 反向代理示例

如果需要通过域名访问，可以在 Nginx 中反代到本地 Uvicorn：

```nginx
server {
    listen 80;
    server_name zhuwei.example.com;

    location / {
        proxy_pass http://127.0.0.1:8010;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

生产环境建议额外启用 HTTPS、访问控制或内网 VPN。

## 10. 数据持久化

需要持久化的目录：

- `backend/data/zhuwei.sqlite3`：主数据库。
- `backend/data/analysis_workspace/`：AI 分析工作目录、可能包含克隆的源码仓库。

备份示例：

```bash
mkdir -p backups
sqlite3 backend/data/zhuwei.sqlite3 ".backup backups/zhuwei_$(date +%Y%m%d_%H%M%S).sqlite3"
tar -czf backups/analysis_workspace_$(date +%Y%m%d_%H%M%S).tgz backend/data/analysis_workspace
```

## 11. 升级流程

1. 停止服务。
2. 备份 SQLite 数据库和分析工作目录。
3. 更新代码。
4. 重新安装依赖。
5. 启动服务并查看日志。
6. 使用新随机 token 登录。
7. 检查 `/api/sources/health`、DeepSeek 状态和 Claude Code 状态。
8. 如升级前已经有大量历史漏洞，可在前端产品库点击“对齐漏洞”，或调用 `POST /api/products/align-vulnerabilities` 回填产品-漏洞关系。

示例：

```bash
sudo systemctl stop zhuwei
sqlite3 backend/data/zhuwei.sqlite3 ".backup backups/pre_upgrade.sqlite3"
. .venv/bin/activate
pip install -r requirements.txt
sudo systemctl start zhuwei
sudo journalctl -u zhuwei -f
```

## 12. 安全建议

- 不要把服务直接暴露在公网。
- 固定并妥善保存 `SESSION_SECRET`。
- 定期轮换 DeepSeek API Key。
- AVD/CNVD/QVD Cookie 只保存在可信机器上。
- 给 `backend/data/` 设置合理文件权限。
- 生产环境用反向代理做 HTTPS 和访问来源限制。

## 13. 故障排查

### 登录失败

确认输入的是当前进程启动日志中的随机 token。服务重启后旧 token 不能再用。

### 页面跳回登录

浏览器 session 已失效。重新打开 `/login` 并输入最新 token。

### Claude Code 不可用

检查：

```bash
which claude
claude --version
curl -H "X-App-Token: <token>" http://127.0.0.1:8010/api/claude-code/status
```

如果需要启动时自动安装，确保 `CLAUDE_CODE_INSTALL_ON_STARTUP=1` 且 npm 可用。

### DeepSeek 分析失败

检查：

- DeepSeek API Key 是否已配置。
- 余额是否充足。
- `ANTHROPIC_BASE_URL` 是否为 `https://api.deepseek.com/anthropic`。
- 日志中是否存在鉴权、限流或超时错误。

### 数据源 429 或验证码

进入源健康中心查看错误类型。对于 429，可以等待退避重试或调大采集间隔；对于验证码和 WAF，需要刷新浏览器 Cookie 或更新会话配置。
