# Docker Compose 国内源部署指南

本文档面向 Linux 云服务器部署，包含应用服务、PostgreSQL、Redis、MinIO、Neo4j 和容器化浏览器代理。

## 1. 准备 Docker 镜像加速

先安装 Docker Engine 与 Docker Compose Plugin，然后配置 Docker Hub 镜像加速。可参考本项目示例：

```bash
sudo mkdir -p /etc/docker
sudo cp deploy/docker/daemon.json.example /etc/docker/daemon.json
sudo systemctl daemon-reload
sudo systemctl restart docker
```

`deploy/docker/daemon.json.example` 默认使用 DaoCloud 公益镜像。若云厂商提供专属镜像源，建议替换为云厂商地址。

## 2. 初始化环境变量

```bash
cp .env.docker.example .env.docker
vim .env.docker
```

至少修改以下字段：

- `SESSION_SECRET`：改成随机长字符串。
- `POSTGRES_PASSWORD`、`MINIO_ROOT_PASSWORD`、`NEO4J_PASSWORD`：改成强密码。
- `DEEPSEEK_API_KEY` 或 `ANTHROPIC_AUTH_TOKEN`：填入自己的模型 API Key。
- `APP_BIND`：公网部署可以保留 `0.0.0.0`，仅本机访问可改为 `127.0.0.1`。

示例文件不会包含真实 API Key，`.env.docker` 已被 `.gitignore` 和 `.dockerignore` 排除。

## 3. 构建并启动

推荐使用封装脚本：

```bash
./scripts/docker_start.sh up
```

启动脚本会自动检查 `.env.docker`、Docker Compose、模板弱密码和小内存 Neo4j 风险。也可以直接执行：

```bash
docker compose --env-file .env.docker build
docker compose --env-file .env.docker up -d
```

查看登录 token：

```bash
docker compose --env-file .env.docker logs -f app
```

应用默认访问地址：

```text
http://服务器IP:8010
```

数据源会在应用启动后自动调度：regular 默认每 30 分钟，slow 默认每天 10:00 和 18:00。页面上的“运行”按钮只是立即补跑一次。AVD、CNVD 等浏览器型源依赖 Playwright Chromium 和站点 Cookie，Docker 镜像会预装 Chromium；如果旧镜像出现 `BrowserType.launch: Executable doesn't exist`，请重新执行 `./scripts/docker_start.sh up` 构建并启动。

## 4. 国内源说明

应用镜像构建时默认使用：

- APT：清华 Debian 镜像
- pip：清华 PyPI 镜像
- npm：npmmirror
- Docker Hub：由 `/etc/docker/daemon.json` 的 `registry-mirrors` 接管

如需替换，修改 `.env.docker` 中的 `APT_MIRROR`、`DEBIAN_SECURITY_MIRROR`、`PIP_INDEX_URL`、`NPM_REGISTRY`。

## 5. 容器化浏览器代理

CNVD 等需要浏览器验证的数据源会通过 `/proxy/browse` 打开临时 Chrome/Chromium 容器。Compose 部署中默认：

- 应用容器挂载 `/var/run/docker.sock`。
- 临时浏览器容器加入 `zhuwei-net` 网络。
- noVNC 和 WebDriver 只在容器网络内访问，不额外暴露公网端口。
- `BROWSER_PROXY_IMAGE` 留空时，后端按 CPU 架构自动选择镜像；ARM 服务器会优先使用 `seleniarm/standalone-chromium:latest`。

注意：挂载 Docker socket 便于后端按需创建临时浏览器容器，但它等价于给应用容器较高的主机容器管理权限。生产环境建议只在可信服务器部署，并通过防火墙或反向代理限制后台访问。

如果服务器无法拉取 Selenium 镜像，先确认 Docker daemon 镜像加速是否生效，或在 `.env.docker` 中指定可访问的私有镜像地址。

## 6. 旧 SQLite 数据迁移

新部署可以跳过本节。若需要把已有 `backend/data/zhuwei.sqlite3` 迁移到 Compose 内的 PostgreSQL：

```bash
docker compose --env-file .env.docker up -d postgres redis minio neo4j
docker compose --env-file .env.docker run --rm \
  -v "$PWD/backend/data:/host-data:ro" \
  app python scripts/migrate_sqlite_to_postgres.py \
  --sqlite /host-data/zhuwei.sqlite3 \
  --drop-target
```

迁移完成后再启动应用：

```bash
docker compose --env-file .env.docker up -d
```

## 7. 常用运维命令

```bash
./scripts/docker_start.sh ps
./scripts/docker_start.sh logs
./scripts/docker_start.sh restart app
./scripts/docker_start.sh down
```

数据库与中间件端口默认只绑定 `127.0.0.1`，避免直接暴露到公网。生产环境建议在应用前面加 Nginx/Caddy，并启用 HTTPS。

完整部署细节见 [Docker 部署文档](docker-deployment.md)。
