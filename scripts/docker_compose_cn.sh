#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-.env.docker}"

cd "$ROOT_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  cp .env.docker.example "$ENV_FILE"
  echo "已生成 $ENV_FILE，请先修改其中的密码、SESSION_SECRET 和 DEEPSEEK_API_KEY 后再启动。"
  exit 1
fi

export APP_ENV_FILE="${APP_ENV_FILE:-$ENV_FILE}"

if docker compose version >/dev/null 2>&1; then
  exec docker compose --env-file "$ENV_FILE" "$@"
fi

if command -v docker-compose >/dev/null 2>&1; then
  exec docker-compose --env-file "$ENV_FILE" "$@"
fi

echo "未找到 Docker Compose。请安装 Docker Compose Plugin，或安装 docker-compose。"
exit 1
