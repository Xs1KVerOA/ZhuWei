#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LOCAL_TOOL_DIR="${LOCAL_TOOL_DIR:-$HOME/.local/share/zhuwei-tools/bin}"
if [ -d "$LOCAL_TOOL_DIR" ]; then
  PATH="$LOCAL_TOOL_DIR:$PATH"
fi
if [ -d "/usr/local/Cellar/docker/28.1.0/bin" ]; then
  PATH="/usr/local/Cellar/docker/28.1.0/bin:$PATH"
fi
export PATH

ENGINE="${CONTAINER_ENGINE:-}"
INFRA_MODE="${INFRA_MODE:-auto}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-zhuwei-postgres}"
REDIS_CONTAINER="${REDIS_CONTAINER:-zhuwei-redis}"
MINIO_CONTAINER="${MINIO_CONTAINER:-zhuwei-minio}"
NEO4J_CONTAINER="${NEO4J_CONTAINER:-zhuwei-neo4j}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:16-alpine}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
MINIO_IMAGE="${MINIO_IMAGE:-minio/minio:latest}"
NEO4J_IMAGE="${NEO4J_IMAGE:-neo4j:5-community}"
POSTGRES_DB="${POSTGRES_DB:-zhuwei}"
POSTGRES_USER="${POSTGRES_USER:-zhuwei}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-zhuwei_change_me}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
REDIS_PORT="${REDIS_PORT:-6379}"
MINIO_PORT="${MINIO_PORT:-9000}"
MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-9001}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-minioadmin}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-minioadmin_change_me}"
NEO4J_HTTP_PORT="${NEO4J_HTTP_PORT:-7474}"
NEO4J_BOLT_PORT="${NEO4J_BOLT_PORT:-7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-zhuwei_neo4j_change_me}"
INFRA_BIND="${INFRA_BIND:-127.0.0.1}"

log() {
  printf '[infra] %s\n' "$*"
}

brew_bin() {
  command -v brew >/dev/null 2>&1 || return 1
  brew --prefix "$1" >/dev/null 2>&1 || return 1
  printf '%s/bin/%s\n' "$(brew --prefix "$1")" "$2"
}

psql_bin() {
  if command -v psql >/dev/null 2>&1; then
    command -v psql
    return
  fi
  brew_bin postgresql@16 psql
}

redis_cli_bin() {
  if command -v redis-cli >/dev/null 2>&1; then
    command -v redis-cli
    return
  fi
  brew_bin redis redis-cli
}

maybe_start_colima() {
  local action="${1:-start}"
  local colima_bin="${COLIMA_BIN:-}"
  if [ -z "$colima_bin" ] && command -v colima >/dev/null 2>&1; then
    colima_bin="$(command -v colima)"
  fi
  if [ -z "$colima_bin" ] && [ -x "$LOCAL_TOOL_DIR/colima" ]; then
    colima_bin="$LOCAL_TOOL_DIR/colima"
  fi
  if [ -z "$colima_bin" ] || [ "$action" != "start" ]; then
    return 1
  fi
  command -v docker >/dev/null 2>&1 || return 1
  printf '[infra] starting Colima Docker runtime\n' >&2
  "$colima_bin" start --arch aarch64 --vm-type vz --cpus 2 --memory 2 --disk 20 --runtime docker >&2
  docker info >/dev/null 2>&1
}

detect_runtime() {
  local action="${1:-start}"
  if [ "$INFRA_MODE" = "brew" ]; then
    printf '%s\n' brew
    return
  fi
  if [ "$INFRA_MODE" != "auto" ] && [ "$INFRA_MODE" != "container" ]; then
    log "unknown INFRA_MODE: $INFRA_MODE"
    exit 1
  fi
  if [ -n "$ENGINE" ]; then
    command -v "$ENGINE" >/dev/null 2>&1 || {
      log "container engine not found: $ENGINE"
      exit 1
    }
    printf '%s\n' "$ENGINE"
    return
  fi
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    printf '%s\n' docker
    return
  fi
  if command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
    printf '%s\n' podman
    return
  fi
  if maybe_start_colima "$action"; then
    printf '%s\n' docker
    return
  fi
  if [ "$INFRA_MODE" = "container" ]; then
    log "no running Docker/Podman engine found"
    log "start Docker Desktop or run: podman machine init && podman machine start"
    exit 1
  fi
  if brew_bin postgresql@16 psql >/dev/null 2>&1 && brew_bin redis redis-cli >/dev/null 2>&1; then
    printf '%s\n' brew
    return
  fi
  log "no running Docker/Podman engine found and Homebrew PostgreSQL/Redis are not installed"
  log "install locally with: brew install postgresql@16 redis"
  exit 1
}

container_exists() {
  "$1" container inspect "$2" >/dev/null 2>&1
}

container_running() {
  [ "$("$1" inspect -f '{{.State.Running}}' "$2" 2>/dev/null || true)" = "true" ]
}

start_postgres() {
  local engine="$1"
  if container_exists "$engine" "$POSTGRES_CONTAINER"; then
    if container_running "$engine" "$POSTGRES_CONTAINER"; then
      log "PostgreSQL already running: $POSTGRES_CONTAINER"
    else
      log "starting PostgreSQL container: $POSTGRES_CONTAINER"
      "$engine" start "$POSTGRES_CONTAINER" >/dev/null
    fi
    return
  fi
  log "creating PostgreSQL container: $POSTGRES_CONTAINER"
  "$engine" run -d \
    --name "$POSTGRES_CONTAINER" \
    --restart unless-stopped \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -p "${INFRA_BIND}:$POSTGRES_PORT:5432" \
    -v zhuwei_postgres_data:/var/lib/postgresql/data \
    "$POSTGRES_IMAGE" >/dev/null
}

start_redis() {
  local engine="$1"
  if container_exists "$engine" "$REDIS_CONTAINER"; then
    if container_running "$engine" "$REDIS_CONTAINER"; then
      log "Redis already running: $REDIS_CONTAINER"
    else
      log "starting Redis container: $REDIS_CONTAINER"
      "$engine" start "$REDIS_CONTAINER" >/dev/null
    fi
    return
  fi
  log "creating Redis container: $REDIS_CONTAINER"
  "$engine" run -d \
    --name "$REDIS_CONTAINER" \
    --restart unless-stopped \
    -p "${INFRA_BIND}:$REDIS_PORT:6379" \
    -v zhuwei_redis_data:/data \
    "$REDIS_IMAGE" \
    redis-server --appendonly yes >/dev/null
}

start_minio() {
  local engine="$1"
  if container_exists "$engine" "$MINIO_CONTAINER"; then
    if container_running "$engine" "$MINIO_CONTAINER"; then
      log "MinIO already running: $MINIO_CONTAINER"
    else
      log "starting MinIO container: $MINIO_CONTAINER"
      "$engine" start "$MINIO_CONTAINER" >/dev/null
    fi
    return
  fi
  log "creating MinIO container: $MINIO_CONTAINER"
  "$engine" run -d \
    --name "$MINIO_CONTAINER" \
    --restart unless-stopped \
    -e MINIO_ROOT_USER="$MINIO_ROOT_USER" \
    -e MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" \
    -p "${INFRA_BIND}:$MINIO_PORT:9000" \
    -p "${INFRA_BIND}:$MINIO_CONSOLE_PORT:9001" \
    -v zhuwei_minio_data:/data \
    "$MINIO_IMAGE" \
    server /data --console-address ":9001" >/dev/null
}

start_neo4j() {
  local engine="$1"
  if container_exists "$engine" "$NEO4J_CONTAINER"; then
    if container_running "$engine" "$NEO4J_CONTAINER"; then
      log "Neo4j already running: $NEO4J_CONTAINER"
    else
      log "starting Neo4j container: $NEO4J_CONTAINER"
      "$engine" start "$NEO4J_CONTAINER" >/dev/null
    fi
    return
  fi
  log "creating Neo4j container: $NEO4J_CONTAINER"
  "$engine" run -d \
    --name "$NEO4J_CONTAINER" \
    --restart unless-stopped \
    -e NEO4J_AUTH="${NEO4J_USER}/${NEO4J_PASSWORD}" \
    -e NEO4J_server_memory_heap_initial__size="${NEO4J_HEAP_INITIAL:-384m}" \
    -e NEO4J_server_memory_heap_max__size="${NEO4J_HEAP_MAX:-384m}" \
    -e NEO4J_server_memory_pagecache_size="${NEO4J_PAGECACHE:-256m}" \
    -e NEO4J_server_jvm_additional="-XX:+ExitOnOutOfMemoryError" \
    -p "${INFRA_BIND}:$NEO4J_HTTP_PORT:7474" \
    -p "${INFRA_BIND}:$NEO4J_BOLT_PORT:7687" \
    -v zhuwei_neo4j_data:/data \
    -v zhuwei_neo4j_logs:/logs \
    "$NEO4J_IMAGE" >/dev/null
}

wait_postgres() {
  local engine="$1"
  log "waiting for PostgreSQL"
  for _ in $(seq 1 60); do
    if "$engine" exec "$POSTGRES_CONTAINER" pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
      log "PostgreSQL ready"
      return
    fi
    sleep 1
  done
  log "PostgreSQL did not become ready in time"
  exit 1
}

wait_redis() {
  local engine="$1"
  log "waiting for Redis"
  for _ in $(seq 1 60); do
    if "$engine" exec "$REDIS_CONTAINER" redis-cli ping >/dev/null 2>&1; then
      log "Redis ready"
      return
    fi
    sleep 1
  done
  log "Redis did not become ready in time"
  exit 1
}

wait_minio() {
  log "waiting for MinIO"
  if ! command -v curl >/dev/null 2>&1; then
    sleep 2
    log "MinIO started (curl unavailable, skipped health probe)"
    return
  fi
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${MINIO_PORT}/minio/health/live" >/dev/null 2>&1; then
      log "MinIO ready"
      return
    fi
    sleep 1
  done
  log "MinIO did not become ready in time"
  exit 1
}

wait_neo4j() {
  local engine="$1"
  log "waiting for Neo4j"
  for _ in $(seq 1 90); do
    if "$engine" exec "$NEO4J_CONTAINER" cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" "RETURN 1" >/dev/null 2>&1; then
      log "Neo4j ready"
      return
    fi
    sleep 1
  done
  log "Neo4j did not become ready in time"
  exit 1
}

status() {
  local engine="$1"
  "$engine" ps --filter "name=$POSTGRES_CONTAINER" --filter "name=$REDIS_CONTAINER" --filter "name=$MINIO_CONTAINER" --filter "name=$NEO4J_CONTAINER"
}

start_brew_postgres() {
  log "starting PostgreSQL via Homebrew"
  brew services start postgresql@16 >/dev/null
}

start_brew_redis() {
  log "starting Redis via Homebrew"
  brew services start redis >/dev/null
}

wait_brew_postgres_admin() {
  local psql
  psql="$(psql_bin)"
  log "waiting for local PostgreSQL admin connection"
  for _ in $(seq 1 60); do
    if "$psql" -d postgres -Atqc "SELECT 1" >/dev/null 2>&1; then
      log "local PostgreSQL admin connection ready"
      return
    fi
    sleep 1
  done
  log "PostgreSQL admin connection did not become ready in time"
  exit 1
}

ensure_brew_postgres_database() {
  local psql
  psql="$(psql_bin)"
  log "ensuring PostgreSQL role/database: ${POSTGRES_USER}/${POSTGRES_DB}"
  "$psql" -d postgres -v ON_ERROR_STOP=1 \
    -v db="$POSTGRES_DB" \
    -v user="$POSTGRES_USER" \
    -v password="$POSTGRES_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'user', :'password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'user')\gexec
ALTER ROLE :"user" WITH PASSWORD :'password';
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'user')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db')\gexec
GRANT ALL PRIVILEGES ON DATABASE :"db" TO :"user";
SQL
}

wait_brew_postgres() {
  local psql
  psql="$(psql_bin)"
  log "waiting for PostgreSQL"
  for _ in $(seq 1 60); do
    if PGPASSWORD="$POSTGRES_PASSWORD" "$psql" -h 127.0.0.1 -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT 1" >/dev/null 2>&1; then
      log "PostgreSQL ready"
      return
    fi
    sleep 1
  done
  log "PostgreSQL did not become ready in time"
  exit 1
}

wait_brew_redis() {
  local redis_cli
  redis_cli="$(redis_cli_bin)"
  log "waiting for Redis"
  for _ in $(seq 1 60); do
    if "$redis_cli" -h 127.0.0.1 -p "$REDIS_PORT" ping >/dev/null 2>&1; then
      log "Redis ready"
      return
    fi
    sleep 1
  done
  log "Redis did not become ready in time"
  exit 1
}

status_brew() {
  printf 'PostgreSQL: '
  if PGPASSWORD="$POSTGRES_PASSWORD" "$(psql_bin)" -h 127.0.0.1 -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT version()" >/dev/null 2>&1; then
    printf 'ready at 127.0.0.1:%s database=%s user=%s\n' "$POSTGRES_PORT" "$POSTGRES_DB" "$POSTGRES_USER"
  else
    printf 'not ready\n'
  fi
  printf 'Redis: '
  if "$(redis_cli_bin)" -h 127.0.0.1 -p "$REDIS_PORT" ping >/dev/null 2>&1; then
    printf 'ready at 127.0.0.1:%s\n' "$REDIS_PORT"
  else
    printf 'not ready\n'
  fi
  printf 'MinIO: not managed by Homebrew mode; use INFRA_MODE=container %s start\n' "$0"
  printf 'Neo4j: not managed by Homebrew mode; use INFRA_MODE=container %s start\n' "$0"
  brew services list | awk 'NR == 1 || $1 == "postgresql@16" || $1 == "redis"'
}

case "${1:-start}" in
  start)
    runtime="$(detect_runtime start)"
    if [ "$runtime" = "brew" ]; then
      start_brew_postgres
      start_brew_redis
      wait_brew_postgres_admin
      ensure_brew_postgres_database
      wait_brew_postgres
      wait_brew_redis
      status_brew
    else
      start_postgres "$runtime"
      start_redis "$runtime"
      start_minio "$runtime"
      start_neo4j "$runtime"
      wait_postgres "$runtime"
      wait_redis "$runtime"
      wait_minio "$runtime"
      wait_neo4j "$runtime"
      status "$runtime"
    fi
    ;;
  status)
    runtime="$(detect_runtime status)"
    if [ "$runtime" = "brew" ]; then
      status_brew
    else
      status "$runtime"
    fi
    ;;
  stop)
    runtime="$(detect_runtime stop)"
    if [ "$runtime" = "brew" ]; then
      brew services stop redis >/dev/null 2>&1 || true
      brew services stop postgresql@16 >/dev/null 2>&1 || true
    else
      "$runtime" stop "$POSTGRES_CONTAINER" "$REDIS_CONTAINER" "$MINIO_CONTAINER" "$NEO4J_CONTAINER" >/dev/null 2>&1 || true
    fi
    ;;
  *)
    echo "usage: $0 {start|status|stop}" >&2
    exit 2
    ;;
esac
