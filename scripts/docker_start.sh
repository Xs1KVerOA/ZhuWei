#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-up}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "$ACTION" in
  infra)
    COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.infra.yml}"
    ;;
  *)
    COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"
    ;;
esac

ENV_FILE="${ENV_FILE:-.env.docker}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-zhuwei}"
BUILD=1
WAIT=1
EXTRA_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  ./scripts/docker_start.sh [command] [options] [compose args...]

Commands:
  up        Build and start the full Docker deployment. This is the default.
  infra     Start only PostgreSQL, Redis, MinIO and Neo4j.
  build     Build the app image.
  pull      Pull service images.
  restart   Restart services.
  down      Stop and remove containers.
  ps        Show compose service status.
  logs      Follow app logs by default.
  token     Print recent login token lines from app logs.
  doctor    Validate Docker, env file and compose config.
  init-env  Create .env.docker from .env.docker.example and exit.

Options for up/infra:
  --no-build  Start without building the app image.
  --no-wait   Do not wait for the app login endpoint.

Environment:
  ENV_FILE=.env.docker
  COMPOSE_FILE=docker-compose.yml
  COMPOSE_PROJECT_NAME=zhuwei
  ALLOW_INSECURE_DEFAULTS=1   Allow placeholder passwords for local tests only.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --no-build)
      BUILD=0
      ;;
    --no-wait)
      WAIT=0
      ;;
    *)
      EXTRA_ARGS+=("$1")
      ;;
  esac
  shift
done

cd "$ROOT_DIR"

fail() {
  echo "[docker-start] ERROR: $*" >&2
  exit 1
}

info() {
  echo "[docker-start] $*"
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" -p "$PROJECT_NAME" "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" -p "$PROJECT_NAME" "$@"
  else
    fail "Docker Compose is not installed. Install the Docker Compose plugin or docker-compose v1."
  fi
}

env_value() {
  local key="$1"
  awk -F= -v key="$key" '
    $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^"|"$/, "", value)
      gsub(/^'\''|'\''$/, "", value)
      print value
    }
  ' "$ENV_FILE" | tail -n 1
}

ensure_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    cp .env.docker.example "$ENV_FILE"
    chmod 600 "$ENV_FILE" || true
    cat <<EOF
[docker-start] Created $ENV_FILE from .env.docker.example.
[docker-start] Edit it before starting:
  - SESSION_SECRET
  - POSTGRES_PASSWORD / MINIO_ROOT_PASSWORD / NEO4J_PASSWORD
  - DEEPSEEK_API_KEY or ANTHROPIC_AUTH_TOKEN
  - APP_BIND / APP_PORT for your exposure model

Then run:
  ./scripts/docker_start.sh up
EOF
    exit 2
  fi
}

check_docker() {
  command -v docker >/dev/null 2>&1 || fail "docker command not found."
  docker info >/dev/null 2>&1 || fail "Docker daemon is not reachable."
}

validate_env() {
  local insecure=()
  [[ "$(env_value SESSION_SECRET)" == "change-me-to-a-different-long-random-secret" ]] && insecure+=("SESSION_SECRET")
  [[ "$(env_value POSTGRES_PASSWORD)" == "zhuwei_change_me" ]] && insecure+=("POSTGRES_PASSWORD")
  [[ "$(env_value MINIO_ROOT_PASSWORD)" == "minioadmin_change_me" ]] && insecure+=("MINIO_ROOT_PASSWORD")
  [[ "$(env_value NEO4J_PASSWORD)" == "zhuwei_neo4j_change_me" ]] && insecure+=("NEO4J_PASSWORD")

  if [[ ${#insecure[@]} -gt 0 && "${ALLOW_INSECURE_DEFAULTS:-0}" != "1" ]]; then
    printf '[docker-start] Refusing to start with placeholder values: %s\n' "${insecure[*]}" >&2
    echo "[docker-start] Edit $ENV_FILE, or set ALLOW_INSECURE_DEFAULTS=1 for disposable local tests." >&2
    exit 1
  fi

  if [[ -z "$(env_value DEEPSEEK_API_KEY)" && -z "$(env_value ANTHROPIC_AUTH_TOKEN)" ]]; then
    info "Model API key is empty; the app can start, but deep analysis will be unavailable until configured."
  fi

  if [[ "$(env_value APP_BIND)" == "0.0.0.0" ]]; then
    info "APP_BIND=0.0.0.0 exposes the app on all interfaces. Put it behind HTTPS/reverse proxy in production."
  fi
}

memory_hint() {
  local bytes
  bytes="$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)"
  if [[ "$bytes" =~ ^[0-9]+$ && "$bytes" -gt 0 && "$bytes" -lt 3221225472 ]]; then
    info "Docker memory is below 3 GiB. Current Neo4j defaults are conservative; increase Docker memory for larger graphs."
  fi
}

wait_for_app() {
  local bind port url i
  bind="$(env_value APP_BIND)"
  port="$(env_value APP_PORT)"
  [[ -z "$port" ]] && port=8010
  if [[ "$bind" == "0.0.0.0" || -z "$bind" ]]; then
    url="http://127.0.0.1:${port}/login"
  else
    url="http://${bind}:${port}/login"
  fi

  info "Waiting for app: $url"
  for i in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      info "App is reachable: $url"
      return 0
    fi
    sleep 2
  done
  info "App did not become reachable within 120 seconds. Check: ./scripts/docker_start.sh logs"
}

print_summary() {
  local bind port url
  bind="$(env_value APP_BIND)"
  port="$(env_value APP_PORT)"
  [[ -z "$port" ]] && port=8010
  if [[ "$bind" == "0.0.0.0" || -z "$bind" ]]; then
    url="http://<server-ip>:${port}"
  else
    url="http://${bind}:${port}"
  fi
  cat <<EOF

[docker-start] Deployment command finished.
[docker-start] App URL: $url
[docker-start] Local check URL: http://127.0.0.1:${port}/login
[docker-start] Recent token lines:
EOF
  compose logs --no-color app 2>/dev/null | grep -E 'random token|Random login token' | tail -n 5 || true
}

case "$ACTION" in
  -h|--help|help)
    usage
    exit 0
    ;;
esac

check_docker

case "$ACTION" in
  init-env)
    if [[ -f "$ENV_FILE" ]]; then
      info "$ENV_FILE already exists."
      exit 0
    fi
    ensure_env
    ;;
  up|start)
    ensure_env
    validate_env
    memory_hint
    if [[ "$BUILD" == "1" ]]; then
      compose up -d --build "${EXTRA_ARGS[@]}"
    else
      compose up -d "${EXTRA_ARGS[@]}"
    fi
    [[ "$WAIT" == "1" ]] && wait_for_app
    print_summary
    ;;
  infra)
    ensure_env
    validate_env
    memory_hint
    compose up -d "${EXTRA_ARGS[@]}" postgres redis minio neo4j
    info "Infrastructure services started with $COMPOSE_FILE."
    ;;
  build)
    ensure_env
    compose build "${EXTRA_ARGS[@]}"
    ;;
  pull)
    ensure_env
    compose pull "${EXTRA_ARGS[@]}"
    ;;
  restart)
    ensure_env
    compose restart "${EXTRA_ARGS[@]}"
    ;;
  down)
    ensure_env
    compose down "${EXTRA_ARGS[@]}"
    ;;
  ps)
    ensure_env
    compose ps "${EXTRA_ARGS[@]}"
    ;;
  logs)
    ensure_env
    if [[ ${#EXTRA_ARGS[@]} -eq 0 ]]; then
      compose logs -f app
    else
      compose logs "${EXTRA_ARGS[@]}"
    fi
    ;;
  token)
    ensure_env
    compose logs --no-color app 2>/dev/null | grep -E 'random token|Random login token' | tail -n 10 || true
    ;;
  doctor)
    ensure_env
    validate_env
    memory_hint
    info "Docker: $(docker --version)"
    if docker compose version >/dev/null 2>&1; then
      info "Compose: $(docker compose version)"
    elif command -v docker-compose >/dev/null 2>&1; then
      info "Compose: $(docker-compose --version)"
    fi
    compose config >/dev/null
    info "Compose config is valid: $COMPOSE_FILE"
    ;;
  *)
    usage
    fail "Unknown command: $ACTION"
    ;;
esac
