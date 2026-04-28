#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8010}"
APP_MODULE="${APP_MODULE:-backend.app.main:app}"
VENV_DIR="${VENV_DIR:-.venv}"
RELOAD="${RELOAD:-0}"
SKIP_DEPENDENCY_INSTALL="${SKIP_DEPENDENCY_INSTALL:-0}"
INSTALL_PLAYWRIGHT="${INSTALL_PLAYWRIGHT:-0}"
PYTHON_BIN="${PYTHON_BIN:-}"

log() {
  printf '[烛微] %s\n' "$*"
}

die() {
  printf '[烛微] ERROR: %s\n' "$*" >&2
  exit 1
}

find_python() {
  if [ -n "$PYTHON_BIN" ]; then
    command -v "$PYTHON_BIN" >/dev/null 2>&1 || die "PYTHON_BIN not found: $PYTHON_BIN"
    printf '%s\n' "$PYTHON_BIN"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "python3"
    return
  fi
  if command -v python >/dev/null 2>&1; then
    printf '%s\n' "python"
    return
  fi
  die "Python 3.11+ is required but python3/python was not found."
}

requirements_hash() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 requirements.txt | awk '{print $1}'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum requirements.txt | awk '{print $1}'
    return
  fi
  wc -c requirements.txt | awk '{print $1}'
}

PYTHON="$(find_python)"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  log "creating virtual environment: $VENV_DIR"
  "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
. "$VENV_DIR/bin/activate"

if [ "$SKIP_DEPENDENCY_INSTALL" != "1" ]; then
  if [ ! -f requirements.txt ]; then
    die "requirements.txt not found"
  fi
  CURRENT_HASH="$(requirements_hash)"
  HASH_FILE="$VENV_DIR/.requirements.sha256"
  INSTALLED_HASH=""
  if [ -f "$HASH_FILE" ]; then
    INSTALLED_HASH="$(cat "$HASH_FILE")"
  fi
  if [ "$CURRENT_HASH" != "$INSTALLED_HASH" ]; then
    log "installing Python dependencies"
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    printf '%s\n' "$CURRENT_HASH" > "$HASH_FILE"
  else
    log "Python dependencies are up to date"
  fi
else
  log "skipping dependency installation"
fi

if [ "$INSTALL_PLAYWRIGHT" = "1" ]; then
  log "installing Playwright Chromium"
  python -m playwright install chromium
fi

mkdir -p backend/data backend/data/analysis_workspace

if [ ! -f .env ] && [ -f .env.example ]; then
  log ".env not found; using application defaults. Copy .env.example to .env when you need custom settings."
fi

UVICORN_ARGS=("$APP_MODULE" "--host" "$HOST" "--port" "$PORT")
if [ "$RELOAD" = "1" ]; then
  UVICORN_ARGS+=("--reload")
fi

DISPLAY_HOST="$HOST"
if [ "$DISPLAY_HOST" = "0.0.0.0" ]; then
  DISPLAY_HOST="127.0.0.1"
fi

log "starting service: http://$DISPLAY_HOST:$PORT"
log "login page: http://$DISPLAY_HOST:$PORT/login"
log "the random login token will be printed by the backend below"
exec "$VENV_DIR/bin/python" -m uvicorn "${UVICORN_ARGS[@]}"
