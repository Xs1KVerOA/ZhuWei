from __future__ import annotations

import os
import platform
import secrets
import shlex
from pathlib import Path

from dotenv import load_dotenv


PROJECT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_DIR / ".env")
GENERATED_APP_TOKEN = secrets.token_urlsafe(24)


def _default_browser_proxy_image() -> str:
    machine = platform.machine().strip().lower()
    if machine in {"arm64", "aarch64"} or machine.startswith("arm"):
        return "seleniarm/standalone-chromium:latest"
    return "selenium/standalone-chrome:latest"


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


class Settings:
    app_token: str
    session_secret: str
    scheduler_timezone: str
    database_path: Path
    database_backend: str
    database_url: str
    redis_url: str
    queue_backend: str
    redis_queue_prefix: str
    worker_role: str
    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    minio_bucket: str
    minio_region: str
    minio_secure: bool
    source_upload_max_mb: int
    source_extract_max_files: int
    source_extract_max_mb: int
    source_extract_max_file_mb: int
    neo4j_enabled: bool
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_database: str
    frontend_dir: Path

    avd_cookie: str
    avd_user_agent: str
    avd_browser_headless: bool
    avd_browser_timeout_seconds: int
    avd_browser_executable_path: str
    cnvd_cookie: str
    cnvd_user_agent: str
    cnvd_keywords: list[str]
    cnvd_probe_keyword: str
    cnvd_page_size: int
    cnvd_max_pages: int
    browser_proxy_enabled: bool
    browser_proxy_image: str
    browser_proxy_host: str
    browser_proxy_bind_host: str
    browser_proxy_connect_host: str
    browser_proxy_connect_mode: str
    browser_proxy_ttl_seconds: int
    browser_proxy_start_timeout_seconds: int
    browser_proxy_pull_timeout_seconds: int
    browser_proxy_docker_command: str
    browser_proxy_docker_network: str
    browser_proxy_pull_image: bool

    claude_code_install_on_startup: bool
    claude_code_required: bool
    claude_code_command: str
    claude_code_install_command: list[str]
    claude_code_install_timeout_seconds: int
    anthropic_base_url: str
    anthropic_auth_token: str
    anthropic_model: str
    anthropic_default_opus_model: str
    anthropic_default_sonnet_model: str
    anthropic_default_haiku_model: str
    claude_code_subagent_model: str
    claude_code_disable_nonessential_traffic: str
    claude_code_disable_nonstreaming_fallback: str
    claude_code_effort_level: str
    vulnerability_analysis_workspace_dir: Path
    vulnerability_analysis_timeout_seconds: int
    vulnerability_analysis_max_turns: int
    vulnerability_analysis_allowed_tools: str
    vulnerability_source_retention_days: int
    deepseek_balance_url: str
    deepseek_balance_interval_minutes: int
    biu_product_max_pages: int
    biu_product_page_delay_ms: int
    biu_product_page_jitter_ms: int
    biu_product_retry_count: int
    biu_product_retry_base_seconds: int
    update_upload_max_mb: int
    update_workspace_dir: Path
    update_cli_timeout_seconds: int
    update_cli_allowed_tools: str
    update_encryption_key: str
    update_require_encryption: bool

    regular_interval_minutes: int = 30
    slow_cron_hours: str = "10,18"

    def __init__(self) -> None:
        self.app_token = GENERATED_APP_TOKEN
        self.session_secret = os.getenv("SESSION_SECRET", self.app_token)
        self.scheduler_timezone = os.getenv("SCHEDULER_TIMEZONE", "Asia/Shanghai")

        db_path = Path(os.getenv("DATABASE_PATH", "backend/data/zhuwei.sqlite3"))
        self.database_path = db_path if db_path.is_absolute() else PROJECT_DIR / db_path
        self.database_backend = os.getenv("DATABASE_BACKEND", "sqlite").strip().lower() or "sqlite"
        self.database_url = os.getenv("DATABASE_URL", "")
        self.redis_url = os.getenv("REDIS_URL", "")
        self.queue_backend = os.getenv(
            "QUEUE_BACKEND",
            "redis" if self.redis_url else "database",
        ).strip().lower() or "database"
        self.redis_queue_prefix = os.getenv("REDIS_QUEUE_PREFIX", "zhuwei")
        self.worker_role = os.getenv("WORKER_ROLE", "all")
        self.minio_endpoint = os.getenv("MINIO_ENDPOINT", "").strip()
        self.minio_access_key = os.getenv("MINIO_ACCESS_KEY", "").strip()
        self.minio_secret_key = os.getenv("MINIO_SECRET_KEY", "").strip()
        self.minio_bucket = os.getenv("MINIO_BUCKET", "source-archives").strip() or "source-archives"
        self.minio_region = os.getenv("MINIO_REGION", "us-east-1").strip() or "us-east-1"
        self.minio_secure = _bool_env("MINIO_SECURE", self.minio_endpoint.startswith("https://"))
        self.source_upload_max_mb = max(1, min(_int_env("SOURCE_UPLOAD_MAX_MB", 200), 2048))
        self.source_extract_max_files = max(1000, min(_int_env("SOURCE_EXTRACT_MAX_FILES", 20000), 200000))
        self.source_extract_max_mb = max(64, min(_int_env("SOURCE_EXTRACT_MAX_MB", 1024), 8192))
        self.source_extract_max_file_mb = max(1, min(_int_env("SOURCE_EXTRACT_MAX_FILE_MB", 25), 1024))
        self.neo4j_uri = os.getenv("NEO4J_URI", "").strip()
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j").strip() or "neo4j"
        self.neo4j_password = os.getenv("NEO4J_PASSWORD", "").strip()
        self.neo4j_database = os.getenv("NEO4J_DATABASE", "neo4j").strip() or "neo4j"
        self.neo4j_enabled = _bool_env("NEO4J_ENABLED", bool(self.neo4j_uri))
        self.frontend_dir = PROJECT_DIR / "frontend"

        self.avd_cookie = os.getenv("AVD_COOKIE", "")
        self.avd_user_agent = os.getenv(
            "AVD_USER_AGENT",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        )
        self.avd_browser_headless = _bool_env("AVD_BROWSER_HEADLESS", False)
        self.avd_browser_timeout_seconds = _int_env("AVD_BROWSER_TIMEOUT_SECONDS", 60)
        self.avd_browser_executable_path = os.getenv("AVD_BROWSER_EXECUTABLE_PATH", "")
        self.cnvd_cookie = os.getenv("CNVD_COOKIE", "")
        self.cnvd_user_agent = os.getenv(
            "CNVD_USER_AGENT",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
        )
        self.cnvd_keywords = [
            item.strip()
            for chunk in os.getenv("CNVD_KEYWORDS", "").replace("\n", ",").split(",")
            for item in [chunk]
            if item.strip()
        ]
        self.cnvd_probe_keyword = os.getenv("CNVD_PROBE_KEYWORD", "")
        self.cnvd_page_size = max(1, min(_int_env("CNVD_PAGE_SIZE", 10), 50))
        self.cnvd_max_pages = max(1, min(_int_env("CNVD_MAX_PAGES", 5), 50))
        self.browser_proxy_enabled = _bool_env("BROWSER_PROXY_ENABLED", True)
        self.browser_proxy_image = os.getenv("BROWSER_PROXY_IMAGE", "").strip() or _default_browser_proxy_image()
        self.browser_proxy_host = os.getenv("BROWSER_PROXY_HOST", "127.0.0.1").strip() or "127.0.0.1"
        self.browser_proxy_bind_host = (
            os.getenv("BROWSER_PROXY_BIND_HOST", "").strip() or self.browser_proxy_host
        )
        self.browser_proxy_connect_host = (
            os.getenv("BROWSER_PROXY_CONNECT_HOST", "").strip() or self.browser_proxy_host
        )
        self.browser_proxy_connect_mode = (
            os.getenv("BROWSER_PROXY_CONNECT_MODE", "published").strip().lower() or "published"
        )
        if self.browser_proxy_connect_mode not in {"published", "container"}:
            self.browser_proxy_connect_mode = "published"
        self.browser_proxy_ttl_seconds = max(300, _int_env("BROWSER_PROXY_TTL_SECONDS", 3600))
        self.browser_proxy_start_timeout_seconds = max(
            10,
            _int_env("BROWSER_PROXY_START_TIMEOUT_SECONDS", 60),
        )
        self.browser_proxy_pull_timeout_seconds = max(
            60,
            _int_env("BROWSER_PROXY_PULL_TIMEOUT_SECONDS", 600),
        )
        self.browser_proxy_docker_command = os.getenv("BROWSER_PROXY_DOCKER_COMMAND", "docker").strip() or "docker"
        self.browser_proxy_docker_network = os.getenv("BROWSER_PROXY_DOCKER_NETWORK", "").strip()
        self.browser_proxy_pull_image = _bool_env("BROWSER_PROXY_PULL_IMAGE", False)

        self.claude_code_install_on_startup = _bool_env("CLAUDE_CODE_INSTALL_ON_STARTUP", True)
        self.claude_code_required = _bool_env("CLAUDE_CODE_REQUIRED", False)
        self.claude_code_command = os.getenv("CLAUDE_CODE_COMMAND", "claude")
        install_command = os.getenv(
            "CLAUDE_CODE_INSTALL_COMMAND",
            "npm install -g @anthropic-ai/claude-code",
        )
        self.claude_code_install_command = shlex.split(install_command)
        self.claude_code_install_timeout_seconds = _int_env("CLAUDE_CODE_INSTALL_TIMEOUT_SECONDS", 300)

        deepseek_api_key = os.getenv("DEEPSEEK_API_KEY", "")
        self.anthropic_base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.deepseek.com/anthropic")
        self.anthropic_auth_token = os.getenv("ANTHROPIC_AUTH_TOKEN") or deepseek_api_key
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "deepseek-v4-pro[1m]")
        self.anthropic_default_opus_model = os.getenv("ANTHROPIC_DEFAULT_OPUS_MODEL", "deepseek-v4-pro")
        self.anthropic_default_sonnet_model = os.getenv("ANTHROPIC_DEFAULT_SONNET_MODEL", "deepseek-v4-pro")
        self.anthropic_default_haiku_model = os.getenv("ANTHROPIC_DEFAULT_HAIKU_MODEL", "deepseek-v4-flash")
        self.claude_code_subagent_model = os.getenv("CLAUDE_CODE_SUBAGENT_MODEL", "deepseek-v4-pro")
        self.claude_code_disable_nonessential_traffic = os.getenv(
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"
        )
        self.claude_code_disable_nonstreaming_fallback = os.getenv(
            "CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK", "1"
        )
        self.claude_code_effort_level = os.getenv("CLAUDE_CODE_EFFORT_LEVEL", "max")
        workspace_dir = Path(
            os.getenv(
                "VULN_ANALYSIS_WORKSPACE_DIR",
                "backend/data/analysis_workspace",
            )
        )
        self.vulnerability_analysis_workspace_dir = (
            workspace_dir if workspace_dir.is_absolute() else PROJECT_DIR / workspace_dir
        )
        self.vulnerability_analysis_timeout_seconds = _int_env(
            "VULN_ANALYSIS_TIMEOUT_SECONDS", 1800
        )
        self.vulnerability_analysis_max_turns = _int_env("VULN_ANALYSIS_MAX_TURNS", 8)
        self.vulnerability_source_retention_days = max(
            1,
            _int_env("VULN_SOURCE_RETENTION_DAYS", 14),
        )
        self.vulnerability_analysis_allowed_tools = os.getenv(
            "VULN_ANALYSIS_ALLOWED_TOOLS",
            ",".join(
                [
                    "WebSearch",
                    "WebFetch",
                    "Read",
                    "Bash(git clone:*)",
                    "Bash(git ls-remote:*)",
                    "Bash(curl:*)",
                    "Bash(npm view:*)",
                    "Bash(npm pack:*)",
                    "Bash(python -m pip download:*)",
                    "Bash(python3 -m pip download:*)",
                    "Bash(tar:*)",
                    "Bash(unzip:*)",
                    "Bash(mkdir:*)",
                    "Bash(rg:*)",
                    "Bash(grep:*)",
                    "Bash(find:*)",
                    "Bash(ls:*)",
                    "Bash(pwd:*)",
                    "Bash(sed:*)",
                    "Bash(head:*)",
                    "Bash(tail:*)",
                    "Bash(cat:*)",
                ]
            ),
        )
        self.deepseek_balance_url = os.getenv(
            "DEEPSEEK_BALANCE_URL",
            "https://api.deepseek.com/user/balance",
        )
        self.deepseek_balance_interval_minutes = _int_env("DEEPSEEK_BALANCE_INTERVAL_MINUTES", 30)
        self.biu_product_max_pages = max(0, _int_env("BIU_PRODUCT_MAX_PAGES", 0))
        self.biu_product_page_delay_ms = max(0, _int_env("BIU_PRODUCT_PAGE_DELAY_MS", 8000))
        self.biu_product_page_jitter_ms = max(0, _int_env("BIU_PRODUCT_PAGE_JITTER_MS", 4000))
        self.biu_product_retry_count = max(0, _int_env("BIU_PRODUCT_RETRY_COUNT", 8))
        self.biu_product_retry_base_seconds = max(1, _int_env("BIU_PRODUCT_RETRY_BASE_SECONDS", 30))
        self.update_upload_max_mb = max(1, min(_int_env("UPDATE_UPLOAD_MAX_MB", 200), 2048))
        update_dir = Path(os.getenv("UPDATE_WORKSPACE_DIR", "backend/data/updates"))
        self.update_workspace_dir = update_dir if update_dir.is_absolute() else PROJECT_DIR / update_dir
        self.update_cli_timeout_seconds = max(60, _int_env("UPDATE_CLI_TIMEOUT_SECONDS", 900))
        self.update_encryption_key = os.getenv("UPDATE_ENCRYPTION_KEY", "").strip()
        self.update_require_encryption = _bool_env("UPDATE_REQUIRE_ENCRYPTION", bool(self.update_encryption_key))
        self.update_cli_allowed_tools = os.getenv(
            "UPDATE_CLI_ALLOWED_TOOLS",
            ",".join(
                [
                    "Read",
                    "Write",
                    "Edit",
                    "MultiEdit",
                    "Glob",
                    "Grep",
                    "Bash(pwd:*)",
                    "Bash(ls:*)",
                    "Bash(find:*)",
                    "Bash(rg:*)",
                    "Bash(grep:*)",
                    "Bash(sed:*)",
                    "Bash(head:*)",
                    "Bash(tail:*)",
                    "Bash(cat:*)",
                    "Bash(file:*)",
                    "Bash(mkdir:*)",
                    "Bash(git status:*)",
                    "Bash(git diff:*)",
                    "Bash(python -m compileall:*)",
                    "Bash(node --check:*)",
                ]
            ),
        )

    def claude_code_env(self) -> dict[str, str]:
        return {
            "ANTHROPIC_BASE_URL": self.anthropic_base_url,
            "ANTHROPIC_AUTH_TOKEN": self.anthropic_auth_token,
            "ANTHROPIC_MODEL": self.anthropic_model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": self.anthropic_default_opus_model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": self.anthropic_default_sonnet_model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.anthropic_default_haiku_model,
            "CLAUDE_CODE_SUBAGENT_MODEL": self.claude_code_subagent_model,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": self.claude_code_disable_nonessential_traffic,
            "CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK": self.claude_code_disable_nonstreaming_fallback,
            "CLAUDE_CODE_EFFORT_LEVEL": self.claude_code_effort_level,
        }


settings = Settings()
