from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default, cast=float):
    return field(default_factory=lambda: cast(os.environ.get(name, default)))


@dataclass
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/relay"
        )
    )
    api_token: str = field(default_factory=lambda: os.environ.get("RELAY_API_TOKEN", "dev-token"))
    # Delivery
    max_attempts: int = _env("RELAY_MAX_ATTEMPTS", 8, int)
    backoff_base: float = _env("RELAY_BACKOFF_BASE", 2.0)  # seconds, doubles each attempt
    backoff_cap: float = _env("RELAY_BACKOFF_CAP", 3600.0)
    request_timeout: float = _env("RELAY_REQUEST_TIMEOUT", 10.0)  # whole request, not per read
    max_response_bytes: int = 65536
    max_redirects: int = 3
    # Workers
    lease_seconds: float = _env("RELAY_LEASE_SECONDS", 30.0)
    poll_interval: float = _env("RELAY_POLL_INTERVAL", 0.5)
    batch_size: int = 10
    # Endpoints
    disable_after: int = _env("RELAY_DISABLE_AFTER", 5, int)
    # Failures must also span this many seconds, so a blip cannot disable an
    # endpoint that has a backlog.
    disable_window: float = _env("RELAY_DISABLE_WINDOW", 600.0)
    # Comma separated CIDRs that may be called although they are not public,
    # for receivers on a private network. Empty by default.
    allow_networks: str = field(default_factory=lambda: os.environ.get("RELAY_ALLOW_NETWORKS", ""))
