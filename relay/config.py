from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/relay"
        )
    )
    api_token: str = field(default_factory=lambda: os.environ.get("RELAY_API_TOKEN", "dev-token"))
    # Delivery
    max_attempts: int = 8
    backoff_base: float = 2.0  # seconds, doubles each attempt
    backoff_cap: float = 3600.0
    request_timeout: float = 10.0  # whole request, not per read
    max_response_bytes: int = 65536
    max_redirects: int = 3
    # Workers
    lease_seconds: float = 30.0
    poll_interval: float = 0.5
    batch_size: int = 10
    # Endpoints
    disable_after: int = 5
