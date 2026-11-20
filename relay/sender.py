"""One HTTP delivery: SSRF check, signed POST, redirect handling."""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from .config import Settings
from .ssrf import Policy, UnsafeTarget, check_url


@dataclass
class Outcome:
    ok: bool
    status_code: int | None
    error: str | None
    duration_ms: int
    permanent: bool = False  # refused by policy, retrying cannot help


async def send(
    client: httpx.AsyncClient,
    policy: Policy,
    settings: Settings,
    url: str,
    body: bytes,
    headers: dict[str, str],
) -> Outcome:
    started = time.monotonic()

    def done(ok, status=None, error=None, permanent=False) -> Outcome:
        return Outcome(ok, status, error, int((time.monotonic() - started) * 1000), permanent)

    hops = 0
    while True:
        try:
            target = await check_url(url, policy)
        except UnsafeTarget as exc:
            return done(False, error=f"blocked: {exc}", permanent=True)
        req_headers = {**headers, "Host": target.host_header}
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        try:
            resp = await client.post(
                target.connect_url,
                content=body,
                headers=req_headers,
                extensions=extensions,
                timeout=settings.request_timeout,
            )
        except httpx.TimeoutException:
            return done(False, error="timeout")
        except httpx.HTTPError as exc:
            return done(False, error=f"{type(exc).__name__}: {exc}"[:200])

        if resp.status_code in (307, 308) and "location" in resp.headers:
            hops += 1
            if hops > settings.max_redirects:
                return done(False, resp.status_code, "too many redirects")
            url = str(httpx.URL(url).join(resp.headers["location"]))
            continue
        if 200 <= resp.status_code < 300:
            return done(True, resp.status_code)
        return done(False, resp.status_code, f"HTTP {resp.status_code}")
