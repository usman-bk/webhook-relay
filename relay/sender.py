"""One HTTP delivery: SSRF check, signed POST, redirect handling."""

from __future__ import annotations

import asyncio
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

    try:
        # One deadline for the whole exchange, redirects included. httpx's own
        # timeouts are per read, so a receiver that sends a byte every few
        # hundred milliseconds would never trip them.
        async with asyncio.timeout(settings.request_timeout):
            return await _exchange(client, policy, settings, url, body, headers, done)
    except TimeoutError:
        return done(False, error="timeout")
    except httpx.HTTPError as exc:
        return done(False, error=f"{type(exc).__name__}: {exc}"[:200])


async def _exchange(client, policy, settings, url, body, headers, done) -> Outcome:
    hops = 0
    while True:
        try:
            target = await check_url(url, policy)
        except UnsafeTarget as exc:
            return done(False, error=f"blocked: {exc}", permanent=True)
        req_headers = {**headers, "Host": target.host_header}
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        async with client.stream(
            "POST", target.connect_url, content=body, headers=req_headers, extensions=extensions
        ) as resp:
            # The answer is not used, so read a little of it and drop the
            # connection rather than let a receiver stream gigabytes at us.
            read = 0
            async for chunk in resp.aiter_raw():
                read += len(chunk)
                if read >= settings.max_response_bytes:
                    break
            status, location = resp.status_code, resp.headers.get("location")

        if status in (307, 308) and location:
            hops += 1
            if hops > settings.max_redirects:
                return done(False, status, "too many redirects")
            url = str(httpx.URL(url).join(location))
            continue
        if 200 <= status < 300:
            return done(True, status)
        return done(False, status, f"HTTP {status}")
