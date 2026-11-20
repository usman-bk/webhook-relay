"""Claims due deliveries and sends them. Run as many of these as you like."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random

import httpx
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from . import store
from .backoff import delay_for
from .config import Settings
from .sender import send
from .ssrf import Policy

log = logging.getLogger("relay.worker")


class Worker:
    def __init__(
        self,
        engine: AsyncEngine,
        settings: Settings,
        policy: Policy | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.policy = policy or Policy()
        self.rng = rng
        self.client = httpx.AsyncClient(follow_redirects=False)
        self._stop = asyncio.Event()

    async def close(self) -> None:
        await self.client.aclose()

    def stop(self) -> None:
        self._stop.set()

    async def run_once(self) -> int:
        await store.reap(self.engine, self.settings.max_attempts)
        jobs = await store.claim(self.engine, self.settings.batch_size, self.settings.lease_seconds)
        if jobs:
            await asyncio.gather(*(self._deliver(j) for j in jobs))
        return len(jobs)

    async def _deliver(self, job: store.Claimed) -> None:
        s = self.settings
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "webhook-relay/0.1",
            "X-Relay-Delivery-Id": str(job.id),
            "X-Relay-Event": job.event_type,
            "X-Relay-Attempt": str(job.attempts),
            "X-Relay-Signature": job.signature,
        }
        out = await send(self.client, self.policy, s, job.url, job.body.encode(), headers)
        retry_in = None
        if not out.ok and not out.permanent and job.attempts < s.max_attempts:
            retry_in = delay_for(job.attempts, s.backoff_base, s.backoff_cap, self.rng)
        wrote = await store.finish(
            self.engine,
            job,
            ok=out.ok,
            status_code=out.status_code,
            error=out.error,
            duration_ms=out.duration_ms,
            retry_in=retry_in,
            disable_after=s.disable_after,
        )
        if not wrote:
            log.warning("delivery %s attempt %s lost its lease", job.id, job.attempts)

    async def run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                n = await self.run_once()
            except Exception:
                log.exception("worker loop failed")
                n = 0
            if n == 0:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), self.settings.poll_interval)


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    settings = Settings()
    engine = create_async_engine(settings.database_url, pool_size=10)
    worker = Worker(engine, settings)
    try:
        await worker.run_forever()
    finally:
        await worker.close()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
