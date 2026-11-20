from __future__ import annotations

import asyncio
import ipaddress
import os
import time

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from relay import store
from relay.config import Settings
from relay.schema import init_db
from relay.ssrf import Policy
from relay.worker import Worker

from .receiver import Receiver

TEST_DB = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/webhook_relay_test"
)


@pytest_asyncio.fixture(scope="session")
async def engine():
    eng = create_async_engine(TEST_DB, pool_size=20)
    await init_db(eng)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean(engine):
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE endpoints, deliveries, attempts RESTART IDENTITY CASCADE")
        )


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url=TEST_DB,
        api_token="test-token",
        max_attempts=4,
        backoff_base=0.05,
        backoff_cap=0.2,
        request_timeout=1.0,
        lease_seconds=5.0,
        poll_interval=0.02,
        batch_size=10,
        disable_after=3,
        disable_window=0.0,
    )


@pytest.fixture
def policy() -> Policy:
    return Policy(allow_networks=[ipaddress.ip_network("127.0.0.1/32")])


@pytest.fixture
def receiver():
    r = Receiver().start()
    yield r
    r.stop()


@pytest_asyncio.fixture
async def make_worker(engine, settings, policy):
    made = []

    def make(**overrides) -> Worker:
        w = Worker(engine, settings, policy)
        for k, v in overrides.items():
            setattr(w.settings, k, v)
        made.append(w)
        return w

    yield make
    for w in made:
        w.stop()
        await w.close()


async def wait_for(check, timeout: float = 10.0, every: float = 0.02):
    """Poll an async predicate until it returns something truthy."""
    deadline = time.monotonic() + timeout
    while True:
        value = await check()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(every)


async def status_of(engine, delivery_id: int) -> str:
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text("SELECT status FROM deliveries WHERE id = :i"), {"i": delivery_id}
            )
        ).scalar_one()


@pytest_asyncio.fixture
async def endpoint(engine, receiver):
    return await store.create_endpoint(engine, receiver.url, ordered=False)


async def drain(worker, engine, ids, timeout: float = 10.0):
    """Run the worker until every delivery in ids has succeeded."""

    async def done():
        await worker.run_once()
        return all([await status_of(engine, i) == "succeeded" for i in ids])

    await wait_for(done, timeout)
