"""One bad second must not switch off an endpoint that has a backlog."""

import asyncio

from sqlalchemy import text

from relay import store

from .conftest import wait_for


async def test_a_short_burst_of_failures_does_not_disable_the_endpoint(
    engine, endpoint, receiver, make_worker, settings
):
    settings.max_attempts = 10
    settings.disable_after = 3
    settings.disable_window = 2.0  # failing for two seconds is an outage, a blip is not
    # The first five requests fail, which is what a receiver restarting looks
    # like to five workers sending at the same moment.
    receiver.script = [("status", 503)] * 5
    ids = [await store.enqueue(engine, endpoint["id"], "t", "{}") for _ in range(8)]
    worker = make_worker()

    async def all_done():
        await worker.run_once()
        async with engine.connect() as conn:
            n = (
                await conn.execute(text("SELECT count(*) FROM deliveries WHERE status='succeeded'"))
            ).scalar_one()
        return n == len(ids)

    await wait_for(all_done)
    ep = await store.get_endpoint(engine, endpoint["id"])
    assert ep["disabled_at"] is None
    assert ep["consecutive_failures"] == 0


async def test_a_sustained_outage_still_disables_it(
    engine, endpoint, receiver, make_worker, settings
):
    settings.max_attempts = 50
    settings.disable_after = 3
    settings.disable_window = 0.6
    settings.backoff_base = 0.05
    settings.backoff_cap = 0.1
    receiver.default = ("status", 503)
    await store.enqueue(engine, endpoint["id"], "t", "{}")
    worker = make_worker()

    async def disabled():
        await worker.run_once()
        return (await store.get_endpoint(engine, endpoint["id"]))["disabled_at"]

    await wait_for(disabled)
    n = receiver.count()
    await asyncio.sleep(0.4)
    await worker.run_once()
    assert receiver.count() == n  # and it stays quiet
