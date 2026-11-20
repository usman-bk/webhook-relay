import asyncio
import ipaddress
import json
import time

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from relay import signing, store
from relay.ssrf import Policy
from relay.worker import Worker

from .conftest import status_of, wait_for


async def publish(engine, endpoint, n=1, body=None):
    ids = []
    for i in range(n):
        payload = body or json.dumps({"n": i})
        ids.append(await store.enqueue(engine, endpoint["id"], "thing.happened", payload))
    return ids


async def run_until(worker, engine, ids, wanted, timeout=10.0):
    async def done():
        await worker.run_once()
        for i in ids:
            if await status_of(engine, i) not in wanted:
                return False
        return True

    await wait_for(done, timeout)


async def test_delivered_once_with_a_valid_signature(engine, endpoint, receiver, make_worker):
    (did,) = await publish(engine, endpoint, body='{"id":"evt_1"}')
    await run_until(make_worker(), engine, [did], {"succeeded"})

    assert receiver.count() == 1
    seen = receiver.seen[0]
    assert seen.body == b'{"id":"evt_1"}'
    assert seen.headers["x-relay-delivery-id"] == str(did)
    assert seen.headers["x-relay-event"] == "thing.happened"
    signing.verify(endpoint["secret"], seen.body, seen.headers["x-relay-signature"])


async def test_5xx_is_retried_until_it_succeeds(engine, endpoint, receiver, make_worker):
    receiver.script = [("status", 500), ("status", 503)]
    (did,) = await publish(engine, endpoint)
    await run_until(make_worker(), engine, [did], {"succeeded"})

    d = await store.get_delivery(engine, did)
    assert d["attempts"] == 3
    assert [a["status_code"] for a in d["attempt_log"]] == [500, 503, 200]
    assert receiver.count() == 3


async def test_retries_wait_for_the_backoff(engine, endpoint, receiver, make_worker):
    receiver.script = [("status", 500)] * 2
    (did,) = await publish(engine, endpoint)
    await run_until(make_worker(), engine, [did], {"succeeded"})
    first, second, third = (s.at for s in receiver.seen)
    # base 0.05: first wait is in [0.025, 0.05], second in [0.05, 0.1]
    assert second - first >= 0.02
    assert third - second >= 0.045


async def test_a_4xx_counts_as_a_failure_too(engine, endpoint, receiver, make_worker):
    receiver.script = [("status", 404)]
    (did,) = await publish(engine, endpoint)
    await run_until(make_worker(), engine, [did], {"succeeded"})
    assert (await store.get_delivery(engine, did))["attempt_log"][0]["status_code"] == 404


async def test_slow_receiver_times_out_and_is_retried(engine, endpoint, receiver, make_worker):
    receiver.script = [("sleep", 1.6, 200)]
    (did,) = await publish(engine, endpoint)
    await run_until(make_worker(), engine, [did], {"succeeded"})
    log = (await store.get_delivery(engine, did))["attempt_log"]
    assert log[0]["error"] == "timeout"
    assert log[0]["status_code"] is None
    assert log[1]["status_code"] == 200


async def test_dropped_connection_is_retried(engine, endpoint, receiver, make_worker):
    receiver.script = [("drop",)]
    (did,) = await publish(engine, endpoint)
    await run_until(make_worker(), engine, [did], {"succeeded"})
    log = (await store.get_delivery(engine, did))["attempt_log"]
    assert log[0]["error"] and log[0]["status_code"] is None
    assert len(log) == 2


async def test_exhausted_delivery_goes_to_dead_letters_then_redelivers(
    engine, endpoint, receiver, make_worker, settings
):
    settings.disable_after = 99
    receiver.default = ("status", 500)
    (did,) = await publish(engine, endpoint)
    worker = make_worker()
    await run_until(worker, engine, [did], {"dead"})

    dead = await store.dead_letters(engine, endpoint["id"])
    assert [d["id"] for d in dead] == [did]
    assert dead[0]["attempts"] == settings.max_attempts
    assert receiver.count() == settings.max_attempts

    receiver.default = ("status", 200)
    assert await store.redeliver(engine, did)
    assert not await store.redeliver(engine, did)  # no longer dead
    await run_until(worker, engine, [did], {"succeeded"})
    assert await store.dead_letters(engine, endpoint["id"]) == []


async def test_endpoint_is_disabled_after_consecutive_failures(
    engine, endpoint, receiver, make_worker, settings
):
    settings.max_attempts = 10
    receiver.default = ("status", 500)
    ids = await publish(engine, endpoint, n=2)
    worker = make_worker()

    async def disabled():
        await worker.run_once()
        return (await store.get_endpoint(engine, endpoint["id"]))["disabled_at"]

    await wait_for(disabled)
    seen_when_disabled = receiver.count()
    # Requests already in flight when the threshold trips still land, so the
    # count can overshoot by the number of deliveries running at that moment.
    assert settings.disable_after <= seen_when_disabled <= settings.disable_after + len(ids) - 1

    # Nothing more goes out while it is disabled.
    for _ in range(10):
        await worker.run_once()
        await asyncio.sleep(0.05)
    assert receiver.count() == seen_when_disabled
    assert [await status_of(engine, i) for i in ids] == ["pending"] * len(ids)

    # Re-enabling resumes the queue.
    receiver.default = ("status", 200)
    assert await store.enable_endpoint(engine, endpoint["id"])
    await run_until(worker, engine, ids, {"succeeded"})
    assert (await store.get_endpoint(engine, endpoint["id"]))["consecutive_failures"] == 0


async def test_a_success_resets_the_failure_streak(
    engine, endpoint, receiver, make_worker, settings
):
    settings.max_attempts = 10
    receiver.script = [("status", 500), ("status", 500), ("status", 200)] * 2
    worker = make_worker()
    for _ in range(2):  # one at a time, so the script is consumed in order
        ids = await publish(engine, endpoint)
        await run_until(worker, engine, ids, {"succeeded"})
    ep = await store.get_endpoint(engine, endpoint["id"])
    assert ep["disabled_at"] is None
    assert receiver.count() == 6


async def test_many_workers_deliver_each_event_exactly_once(
    engine, endpoint, receiver, make_worker
):
    ids = await publish(engine, endpoint, n=60)
    workers = [make_worker() for _ in range(5)]
    tasks = [asyncio.create_task(w.run_forever()) for w in workers]
    try:

        async def all_done():
            async with engine.connect() as conn:
                n = (
                    await conn.execute(
                        text("SELECT count(*) FROM deliveries WHERE status = 'succeeded'")
                    )
                ).scalar_one()
            return n == len(ids)

        await wait_for(all_done)
    finally:
        for w in workers:
            w.stop()
        await asyncio.gather(*tasks)

    delivered = [s.headers["x-relay-delivery-id"] for s in receiver.seen]
    assert len(delivered) == 60
    assert len(set(delivered)) == 60


async def test_ordered_endpoint_waits_for_the_head_of_the_line(
    engine, receiver, make_worker, settings
):
    ep = await store.create_endpoint(engine, receiver.url, ordered=True)
    settings.max_attempts = 10
    receiver.script = [("status", 500), ("status", 500)]
    ids = await publish(engine, ep, n=4)
    workers = [make_worker() for _ in range(3)]
    tasks = [asyncio.create_task(w.run_forever()) for w in workers]
    try:

        async def finished():
            return all([await status_of(engine, i) == "succeeded" for i in ids])

        await wait_for(finished)
    finally:
        for w in workers:
            w.stop()
        await asyncio.gather(*tasks)

    order = [int(s.headers["x-relay-delivery-id"]) for s in receiver.seen]
    # delivery 1 is tried three times, then 2, 3, 4 in order
    assert order == [ids[0]] * 3 + ids[1:]


async def test_unordered_endpoint_does_not_block_behind_a_failure(
    engine, endpoint, receiver, make_worker, settings
):
    settings.max_attempts = 10
    settings.backoff_base = 5.0  # the failed one will not be back during this test
    settings.backoff_cap = 5.0
    receiver.script = [("status", 500)]
    ids = await publish(engine, endpoint, n=3)
    worker = make_worker()
    for _ in range(5):
        await worker.run_once()
        await asyncio.sleep(0.05)
    statuses = [await status_of(engine, i) for i in ids]
    # Which of the three gets the 500 depends on arrival order, so count them.
    assert sorted(statuses) == ["pending", "succeeded", "succeeded"]


async def test_worker_survives_a_restart_between_attempts(engine, endpoint, receiver, settings):
    pol = Policy(allow_networks=[ipaddress.ip_network("127.0.0.1/32")])
    settings.backoff_base = 0.4
    settings.backoff_cap = 0.4
    receiver.script = [("status", 500)]
    (did,) = await publish(engine, endpoint)

    first_engine = create_async_engine(settings.database_url)
    w1 = Worker(first_engine, settings, pol)
    assert await w1.run_once() == 1
    await w1.close()
    await first_engine.dispose()  # the "process" is gone, the retry is only in Postgres

    assert await status_of(engine, did) == "pending"
    second_engine = create_async_engine(settings.database_url)
    w2 = Worker(second_engine, settings, pol)
    try:
        t0 = time.monotonic()
        await run_until(w2, engine, [did], {"succeeded"})
        assert time.monotonic() - t0 >= 0.1  # it waited out the stored schedule
    finally:
        await w2.close()
        await second_engine.dispose()
    assert receiver.count() == 2
