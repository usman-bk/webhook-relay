"""An ordered endpoint and two requests committing out of id order."""

import asyncio

from relay import store

from .conftest import drain


async def test_ordered_events_keep_the_order_they_were_accepted_in(engine, receiver, make_worker):
    """A transaction that took the lower id but commits last must still go first."""
    ep = await store.create_endpoint(engine, receiver.url, ordered=True)
    worker = make_worker()

    first_conn = await engine.connect()
    tx = await first_conn.begin()
    first = await store.enqueue_in(first_conn, ep["id"], "t", '{"n":"first"}')

    second_task = asyncio.create_task(store.enqueue(engine, ep["id"], "t", '{"n":"second"}'))
    await asyncio.sleep(0.4)  # the second request commits now, unless it has to wait
    await worker.run_once()
    await tx.commit()
    await first_conn.close()
    second = await second_task

    await drain(worker, engine, [first, second])
    order = [s.body for s in receiver.seen]
    assert order == [b'{"n":"first"}', b'{"n":"second"}']
