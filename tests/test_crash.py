"""A real worker process killed with SIGKILL in the middle of a request."""

import os
import signal
import subprocess
import sys

from relay import store

from .conftest import TEST_DB, status_of, wait_for


def spawn_worker(**env_overrides):
    env = {
        **os.environ,
        "DATABASE_URL": TEST_DB,
        "RELAY_ALLOW_NETWORKS": "127.0.0.1/32",
        "RELAY_POLL_INTERVAL": "0.05",
        "RELAY_LEASE_SECONDS": "1.5",
        "RELAY_REQUEST_TIMEOUT": "5",
        "RELAY_BACKOFF_BASE": "0.05",
        **env_overrides,
    }
    return subprocess.Popen([sys.executable, "-m", "relay.worker"], env=env)


async def test_killed_worker_leaves_the_delivery_for_another_one(engine, receiver):
    ep = await store.create_endpoint(engine, receiver.url, ordered=False)
    # The first request hangs for 3s, long enough to kill the worker during it.
    receiver.script = [("sleep", 3.0, 200)]
    did = await store.enqueue(engine, ep["id"], "t", '{"n":1}')

    first = spawn_worker()
    procs = [first]
    try:

        async def arrived():
            return receiver.count() >= 1

        await wait_for(arrived)
        assert await status_of(engine, did) == "delivering"
        first.send_signal(signal.SIGKILL)
        first.wait(timeout=5)

        # Nothing was recorded by the dead process. The row says so.
        assert await status_of(engine, did) == "delivering"

        second = spawn_worker()
        procs.append(second)

        async def delivered():
            return await status_of(engine, did) == "succeeded"

        await wait_for(delivered, timeout=15)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=5)

    d = await store.get_delivery(engine, did)
    # The killed attempt counts, so the receiver saw the same event twice:
    # delivery is at least once, and the id header is how it is de-duplicated.
    assert d["attempts"] == 2
    ids = {s.headers["x-relay-delivery-id"] for s in receiver.seen}
    assert ids == {str(did)}
    assert receiver.count() == 2
