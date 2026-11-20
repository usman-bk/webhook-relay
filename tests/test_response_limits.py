"""A receiver must not be able to hold or flood a worker."""

from relay import store

from .conftest import drain


async def test_a_dripping_response_is_cut_off_at_the_deadline(
    engine, endpoint, receiver, make_worker, settings
):
    """One byte every 100ms never trips a per-read timeout of 0.5s."""
    settings.request_timeout = 0.5
    receiver.script = [("drip", 2.5)]
    did = await store.enqueue(engine, endpoint["id"], "t", "{}")
    await drain(make_worker(), engine, [did])

    first = (await store.get_delivery(engine, did))["attempt_log"][0]
    assert first["error"] == "timeout"
    assert first["duration_ms"] < 1200


async def test_a_huge_response_body_is_not_read_to_the_end(
    engine, endpoint, receiver, make_worker, settings
):
    settings.max_response_bytes = 1024
    receiver.script = [("big", 64)]
    did = await store.enqueue(engine, endpoint["id"], "t", "{}")
    await drain(make_worker(), engine, [did])

    assert receiver.bytes_sent < 16 * 1024 * 1024
