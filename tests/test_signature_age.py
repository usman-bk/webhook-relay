"""Retries are signed when they are sent, not when they were queued."""

from relay import signing, store

from .conftest import drain


async def test_every_attempt_carries_a_fresh_timestamp(
    engine, endpoint, receiver, make_worker, settings
):
    """A receiver that enforces a 2 second window must accept the retry."""
    settings.backoff_base = 5.0  # first wait lands between 2.5s and 5s
    settings.backoff_cap = 5.0
    receiver.script = [("status", 500)]
    did = await store.enqueue(engine, endpoint["id"], "t", '{"a":1}')
    await drain(make_worker(), engine, [did])

    assert receiver.count() == 2
    for req in receiver.seen:
        ts, _ = signing.parse(req.headers["x-relay-signature"])
        assert abs(req.at - ts) <= 2.0, "signature timestamp is stale for the receiver"
        signing.verify(
            endpoint["secret"], req.body, req.headers["x-relay-signature"], tolerance=2, now=req.at
        )
