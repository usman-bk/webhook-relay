"""SSRF protection as the worker sees it: real requests, real receiver."""

import httpx
import pytest

from relay import store
from relay.ssrf import Policy
from relay.worker import Worker

from .conftest import status_of, wait_for


async def run_to_end(worker, engine, did, wanted):
    async def done():
        await worker.run_once()
        return await status_of(engine, did) in wanted

    await wait_for(done)


async def test_loopback_receiver_is_never_called_without_the_allow_list(engine, receiver, settings):
    ep = await store.create_endpoint(engine, receiver.url, ordered=False)
    did = await store.enqueue(engine, ep["id"], "t", "{}")
    worker = Worker(engine, settings, Policy())  # production policy
    try:
        await run_to_end(worker, engine, did, {"dead"})
    finally:
        await worker.close()

    assert receiver.count() == 0
    d = await store.get_delivery(engine, did)
    assert d["attempts"] == 1  # refusal is final, no retry budget is burned
    assert d["last_error"].startswith("blocked:")


async def test_api_refuses_to_register_a_private_target(settings):
    from relay.api import create_app

    app = create_app(settings, Policy())
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            auth = {"Authorization": "Bearer test-token"}
            for url in ("http://169.254.169.254/", "http://10.0.0.1/x", "http://localhost:9/"):
                r = await c.post("/endpoints", json={"url": url}, headers=auth)
                assert r.status_code == 422, url


async def test_redirect_to_a_private_address_is_not_followed(
    engine, receiver, make_worker, settings, policy
):
    seen_hosts = []

    async def resolver(host, port):
        seen_hosts.append(host)
        return {"internal.test": ["10.9.8.7"]}[host]

    policy.resolver = resolver
    receiver.script = [("redirect", 307, "http://internal.test:9999/admin")]
    ep = await store.create_endpoint(engine, receiver.url, ordered=False)
    did = await store.enqueue(engine, ep["id"], "t", "{}")
    await run_to_end(make_worker(), engine, did, {"dead"})

    d = await store.get_delivery(engine, did)
    assert "10.9.8.7" in d["last_error"]
    assert seen_hosts == ["internal.test"]
    assert receiver.count() == 1


async def test_redirect_to_a_listed_address_is_followed_with_body_and_signature(
    engine, receiver, make_worker
):
    receiver.script = [("redirect", 307, f"http://127.0.0.1:{receiver.port}/moved")]
    ep = await store.create_endpoint(engine, receiver.url, ordered=False)
    did = await store.enqueue(engine, ep["id"], "t", '{"k":1}')
    await run_to_end(make_worker(), engine, did, {"succeeded"})

    first, second = receiver.seen
    assert second.path == "/moved"
    assert second.body == b'{"k":1}'
    assert second.headers["x-relay-signature"].startswith("t=")


@pytest.mark.parametrize("code", [301, 302, 303])
async def test_redirects_that_turn_the_post_into_a_get_are_failures(
    engine, receiver, make_worker, code
):
    receiver.script = [("redirect", code, f"http://127.0.0.1:{receiver.port}/elsewhere")]
    ep = await store.create_endpoint(engine, receiver.url, ordered=False)
    did = await store.enqueue(engine, ep["id"], "t", "{}")
    await run_to_end(make_worker(), engine, did, {"succeeded"})
    log = (await store.get_delivery(engine, did))["attempt_log"]
    assert log[0]["status_code"] == code
    assert all(s.path == "/hook" for s in receiver.seen)


async def test_a_redirect_loop_stops(engine, receiver, make_worker, settings):
    settings.max_attempts = 1
    receiver.default = ("redirect", 307, f"http://127.0.0.1:{receiver.port}/hook")
    ep = await store.create_endpoint(engine, receiver.url, ordered=False)
    did = await store.enqueue(engine, ep["id"], "t", "{}")
    await run_to_end(make_worker(), engine, did, {"dead"})
    assert receiver.count() == settings.max_redirects + 1
    assert (await store.get_delivery(engine, did))["last_error"] == "too many redirects"


async def test_the_address_that_was_checked_is_the_address_that_is_called(
    engine, receiver, make_worker, policy
):
    """The name is resolved once. An answer that changes afterwards is never asked for."""
    answers = [["127.0.0.1"], ["10.0.0.1"], ["10.0.0.1"]]
    calls = []

    async def resolver(host, port):
        calls.append(host)
        return answers.pop(0)

    policy.resolver = resolver
    url = f"http://rebind.test:{receiver.port}/hook"
    ep = await store.create_endpoint(engine, url, ordered=False)
    did = await store.enqueue(engine, ep["id"], "t", "{}")
    await run_to_end(make_worker(), engine, did, {"succeeded"})

    assert calls == ["rebind.test"]
    assert receiver.seen[0].headers["host"] == f"rebind.test:{receiver.port}"
