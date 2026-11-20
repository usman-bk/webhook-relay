import httpx
import pytest_asyncio

from relay import signing
from relay.api import create_app

from .conftest import status_of, wait_for

AUTH = {"Authorization": "Bearer test-token"}


@pytest_asyncio.fixture
async def client(settings, policy):
    app = create_app(settings, policy)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            yield c


async def test_requires_the_token(client):
    assert (await client.post("/endpoints", json={"url": "http://x"})).status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert (await client.get("/dead-letters", headers=bad)).status_code == 401
    assert (await client.get("/health")).status_code == 200


async def test_publish_deliver_inspect_over_http(client, receiver, make_worker, engine):
    ep = (await client.post("/endpoints", json={"url": receiver.url}, headers=AUTH)).json()
    assert ep["secret"].startswith("whsec_")

    r = await client.post(
        f"/endpoints/{ep['id']}/events",
        json={"type": "order.created", "payload": {"b": 2, "a": 1}},
        headers=AUTH,
    )
    assert r.status_code == 202
    did = r.json()["delivery_id"]

    worker = make_worker()

    async def done():
        await worker.run_once()
        return await status_of(engine, did) == "succeeded"

    await wait_for(done)

    body = receiver.seen[0].body
    assert body == b'{"data":{"a":1,"b":2},"type":"order.created"}'
    signing.verify(ep["secret"], body, receiver.seen[0].headers["x-relay-signature"])

    d = (await client.get(f"/deliveries/{did}", headers=AUTH)).json()
    assert d["status"] == "succeeded"
    assert d["attempt_log"][0]["status_code"] == 200


async def test_dead_letter_list_and_manual_redelivery(
    client, receiver, make_worker, engine, settings
):
    settings.disable_after = 99
    receiver.default = ("status", 500)
    ep = (await client.post("/endpoints", json={"url": receiver.url}, headers=AUTH)).json()
    did = (
        await client.post(
            f"/endpoints/{ep['id']}/events", json={"type": "t", "payload": {}}, headers=AUTH
        )
    ).json()["delivery_id"]
    worker = make_worker()

    async def dead():
        await worker.run_once()
        return await status_of(engine, did) == "dead"

    await wait_for(dead)
    listed = (
        await client.get("/dead-letters", params={"endpoint_id": ep["id"]}, headers=AUTH)
    ).json()
    assert [x["id"] for x in listed] == [did]
    other = (
        await client.get(
            "/dead-letters",
            params={"endpoint_id": "00000000-0000-0000-0000-000000000000"},
            headers=AUTH,
        )
    ).json()
    assert other == []

    # Only dead ones can be redelivered.
    receiver.default = ("status", 200)
    assert (await client.post(f"/deliveries/{did}/redeliver", headers=AUTH)).status_code == 200
    assert (await client.post(f"/deliveries/{did}/redeliver", headers=AUTH)).status_code == 409

    async def ok():
        await worker.run_once()
        return await status_of(engine, did) == "succeeded"

    await wait_for(ok)
    assert (await client.get("/dead-letters", headers=AUTH)).json() == []


async def test_unknown_ids(client):
    assert (await client.get("/deliveries/999", headers=AUTH)).status_code == 404
    assert (
        await client.post(
            "/endpoints/00000000-0000-0000-0000-000000000000/events",
            json={"type": "t", "payload": {}},
            headers=AUTH,
        )
    ).status_code == 404
    assert (await client.post("/deliveries/999/redeliver", headers=AUTH)).status_code == 409
