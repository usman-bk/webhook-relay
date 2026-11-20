from __future__ import annotations

import hmac
import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine

from . import store
from .config import Settings
from .schema import init_db
from .ssrf import Policy, UnsafeTarget, check_url


class EndpointIn(BaseModel):
    url: str
    ordered: bool = False


class EventIn(BaseModel):
    type: str
    payload: dict[str, Any]


def create_app(settings: Settings | None = None, policy: Policy | None = None) -> FastAPI:
    settings = settings or Settings()
    policy = policy or Policy()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = create_async_engine(settings.database_url, pool_size=10)
        await init_db(engine)
        app.state.engine = engine
        yield
        await engine.dispose()

    app = FastAPI(title="webhook-relay", lifespan=lifespan)

    def auth(authorization: str = Header(default="")) -> None:
        expected = f"Bearer {settings.api_token}"
        if not hmac.compare_digest(authorization.encode(), expected.encode()):
            raise HTTPException(401, "bad token")

    def engine_of():
        return app.state.engine

    @app.get("/health")
    async def health():
        return {"ok": True}

    @app.post("/endpoints", status_code=201, dependencies=[Depends(auth)])
    async def create_endpoint(body: EndpointIn):
        try:
            await check_url(body.url, policy)
        except UnsafeTarget as exc:
            raise HTTPException(422, str(exc)) from exc
        return await store.create_endpoint(engine_of(), body.url, body.ordered)

    @app.get("/endpoints/{endpoint_id}", dependencies=[Depends(auth)])
    async def get_endpoint(endpoint_id: str):
        ep = await store.get_endpoint(engine_of(), endpoint_id)
        if not ep:
            raise HTTPException(404)
        return ep

    @app.post("/endpoints/{endpoint_id}/enable", dependencies=[Depends(auth)])
    async def enable(endpoint_id: str):
        if not await store.enable_endpoint(engine_of(), endpoint_id):
            raise HTTPException(404)
        return {"enabled": True}

    @app.post("/endpoints/{endpoint_id}/events", status_code=202, dependencies=[Depends(auth)])
    async def publish(endpoint_id: str, event: EventIn):
        body = json.dumps(
            {"type": event.type, "data": event.payload}, separators=(",", ":"), sort_keys=True
        )
        delivery_id = await store.enqueue(engine_of(), endpoint_id, event.type, body)
        if delivery_id is None:
            raise HTTPException(404)
        return {"delivery_id": delivery_id}

    @app.get("/deliveries/{delivery_id}", dependencies=[Depends(auth)])
    async def delivery(delivery_id: int):
        d = await store.get_delivery(engine_of(), delivery_id)
        if not d:
            raise HTTPException(404)
        return d

    @app.get("/dead-letters", dependencies=[Depends(auth)])
    async def dead(endpoint_id: str | None = Query(default=None)):
        return await store.dead_letters(engine_of(), endpoint_id)

    @app.post("/deliveries/{delivery_id}/redeliver", dependencies=[Depends(auth)])
    async def redeliver(delivery_id: int):
        if not await store.redeliver(engine_of(), delivery_id):
            raise HTTPException(409, "only dead deliveries can be redelivered")
        return {"queued": True}

    return app


app = create_app()
