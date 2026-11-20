"""Every query the service runs. State lives in Postgres and nowhere else."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from . import signing


@dataclass
class Claimed:
    id: int
    endpoint_id: str
    url: str
    secret: str
    body: str
    signature: str
    event_type: str
    attempts: int


async def create_endpoint(engine: AsyncEngine, url: str, ordered: bool) -> dict[str, Any]:
    secret = "whsec_" + secrets.token_urlsafe(24)
    async with engine.begin() as conn:
        row = (
            (
                await conn.execute(
                    text(
                        "INSERT INTO endpoints (url, secret, ordered) VALUES (:u, :s, :o) "
                        "RETURNING id, url, secret, ordered, consecutive_failures, disabled_at"
                    ),
                    {"u": url, "s": secret, "o": ordered},
                )
            )
            .mappings()
            .one()
        )
    return _endpoint(row)


def _endpoint(row) -> dict[str, Any]:
    d = dict(row)
    d["id"] = str(d["id"])
    return d


async def get_endpoint(engine: AsyncEngine, endpoint_id: str) -> dict[str, Any] | None:
    async with engine.connect() as conn:
        row = (
            (
                await conn.execute(
                    text(
                        "SELECT id, url, secret, ordered, consecutive_failures, disabled_at "
                        "FROM endpoints WHERE id = :id"
                    ),
                    {"id": endpoint_id},
                )
            )
            .mappings()
            .first()
        )
    return _endpoint(row) if row else None


async def enable_endpoint(engine: AsyncEngine, endpoint_id: str) -> bool:
    async with engine.begin() as conn:
        res = await conn.execute(
            text(
                "UPDATE endpoints SET disabled_at = NULL, consecutive_failures = 0 WHERE id = :id"
            ),
            {"id": endpoint_id},
        )
    return res.rowcount == 1


async def enqueue(engine: AsyncEngine, endpoint_id: str, event_type: str, body: str) -> int | None:
    async with engine.begin() as conn:
        return await enqueue_in(conn, endpoint_id, event_type, body)


async def enqueue_in(
    conn: AsyncConnection, endpoint_id: str, event_type: str, body: str
) -> int | None:
    row = (
        await conn.execute(
            text("SELECT secret, ordered FROM endpoints WHERE id = :id"), {"id": endpoint_id}
        )
    ).first()
    if row is None:
        return None
    secret, ordered = row
    if ordered:
        # Ids come from a sequence, commit order is another thing. Without this
        # lock a request that took id 5 can commit after the one with id 6, and
        # the worker would send 6 first. Holding the lock until commit makes the
        # id order and the commit order the same order.
        await conn.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:id, 0))"), {"id": endpoint_id}
        )
    header = signing.sign(secret, body.encode())
    return (
        await conn.execute(
            text(
                "INSERT INTO deliveries (endpoint_id, event_type, body, signature) "
                "VALUES (:e, :t, :b, :s) RETURNING id"
            ),
            {"e": endpoint_id, "t": event_type, "b": body, "s": header},
        )
    ).scalar_one()


CLAIM = text(
    """
    WITH due AS (
        SELECT d.id FROM deliveries d
        JOIN endpoints e ON e.id = d.endpoint_id
        WHERE d.status = 'pending'
          AND d.next_attempt_at <= now()
          AND e.disabled_at IS NULL
          AND (NOT e.ordered OR NOT EXISTS (
                SELECT 1 FROM deliveries p
                WHERE p.endpoint_id = d.endpoint_id
                  AND p.id < d.id
                  AND p.status IN ('pending', 'delivering')))
        ORDER BY d.next_attempt_at, d.id
        LIMIT :n
        FOR UPDATE OF d SKIP LOCKED
    )
    UPDATE deliveries d
    SET status = 'delivering',
        attempts = d.attempts + 1,
        locked_until = now() + make_interval(secs => :lease)
    FROM due, endpoints e
    WHERE d.id = due.id AND e.id = d.endpoint_id
    RETURNING d.id, d.endpoint_id, e.url, e.secret, d.body, d.signature, d.event_type, d.attempts
    """
)


async def claim(engine: AsyncEngine, limit: int, lease_seconds: float) -> list[Claimed]:
    async with engine.begin() as conn:
        rows = (await conn.execute(CLAIM, {"n": limit, "lease": lease_seconds})).all()
    return [Claimed(r[0], str(r[1]), r[2], r[3], r[4], r[5], r[6], r[7]) for r in rows]


async def reap(engine: AsyncEngine, max_attempts: int) -> int:
    """Take back deliveries whose worker vanished. An attempt that was claimed
    counts, because the request may have gone out."""
    async with engine.begin() as conn:
        res = await conn.execute(
            text(
                """
                UPDATE deliveries
                SET status = CASE WHEN attempts >= :max THEN 'dead' ELSE 'pending' END,
                    next_attempt_at = now(),
                    locked_until = NULL,
                    last_error = coalesce(last_error, 'worker lost'),
                    finished_at = CASE WHEN attempts >= :max THEN now() END
                WHERE status = 'delivering' AND locked_until < now()
                """
            ),
            {"max": max_attempts},
        )
    return res.rowcount


async def record_attempt(
    conn: AsyncConnection,
    delivery_id: int,
    attempt: int,
    duration_ms: int,
    status_code: int | None,
    error: str | None,
) -> None:
    await conn.execute(
        text(
            "INSERT INTO attempts (delivery_id, attempt, duration_ms, status_code, error) "
            "VALUES (:d, :a, :ms, :s, :e)"
        ),
        {"d": delivery_id, "a": attempt, "ms": duration_ms, "s": status_code, "e": error},
    )


async def finish(
    engine: AsyncEngine,
    job: Claimed,
    *,
    ok: bool,
    status_code: int | None,
    error: str | None,
    duration_ms: int,
    retry_in: float | None,
    disable_after: int,
) -> bool:
    """Record the result. `retry_in` None means give up. Returns False when this
    worker no longer owns the delivery, in which case nothing is written."""
    async with engine.begin() as conn:
        await record_attempt(conn, job.id, job.attempts, duration_ms, status_code, error)
        if ok:
            new_status, retry = "succeeded", None
        elif retry_in is None:
            new_status, retry = "dead", None
        else:
            new_status, retry = "pending", retry_in
        res = await conn.execute(
            text(
                """
                UPDATE deliveries
                SET status = :st,
                    next_attempt_at = CASE WHEN :st = 'pending'
                        THEN now() + make_interval(secs => :retry) ELSE next_attempt_at END,
                    locked_until = NULL,
                    last_status = :code,
                    last_error = :err,
                    finished_at = CASE WHEN :st = 'pending' THEN NULL ELSE now() END
                WHERE id = :id AND status = 'delivering' AND attempts = :attempt
                """
            ),
            {
                "st": new_status,
                "retry": retry or 0,
                "code": status_code,
                "err": error,
                "id": job.id,
                "attempt": job.attempts,
            },
        )
        if res.rowcount != 1:
            return False
        if ok:
            await conn.execute(
                text("UPDATE endpoints SET consecutive_failures = 0 WHERE id = :e"),
                {"e": job.endpoint_id},
            )
        else:
            await conn.execute(
                text(
                    """
                    UPDATE endpoints
                    SET consecutive_failures = consecutive_failures + 1,
                        disabled_at = CASE WHEN consecutive_failures + 1 >= :n
                            AND disabled_at IS NULL THEN now() ELSE disabled_at END
                    WHERE id = :e
                    """
                ),
                {"e": job.endpoint_id, "n": disable_after},
            )
    return True


async def get_delivery(engine: AsyncEngine, delivery_id: int) -> dict[str, Any] | None:
    async with engine.connect() as conn:
        row = (
            (
                await conn.execute(
                    text(
                        "SELECT id, endpoint_id, event_type, status, attempts, next_attempt_at, "
                        "last_status, last_error, created_at, finished_at "
                        "FROM deliveries WHERE id = :id"
                    ),
                    {"id": delivery_id},
                )
            )
            .mappings()
            .first()
        )
        if not row:
            return None
        att = (
            (
                await conn.execute(
                    text(
                        "SELECT attempt, started_at, duration_ms, status_code, error "
                        "FROM attempts WHERE delivery_id = :id ORDER BY id"
                    ),
                    {"id": delivery_id},
                )
            )
            .mappings()
            .all()
        )
    d = dict(row)
    d["endpoint_id"] = str(d["endpoint_id"])
    d["attempt_log"] = [dict(a) for a in att]
    return d


async def dead_letters(engine: AsyncEngine, endpoint_id: str | None) -> list[dict[str, Any]]:
    async with engine.connect() as conn:
        rows = (
            (
                await conn.execute(
                    text(
                        "SELECT id, endpoint_id, event_type, attempts, last_status, last_error, "
                        "finished_at FROM deliveries WHERE status = 'dead' "
                        "AND (CAST(:e AS uuid) IS NULL OR endpoint_id = CAST(:e AS uuid)) "
                        "ORDER BY id"
                    ),
                    {"e": endpoint_id},
                )
            )
            .mappings()
            .all()
        )
    return [{**dict(r), "endpoint_id": str(r["endpoint_id"])} for r in rows]


async def redeliver(engine: AsyncEngine, delivery_id: int) -> bool:
    """Put a dead delivery back in the queue with a fresh attempt budget."""
    async with engine.begin() as conn:
        res = await conn.execute(
            text(
                "UPDATE deliveries SET status = 'pending', attempts = 0, next_attempt_at = now(), "
                "locked_until = NULL, finished_at = NULL WHERE id = :id AND status = 'dead'"
            ),
            {"id": delivery_id},
        )
    return res.rowcount == 1
