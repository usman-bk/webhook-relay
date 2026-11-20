from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

DDL = [
    """
    CREATE TABLE IF NOT EXISTS endpoints (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        url text NOT NULL,
        secret text NOT NULL,
        ordered boolean NOT NULL DEFAULT false,
        consecutive_failures integer NOT NULL DEFAULT 0,
        disabled_at timestamptz,
        failing_since timestamptz,
        created_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS failing_since timestamptz",
    """
    CREATE TABLE IF NOT EXISTS deliveries (
        id bigserial PRIMARY KEY,
        endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
        event_type text NOT NULL,
        body text NOT NULL,
        status text NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'delivering', 'succeeded', 'dead')),
        attempts integer NOT NULL DEFAULT 0,
        next_attempt_at timestamptz NOT NULL DEFAULT now(),
        locked_until timestamptz,
        last_status integer,
        last_error text,
        created_at timestamptz NOT NULL DEFAULT now(),
        finished_at timestamptz
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries (next_attempt_at, id)
        WHERE status = 'pending'
    """,
    """
    CREATE INDEX IF NOT EXISTS deliveries_by_endpoint ON deliveries (endpoint_id, id)
    """,
    """
    CREATE TABLE IF NOT EXISTS attempts (
        id bigserial PRIMARY KEY,
        delivery_id bigint NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
        attempt integer NOT NULL,
        started_at timestamptz NOT NULL DEFAULT now(),
        duration_ms integer NOT NULL,
        status_code integer,
        error text
    )
    """,
]


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for stmt in DDL:
            await conn.execute(text(stmt))
