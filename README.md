# webhook-relay

_Built with AI assistance._

Delivers webhooks to customer URLs and keeps trying until the customer's
server answers, without being tricked into calling anything it should not.
Every request is signed, every retry is stored in Postgres, and a worker that
is killed mid request loses nothing.

FastAPI, SQLAlchemy async on asyncpg, httpx, PostgreSQL 16. The tests run
against a real Postgres and a real HTTP receiver that can answer 5xx, hang,
hang up, drip its answer one byte at a time, redirect, or stream 64 MB. One
test starts actual worker processes and sends them `SIGKILL`.

```
relay/signing.py   t=<unix>,v1=<hmac> header, tolerance window, constant time compare
relay/ssrf.py      resolve, test every address, hand back the address that passed
relay/sender.py    one deadline per delivery, redirects re-checked, response read capped
relay/store.py     every SQL statement: claim, finish, reap, redeliver
relay/worker.py    claim loop, backoff with jitter
relay/api.py       endpoints, events, delivery log, dead letters
tests/receiver.py  the misbehaving receiver
```

## How a delivery moves

`pending` -> `delivering` -> `succeeded`, or back to `pending` with a later
`next_attempt_at`, or `dead` after `RELAY_MAX_ATTEMPTS` (default 8).

A worker claims rows with `FOR UPDATE SKIP LOCKED` and sets a lease
(`locked_until`). The attempt number is bumped at claim time and acts as a
fence: the result is written only `WHERE status = 'delivering' AND attempts = N`,
so a worker that stalls past its lease and wakes up later writes nothing.
Rows whose lease ran out are put back by the next worker's `reap`.

The wait after attempt `n` is `step/2 + uniform(0, step/2)` with
`step = min(cap, base * 2^(n-1))`. Half is fixed so the wait is never near
zero, half is random so a receiver coming back does not get everything at once.

## Signatures

`X-Relay-Signature: t=1767225600,v1=<hex>` where the MAC is HMAC-SHA256 over
`<t>.<raw body>`. Verification rejects a timestamp too far in the past or the
future (default 300 s), compares in constant time, and checks every `v1` it
is given so a secret can be rotated with two live values.

`X-Relay-Delivery-Id` is the same on every attempt. Delivery is at least
once, so receivers de-duplicate on it.

## What the tests found

**Ordering broke when two commits crossed.** For an ordered endpoint the
worker sends the lowest unfinished id first. Ids come from a sequence, and
commit order is a different thing: a transaction can take id 1, a second one
takes id 2 and commits, a worker runs, and then id 1 appears. `test_order_race`
holds the first transaction open on purpose and saw `second` arrive before
`first`. Publishing to an ordered endpoint now takes a per-endpoint advisory
lock held to commit, which makes id order and commit order the same order.

**Retries were signed when they were queued.** The signature was stored with
the row. A retry that went out after the backoff carried the old timestamp, so
any receiver enforcing a replay window rejected it, and the longer the backoff
the surer the rejection. `test_signature_age` runs a receiver with a 2 s window
and a first retry 2.5 to 5 s later: the stored signature failed, so the
signature is now made at send time and no longer stored.

**A receiver could hold a worker as long as it liked.** httpx timeouts apply to
each read, so a response sent one byte every 100 ms never timed out: a 2.5 s
drip came back as a success with a 0.5 s timeout set. The whole exchange,
redirects included, now sits under one `asyncio.timeout`. The same test file
streams a 64 MB body: before, all 64 MB were read for an answer nobody uses
(`bytes_sent` 67,108,864); now the read stops at 64 KB and the connection is
dropped (under 16 MB sent, asserted).

**A one second blip disabled an endpoint with a backlog.** The first version
disabled an endpoint after N consecutive failed attempts. Fifty requests in
flight against a receiver that was briefly refusing connections gave N
failures in a few milliseconds: 37 delivered, 13 failed with
`ConnectError`, 10 never started, endpoint disabled. This surfaced as a flaky
test, and the cause turned out to be the test server's listen backlog of 5, but
the product behaviour was real. Disabling now needs both N failures and a
failing streak at least `RELAY_DISABLE_WINDOW` seconds long (default 600).
`test_disable_burst` covers the blip and the real outage.

## SSRF

The URL is checked when an endpoint is registered and again on every attempt,
because DNS can change in between. The host is resolved once, every answer must
be a public address, and the connection goes to that address with the original
`Host` header and, for https, the original name as SNI. The HTTP client never
resolves the name itself, which is what removes the rebinding gap
(`test_the_address_that_was_checked_is_the_address_that_is_called` counts the
resolver calls).

Refused: loopback, RFC 1918, link-local including `169.254.169.254`, `100.64/10`,
multicast, unspecified, IPv6 unique-local, and IPv4 hidden inside
`::ffff:a.b.c.d`, NAT64 and 6to4 forms. A name with one public and one private
answer is refused. Only 307 and 308 redirects are followed (the body and
signature are replayed), at most 3, and each hop goes through the same check.
Redirects that would turn the POST into a GET are failures. A refused target is
dead on the first attempt: retrying cannot change the answer.

`RELAY_ALLOW_NETWORKS` (CIDRs, empty by default) opens specific private ranges
for receivers inside your own network. The tests use `127.0.0.1/32`.

## Numbers

All measured on one laptop with the receiver in the same process, so they say
something about the relay's overhead and nothing about the internet.

| What | Result |
|---|---|
| Tests | 75, about 28 s, real Postgres and real sockets |
| Enqueue | about 845 events/s, one connection |
| Delivery, 4 workers, batch 25 | about 242 deliveries/s, 2,000 delivered, 0 duplicates |
| 5 workers, 60 events | each delivered once, no duplicate ids at the receiver |
| Killed worker | event delivered twice (attempts = 2), same delivery id both times |

## Running it

```
docker compose up --build        # db, api on :8000, two workers
curl -X POST localhost:8000/endpoints -H 'Authorization: Bearer change-me' \
  -H 'content-type: application/json' -d '{"url":"https://example.com/hook","ordered":true}'
```

Tests need a Postgres database. `TEST_DATABASE_URL` defaults to
`postgresql+asyncpg://postgres:postgres@localhost:5432/webhook_relay_test`, so point it at your own.

```
uv sync && uv run ruff check . && uv run pytest
```

Endpoints: `POST /endpoints`, `POST /endpoints/{id}/events`,
`POST /endpoints/{id}/enable`, `GET /deliveries/{id}` (with every attempt),
`GET /dead-letters`, `POST /deliveries/{id}/redeliver`.

## Where this stops

- At least once, never exactly once. A worker killed after the receiver
  answered and before the row was written sends again. That is the duplicate in
  the table above.
- An ordered endpoint is head-of-line blocked: one failing event holds the
  rest until it succeeds or goes dead. When it goes dead the later events
  proceed, so a manual redelivery arrives out of order. Publishing to an
  ordered endpoint is serialised per endpoint by the lock.
- Auto-disable counts attempts, and requests already in flight when the
  threshold trips still go out.
- Any non-2xx is retried, including 400 and 410. There is no permanent-failure
  list.
- Secrets are stored as plain text, since the relay needs them to sign. There is
  no API to rotate one, although the signing code accepts several.
- Workers poll, there is no `LISTEN/NOTIFY`. With the default 0.5 s poll an idle
  system adds up to half a second.
- Redirects are checked as addresses, but a 307 to a public host is followed
  with the same signature and body, which is intended and worth knowing.
- No metrics, no per-customer rate limit, no payload size limit on `POST`.
