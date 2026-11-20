"""HMAC-SHA256 signatures over `<timestamp>.<raw body>`.

The header looks like `t=1767225600,v1=<hex>`. Several `v1=` parts may be
present so a secret can be rotated: the receiver accepts the request if any of
them matches.
"""

from __future__ import annotations

import hashlib
import hmac
import time

HEADER = "X-Relay-Signature"
DEFAULT_TOLERANCE = 300


class SignatureError(Exception):
    pass


def _mac(secret: str, timestamp: int, body: bytes) -> str:
    msg = str(timestamp).encode() + b"." + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def sign(secret: str | list[str], body: bytes, timestamp: int | None = None) -> str:
    ts = int(time.time()) if timestamp is None else timestamp
    secrets = [secret] if isinstance(secret, str) else secret
    parts = [f"t={ts}"] + [f"v1={_mac(s, ts, body)}" for s in secrets]
    return ",".join(parts)


def parse(header: str) -> tuple[int, list[str]]:
    ts: int | None = None
    sigs: list[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                ts = int(value)
            except ValueError:
                raise SignatureError("timestamp is not a number") from None
        elif key == "v1":
            sigs.append(value)
    if ts is None or not sigs:
        raise SignatureError("header needs a timestamp and at least one v1 signature")
    return ts, sigs


def verify(
    secret: str,
    body: bytes,
    header: str,
    tolerance: int = DEFAULT_TOLERANCE,
    now: float | None = None,
) -> None:
    """Raise SignatureError unless the header is a fresh, valid signature of body."""
    ts, sigs = parse(header)
    current = time.time() if now is None else now
    # Both directions: a timestamp far in the future is as suspect as an old one.
    if abs(current - ts) > tolerance:
        raise SignatureError("timestamp outside the tolerance window")
    expected = _mac(secret, ts, body)
    # Check every candidate, never stop at the first, so timing says nothing.
    ok = False
    for candidate in sigs:
        if hmac.compare_digest(candidate.encode(), expected.encode()):
            ok = True
    if not ok:
        raise SignatureError("no signature matches")
