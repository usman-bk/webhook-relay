"""Decide whether a customer supplied URL may be called.

The check runs on addresses, not names: the host is resolved, every answer is
tested, and the caller connects to the address that was tested. Testing a name
and then letting the HTTP client resolve it again is the DNS rebinding hole.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

IP = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

NAT64 = ipaddress.ip_network("64:ff9b::/96")
SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


class UnsafeTarget(Exception):
    """The URL points somewhere a customer must not be able to make us call."""


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"cannot resolve {host}") from exc
    seen: list[str] = []
    for info in infos:
        addr = info[4][0].split("%")[0]
        if addr not in seen:
            seen.append(addr)
    return seen


def networks_from(text: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(p.strip()) for p in text.split(",") if p.strip()]


@dataclass
class Policy:
    resolver: Resolver = system_resolver
    # Networks that are allowed even though they are not public. Empty in
    # production. The tests allow 127.0.0.1/32 so a local receiver can be reached.
    allow_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list
    )
    allowed_schemes: tuple[str, ...] = ("http", "https")

    def address_ok(self, ip: IP) -> bool:
        for net in self.allow_networks:
            if ip.version == net.version and ip in net:
                return True
        return _is_public(ip)


def _is_public(ip: IP) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _is_public(ip.ipv4_mapped)
        if ip in NAT64:
            return _is_public(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip in SIX_TO_FOUR:
            return _is_public(ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF))
    return ip.is_global and not ip.is_multicast


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str  # path and query, always starting with /
    ip: str  # the address that passed the check

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def connect_url(self) -> str:
        ip = f"[{self.ip}]" if ":" in self.ip else self.ip
        return f"{self.scheme}://{ip}:{self.port}{self.path}"


async def check_url(url: str, policy: Policy) -> Target:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeTarget(f"not a valid URL: {exc}") from exc
    if parts.scheme not in policy.allowed_schemes:
        raise UnsafeTarget(f"scheme {parts.scheme!r} is not allowed")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTarget("credentials in the URL are not allowed")
    host = parts.hostname
    if not host:
        raise UnsafeTarget("URL has no host")
    if port is None:
        port = 443 if parts.scheme == "https" else 80

    try:
        literal: IP | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    addresses = [str(literal)] if literal else await policy.resolver(host, port)
    if not addresses:
        raise UnsafeTarget(f"{host} resolved to nothing")

    # Every answer must be fine. A name with one public and one private record
    # is refused, because the client may pick either.
    for addr in addresses:
        if not policy.address_ok(ipaddress.ip_address(addr)):
            raise UnsafeTarget(f"{host} resolves to {addr}, which is not a public address")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(parts.scheme, host, port, path, addresses[0])
