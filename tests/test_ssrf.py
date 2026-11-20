import ipaddress

import pytest

from relay.ssrf import Policy, UnsafeTarget, check_url


def fake_resolver(table):
    async def resolve(host, port):
        return table[host]

    return resolve


PUBLIC = "93.184.216.34"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://127.1.2.3/hook",
        "http://localhost/hook",
        "http://10.0.0.5/hook",
        "http://172.16.9.9/hook",
        "http://192.168.1.1/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/hook",
        "http://0.0.0.0/hook",
        "http://[::1]/hook",
        "http://[fe80::1]/hook",
        "http://[fd00::1]/hook",
        "http://[::ffff:127.0.0.1]/hook",
        "http://[::ffff:10.0.0.1]/hook",
        "http://[64:ff9b::7f00:1]/hook",
        "http://[2002:7f00:1::]/hook",
        "http://224.0.0.1/hook",
    ],
)
async def test_non_public_literals_refused(url):
    policy = Policy(resolver=fake_resolver({"localhost": ["127.0.0.1", "::1"]}))
    with pytest.raises(UnsafeTarget):
        await check_url(url, policy)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/x",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http://user:pw@example.com/",
        "http:///nohost",
        "http://example.com:99999/",
    ],
)
async def test_bad_shapes_refused(url):
    policy = Policy(resolver=fake_resolver({"example.com": [PUBLIC]}))
    with pytest.raises(UnsafeTarget):
        await check_url(url, policy)


async def test_decimal_and_hex_loopback_forms():
    # Python's ipaddress does not parse these, so they fall through to the
    # resolver. The system resolver turns them into 127.0.0.1, which is refused.
    policy = Policy(resolver=fake_resolver({"2130706433": ["127.0.0.1"], "0x7f.1": ["127.0.0.1"]}))
    for host in ("2130706433", "0x7f.1"):
        with pytest.raises(UnsafeTarget):
            await check_url(f"http://{host}/", policy)


async def test_name_with_one_private_answer_is_refused():
    policy = Policy(resolver=fake_resolver({"mixed.test": [PUBLIC, "10.1.1.1"]}))
    with pytest.raises(UnsafeTarget, match="10.1.1.1"):
        await check_url("https://mixed.test/hook", policy)


async def test_public_name_passes_and_is_pinned():
    policy = Policy(resolver=fake_resolver({"hooks.example.com": [PUBLIC]}))
    target = await check_url("https://hooks.example.com/in?x=1", policy)
    assert target.ip == PUBLIC
    assert target.connect_url == f"https://{PUBLIC}:443/in?x=1"
    assert target.host_header == "hooks.example.com"


async def test_non_default_port_in_host_header():
    policy = Policy(resolver=fake_resolver({"hooks.example.com": [PUBLIC]}))
    target = await check_url("http://hooks.example.com:8080/", policy)
    assert target.host_header == "hooks.example.com:8080"


async def test_allow_list_only_opens_what_it_names():
    policy = Policy(allow_networks=[ipaddress.ip_network("127.0.0.1/32")])
    await check_url("http://127.0.0.1:9000/", policy)
    with pytest.raises(UnsafeTarget):
        await check_url("http://127.0.0.2:9000/", policy)
    with pytest.raises(UnsafeTarget):
        await check_url("http://169.254.169.254/", policy)


async def test_unresolvable_name_is_refused():
    with pytest.raises(UnsafeTarget):
        await check_url("http://no-such-host.invalid/", Policy())
