import pytest

from relay import signing

BODY = b'{"id":"evt_1","type":"invoice.paid"}'


def test_round_trip():
    header = signing.sign("s3cret", BODY, timestamp=1_000_000)
    signing.verify("s3cret", BODY, header, now=1_000_000)


def test_wrong_secret_rejected():
    header = signing.sign("s3cret", BODY, timestamp=1_000_000)
    with pytest.raises(signing.SignatureError):
        signing.verify("other", BODY, header, now=1_000_000)


def test_one_changed_byte_rejected():
    header = signing.sign("s3cret", BODY, timestamp=1_000_000)
    with pytest.raises(signing.SignatureError):
        signing.verify("s3cret", BODY.replace(b"paid", b"Paid"), header, now=1_000_000)


def test_old_timestamp_is_a_replay():
    header = signing.sign("s3cret", BODY, timestamp=1_000_000)
    signing.verify("s3cret", BODY, header, tolerance=300, now=1_000_300)
    with pytest.raises(signing.SignatureError, match="tolerance"):
        signing.verify("s3cret", BODY, header, tolerance=300, now=1_000_301)


def test_future_timestamp_is_rejected_too():
    header = signing.sign("s3cret", BODY, timestamp=1_001_000)
    with pytest.raises(signing.SignatureError, match="tolerance"):
        signing.verify("s3cret", BODY, header, tolerance=300, now=1_000_000)


def test_moving_the_timestamp_breaks_the_signature():
    header = signing.sign("s3cret", BODY, timestamp=1_000_000)
    forged = header.replace("t=1000000", "t=1000100")
    with pytest.raises(signing.SignatureError, match="no signature"):
        signing.verify("s3cret", BODY, forged, now=1_000_100)


def test_rotation_accepts_either_secret():
    header = signing.sign(["old", "new"], BODY, timestamp=1_000_000)
    signing.verify("old", BODY, header, now=1_000_000)
    signing.verify("new", BODY, header, now=1_000_000)


@pytest.mark.parametrize("header", ["", "v1=abc", "t=12", "t=x,v1=abc", "garbage"])
def test_malformed_headers(header):
    with pytest.raises(signing.SignatureError):
        signing.verify("s3cret", BODY, header, now=12)


def test_comparison_is_constant_time_call(monkeypatch):
    calls = []
    real = signing.hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(signing.hmac, "compare_digest", spy)
    header = signing.sign(["a", "b", "c"], BODY, timestamp=5)
    signing.verify("a", BODY, header, now=5)
    assert len(calls) == 3
