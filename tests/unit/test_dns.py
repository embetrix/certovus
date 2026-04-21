"""Unit tests for broker/dns/ — CloudflareDNS and MockDNS."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from broker.dns import challenge_record_name
from broker.dns.cloudflare import CloudflareDNS, _txt_value_visible
from broker.dns.mock import MockDNS, _fqdn
from broker.errors import DNSError

# ── challenge_record_name helper ──────────────────────────────────────────────


def test_challenge_record_name():
    assert challenge_record_name("dev-01.embetrix.works") == "_acme-challenge.dev-01.embetrix.works"


def test_challenge_record_name_preserves_subdomains():
    assert challenge_record_name("a.b.c") == "_acme-challenge.a.b.c"


# ── MockDNS ───────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_dns():
    return MockDNS("http://challtestsrv:8055", propagation_wait=0)


class TestMockDNS:
    def test_set_txt_posts_to_set_txt_endpoint(self, mock_dns):
        with patch("broker.dns.mock.requests.post") as mock_post:
            mock_post.return_value.raise_for_status = MagicMock()
            mock_dns.set_txt("dev-01.embetrix.works", "challenge-value")
            mock_post.assert_called_once_with(
                "http://challtestsrv:8055/set-txt",
                json={
                    "host": "_acme-challenge.dev-01.embetrix.works.",
                    "value": "challenge-value",
                },
                timeout=10,
            )

    def test_delete_txt_posts_to_clear_txt_endpoint(self, mock_dns):
        with patch("broker.dns.mock.requests.post") as mock_post:
            mock_post.return_value.raise_for_status = MagicMock()
            mock_dns.delete_txt("dev-01.embetrix.works")
            mock_post.assert_called_once_with(
                "http://challtestsrv:8055/clear-txt",
                json={"host": "_acme-challenge.dev-01.embetrix.works."},
                timeout=10,
            )

    def test_set_txt_wraps_request_error_as_dns_error(self, mock_dns):
        import requests as req_lib
        with patch("broker.dns.mock.requests.post", side_effect=req_lib.ConnectionError("refused")):
            with pytest.raises(DNSError, match="challtestsrv"):
                mock_dns.set_txt("dev-01.embetrix.works", "val")

    def test_delete_txt_wraps_http_error_as_dns_error(self, mock_dns):
        import requests as req_lib
        with patch("broker.dns.mock.requests.post", side_effect=req_lib.ConnectionError("refused")):
            with pytest.raises(DNSError):
                mock_dns.delete_txt("dev-01.embetrix.works")

    def test_wait_for_propagation_sleeps_configured_duration(self):
        dns = MockDNS("http://challtestsrv:8055", propagation_wait=0.05)
        import time
        start = time.monotonic()
        dns.wait_for_propagation("dev-01.embetrix.works", "val")
        assert time.monotonic() - start >= 0.04

    def test_wait_for_propagation_zero_returns_immediately(self, mock_dns):
        import time
        start = time.monotonic()
        mock_dns.wait_for_propagation("dev-01.embetrix.works", "val")
        assert time.monotonic() - start < 0.1

    def test_set_txt_trailing_dot_added(self, mock_dns):
        with patch("broker.dns.mock.requests.post") as mock_post:
            mock_post.return_value.raise_for_status = MagicMock()
            mock_dns.set_txt("dev-01.embetrix.works", "v")
            payload = mock_post.call_args.kwargs["json"]
            assert payload["host"].endswith(".")


# ── _fqdn helper ──────────────────────────────────────────────────────────────


def test_fqdn_adds_trailing_dot():
    assert _fqdn("example.com") == "example.com."


def test_fqdn_does_not_double_dot():
    assert _fqdn("example.com.") == "example.com."


# ── CloudflareDNS ─────────────────────────────────────────────────────────────


def _make_cf_dns(**kwargs) -> tuple[CloudflareDNS, MagicMock]:
    """Return a CloudflareDNS instance with a mocked Cloudflare client."""
    with patch("broker.dns.cloudflare.cf_sdk.Cloudflare") as MockClient:
        instance = MockClient.return_value
        dns = CloudflareDNS(
            api_token="tok",
            zone_id="zone123",
            propagation_timeout=kwargs.get("propagation_timeout", 10),
            poll_interval=kwargs.get("poll_interval", 1),
        )
        dns._client = instance
        return dns, instance


class TestCloudflareDNS:
    def test_set_txt_deletes_existing_then_creates(self):
        cf, client = _make_cf_dns()
        existing = MagicMock()
        existing.id = "rec1"
        client.dns.records.list.return_value = [existing]

        cf.set_txt("dev-01.embetrix.works", "new-value")

        client.dns.records.delete.assert_called_once_with("rec1", zone_id="zone123")
        client.dns.records.create.assert_called_once_with(
            zone_id="zone123",
            type="TXT",
            name="_acme-challenge.dev-01.embetrix.works",
            content="new-value",
            ttl=60,
        )

    def test_set_txt_creates_when_no_existing(self):
        cf, client = _make_cf_dns()
        client.dns.records.list.return_value = []

        cf.set_txt("dev-01.embetrix.works", "val")

        client.dns.records.delete.assert_not_called()
        client.dns.records.create.assert_called_once()

    def test_set_txt_wraps_api_error(self):
        import cloudflare as cf_sdk
        cf, client = _make_cf_dns()
        client.dns.records.list.return_value = []
        client.dns.records.create.side_effect = cf_sdk.APIError(
            "rate limited", MagicMock(), body=None
        )
        with pytest.raises(DNSError, match="Cloudflare set_txt"):
            cf.set_txt("dev-01.embetrix.works", "val")

    def test_delete_txt_removes_all_matching_records(self):
        cf, client = _make_cf_dns()
        r1, r2 = MagicMock(id="a"), MagicMock(id="b")
        client.dns.records.list.return_value = [r1, r2]

        cf.delete_txt("dev-01.embetrix.works")

        assert client.dns.records.delete.call_count == 2
        client.dns.records.delete.assert_any_call("a", zone_id="zone123")
        client.dns.records.delete.assert_any_call("b", zone_id="zone123")

    def test_delete_txt_is_idempotent_when_no_records(self):
        cf, client = _make_cf_dns()
        client.dns.records.list.return_value = []
        cf.delete_txt("dev-01.embetrix.works")
        client.dns.records.delete.assert_not_called()

    def test_wait_for_propagation_returns_when_record_visible(self):
        cf, _ = _make_cf_dns(propagation_timeout=10, poll_interval=0)
        with patch("broker.dns.cloudflare._txt_value_visible", return_value=True):
            cf.wait_for_propagation("dev-01.embetrix.works", "val")

    def test_wait_for_propagation_raises_on_timeout(self):
        cf, _ = _make_cf_dns(propagation_timeout=0, poll_interval=0)
        with patch("broker.dns.cloudflare._txt_value_visible", return_value=False):
            with pytest.raises(DNSError, match="did not propagate"):
                cf.wait_for_propagation("dev-01.embetrix.works", "val")


# ── _txt_value_visible ────────────────────────────────────────────────────────


class TestTxtValueVisible:
    def test_returns_true_when_value_matches(self):
        rdata = MagicMock()
        rdata.strings = [b"expected-value"]
        answers = [rdata]
        resolver = MagicMock()
        resolver.resolve.return_value = answers
        assert _txt_value_visible(resolver, "_acme-challenge.x.com", "expected-value") is True

    def test_returns_false_when_value_mismatches(self):
        rdata = MagicMock()
        rdata.strings = [b"other-value"]
        resolver = MagicMock()
        resolver.resolve.return_value = [rdata]
        assert _txt_value_visible(resolver, "_acme-challenge.x.com", "expected") is False

    def test_returns_false_on_dns_exception(self):
        import dns.exception
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException()
        assert _txt_value_visible(resolver, "_acme-challenge.x.com", "val") is False
