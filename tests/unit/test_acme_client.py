"""Unit tests for broker/acme_client.py.

All ACME network I/O and DNS provider calls are mocked — no real network needed.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import josepy
import pytest
from acme import challenges, errors as acme_errors, messages
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from broker.acme_client import (
    ACMEClient,
    _answer_all,
    _collect_dns01_challenges,
    _delete_all_txt,
    _set_all_txt,
    _wait_all_propagation,
)
from broker.errors import ACMEError


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def key_path(tmp_path) -> Path:
    return tmp_path / "account.key"


@pytest.fixture
def client(key_path) -> ACMEClient:
    return ACMEClient(
        directory_url="https://pebble:14000/dir",
        account_key_path=str(key_path),
        verify_ssl=False,
    )


def _make_ec_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _make_challb(domain: str):
    """Return a fake (domain, challb, response, validation) tuple."""
    return (domain, MagicMock(), MagicMock(), f"validation-for-{domain}")


def _make_order(*domains: str):
    """Return a fake OrderResource with one DNS-01 challenge per domain."""
    authzrs = []
    for domain in domains:
        dns01_chall = MagicMock(spec=challenges.DNS01)
        dns01_chall.response_and_validation.return_value = (
            MagicMock(),
            f"validation-for-{domain}",
        )
        challb = MagicMock()
        challb.chall = dns01_chall
        authzr_body = MagicMock()
        authzr_body.identifier.value = domain
        authzr_body.challenges = [challb]
        authzr = MagicMock()
        authzr.body = authzr_body
        authzrs.append(authzr)
    order = MagicMock(spec=messages.OrderResource)
    order.authorizations = authzrs
    order.fullchain_pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
    order.uri = "https://pebble/order/1"
    return order


# ── Account key lifecycle ─────────────────────────────────────────────────────


class TestAccountKey:
    def test_creates_key_if_absent(self, client, key_path):
        jwk = client._load_or_create_account_key()
        assert key_path.exists()
        assert isinstance(jwk, josepy.JWKEC)

    def test_new_key_is_p256(self, client, key_path):
        client._load_or_create_account_key()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(key_path.read_bytes(), password=None)
        assert isinstance(key.curve, ec.SECP256R1)

    def test_new_key_has_0600_permissions(self, client, key_path):
        client._load_or_create_account_key()
        mode = stat.S_IMODE(key_path.stat().st_mode)
        assert mode == 0o600

    def test_loads_existing_key(self, client, key_path):
        pem = _make_ec_pem()
        key_path.write_bytes(pem)
        key_path.chmod(0o600)
        jwk = client._load_or_create_account_key()
        assert isinstance(jwk, josepy.JWKEC)

    def test_idempotent_second_load(self, client, key_path):
        jwk1 = client._load_or_create_account_key()
        jwk2 = client._load_or_create_account_key()
        assert jwk1.key.private_numbers() == jwk2.key.private_numbers()

    def test_non_ec_key_raises(self, client, key_path):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        rsa_key = rsa.generate_private_key(65537, 2048, default_backend())
        pem = rsa_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        key_path.write_bytes(pem)
        with pytest.raises(ACMEError, match="not an EC key"):
            client._load_or_create_account_key()

    def test_corrupt_key_raises(self, client, key_path):
        key_path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnotbase64!!!\n-----END PRIVATE KEY-----\n")
        with pytest.raises(ACMEError, match="failed to load account key"):
            client._load_or_create_account_key()

    def test_creates_parent_directories(self, tmp_path):
        deep_path = tmp_path / "a" / "b" / "c" / "account.key"
        c = ACMEClient("https://x", str(deep_path))
        c._load_or_create_account_key()
        assert deep_path.exists()


# ── _collect_dns01_challenges ─────────────────────────────────────────────────


class TestCollectDns01Challenges:
    def test_returns_one_tuple_per_domain(self):
        order = _make_order("a.example.com", "b.example.com")
        account_key = MagicMock()
        result = _collect_dns01_challenges(order, account_key)
        assert len(result) == 2
        assert result[0][0] == "a.example.com"
        assert result[1][0] == "b.example.com"

    def test_validation_string_in_tuple(self):
        order = _make_order("x.example.com")
        result = _collect_dns01_challenges(order, MagicMock())
        domain, challb, response, validation = result[0]
        assert validation == "validation-for-x.example.com"

    def test_missing_dns01_raises(self):
        authzr_body = MagicMock()
        authzr_body.identifier.value = "bad.example.com"
        authzr_body.challenges = [MagicMock()]
        authzr_body.challenges[0].chall = MagicMock()  # not DNS01
        authzr = MagicMock()
        authzr.body = authzr_body
        order = MagicMock()
        order.authorizations = [authzr]
        with pytest.raises(ACMEError, match="no DNS-01 challenge"):
            _collect_dns01_challenges(order, MagicMock())


# ── _set_all_txt ──────────────────────────────────────────────────────────────


class TestSetAllTxt:
    def test_calls_set_txt_for_each_domain(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        provider = MagicMock()
        _set_all_txt(challbs, provider)
        provider.set_txt.assert_any_call("a.example.com", "validation-for-a.example.com")
        provider.set_txt.assert_any_call("b.example.com", "validation-for-b.example.com")

    def test_cleans_up_previous_on_failure(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        provider = MagicMock()
        provider.set_txt.side_effect = [None, Exception("DNS API down")]
        with pytest.raises(ACMEError, match="failed to set DNS TXT"):
            _set_all_txt(challbs, provider)
        provider.delete_txt.assert_called_once_with("a.example.com")

    def test_cleanup_failure_does_not_mask_original_error(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        provider = MagicMock()
        provider.set_txt.side_effect = [None, Exception("primary error")]
        provider.delete_txt.side_effect = Exception("cleanup error")
        with pytest.raises(ACMEError, match="primary error"):
            _set_all_txt(challbs, provider)


# ── _wait_all_propagation ─────────────────────────────────────────────────────


class TestWaitAllPropagation:
    def test_calls_wait_for_each_domain(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        provider = MagicMock()
        _wait_all_propagation(challbs, provider)
        provider.wait_for_propagation.assert_any_call("a.example.com", "validation-for-a.example.com")
        provider.wait_for_propagation.assert_any_call("b.example.com", "validation-for-b.example.com")

    def test_propagation_timeout_raises_acme_error(self):
        challbs = [_make_challb("slow.example.com")]
        provider = MagicMock()
        provider.wait_for_propagation.side_effect = TimeoutError("timed out")
        with pytest.raises(ACMEError, match="DNS propagation timed out"):
            _wait_all_propagation(challbs, provider)


# ── _answer_all ───────────────────────────────────────────────────────────────


class TestAnswerAll:
    def test_calls_answer_challenge_for_each(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        acme = MagicMock()
        _answer_all(challbs, acme)
        assert acme.answer_challenge.call_count == 2

    def test_acme_error_wrapped(self):
        challbs = [_make_challb("a.example.com")]
        acme = MagicMock()
        acme.answer_challenge.side_effect = acme_errors.Error("bad challenge")
        with pytest.raises(ACMEError, match="failed to answer ACME challenge"):
            _answer_all(challbs, acme)


# ── _delete_all_txt ───────────────────────────────────────────────────────────


class TestDeleteAllTxt:
    def test_calls_delete_for_each_domain(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        provider = MagicMock()
        _delete_all_txt(challbs, provider)
        provider.delete_txt.assert_any_call("a.example.com")
        provider.delete_txt.assert_any_call("b.example.com")

    def test_never_raises_on_failure(self):
        challbs = [_make_challb("a.example.com")]
        provider = MagicMock()
        provider.delete_txt.side_effect = Exception("DNS down")
        _delete_all_txt(challbs, provider)  # must not raise

    def test_continues_after_partial_failure(self):
        challbs = [_make_challb("a.example.com"), _make_challb("b.example.com")]
        provider = MagicMock()
        provider.delete_txt.side_effect = [Exception("first fails"), None]
        _delete_all_txt(challbs, provider)
        assert provider.delete_txt.call_count == 2


# ── ACMEClient.issue ──────────────────────────────────────────────────────────


def _patched_client(client: ACMEClient, order: MagicMock):
    """Patch _get_client() to return a mock acme ClientV2."""
    acme_mock = MagicMock()
    acme_mock.new_order.return_value = order
    acme_mock.poll_and_finalize.return_value = order
    acme_mock.net.key = MagicMock()
    client._acme = acme_mock
    return acme_mock


class TestIssue:
    def test_returns_fullchain_pem(self, client):
        order = _make_order("dev.example.com")
        acme_mock = _patched_client(client, order)
        provider = MagicMock()
        result = client.issue("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----", provider)
        assert result == order.fullchain_pem

    def test_set_before_wait_before_answer(self, client):
        order = _make_order("dev.example.com")
        _patched_client(client, order)
        provider = MagicMock()
        call_log: list[str] = []
        provider.set_txt.side_effect = lambda *a: call_log.append("set")
        provider.wait_for_propagation.side_effect = lambda *a: call_log.append("wait")
        provider.delete_txt.side_effect = lambda *a: call_log.append("delete")
        client._acme.answer_challenge.side_effect = lambda *a: call_log.append("answer")
        client.issue("fake_csr", provider)
        set_idx = call_log.index("set")
        wait_idx = call_log.index("wait")
        answer_idx = call_log.index("answer")
        delete_idx = call_log.index("delete")
        assert set_idx < wait_idx < answer_idx < delete_idx

    def test_txt_cleanup_on_answer_failure(self, client):
        order = _make_order("dev.example.com")
        acme_mock = _patched_client(client, order)
        acme_mock.answer_challenge.side_effect = acme_errors.Error("bad")
        provider = MagicMock()
        with pytest.raises(ACMEError):
            client.issue("fake_csr", provider)
        provider.delete_txt.assert_called_once_with("dev.example.com")

    def test_txt_cleanup_on_finalize_failure(self, client):
        order = _make_order("dev.example.com")
        acme_mock = _patched_client(client, order)
        acme_mock.poll_and_finalize.side_effect = acme_errors.Error("timeout")
        provider = MagicMock()
        with pytest.raises(ACMEError):
            client.issue("fake_csr", provider)
        provider.delete_txt.assert_called_once_with("dev.example.com")

    def test_txt_cleanup_on_propagation_failure(self, client):
        order = _make_order("dev.example.com")
        _patched_client(client, order)
        provider = MagicMock()
        provider.wait_for_propagation.side_effect = TimeoutError("slow")
        with pytest.raises(ACMEError):
            client.issue("fake_csr", provider)
        provider.delete_txt.assert_called_once_with("dev.example.com")

    def test_new_order_failure_raises(self, client):
        order = _make_order("dev.example.com")
        acme_mock = _patched_client(client, order)
        acme_mock.new_order.side_effect = acme_errors.Error("rejected")
        with pytest.raises(ACMEError, match="failed to create ACME order"):
            client.issue("fake_csr", MagicMock())

    def test_missing_fullchain_pem_raises(self, client):
        order = _make_order("dev.example.com")
        order.fullchain_pem = None
        _patched_client(client, order)
        with pytest.raises(ACMEError, match="no certificate was returned"):
            client.issue("fake_csr", MagicMock())

    def test_multi_domain_sets_all_txt(self, client):
        order = _make_order("a.example.com", "b.example.com", "c.example.com")
        _patched_client(client, order)
        provider = MagicMock()
        client.issue("fake_csr", provider)
        assert provider.set_txt.call_count == 3
        assert provider.delete_txt.call_count == 3


# ── ACMEClient.revoke ─────────────────────────────────────────────────────────


class TestRevoke:
    def _fake_cert_pem(self) -> str:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timedelta, timezone
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=90))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(Encoding.PEM).decode()

    def test_calls_acme_revoke(self, client):
        acme_mock = MagicMock()
        client._acme = acme_mock
        cert_pem = self._fake_cert_pem()
        client.revoke(cert_pem, reason=0)
        acme_mock.revoke.assert_called_once()

    def test_acme_error_wrapped(self, client):
        acme_mock = MagicMock()
        acme_mock.revoke.side_effect = acme_errors.ClientError("not authorized")
        client._acme = acme_mock
        cert_pem = self._fake_cert_pem()
        with pytest.raises(ACMEError, match="ACME revocation failed"):
            client.revoke(cert_pem)

    def test_unexpected_error_wrapped(self, client):
        acme_mock = MagicMock()
        acme_mock.revoke.side_effect = RuntimeError("unexpected")
        client._acme = acme_mock
        cert_pem = self._fake_cert_pem()
        with pytest.raises(ACMEError, match="revocation error"):
            client.revoke(cert_pem)
