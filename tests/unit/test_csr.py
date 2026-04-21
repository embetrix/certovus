"""Unit tests for broker/csr.py."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from broker.csr import ParsedCSR, parse_csr, validate_hostnames
from broker.errors import CSRError, HostnameDeniedError


# ── CSR generation helpers ────────────────────────────────────────────────────


def _make_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _make_csr(
    cn: str,
    sans: list[str] | None = None,
    extra_sans: list[x509.GeneralName] | None = None,
    key: ec.EllipticCurvePrivateKey | None = None,
) -> str:
    """Generate a PEM CSR for testing."""
    if key is None:
        key = _make_key()
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    all_sans: list[x509.GeneralName] = [x509.DNSName(s) for s in (sans or [])]
    if extra_sans:
        all_sans.extend(extra_sans)
    if all_sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(all_sans), critical=False
        )
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(Encoding.PEM).decode()


def _tamper(pem: str) -> str:
    """Corrupt the last base64 body line (signature bytes) to make the CSR invalid."""
    lines = pem.strip().splitlines()
    # lines[0]  = -----BEGIN CERTIFICATE REQUEST-----
    # lines[-1] = -----END CERTIFICATE REQUEST-----
    # lines[-2] = last body line — contains the trailing signature bytes
    last_body = lines[-2]
    corrupted = last_body[:-4] + ("AAAA" if last_body[-4:] != "AAAA" else "BBBB")
    lines[-2] = corrupted
    return "\n".join(lines) + "\n"


# ── parse_csr ─────────────────────────────────────────────────────────────────


class TestParseCsr:
    def test_valid_cn_only(self):
        pem = _make_csr("dev-01.embetrix.works")
        result = parse_csr(pem)
        assert isinstance(result, ParsedCSR)
        assert result.cn == "dev-01.embetrix.works"
        assert result.sans == []
        assert result.requested_names == ["dev-01.embetrix.works"]

    def test_valid_with_sans(self):
        pem = _make_csr(
            "dev-01.embetrix.works",
            sans=["dev-01.embetrix.works", "alt.embetrix.works"],
        )
        result = parse_csr(pem)
        assert result.cn == "dev-01.embetrix.works"
        assert result.sans == ["dev-01.embetrix.works", "alt.embetrix.works"]

    def test_requested_names_deduplicates_cn_and_sans(self):
        # CN also appears as the first SAN — common in real device certs
        pem = _make_csr(
            "dev-01.embetrix.works",
            sans=["dev-01.embetrix.works", "alt.embetrix.works"],
        )
        result = parse_csr(pem)
        assert result.requested_names == ["dev-01.embetrix.works", "alt.embetrix.works"]
        assert len(result.requested_names) == 2

    def test_requested_names_cn_first_when_not_in_sans(self):
        pem = _make_csr("dev-01.embetrix.works", sans=["alt.embetrix.works"])
        result = parse_csr(pem)
        assert result.requested_names == ["dev-01.embetrix.works", "alt.embetrix.works"]

    def test_csr_hash_is_sha256_hex(self):
        pem = _make_csr("dev-01.embetrix.works")
        result = parse_csr(pem)
        assert len(result.csr_hash) == 64
        assert all(c in "0123456789abcdef" for c in result.csr_hash)

    def test_csr_hash_is_stable(self):
        pem = _make_csr("dev-01.embetrix.works")
        assert parse_csr(pem).csr_hash == parse_csr(pem).csr_hash

    def test_same_key_same_csr_same_hash(self):
        key = _make_key()
        pem = _make_csr("dev-01.embetrix.works", key=key)
        assert parse_csr(pem).csr_hash == parse_csr(pem).csr_hash

    def test_pem_is_stripped(self):
        pem = "  \n" + _make_csr("dev-01.embetrix.works") + "\n  "
        result = parse_csr(pem)
        assert result.pem == pem.strip()

    def test_empty_pem_raises(self):
        with pytest.raises(CSRError, match="empty"):
            parse_csr("")

    def test_whitespace_only_raises(self):
        with pytest.raises(CSRError, match="empty"):
            parse_csr("   \n  ")

    def test_garbage_raises(self):
        with pytest.raises(CSRError, match="failed to parse"):
            parse_csr("not a csr at all")

    def test_invalid_signature_raises(self):
        # Tampered CSR raises CSRError — exact message depends on where corruption lands.
        pem = _tamper(_make_csr("dev-01.embetrix.works"))
        with pytest.raises(CSRError):
            parse_csr(pem)

    def test_ip_san_raises(self):
        import ipaddress
        pem = _make_csr(
            "dev-01.embetrix.works",
            extra_sans=[x509.IPAddress(ipaddress.IPv4Address("192.168.1.1"))],
        )
        with pytest.raises(CSRError, match="non-DNS SAN"):
            parse_csr(pem)

    def test_email_san_raises(self):
        pem = _make_csr(
            "dev-01.embetrix.works",
            extra_sans=[x509.RFC822Name("user@example.com")],
        )
        with pytest.raises(CSRError, match="non-DNS SAN"):
            parse_csr(pem)


# ── validate_hostnames ────────────────────────────────────────────────────────


class TestValidateHostnames:
    def _parsed(self, cn: str, sans: list[str] | None = None) -> ParsedCSR:
        return parse_csr(_make_csr(cn, sans=sans))

    def test_cn_in_allowlist_passes(self):
        p = self._parsed("dev-01.embetrix.works")
        validate_hostnames(p, ["dev-01.embetrix.works"])

    def test_cn_and_sans_all_allowed_passes(self):
        p = self._parsed(
            "dev-01.embetrix.works",
            sans=["dev-01.embetrix.works", "alt.embetrix.works"],
        )
        validate_hostnames(p, ["dev-01.embetrix.works", "alt.embetrix.works"])

    def test_cn_not_in_allowlist_raises(self):
        p = self._parsed("dev-01.embetrix.works")
        with pytest.raises(HostnameDeniedError, match="dev-01.embetrix.works"):
            validate_hostnames(p, ["dev-99.embetrix.works"])

    def test_san_not_in_allowlist_raises(self):
        p = self._parsed(
            "dev-01.embetrix.works",
            sans=["dev-01.embetrix.works", "evil.example.com"],
        )
        with pytest.raises(HostnameDeniedError, match="evil.example.com"):
            validate_hostnames(p, ["dev-01.embetrix.works"])

    def test_empty_allowlist_raises(self):
        p = self._parsed("dev-01.embetrix.works")
        with pytest.raises(HostnameDeniedError):
            validate_hostnames(p, [])

    def test_superset_allowlist_passes(self):
        p = self._parsed("dev-01.embetrix.works")
        validate_hostnames(p, ["dev-01.embetrix.works", "dev-02.embetrix.works"])

    def test_exact_match_only_no_wildcards(self):
        p = self._parsed("sub.dev-01.embetrix.works")
        with pytest.raises(HostnameDeniedError):
            validate_hostnames(p, ["dev-01.embetrix.works"])
