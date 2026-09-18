"""Authentication and certificate-pinning helpers."""

from __future__ import annotations

import hashlib
import secrets
import ssl
import time
from dataclasses import dataclass


@dataclass
class PairingCode:
    """A short-lived, single-use pairing code kept only in process memory."""

    value: str
    expires_at: float
    used: bool = False

    @classmethod
    def create(cls, ttl_seconds: int = 300) -> "PairingCode":
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        value = f"{secrets.randbelow(1_000_000):06d}"
        return cls(value=value, expires_at=time.monotonic() + ttl_seconds)

    def consume(self, candidate: str) -> bool:
        """Constant-time compare, then invalidate the code on success."""
        if self.used or time.monotonic() >= self.expires_at:
            return False
        valid = secrets.compare_digest(self.value, candidate.strip())
        if valid:
            self.used = True
        return valid


def certificate_fingerprint(cert_file: str) -> str:
    """Return a colon-separated SHA-256 fingerprint for a PEM certificate."""
    with open(cert_file, "rb") as handle:
        pem = handle.read()
    try:
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"invalid PEM certificate: {cert_file}") from exc
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def peer_fingerprint(ssl_object: ssl.SSLObject) -> str:
    """Return the SHA-256 fingerprint of the certificate received from a peer."""
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        raise ValueError("peer did not present a certificate")
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def normalize_fingerprint(value: str) -> str:
    return "".join(value.split()).replace(":", "").lower()


def fingerprints_match(expected: str, actual: str) -> bool:
    return secrets.compare_digest(
        normalize_fingerprint(expected), normalize_fingerprint(actual)
    )
