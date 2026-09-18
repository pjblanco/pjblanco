"""Generate a temporary self-signed certificate for local/LAN testing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def generate_certificate(cert: str, key: str, days: int = 30) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL was not found on PATH")
    cert_path = Path(cert)
    key_path = Path(key)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        str(days),
        "-subj",
        "/CN=consent-remote-support",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        key_path.chmod(0o600)
    except OSError:
        # Windows uses ACLs; the caller is responsible for protecting the key there.
        pass
