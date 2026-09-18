import tempfile
import time
import unittest
from pathlib import Path

from remote_support.security import (
    PairingCode,
    certificate_fingerprint,
    fingerprints_match,
    normalize_fingerprint,
)


class PairingCodeTests(unittest.TestCase):
    def test_code_is_single_use(self) -> None:
        code = PairingCode.create(ttl_seconds=10)
        self.assertTrue(code.consume(code.value))
        self.assertFalse(code.consume(code.value))

    def test_code_expires(self) -> None:
        code = PairingCode.create(ttl_seconds=1)
        code.expires_at = time.monotonic() - 1
        self.assertFalse(code.consume(code.value))

    def test_wrong_code_does_not_consume(self) -> None:
        code = PairingCode.create(ttl_seconds=10)
        self.assertFalse(code.consume("000000" if code.value != "000000" else "111111"))
        self.assertTrue(code.consume(code.value))


class FingerprintTests(unittest.TestCase):
    def test_normalization(self) -> None:
        value = "AA:bb cc"
        self.assertEqual(normalize_fingerprint(value), "aabbcc")
        self.assertTrue(fingerprints_match("AA:BB", "aabb"))
        self.assertFalse(fingerprints_match("AA:BB", "aabbcc"))

    def test_certificate_fingerprint_reads_pem(self) -> None:
        # A tiny malformed file should fail clearly rather than silently disabling pinning.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pem"
            path.write_text("not a certificate", encoding="ascii")
            with self.assertRaises(ValueError):
                certificate_fingerprint(str(path))


if __name__ == "__main__":
    unittest.main()
