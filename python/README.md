# Consent-based remote support — single-file version

[`remote_support.py`](remote_support.py) is a security-first, read-only remote-support prototype. It provides screen sharing over TLS only after the person at the host explicitly approves the session.

It intentionally does **not** provide stealth, persistence, security-control bypasses, privilege escalation, remote shell/command execution, keyboard or mouse injection, unattended access, or file transfer.

## Security properties

- A fresh six-digit pairing code is generated for every host run and expires after five minutes.
- The code is single-use and is never written to disk.
- TLS 1.2 or newer is mandatory.
- The viewer pins the host certificate fingerprint, protecting against a man-in-the-middle when the fingerprint is verified out of band.
- The host displays a consent prompt before any frame is captured or sent.
- Only one session is allowed at a time.
- The host shows a visible session banner and records JSON audit events.
- Stopping either side ends the session. No background service or installer is included.

## Requirements

Python 3.11+, Pillow, and OpenSSL for certificate generation:

```bash
cd python
python -m pip install Pillow
```

On Linux, the host's desktop session must permit screenshots. Wayland desktops may require a portal or desktop-specific permission; the program reports a capture error instead of attempting to bypass it.

## Quick start

### 1. Create a temporary host certificate

Run this on the host computer. Protect the private key so only the host user can read it.

```bash
python remote_support.py cert --cert host-cert.pem --key host-key.pem
```

On Windows, protect the key using filesystem ACLs instead of `chmod`.

### 2. Start a host session

```bash
python remote_support.py host \
  --cert host-cert.pem \
  --key host-key.pem \
  --bind 0.0.0.0 \
  --port 8765
```

The host prints an address, certificate fingerprint, and one-time pairing code. Share those values with the trusted viewer through a separate channel. Do not post them publicly. Approve the viewer at the host prompt when the identity is expected.

Use a firewall or VPN to restrict port `8765` to the viewer's network. Do not port-forward this prototype directly to the public internet.

### 3. Connect a viewer

```bash
python remote_support.py viewer \
  --host 192.168.1.20 \
  --port 8765 \
  --code 123456 \
  --fingerprint SHA256_FINGERPRINT_FROM_HOST
```

The default viewer opens a small window and writes the latest received frame to `session-output/latest.jpg`. For a terminal-only session:

```bash
python remote_support.py viewer \
  --host 192.168.1.20 \
  --port 8765 \
  --code 123456 \
  --fingerprint SHA256_FINGERPRINT_FROM_HOST \
  --headless \
  --output ./session-output
```

The fingerprint may be copied with or without colons. The viewer refuses to continue if it does not exactly match the certificate presented by the host.

This is an intentionally limited foundation for a legitimate support workflow. Before production use, add a reviewed identity system, a managed relay with end-to-end encryption, OS-specific consent UX, device management, and a formal security review.
