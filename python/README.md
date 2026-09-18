# Consent-based remote support — friendly GUI

[`remote_support.py`](remote_support.py) is a single-file, security-first remote-support prototype. It provides read-only screen sharing over TLS only after the person at the host explicitly approves the session.

It intentionally does **not** provide stealth, persistence, security-control bypasses, privilege escalation, remote shell/command execution, keyboard or mouse injection, unattended access, or file transfer.

## Requirements

Python 3.11+, Pillow, Tkinter, and OpenSSL for certificate generation:

```bash
cd python
python -m pip install Pillow
```

On Windows, use a Python installer that includes **Tkinter**. On Linux, install the distribution's Tk package if needed, commonly `python3-tk`.

On Linux, the host's desktop session must permit screenshots. Wayland desktops may require a portal or desktop-specific permission; the program reports a capture error instead of attempting to bypass it.

## Start the friendly interface

Run without arguments to open the desktop interface:

```bash
python remote_support.py
```

You can also run:

```bash
python remote_support.py gui
```

The interface has two tabs:

1. **Host a session**
   - Click **Start sharing**. A temporary TLS certificate is created automatically when needed.
   - Share the displayed IP address and session password with the trusted viewer.
   - Approve the incoming request in the consent dialog.
2. **Join a session**
   - Enter only the host IP address and session password.
   - On the first connection, review and accept the host certificate prompt. The GUI remembers that certificate for the current run.
   - Click **Connect**. The host must approve the request before frames are shown.

The host password is generated in memory, expires after five minutes by default, and is single-use. The private key should be protected so only the host user can read it.

Use a firewall or VPN to restrict the host port, which defaults to `8765`. Do not port-forward this prototype directly to the public internet.

## Build a Windows executable

Install PyInstaller:

```powershell
cd python
py -m pip install Pillow pyinstaller
```

Build a GUI executable:

```powershell
python -m PyInstaller `
  --clean `
  --noconfirm `
  --onefile `
  --windowed `
  --name SecureRemoteSupport `
  remote_support.py
```

The executable is created at:

```text
dist\SecureRemoteSupport.exe
```

Double-clicking it opens the friendly interface. Build on Windows to produce a Windows `.exe`; PyInstaller does not cross-compile between operating systems.

The automatic certificate setup uses OpenSSL. If OpenSSL is not installed, create `host-cert.pem` and `host-key.pem` separately before starting the host.

## Optional terminal mode

The same file retains terminal commands for automation and headless viewers:

```bash
python remote_support.py cert --cert host-cert.pem --key host-key.pem
python remote_support.py host --cert host-cert.pem --key host-key.pem
python remote_support.py viewer --host 192.168.1.20 --port 8765 \
  --code 123456 --fingerprint SHA256_FINGERPRINT_FROM_HOST --headless
```

Before production use, add a reviewed identity system, a managed relay with end-to-end encryption, OS-specific consent UX, device management, and a formal security review.
