#!/usr/bin/env python3
"""Consent-based, read-only remote screen sharing in one Python file.

This program deliberately does not implement stealth, persistence, privilege
escalation, remote shell execution, file transfer, keyboard injection, or mouse
injection. The host must approve every session.

Dependencies:
    python -m pip install Pillow

OpenSSL is required only for the ``cert`` command.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import io
import json
import queue
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

MAX_MESSAGE_BYTES = 8 * 1024 * 1024
STREAM_LIMIT = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Bounded JSON-lines protocol
# ---------------------------------------------------------------------------

class ProtocolError(ValueError):
    """Raised for malformed or oversized protocol messages."""


async def read_message(reader: asyncio.StreamReader) -> dict[str, Any]:
    line = await reader.readline()
    if not line:
        raise ConnectionError("peer closed the connection")
    if len(line) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message is too large")
    try:
        message = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError("message is not valid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("message must be a JSON object")
    return message


async def write_message(writer: asyncio.StreamWriter, message: dict[str, Any]) -> None:
    try:
        encoded = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("message cannot be encoded") from exc
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message is too large")
    writer.write(encoded)
    await writer.drain()


# ---------------------------------------------------------------------------
# Pairing and certificate pinning
# ---------------------------------------------------------------------------

@dataclass
class PairingCode:
    """A short-lived, single-use code kept only in process memory."""

    value: str
    expires_at: float
    used: bool = False

    @classmethod
    def create(cls, ttl_seconds: int = 300) -> "PairingCode":
        if ttl_seconds <= 0:
            raise ValueError("pairing TTL must be positive")
        return cls(
            value=f"{secrets.randbelow(1_000_000):06d}",
            expires_at=time.monotonic() + ttl_seconds,
        )

    def consume(self, candidate: str) -> bool:
        if self.used or time.monotonic() >= self.expires_at:
            return False
        valid = secrets.compare_digest(self.value, candidate.strip())
        if valid:
            self.used = True
        return valid


def certificate_fingerprint(cert_file: str) -> str:
    with open(cert_file, "rb") as handle:
        pem = handle.read()
    try:
        der = ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"invalid PEM certificate: {cert_file}") from exc
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index : index + 2] for index in range(0, len(digest), 2))


def peer_fingerprint(ssl_object: Any) -> str:
    if ssl_object is None:
        raise ValueError("peer did not establish TLS")
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


# ---------------------------------------------------------------------------
# Audit, certificates, and screen capture
# ---------------------------------------------------------------------------

class AuditLog:
    """JSONL audit logger that never records pairing codes or frame contents."""

    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else None

    def event(self, name: str, **fields: Any) -> None:
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": name,
            **fields,
        }
        encoded = json.dumps(record, sort_keys=True)
        print(encoded, file=sys.stderr, flush=True)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")


def generate_certificate(cert: str, key: str, days: int = 30) -> None:
    if days <= 0:
        raise ValueError("certificate lifetime must be positive")
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
        # Windows uses ACLs; the caller is responsible for protecting the key.
        pass


def advertised_addresses(bind: str, port: int) -> str:
    if bind not in {"0.0.0.0", "::"}:
        return f"{bind}:{port}"
    addresses: set[str] = set()
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("10.255.255.255", 1))
        addresses.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        with contextlib.suppress(OSError):
            addresses.add(socket.gethostbyname(socket.gethostname()))
    addresses.discard("127.0.0.1")
    return ", ".join(f"{address}:{port}" for address in sorted(addresses)) or f"127.0.0.1:{port}"


def capture_jpeg(max_width: int = 1600, quality: int = 70) -> tuple[bytes | None, str | None]:
    """Capture the desktop without attempting to bypass OS screenshot policy."""
    try:
        from PIL import Image, ImageGrab
    except ImportError:
        return None, "Pillow is not installed; run: python -m pip install Pillow"

    try:
        image = ImageGrab.grab(all_screens=True)
        if image.width > max_width:
            ratio = max_width / image.width
            image = image.resize(
                (max_width, max(1, int(image.height * ratio))),
                Image.Resampling.LANCZOS,
            )
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")
        output = io.BytesIO()
        image.save(output, format="JPEG", quality=quality, optimize=True)
        return output.getvalue(), None
    except Exception as exc:  # desktop screenshot APIs vary by platform
        return None, f"screen capture unavailable: {exc}"


# ---------------------------------------------------------------------------
# Host
# ---------------------------------------------------------------------------

@dataclass
class HostConfig:
    bind: str
    port: int
    cert: str
    key: str
    pairing_ttl: int = 300
    frame_interval: float = 0.5
    audit_path: str | None = None


class RemoteHost:
    def __init__(
        self,
        config: HostConfig,
        consent_callback: Callable[[str, str], Awaitable[bool]] | None = None,
        ready_callback: Callable[[str, str, str], None] | None = None,
        status_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self.pairing = PairingCode.create(config.pairing_ttl)
        self.audit = AuditLog(config.audit_path)
        self.session_lock = asyncio.Lock()
        self.server: asyncio.AbstractServer | None = None
        self.consent_callback = consent_callback
        self.ready_callback = ready_callback
        self.status_callback = status_callback
        self.active_task: asyncio.Task[Any] | None = None

    def status(self, message: str) -> None:
        if self.status_callback:
            self.status_callback(message)

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        if self.active_task and self.active_task is not asyncio.current_task():
            self.active_task.cancel()

    def tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(certfile=self.config.cert, keyfile=self.config.key)
        return context

    async def run(self) -> None:
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.config.bind,
            port=self.config.port,
            ssl=self.tls_context(),
            limit=STREAM_LIMIT,
        )
        addresses = ", ".join(str(sock.getsockname()) for sock in self.server.sockets or [])
        fingerprint = certificate_fingerprint(self.config.cert)
        print("\nSecure Remote Support host is ready")
        print(f"Listening: {addresses}")
        print(f"Certificate SHA-256: {fingerprint}")
        print(f"One-time pairing code: {self.pairing.value}")
        print(f"Code expires in {self.config.pairing_ttl} seconds")
        print(f"Share address: {advertised_addresses(self.config.bind, self.config.port)}")
        print("Share the fingerprint and code through a trusted channel.\n")
        self.status("Host is ready and waiting for a viewer")
        if self.ready_callback:
            self.ready_callback(
                advertised_addresses(self.config.bind, self.config.port),
                fingerprint,
                self.pairing.value,
            )
        self.audit.event("host_started", addresses=addresses)
        async with self.server:
            await self.server.serve_forever()
        self.audit.event("host_stopped")
        self.status("Host stopped")

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        peer_label = str(peer)
        try:
            hello = await asyncio.wait_for(read_message(reader), timeout=15)
            if hello.get("type") != "hello" or hello.get("role") != "viewer":
                await write_message(writer, {"type": "error", "message": "invalid hello"})
                self.audit.event("rejected_client", peer=peer_label, reason="invalid_hello")
                return
            client_name = str(hello.get("client_name", "viewer"))[:80] or "viewer"
            if not self.pairing.consume(str(hello.get("code", ""))):
                await write_message(
                    writer,
                    {"type": "error", "message": "invalid or expired pairing code"},
                )
                self.audit.event("rejected_client", peer=peer_label, reason="bad_pairing_code")
                return
            if self.session_lock.locked():
                await write_message(writer, {"type": "error", "message": "another session is active"})
                self.audit.event("rejected_client", peer=peer_label, reason="busy")
                return
            async with self.session_lock:
                self.active_task = asyncio.current_task()
                try:
                    await self.run_approved_session(reader, writer, peer_label, client_name)
                finally:
                    self.active_task = None
        except (ConnectionError, asyncio.IncompleteReadError, ProtocolError, asyncio.TimeoutError) as exc:
            self.audit.event("client_error", peer=peer_label, error=str(exc))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def run_approved_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: str,
        client_name: str,
    ) -> None:
        await write_message(
            writer,
            {
                "type": "consent_request",
                "client_name": client_name,
                "peer": peer,
                "message": "A viewer requests a read-only screen session.",
            },
        )
        if self.consent_callback:
            approved = await self.consent_callback(client_name, peer)
        else:
            answer = await asyncio.to_thread(
                input,
                f"\n[CONSENT REQUIRED] Allow read-only screen sharing to {client_name} ({peer})? [y/N] ",
            )
            approved = answer.strip().lower() in {"y", "yes"}
        if not approved:
            await write_message(writer, {"type": "denied", "message": "host declined the session"})
            self.audit.event("session_denied", peer=peer, client_name=client_name)
            return

        await write_message(writer, {"type": "session_started", "mode": "read-only-screen"})
        self.audit.event("session_approved", peer=peer, client_name=client_name)
        print(
            f"\n[REMOTE SESSION ACTIVE] Read-only screen sharing to {client_name}. "
            "Press Ctrl-C to stop the host."
        )
        self.status(f"Remote session active with {client_name}")
        control_task: asyncio.Task[dict[str, Any]] = asyncio.create_task(read_message(reader))
        frame_count = 0
        try:
            while True:
                done, _ = await asyncio.wait({control_task}, timeout=self.config.frame_interval)
                if control_task in done:
                    message = control_task.result()
                    if message.get("type") == "stop":
                        self.audit.event("session_stopped_by_viewer", peer=peer, frames=frame_count)
                        break
                    control_task = asyncio.create_task(read_message(reader))
                frame, error = await asyncio.to_thread(capture_jpeg)
                if error:
                    await write_message(writer, {"type": "capture_error", "message": error})
                    await asyncio.sleep(1.0)
                    continue
                assert frame is not None
                await write_message(
                    writer,
                    {
                        "type": "frame",
                        "sequence": frame_count,
                        "jpeg": base64.b64encode(frame).decode("ascii"),
                    },
                )
                frame_count += 1
        except (ConnectionError, asyncio.IncompleteReadError, ProtocolError) as exc:
            self.audit.event("session_disconnected", peer=peer, frames=frame_count, error=str(exc))
        finally:
            control_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await control_task
            self.audit.event("session_ended", peer=peer, frames=frame_count)
            self.status("Session ended; restart the host to create a new pairing code")
            print("[REMOTE SESSION ENDED]\n")


# ---------------------------------------------------------------------------
# Viewer
# ---------------------------------------------------------------------------

class ViewerError(RuntimeError):
    pass


def notify(events: queue.Queue[tuple[str, Any]] | None, kind: str, value: Any) -> None:
    if events is not None:
        events.put((kind, value))
    elif kind == "status":
        print(str(value), file=sys.stderr, flush=True)


async def receive_frames(
    host: str,
    port: int,
    code: str,
    fingerprint: str,
    output: Path,
    client_name: str,
    events: queue.Queue[tuple[str, Any]] | None = None,
    stop_event: threading.Event | None = None,
    fingerprint_callback: Callable[[str], Awaitable[bool]] | None = None,
) -> None:
    # The certificate is deliberately checked manually below using its pinned
    # fingerprint. Sending the pairing code happens only after that check.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        host, port, ssl=context, limit=STREAM_LIMIT
    )
    try:
        actual = peer_fingerprint(writer.get_extra_info("ssl_object"))
        if fingerprint:
            if not fingerprints_match(fingerprint, actual):
                raise ViewerError(
                    "certificate fingerprint mismatch; refusing to connect "
                    f"(received {actual})"
                )
        else:
            # The friendly GUI intentionally uses only IP + password. TLS still
            # encrypts the session, while terminal mode can additionally pin a
            # certificate fingerprint for stronger host authentication.
            notify(events, "status", "Encrypted TLS session established")
        await write_message(
            writer,
            {
                "type": "hello",
                "role": "viewer",
                "code": code,
                "client_name": client_name[:80] or "viewer",
            },
        )
        output.mkdir(parents=True, exist_ok=True)
        if fingerprint:
            notify(events, "status", f"TLS verified: {actual}")
        frame_count = 0
        while True:
            if stop_event and stop_event.is_set():
                await write_message(writer, {"type": "stop"})
                return
            try:
                message = await asyncio.wait_for(read_message(reader), timeout=0.25)
            except asyncio.TimeoutError:
                continue
            message_type = message.get("type")
            if message_type == "consent_request":
                notify(events, "status", "Waiting for the host to approve this session...")
            elif message_type == "session_started":
                notify(events, "status", "Session approved: read-only screen sharing")
            elif message_type == "frame":
                try:
                    frame = base64.b64decode(message["jpeg"], validate=True)
                except (KeyError, ValueError) as exc:
                    raise ProtocolError("invalid frame data") from exc
                (output / "latest.jpg").write_bytes(frame)
                frame_count += 1
                notify(events, "frame", frame)
                notify(events, "status", f"Receiving frame {message.get('sequence', frame_count - 1)}")
            elif message_type == "capture_error":
                notify(
                    events,
                    "status",
                    f"Host capture unavailable: {message.get('message', 'unknown error')}",
                )
            elif message_type in {"denied", "error"}:
                raise ViewerError(str(message.get("message", "host rejected the session")))
            else:
                notify(events, "status", f"Host sent an unknown event: {message_type}")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def run_headless(
    host: str,
    port: int,
    code: str,
    fingerprint: str,
    output: Path,
    client_name: str,
) -> None:
    try:
        asyncio.run(receive_frames(host, port, code, fingerprint, output, client_name))
    except (OSError, ViewerError, ProtocolError) as exc:
        raise SystemExit(f"viewer error: {exc}") from exc


def run_gui(
    host: str,
    port: int,
    code: str,
    fingerprint: str,
    output: Path,
    client_name: str,
) -> None:
    try:
        import tkinter as tk
        from PIL import Image, ImageTk
    except ImportError as exc:
        raise SystemExit("GUI mode requires Tkinter and Pillow; use --headless instead") from exc

    events: queue.Queue[tuple[str, Any]] = queue.Queue()
    stop_event = threading.Event()

    def worker() -> None:
        try:
            asyncio.run(
                receive_frames(
                    host,
                    port,
                    code,
                    fingerprint,
                    output,
                    client_name,
                    events,
                    stop_event,
                )
            )
        except (OSError, ViewerError, ProtocolError) as exc:
            events.put(("error", str(exc)))
        finally:
            events.put(("done", None))

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit("GUI display is unavailable; use --headless instead") from exc
    root.title("Consent Remote Support — read-only")
    root.geometry("1000x720")
    status = tk.StringVar(value="Connecting…")
    tk.Label(root, textvariable=status, anchor="w").pack(fill="x", padx=10, pady=(10, 4))
    image_label = tk.Label(root, text="Waiting for host consent…", bg="#20242a", fg="white")
    image_label.pack(fill="both", expand=True, padx=10, pady=4)

    def close() -> None:
        stop_event.set()
        root.destroy()

    tk.Button(root, text="Stop session", command=close).pack(pady=(4, 10))
    root.protocol("WM_DELETE_WINDOW", close)

    def poll() -> None:
        try:
            while True:
                kind, value = events.get_nowait()
                if kind == "status":
                    status.set(str(value))
                elif kind == "error":
                    status.set(f"Error: {value}")
                elif kind == "frame":
                    image = Image.open(io.BytesIO(value))
                    image.thumbnail((960, 640))
                    photo = ImageTk.PhotoImage(image.copy())
                    image_label.configure(image=photo, text="")
                    image_label.image = photo
                elif kind == "done":
                    status.set("Session ended")
        except queue.Empty:
            pass
        if root.winfo_exists():
            root.after(100, poll)

    threading.Thread(target=worker, daemon=True).start()
    root.after(100, poll)
    root.mainloop()


# ---------------------------------------------------------------------------
# Friendly Tkinter GUI
# ---------------------------------------------------------------------------

class FriendlyApp:
    """Small Tkinter launcher for hosts and viewers.

    Networking runs in worker threads, while all dialogs and widgets stay on
    Tk's main thread. The host consent dialog is therefore visible even when
    the program is packaged with PyInstaller's ``--windowed`` option.
    """

    def __init__(self) -> None:
        try:
            import tkinter as tk
            from tkinter import filedialog, messagebox, ttk
        except ImportError as exc:
            raise SystemExit("This GUI requires a Python installation with Tkinter") from exc

        self.tk = tk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.ttk = ttk
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            raise SystemExit("GUI display is unavailable; use the terminal commands instead") from exc
        self.root.title("Secure Remote Support")
        self.root.geometry("900x700")
        self.root.minsize(760, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.host_loop: asyncio.AbstractEventLoop | None = None
        self.host_runner: RemoteHost | None = None
        self.host_thread: threading.Thread | None = None
        self.viewer_thread: threading.Thread | None = None
        self.viewer_stop = threading.Event()
        self.viewer_events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.viewer_photo: Any = None
        self.viewer_image: Any = None
        try:
            from PIL import Image, ImageTk
            self.image_module = Image
            self.image_tk_module = ImageTk
        except ImportError:
            self.image_module = None
            self.image_tk_module = None

        style = ttk.Style(self.root)
        with contextlib.suppress(Exception):
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Subtitle.TLabel", foreground="#5b6470")
        style.configure("Card.TLabelframe", padding=12)

        self.build_widgets()
        self.root.after(100, self.poll_viewer_events)

    def build_widgets(self) -> None:
        tk, ttk = self.tk, self.ttk
        outer = ttk.Frame(self.root, padding=20)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Secure Remote Support", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Share your screen only after you approve the session. No remote control or shell access is included.",
            style="Subtitle.TLabel",
            wraplength=820,
        ).pack(anchor="w", pady=(2, 16))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        self.host_tab = ttk.Frame(notebook, padding=16)
        self.viewer_tab = ttk.Frame(notebook, padding=16)
        notebook.add(self.host_tab, text="Host a session")
        notebook.add(self.viewer_tab, text="Join a session")
        self.build_host_tab()
        self.build_viewer_tab()

    def entry_row(
        self,
        parent: Any,
        row: int,
        label: str,
        variable: Any,
        browse: bool = False,
        directory: bool = False,
    ) -> None:
        ttk = self.ttk
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=6)
        if browse:
            ttk.Button(
                parent,
                text="Browse…",
                command=lambda: self.choose_path(variable, directory),
            ).grid(row=row, column=2, padx=(8, 0), pady=6)

    def choose_path(self, variable: Any, directory: bool = False) -> None:
        if directory:
            selected = self.filedialog.askdirectory()
        else:
            selected = self.filedialog.askopenfilename()
        if selected:
            variable.set(selected)

    def build_host_tab(self) -> None:
        ttk = self.ttk
        tab = self.host_tab
        tab.columnconfigure(0, weight=1)

        self.host_cert_var = self.tk.StringVar(value="host-cert.pem")
        self.host_key_var = self.tk.StringVar(value="host-key.pem")
        self.host_bind_var = self.tk.StringVar(value="0.0.0.0")
        self.host_port_var = self.tk.StringVar(value="8765")
        self.host_ttl_var = self.tk.StringVar(value="300")
        self.host_audit_var = self.tk.StringVar(value="")
        self.host_status_var = self.tk.StringVar(value="Host is stopped")
        self.host_address_var = self.tk.StringVar(value="Start the host to show the address")
        self.host_code_var = self.tk.StringVar(value="—")
        self.host_fingerprint_var = self.tk.StringVar(value="—")

        ttk.Label(
            tab,
            text="Share your screen with a trusted person. The viewer will need the address and password below.",
            wraplength=700,
        ).grid(row=0, column=0, sticky="w", pady=(0, 18))

        info = ttk.LabelFrame(tab, text="Connection details", style="Card.TLabelframe")
        info.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        info.columnconfigure(1, weight=1)
        ttk.Label(info, text="IP address and port").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=8)
        ttk.Entry(info, textvariable=self.host_address_var, state="readonly").grid(row=0, column=1, sticky="ew", pady=8)
        ttk.Button(info, text="Copy", command=lambda: self.copy_value(self.host_address_var.get())).grid(row=0, column=2, padx=(8, 0), pady=8)
        ttk.Label(info, text="Session password").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=8)
        ttk.Entry(info, textvariable=self.host_code_var, state="readonly").grid(row=1, column=1, sticky="ew", pady=8)
        ttk.Button(info, text="Copy", command=lambda: self.copy_value(self.host_code_var.get())).grid(row=1, column=2, padx=(8, 0), pady=8)

        button_row = ttk.Frame(tab)
        button_row.grid(row=2, column=0, sticky="w", pady=(4, 14))
        self.host_start_button = ttk.Button(button_row, text="Start sharing", command=self.start_host)
        self.host_start_button.pack(side="left")
        self.host_stop_button = ttk.Button(button_row, text="Stop sharing", command=self.stop_host, state="disabled")
        self.host_stop_button.pack(side="left", padx=(8, 0))

        ttk.Label(
            tab,
            text="The first start creates a temporary TLS certificate automatically. The host will show a consent dialog before sharing any screen frames.",
            wraplength=700,
        ).grid(row=3, column=0, sticky="w", pady=(0, 10))
        ttk.Label(tab, textvariable=self.host_status_var, wraplength=760).grid(
            row=4, column=0, sticky="w"
        )

    def build_viewer_tab(self) -> None:
        ttk = self.ttk
        tab = self.viewer_tab
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(4, weight=1)

        ttk.Label(
            tab,
            text="Enter the host computer's IP address and session password. The host must approve your request.",
            wraplength=700,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 18))

        self.viewer_host_var = self.tk.StringVar(value="127.0.0.1")
        self.viewer_port_var = self.tk.StringVar(value="8765")
        self.viewer_code_var = self.tk.StringVar()
        self.viewer_fingerprint_var = self.tk.StringVar()
        self.viewer_name_var = self.tk.StringVar(value="support-viewer")
        self.viewer_output_var = self.tk.StringVar(value="session-output")
        self.viewer_status_var = self.tk.StringVar(value="Not connected")

        ttk.Label(tab, text="IP address").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=8)
        ttk.Entry(tab, textvariable=self.viewer_host_var).grid(row=1, column=1, sticky="ew", pady=8)
        ttk.Label(tab, text="Password").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=8)
        password_entry = ttk.Entry(tab, textvariable=self.viewer_code_var, show="•")
        password_entry.grid(row=2, column=1, sticky="ew", pady=8)

        button_row = ttk.Frame(tab)
        button_row.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 12))
        self.viewer_connect_button = ttk.Button(button_row, text="Connect", command=self.start_viewer)
        self.viewer_connect_button.pack(side="left")
        self.viewer_stop_button = ttk.Button(button_row, text="Disconnect", command=self.stop_viewer, state="disabled")
        self.viewer_stop_button.pack(side="left", padx=(8, 0))

        self.viewer_image_label = self.tk.Label(
            tab,
            text="The remote screen will appear here",
            bg="#20242a",
            fg="white",
            anchor="center",
        )
        self.viewer_image_label.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(4, 10))
        ttk.Label(tab, textvariable=self.viewer_status_var, wraplength=760).grid(
            row=5, column=0, columnspan=2, sticky="w"
        )
    def copy_value(self, value: str) -> None:
        if value and value != "—":
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.host_status_var.set("Copied to clipboard")

    def generate_host_certificate(self) -> None:
        try:
            generate_certificate(self.host_cert_var.get(), self.host_key_var.get())
            fingerprint = certificate_fingerprint(self.host_cert_var.get())
            self.host_fingerprint_var.set(fingerprint)
            self.host_status_var.set("Certificate created. Protect the private key and start the host.")
        except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
            self.messagebox.showerror("Certificate error", str(exc), parent=self.root)

    def start_host(self) -> None:
        if self.host_thread and self.host_thread.is_alive():
            return
        try:
            port = int(self.host_port_var.get())
            ttl = int(self.host_ttl_var.get())
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            if ttl <= 0:
                raise ValueError("code lifetime must be positive")
            cert_path = Path(self.host_cert_var.get())
            key_path = Path(self.host_key_var.get())
            if not cert_path.is_file() or not key_path.is_file():
                self.host_status_var.set("Creating local TLS certificate…")
                generate_certificate(str(cert_path), str(key_path))
        except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
            self.messagebox.showerror("Host settings", str(exc), parent=self.root)
            return

        config = HostConfig(
            bind=self.host_bind_var.get().strip() or "0.0.0.0",
            port=port,
            cert=self.host_cert_var.get(),
            key=self.host_key_var.get(),
            pairing_ttl=ttl,
            audit_path=self.host_audit_var.get().strip() or None,
        )
        self.host_code_var.set("Generating…")
        self.host_fingerprint_var.set("Generating…")
        self.host_start_button.configure(state="disabled")
        self.host_stop_button.configure(state="normal")
        self.host_status_var.set("Starting host…")
        loop = asyncio.new_event_loop()
        self.host_loop = loop

        def run_host() -> None:
            asyncio.set_event_loop(loop)
            runner = RemoteHost(
                config,
                consent_callback=self.request_consent,
                ready_callback=self.host_ready,
                status_callback=self.host_status,
            )
            self.host_runner = runner
            try:
                loop.run_until_complete(runner.run())
            except (OSError, ssl.SSLError, ValueError) as exc:
                self.post_to_ui(lambda: self.host_status_var.set(f"Host error: {exc}"))
            finally:
                loop.close()
                self.post_to_ui(self.host_thread_finished)

        self.host_thread = threading.Thread(target=run_host, name="remote-support-host", daemon=True)
        self.host_thread.start()

    def stop_host(self) -> None:
        if self.host_runner and self.host_loop and self.host_loop.is_running():
            asyncio.run_coroutine_threadsafe(self.host_runner.stop(), self.host_loop)
        self.host_status_var.set("Stopping host…")

    async def request_consent(self, client_name: str, peer: str) -> bool:
        loop = asyncio.get_running_loop()
        decision = loop.create_future()

        def ask() -> None:
            try:
                allowed = self.messagebox.askyesno(
                    "Remote session request",
                    f"{client_name} ({peer}) is requesting read-only screen sharing.\n\nAllow this session?",
                    parent=self.root,
                )
            except self.tk.TclError:
                allowed = False
            def finish() -> None:
                if not decision.done():
                    decision.set_result(allowed)
            loop.call_soon_threadsafe(finish)

        try:
            self.root.after(0, ask)
        except self.tk.TclError:
            return False
        return await decision

    def host_ready(self, addresses: str, fingerprint: str, code: str) -> None:
        self.post_to_ui(lambda: self.host_address_var.set(addresses))
        self.post_to_ui(lambda: self.host_code_var.set(code))
        self.post_to_ui(lambda: self.host_fingerprint_var.set(fingerprint))
        self.post_to_ui(lambda: self.host_status_var.set(f"Listening on {addresses}. Waiting for viewer approval."))

    def host_status(self, message: str) -> None:
        self.post_to_ui(lambda: self.host_status_var.set(message))

    def host_thread_finished(self) -> None:
        self.host_stop_button.configure(state="disabled")
        self.host_start_button.configure(state="normal")
        self.host_runner = None
        self.host_loop = None

    def start_viewer(self) -> None:
        if self.viewer_thread and self.viewer_thread.is_alive():
            return
        if self.image_module is None:
            self.messagebox.showerror("Pillow required", "Install Pillow first with: python -m pip install Pillow", parent=self.root)
            return
        try:
            port = int(self.viewer_port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            if not self.viewer_host_var.get().strip() or not self.viewer_code_var.get().strip():
                raise ValueError("enter the host IP address and password")
        except ValueError as exc:
            self.messagebox.showerror("Viewer settings", str(exc), parent=self.root)
            return

        self.viewer_stop.clear()
        self.viewer_events = queue.Queue()
        self.viewer_connect_button.configure(state="disabled")
        self.viewer_stop_button.configure(state="normal")
        self.viewer_status_var.set("Connecting…")
        host = self.viewer_host_var.get().strip()
        password = self.viewer_code_var.get()
        client_name = self.viewer_name_var.get()
        output = Path(self.viewer_output_var.get().strip() or "session-output")

        def run_viewer() -> None:
            try:
                asyncio.run(
                    receive_frames(
                        host,
                        port,
                        password,
                        "",
                        output,
                        client_name,
                        self.viewer_events,
                        self.viewer_stop,
                    )
                )
            except (OSError, ViewerError, ProtocolError) as exc:
                self.viewer_events.put(("error", str(exc)))
            finally:
                self.viewer_events.put(("done", None))

        self.viewer_thread = threading.Thread(target=run_viewer, name="remote-support-viewer", daemon=True)
        self.viewer_thread.start()

    def stop_viewer(self) -> None:
        self.viewer_stop.set()
        self.viewer_status_var.set("Disconnecting…")

    def poll_viewer_events(self) -> None:
        try:
            while True:
                kind, value = self.viewer_events.get_nowait()
                if kind == "status":
                    self.viewer_status_var.set(str(value))
                elif kind == "error":
                    self.viewer_status_var.set(f"Error: {value}")
                elif kind == "frame":
                    self.show_frame(value)
                elif kind == "done":
                    self.viewer_connect_button.configure(state="normal")
                    self.viewer_stop_button.configure(state="disabled")
                    if self.viewer_status_var.get() == "Disconnecting…":
                        self.viewer_status_var.set("Disconnected")
        except queue.Empty:
            pass
        if self.root.winfo_exists():
            self.root.after(100, self.poll_viewer_events)

    def show_frame(self, data: bytes) -> None:
        if self.image_module is None or self.image_tk_module is None:
            return
        try:
            image = self.image_module.open(io.BytesIO(data))
            image.thumbnail((820, 480))
            self.viewer_photo = self.image_tk_module.PhotoImage(image.copy())
            self.viewer_image_label.configure(image=self.viewer_photo, text="")
        except Exception as exc:
            self.viewer_status_var.set(f"Unable to display frame: {exc}")

    def post_to_ui(self, callback: Callable[[], None]) -> None:
        with contextlib.suppress(self.tk.TclError):
            self.root.after(0, callback)

    def close(self) -> None:
        self.viewer_stop.set()
        if self.host_runner and self.host_loop and self.host_loop.is_running():
            asyncio.run_coroutine_threadsafe(self.host_runner.stop(), self.host_loop)
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def launch_gui() -> None:
    FriendlyApp().run()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="remote_support.py",
        description="Consent-based, read-only remote screen sharing over pinned TLS.",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("gui", help="open the friendly desktop interface")

    cert = subparsers.add_parser("cert", help="generate a temporary self-signed TLS certificate")
    cert.add_argument("--cert", default="host-cert.pem")
    cert.add_argument("--key", default="host-key.pem")
    cert.add_argument("--days", type=int, default=30)

    host = subparsers.add_parser("host", help="start a host and wait for explicit consent")
    host.add_argument("--bind", default="0.0.0.0", help="use 127.0.0.1 for local testing")
    host.add_argument("--port", type=int, default=8765)
    host.add_argument("--cert", required=True)
    host.add_argument("--key", required=True)
    host.add_argument("--pairing-ttl", type=int, default=300)
    host.add_argument("--frame-interval", type=float, default=0.5)
    host.add_argument("--audit", help="optional JSONL audit log path")

    viewer = subparsers.add_parser("viewer", help="connect to an approved read-only session")
    viewer.add_argument("--host", required=True)
    viewer.add_argument("--port", type=int, default=8765)
    viewer.add_argument("--code", required=True, help="one-time code shown by the host")
    viewer.add_argument("--fingerprint", required=True, help="SHA-256 fingerprint shown by the host")
    viewer.add_argument("--client-name", default="support-viewer")
    viewer.add_argument("--output", type=Path, default=Path("session-output"))
    viewer.add_argument("--headless", action="store_true", help="save latest.jpg without opening a GUI")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command in {None, "gui"}:
        launch_gui()
        return
    if args.command == "cert":
        try:
            generate_certificate(args.cert, args.key, args.days)
            print(f"Certificate written to {args.cert}")
            print(f"Private key written to {args.key}")
            print(f"SHA-256: {certificate_fingerprint(args.cert)}")
        except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
            raise SystemExit(f"certificate error: {exc}") from exc
        return

    if args.command == "host":
        if not 1 <= args.port <= 65535:
            raise SystemExit("--port must be between 1 and 65535")
        if args.pairing_ttl <= 0:
            raise SystemExit("--pairing-ttl must be positive")
        if args.frame_interval <= 0:
            raise SystemExit("--frame-interval must be positive")
        config = HostConfig(
            bind=args.bind,
            port=args.port,
            cert=args.cert,
            key=args.key,
            pairing_ttl=args.pairing_ttl,
            frame_interval=args.frame_interval,
            audit_path=args.audit,
        )
        try:
            asyncio.run(RemoteHost(config).run())
        except KeyboardInterrupt:
            print("\nHost stopped.")
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise SystemExit(f"host error: {exc}") from exc
        return

    if args.command == "viewer":
        if not 1 <= args.port <= 65535:
            raise SystemExit("--port must be between 1 and 65535")
        if args.headless:
            run_headless(
                args.host,
                args.port,
                args.code,
                args.fingerprint,
                args.output,
                args.client_name,
            )
        else:
            run_gui(
                args.host,
                args.port,
                args.code,
                args.fingerprint,
                args.output,
                args.client_name,
            )


if __name__ == "__main__":
    main()
