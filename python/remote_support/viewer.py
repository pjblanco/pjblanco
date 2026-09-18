"""TLS-pinned read-only viewer with optional Tk display."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import queue
import ssl
import threading
from pathlib import Path
from typing import Any

from .protocol import ProtocolError, read_message, write_message
from .security import fingerprints_match, peer_fingerprint


class ViewerError(RuntimeError):
    pass


async def receive_frames(
    host: str,
    port: int,
    code: str,
    fingerprint: str,
    output: Path,
    events: queue.Queue[tuple[str, Any]],
    stop_event: threading.Event | None = None,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.open_connection(
        host, port, ssl=context, limit=16 * 1024 * 1024
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        actual = peer_fingerprint(ssl_object)
        if not fingerprints_match(fingerprint, actual):
            raise ViewerError(
                "certificate fingerprint mismatch; refusing to connect "
                f"(received {actual})"
            )
        await write_message(
            writer,
            {
                "type": "hello",
                "role": "viewer",
                "code": code,
                "client_name": "support-viewer",
            },
        )
        output.mkdir(parents=True, exist_ok=True)
        events.put(("status", f"TLS verified: {actual}"))
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
                events.put(("status", "Waiting for the host to approve this session..."))
            elif message_type == "session_started":
                events.put(("status", "Session approved: read-only screen sharing"))
            elif message_type == "frame":
                try:
                    frame = base64.b64decode(message["jpeg"], validate=True)
                except (KeyError, ValueError) as exc:
                    raise ProtocolError("invalid frame data") from exc
                (output / "latest.jpg").write_bytes(frame)
                frame_count += 1
                events.put(("frame", frame))
                events.put(("status", f"Receiving frame {message.get('sequence', frame_count - 1)}"))
            elif message_type == "capture_error":
                events.put(("status", f"Host capture unavailable: {message.get('message', 'unknown error')}"))
            elif message_type in {"denied", "error"}:
                raise ViewerError(str(message.get("message", "host rejected the session")))
            else:
                events.put(("status", f"Host sent an unknown event: {message_type}"))
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def run_headless(
    host: str, port: int, code: str, fingerprint: str, output: Path
) -> None:
    events: queue.Queue[tuple[str, Any]] = queue.Queue()
    try:
        asyncio.run(receive_frames(host, port, code, fingerprint, output, events))
    except (OSError, ViewerError, ProtocolError) as exc:
        raise SystemExit(f"viewer error: {exc}") from exc


def run_gui(host: str, port: int, code: str, fingerprint: str, output: Path) -> None:
    try:
        import tkinter as tk
        from PIL import Image, ImageTk
    except ImportError as exc:
        raise SystemExit("GUI mode requires Tkinter and Pillow; use --headless instead") from exc

    events: queue.Queue[tuple[str, Any]] = queue.Queue()
    stop_event = threading.Event()

    def worker() -> None:
        try:
            asyncio.run(receive_frames(host, port, code, fingerprint, output, events, stop_event))
        except (OSError, ViewerError, ProtocolError) as exc:
            events.put(("error", str(exc)))
        finally:
            events.put(("done", None))

    root = tk.Tk()
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
