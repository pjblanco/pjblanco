"""Consent-gated TLS host that sends read-only screen frames."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ssl
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .capture import capture_jpeg
from .protocol import ProtocolError, read_message, write_message
from .security import PairingCode, certificate_fingerprint


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
    def __init__(self, config: HostConfig) -> None:
        self.config = config
        self.pairing = PairingCode.create(config.pairing_ttl)
        self.audit = AuditLog(config.audit_path)
        self.session_lock = asyncio.Lock()
        self.server: asyncio.AbstractServer | None = None

    def tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(certfile=self.config.cert, keyfile=self.config.key)
        return context

    async def run(self) -> None:
        context = self.tls_context()
        self.server = await asyncio.start_server(
            self.handle_client,
            host=self.config.bind,
            port=self.config.port,
            ssl=context,
            limit=16 * 1024 * 1024,
        )
        addresses = ", ".join(str(sock.getsockname()) for sock in self.server.sockets or [])
        fingerprint = certificate_fingerprint(self.config.cert)
        print("\nSecure Remote Support host is ready")
        print(f"Listening: {addresses}")
        print(f"Certificate SHA-256: {fingerprint}")
        print(f"One-time pairing code: {self.pairing.value}")
        print(f"Code expires in {self.config.pairing_ttl} seconds")
        print("Share the fingerprint and code through a trusted channel.\n")
        self.audit.event("host_started", addresses=addresses)
        async with self.server:
            await self.server.serve_forever()

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
            client_name = str(hello.get("client_name", "viewer"))[:80]
            candidate = str(hello.get("code", ""))
            if not self.pairing.consume(candidate):
                await write_message(writer, {"type": "error", "message": "invalid or expired pairing code"})
                self.audit.event("rejected_client", peer=peer_label, reason="bad_pairing_code")
                return
            if self.session_lock.locked():
                await write_message(writer, {"type": "error", "message": "another session is active"})
                self.audit.event("rejected_client", peer=peer_label, reason="busy")
                return
            async with self.session_lock:
                await self.run_approved_session(reader, writer, peer_label, client_name)
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
        answer = await asyncio.to_thread(
            input,
            f"\n[CONSENT REQUIRED] Allow read-only screen sharing to {client_name} ({peer})? [y/N] ",
        )
        if answer.strip().lower() not in {"y", "yes"}:
            await write_message(writer, {"type": "denied", "message": "host declined the session"})
            self.audit.event("session_denied", peer=peer, client_name=client_name)
            return

        await write_message(writer, {"type": "session_started", "mode": "read-only-screen"})
        self.audit.event("session_approved", peer=peer, client_name=client_name)
        print(f"\n[REMOTE SESSION ACTIVE] Read-only screen sharing to {client_name}. Press Ctrl-C to stop the host.")
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
            print("[REMOTE SESSION ENDED]\n")
