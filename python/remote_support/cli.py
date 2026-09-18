"""Command-line entry point for the consent-based remote support tool."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .certificates import generate_certificate
from .server import HostConfig, RemoteHost
from .security import certificate_fingerprint
from .viewer import run_gui, run_headless


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="remote-support",
        description="Consent-based, read-only remote screen sharing over pinned TLS.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    cert = subparsers.add_parser("cert", help="generate a temporary self-signed TLS certificate")
    cert.add_argument("--cert", default="host-cert.pem")
    cert.add_argument("--key", default="host-key.pem")
    cert.add_argument("--days", type=int, default=30)

    host = subparsers.add_parser("host", help="start a host and wait for explicit consent")
    host.add_argument("--bind", default="0.0.0.0", help="listen address; use 127.0.0.1 for local testing")
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
    viewer.add_argument("--output", type=Path, default=Path("session-output"))
    viewer.add_argument("--headless", action="store_true", help="save latest.jpg without opening a GUI")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "cert":
        if args.days <= 0:
            raise SystemExit("--days must be positive")
        generate_certificate(args.cert, args.key, args.days)
        print(f"Certificate written to {args.cert}")
        print(f"Private key written to {args.key}")
        print(f"SHA-256: {certificate_fingerprint(args.cert)}")
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
        return
    if args.command == "viewer":
        if args.headless:
            run_headless(args.host, args.port, args.code, args.fingerprint, args.output)
        else:
            run_gui(args.host, args.port, args.code, args.fingerprint, args.output)


if __name__ == "__main__":
    main()
