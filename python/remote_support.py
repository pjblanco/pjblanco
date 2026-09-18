#!/usr/bin/env python3
"""Simple Windows Remote Desktop launcher.

This is a small GUI around Microsoft's built-in mstsc.exe client. It does not
install a remote-access agent, change the registry, open firewall ports, or
store passwords. Windows Remote Desktop must already be enabled on the target
computer by an administrator.

The password is entered in Microsoft's native Windows credential dialog rather
than being passed on this program's command line or stored in a file.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Callable

# Tkinter is loaded only when the GUI is opened, so validation helpers and the
# terminal error message still work on systems that do not ship Tkinter.
tk = None
messagebox = None
ttk = None

DEFAULT_RDP_PORT = 3389


def find_mstsc() -> str | None:
    """Find the Windows Remote Desktop client."""
    if os.name != "nt":
        return None
    return shutil.which("mstsc.exe") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "mstsc.exe")


def validate_host(value: str) -> str:
    host = value.strip()
    if not host or any(character in host for character in "\r\n\t"):
        raise ValueError("enter a computer name or IP address")
    if len(host) > 253:
        raise ValueError("computer name or IP address is too long")
    return host


def validate_port(value: str) -> int:
    try:
        port = int(value.strip())
    except ValueError as exc:
        raise ValueError("port must be a number") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def rdp_target(host: str, port: int) -> str:
    # RDP uses brackets for an IPv6 address when a port is appended.
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def clean_rdp_value(value: str) -> str:
    """Prevent line injection in the temporary .rdp file."""
    return value.replace("\r", " ").replace("\n", " ").strip()


def launch_rdp(
    host: str,
    port: int,
    username: str,
    status: Callable[[str], None] | None = None,
) -> None:
    """Launch mstsc.exe using a temporary configuration without a password."""
    mstsc = find_mstsc()
    if not mstsc or not Path(mstsc).exists():
        raise RuntimeError("mstsc.exe was not found. This feature requires Windows Remote Desktop.")

    target = rdp_target(host, port)
    lines = [
        "screen mode id:i:2",
        "use multimon:i:0",
        "session bpp:i:32",
        f"full address:s:{clean_rdp_value(target)}",
        "prompt for credentials:i:1",
        "authentication level:i:2",
        "enablecredsspsupport:i:1",
        "negotiate security layer:i:1",
    ]
    username = clean_rdp_value(username)
    if username:
        lines.append(f"username:s:{username}")

    temporary = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".rdp",
        prefix="secure-remote-support-",
        delete=False,
    )
    path = Path(temporary.name)
    try:
        temporary.write("\n".join(lines) + "\n")
        temporary.close()
        process = subprocess.Popen([mstsc, str(path)])
    except Exception:
        temporary.close()
        path.unlink(missing_ok=True)
        raise

    if status:
        status(f"Remote Desktop opened for {target}. Enter the password in the Windows prompt.")

    def cleanup() -> None:
        process.wait()
        path.unlink(missing_ok=True)
        if status:
            status("Remote Desktop session closed")

    threading.Thread(target=cleanup, name="rdp-cleanup", daemon=True).start()


def open_remote_desktop_settings() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows Remote Desktop settings are only available on Windows")
    os.startfile("ms-settings:remotedesktop")  # type: ignore[attr-defined]


class RdpGui:
    def __init__(self) -> None:
        global tk, messagebox, ttk
        if tk is None:
            try:
                import tkinter as tk_module
                from tkinter import messagebox as messagebox_module
                from tkinter import ttk as ttk_module
            except ImportError as exc:
                raise SystemExit("This GUI requires a Python installation with Tkinter") from exc
            tk = tk_module
            messagebox = messagebox_module
            ttk = ttk_module
        self.root = tk.Tk()
        self.root.title("Windows Remote Desktop")
        self.root.geometry("620x470")
        self.root.minsize(520, 400)
        self.root.protocol("WM_DELETE_WINDOW", self.root.destroy)

        style = ttk.Style(self.root)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Muted.TLabel", foreground="#5b6470")

        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value=str(DEFAULT_RDP_PORT))
        self.username_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.build()

    def build(self) -> None:
        outer = ttk.Frame(self.root, padding=24)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(1, weight=1)

        ttk.Label(outer, text="Windows Remote Desktop", style="Title.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        ttk.Label(
            outer,
            text="Connect using Windows' built-in RDP client. Only the computer address, port, and username are entered here; Windows securely asks for the password.",
            style="Muted.TLabel",
            wraplength=560,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 24))

        card = ttk.LabelFrame(outer, text="Connection", padding=16)
        card.grid(row=2, column=0, columnspan=3, sticky="ew")
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="Computer / IP address").grid(row=0, column=0, sticky="w", padx=(0, 14), pady=8)
        host_entry = ttk.Entry(card, textvariable=self.host_var)
        host_entry.grid(row=0, column=1, columnspan=2, sticky="ew", pady=8)

        ttk.Label(card, text="Port").grid(row=1, column=0, sticky="w", padx=(0, 14), pady=8)
        port_entry = ttk.Entry(card, textvariable=self.port_var, width=12)
        port_entry.grid(row=1, column=1, sticky="w", pady=8)
        ttk.Label(card, text="Default: 3389").grid(row=1, column=2, sticky="w", padx=(10, 0), pady=8)

        ttk.Label(card, text="Username").grid(row=2, column=0, sticky="w", padx=(0, 14), pady=8)
        username_entry = ttk.Entry(card, textvariable=self.username_var)
        username_entry.grid(row=2, column=1, columnspan=2, sticky="ew", pady=8)

        button_row = ttk.Frame(outer)
        button_row.grid(row=3, column=0, columnspan=3, sticky="w", pady=(18, 12))
        ttk.Button(button_row, text="Connect with Remote Desktop", command=self.connect).pack(side="left")
        ttk.Button(button_row, text="Open RDP settings", command=self.open_settings).pack(side="left", padx=(10, 0))

        info = ttk.LabelFrame(outer, text="Important", padding=14)
        info.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(8, 16))
        ttk.Label(
            info,
            text=(
                "The target computer must have Remote Desktop enabled, your Windows account must be allowed to sign in, "
                "and its firewall must allow the selected port. Changing the listening port on the target requires administrator access."
            ),
            wraplength=540,
            justify="left",
        ).pack(anchor="w")

        ttk.Label(outer, textvariable=self.status_var, wraplength=560).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )
        host_entry.focus_set()
        self.root.bind("<Return>", lambda _event: self.connect())

    def set_status(self, message: str) -> None:
        self.root.after(0, lambda: self.status_var.set(message))

    def connect(self) -> None:
        try:
            host = validate_host(self.host_var.get())
            port = validate_port(self.port_var.get())
        except ValueError as exc:
            messagebox.showerror("Connection details", str(exc), parent=self.root)
            return
        try:
            launch_rdp(host, port, self.username_var.get(), self.set_status)
        except (OSError, RuntimeError, ValueError) as exc:
            messagebox.showerror("Remote Desktop", str(exc), parent=self.root)

    def open_settings(self) -> None:
        try:
            open_remote_desktop_settings()
        except (OSError, RuntimeError) as exc:
            messagebox.showerror("RDP settings", str(exc), parent=self.root)

    def run(self) -> None:
        self.root.mainloop()


def run_gui() -> None:
    if os.name != "nt":
        raise SystemExit("This simplified launcher uses Windows mstsc.exe and must run on Windows.")
    RdpGui().run()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple launcher for Windows Remote Desktop")
    parser.add_argument("--host", help="computer name or IP address")
    parser.add_argument("--port", default=str(DEFAULT_RDP_PORT), help="RDP port, default 3389")
    parser.add_argument("--username", default="", help="optional Windows username")
    args = parser.parse_args()

    if not args.host:
        run_gui()
        return
    try:
        host = validate_host(args.host)
        port = validate_port(args.port)
        launch_rdp(host, port, args.username, print)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
