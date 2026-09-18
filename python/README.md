# Simple Windows Remote Desktop launcher

[`remote_support.py`](remote_support.py) is a single-file GUI that launches Microsoft's built-in Windows Remote Desktop client, `mstsc.exe`.

It does not install an agent, use third-party networking libraries, change the registry, open firewall ports, or store passwords. The target computer must already have Windows Remote Desktop enabled.

## Run

On Windows, with Python installed:

```powershell
cd python
python remote_support.py
```

The GUI only asks for:

- Computer name or IP address
- Port, default `3389`
- Optional Windows username

Click **Connect with Remote Desktop**. Windows opens its own native credential dialog where the password is entered. The password is never placed in the command line or saved in a file by this program.

You can also connect from a terminal:

```powershell
python remote_support.py --host 192.168.1.20 --port 3389 --username CONTOSO\alice
```

## Target computer setup

On the target Windows computer:

1. Open **Settings → System → Remote Desktop**.
2. Enable **Remote Desktop**.
3. Ensure the Windows account is allowed to connect.
4. Ensure Windows Firewall allows the selected port.

The **Open RDP settings** button opens the local Windows Remote Desktop settings page. Changing the RDP listening port requires administrator access and a matching firewall rule; this launcher only selects the destination port.

Do not expose RDP directly to the public internet. Prefer a private network or VPN, and use strong Windows passwords with Network Level Authentication enabled.

## Build a standalone `.exe`

Tkinter is included with the standard Windows Python installer. Build with PyInstaller:

```powershell
cd python
py -m pip install pyinstaller
python -m PyInstaller `
  --clean `
  --noconfirm `
  --onefile `
  --windowed `
  --name SimpleRemoteDesktop `
  remote_support.py
```

The executable is created at:

```text
dist\SimpleRemoteDesktop.exe
```

This executable uses only the Windows built-in `mstsc.exe` client. Build on Windows to produce a Windows executable.
