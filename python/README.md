# Simple Windows Remote Desktop launcher and host setup

[`remote_support.py`](remote_support.py) is a single-file GUI around Microsoft's built-in Windows Remote Desktop client (`mstsc.exe`) and server service (`TermService`). It does not install a third-party remote-access agent and never stores passwords.

## Run

On Windows, with Python installed:

```powershell
cd python
python remote_support.py
```

The GUI has two simple tasks:

### Connect to another computer

Enter:

- Computer name or IP address
- Port, default `3389`
- Optional Windows username

Click **Connect with Remote Desktop**. Windows opens its native credential dialog where the password is entered. The password is never placed in this program's command line or saved in a file.

### Enable this computer as an RDP host

Click **Enable Remote Desktop (Admin)**. After UAC/Administrator approval, the program:

- Enables native Windows Remote Desktop;
- Requires Network Level Authentication;
- Enables the built-in Remote Desktop firewall group;
- Starts the Windows Remote Desktop service when possible.

This does not bypass Windows security and does not create a new account. Connect using an existing permitted Windows account and its normal password. Windows Home editions generally do not include the RDP host service; Pro, Enterprise, and Education editions are supported by Microsoft.

The host uses the standard RDP port `3389`. The connection screen lets you choose a different destination port when the target has already been configured to listen on that port. Changing the native RDP listening port requires administrator access and a matching firewall rule; the **Open RDP settings** button opens Windows settings for the remaining configuration.

Do not expose RDP directly to the public internet. Prefer a private network or VPN, use strong Windows passwords, and keep Network Level Authentication enabled.

## Terminal mode

You can launch the native client directly:

```powershell
python remote_support.py --host 192.168.1.20 --port 3389 --username CONTOSO\alice
```

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

This executable uses only Windows' built-in RDP client and server service at runtime. Build on Windows to produce a Windows executable.
