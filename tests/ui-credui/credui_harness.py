"""Raising and reading a real Windows credential dialog.

The dialog under test is the one `CredentialUIBroker` owns -- the "Windows
Security" prompt that keepassxreboot/keepassxc#12956 is about. Two things about
it shape every helper here:

  * UIA reports **zero** Edit children for it, even before anything is typed.
    A field-contents check therefore cannot tell "the text did not arrive" from
    "the text cannot be read", and the first version of these tests did exactly
    that.
  * `Get-Credential` refuses to show it in a non-interactive host ("Access is
    denied"), so it is raised by calling credui directly.

So the witness is the API's own return value, carried out of the hosting process
through a file, plus a screenshot for the human reading a CI artifact.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from wintegrate.diagnostics import WindowCensus

HOST_SCRIPT = Path(__file__).with_name("credui_host.py")
RESULT_FILE = Path(os.environ.get("TEMP", r"C:\Users\Public")) / "credui_probe_result.txt"

DIALOG_CLASS = "Credential Dialog Xaml Host"
BROKER = "CredentialUIBroker"


def dialogs() -> list:
    return [
        snapshot
        for snapshot in WindowCensus.capture()
        if snapshot.is_visible and (snapshot.class_name or "") == DIALOG_CLASS
    ]


def powershell(script: str, timeout: float = 180.0) -> str:
    done = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
    )
    if done.returncode != 0:
        print(f"powershell exited {done.returncode}: {done.stderr.strip()[:400]}")
    return (done.stdout or "").strip()


def broker_pids() -> list[str]:
    listed = powershell(
        f"(Get-Process -Name {BROKER} -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Id) -join ','"
    )
    return [p for p in listed.split(",") if p]


def is_elevated() -> bool:
    """Whether this process holds an elevated token.

    The integrity level is the variable that decides this bug, and a GitHub
    hosted runner is administrator -- so a test that types in-process there
    measures the *working* path and the reproduction inverts. Everything that
    depends on privilege branches on this rather than assuming.
    """
    import ctypes
    from ctypes import wintypes

    TOKEN_QUERY = 0x0008
    TOKEN_ELEVATION = 20
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Declared, not inferred. Without argtypes ctypes passes the process handle
    # as a C int and raises "OverflowError: int too long to convert" -- which
    # surfaces as a broken test rather than as a missing declaration.
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY,
                                     ctypes.byref(token)):
        return False
    elevated = wintypes.DWORD(0)
    size = wintypes.DWORD(0)
    ok = advapi32.GetTokenInformation(
        token, TOKEN_ELEVATION, ctypes.byref(elevated), ctypes.sizeof(elevated),
        ctypes.byref(size),
    )
    if not ok:
        return False
    return bool(elevated.value)


def type_at_medium_integrity(hwnd: int, sequence: str, report: Path, timeout: float = 90.0) -> str:
    """Types `sequence` into `hwnd` from a *non-elevated* process, and reports.

    Uses a scheduled task registered with RunLevel Limited, which is the
    reliable way to drop from an elevated session to an ordinary one --
    CreateProcess cannot lower its own integrity level, and `runas
    /trustlevel:0x20000` yields a restricted token rather than a plain user one.
    """
    if report.exists():
        report.unlink()

    script = Path(__file__).with_name("type_into.py")
    python = sys.executable
    task = "CredUiMediumIntegrityTyper"
    argument = f'"{script}" {hwnd} "{sequence}" "{report}"'

    powershell(
        "$ErrorActionPreference='Stop'; "
        f"$a = New-ScheduledTaskAction -Execute '{python}' -Argument '{argument}'; "
        "$p = New-ScheduledTaskPrincipal -UserId \"$env:USERDOMAIN\\$env:USERNAME\" "
        "-LogonType Interactive -RunLevel Limited; "
        f"Register-ScheduledTask -TaskName {task} -Action $a -Principal $p -Force | Out-Null; "
        f"Start-ScheduledTask -TaskName {task}"
    )

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if report.exists():
            text = report.read_text(encoding="utf-8", errors="replace").strip()
            if "typed=" in text:
                powershell(f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false "
                           "-ErrorAction SilentlyContinue")
                return text
        time.sleep(0.5)
    powershell(f"Unregister-ScheduledTask -TaskName {task} -Confirm:$false -ErrorAction SilentlyContinue")
    return "<the de-elevated typer never reported>"


class CredentialPrompt:
    """A raised credential dialog, and the outcome of the call that raised it."""

    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None

    def __enter__(self) -> "CredentialPrompt":
        if RESULT_FILE.exists():
            RESULT_FILE.unlink()
        env = dict(os.environ, CREDUI_PROBE_RESULT=str(RESULT_FILE))
        self.process = subprocess.Popen([sys.executable, str(HOST_SCRIPT)], env=env)
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            if dialogs():
                return self
            if self.process.poll() is not None:
                raise AssertionError(
                    f"the credential host exited with {self.process.returncode} before a "
                    f"dialog appeared"
                )
            time.sleep(0.5)
        raise AssertionError("no credential dialog appeared within 30s")

    def __exit__(self, *exc) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
        for snapshot in dialogs():
            # Escape rather than a click: the dialog may have moved.
            from wintegrate.interop import send_keys

            send_keys("{ESC}")
            time.sleep(0.5)
            break

    @property
    def window(self):
        found = dialogs()
        assert found, "the credential dialog is gone"
        return found[0]

    def outcome(self, timeout: float = 6.0) -> str:
        """What CredUIPromptForWindowsCredentials returned, or '' if it has not.

        An empty string is a meaningful answer: it means the dialog was never
        submitted, which is what a swallowed keystroke looks like from here.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if RESULT_FILE.exists():
                text = RESULT_FILE.read_text(encoding="utf-8").strip()
                if text:
                    return text
            time.sleep(0.5)
        return ""
