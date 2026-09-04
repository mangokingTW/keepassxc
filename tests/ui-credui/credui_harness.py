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


def uac_enabled() -> bool:
    """Whether this machine has UAC on.

    Not on its own a sufficient condition: a GitHub hosted runner reports
    EnableLUA=1 and still runs a RunLevel Limited scheduled task elevated. So
    this is reported, and whether de-elevation actually happened is decided by
    what the typer reports about itself.
    """
    value = powershell(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\Policies\\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA"
    )
    return value.strip() == "1"


def type_at_medium_integrity(hwnd: int, sequence: str, report: Path, timeout: float = 120.0) -> str:
    """Types `sequence` into `hwnd` from a process at the Medium mandatory level.

    Two routes, because neither works everywhere:

      * if this process is already unelevated, run the typer directly -- that is
        an ordinary user session and nothing needs lowering;
      * otherwise go through run_at_medium_integrity.py, which duplicates this
        token, sets the copy's integrity level to Medium and launches the child
        with it.

    The scheduled-task route (`RunLevel Limited`) was tried first and does not
    de-elevate on a GitHub hosted runner: the account is runneradmin with
    EnableLUA=1 and FilterAdministratorToken unset, so the session has no
    filtered token to fall back on and the task ran elevated. Lowering the token
    directly does not depend on UAC having prepared one.
    """
    if report.exists():
        report.unlink()

    typer = Path(__file__).with_name("type_into.py")
    launcher = Path(__file__).with_name("run_at_medium_integrity.py")
    argv = [sys.executable, str(typer), str(hwnd), sequence, str(report)]
    if is_elevated():
        argv = [sys.executable, str(launcher)] + argv

    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if done.stdout.strip():
        print(f"typer launcher stdout: {done.stdout.strip()}")
    if done.returncode != 0 and done.stderr.strip():
        print(f"typer launcher stderr: {done.stderr.strip()[:600]}")

    if not report.exists():
        return f"<no report; launcher exited {done.returncode}>"
    return report.read_text(encoding="utf-8", errors="replace").strip()


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
