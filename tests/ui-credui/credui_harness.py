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


def broker_pids() -> list[str]:
    listed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-Process -Name {BROKER} -ErrorAction SilentlyContinue | "
         "Select-Object -ExpandProperty Id) -join ','"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    return [p for p in listed.split(",") if p]


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
