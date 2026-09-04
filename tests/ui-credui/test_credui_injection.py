"""keepassxreboot/keepassxc#12956, as a baseline anyone can re-run.

The claim under test: keyboard input injected by an ordinary-integrity process
does not reach the "Windows Security" credential dialog. That is measured three
ways, because the obvious way is unreliable:

  * `test_dialog_is_the_brokered_one` fixes what is being measured -- a dialog
    of class "Credential Dialog Xaml Host" owned by CredentialUIBroker, not some
    look-alike, and records that UIA cannot enumerate its fields.
  * `test_injected_input_reaches_the_dialog` is the reproduction, written as the
    behaviour a user expects and marked **strict xfail**: it xfails while the
    bug is present and becomes a hard failure once a build or a Windows update
    fixes it, so the baseline cannot rot silently.
  * `test_uiaccess_helper_reaches_the_dialog` is the proposed fix. It skips with
    a reason unless a signed uiAccess helper is installed, because "the fix
    works" and "the fix is not installed" must not look alike.

What is deliberately *not* asserted: that the January 2026 update caused this.
Showing that needs a machine without it, and there isn't one here -- these tests
say what today does, not what changed.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest
from credui_harness import (
    BROKER,
    CredentialPrompt,
    broker_pids,
    is_elevated,
    type_at_medium_integrity,
    uac_enabled,
)
from wintegrate.element import UiaElement
from wintegrate.interop import send_keys

PROBE_USER = "wintegrate-probe"
PROBE_PASSWORD = "probe-password"

# Where an installed helper would live. Under Program Files on purpose: Windows
# grants uiAccess only to a signed binary in a path a standard user cannot write.
HELPER = Path(os.environ.get("CREDUI_UIACCESS_HELPER",
                             r"C:\Program Files\wintegrate-uiaccess\typehelper.exe"))


def _shell_execute(exe: Path, params: str) -> bool:
    """Starts `exe` through ShellExecuteEx and waits for it.

    Needed because uiAccess binaries cannot be started with CreateProcess; see
    the note in the test below.
    """
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", wintypes.LPVOID),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    SEE_MASK_NOASYNC = 0x00000100
    SW_SHOWMINNOACTIVE = 7

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
    info.lpVerb = "open"
    info.lpFile = str(exe)
    info.lpParameters = params
    # Minimised and not activated: the helper must not take the foreground from
    # the dialog it is about to type into.
    info.nShow = SW_SHOWMINNOACTIVE

    ok = shell32.ShellExecuteExW(ctypes.byref(info))
    if not ok:
        print(f"ShellExecuteExW failed: {ctypes.get_last_error()}")
    return bool(ok)


def _submit(text: str = PROBE_USER) -> None:
    """Types a username, a password, and Enter -- the auto-type shape."""
    send_keys(text)
    time.sleep(0.6)
    send_keys("{TAB}")
    time.sleep(0.4)
    send_keys(PROBE_PASSWORD)
    time.sleep(0.6)
    send_keys("{ENTER}")


def test_dialog_is_the_brokered_one():
    """Pins the target, so a later failure cannot be a different window."""
    with CredentialPrompt() as prompt:
        window = prompt.window
        assert (window.class_name or "") == "Credential Dialog Xaml Host"
        assert str(window.pid) in broker_pids(), (
            f"the dialog belongs to pid {window.pid}, which is not a {BROKER} process "
            f"({broker_pids()}) -- this is not the dialog the issue is about"
        )
        # Recorded, not asserted as desirable: UIA sees no fields here, which is
        # why these tests use the API's return value as the witness.
        fields = UiaElement.from_handle(window.hwnd).find_all(control_type_id=50004)
        print(f"UIA Edit children: {len(fields)}")


@pytest.fixture
def medium_integrity_submission():
    """A raised dialog that a non-elevated process has just typed into.

    The preconditions live here rather than in the test on purpose. A strict
    xfail swallows *any* failure in the test body, so a broken de-elevation
    would be recorded as "the bug reproduced" -- which happened: a
    PermissionError from pytest's own tmp_path was reported as an xfail.
    A failure in a fixture is an error instead, and errors are loud.
    """
    # Not tmp_path: pytest's numbered temp directories were created by an
    # elevated run earlier and scanning them raised PermissionError for an
    # ordinary user.
    root = Path(os.environ.get("RUNNER_TEMP") or os.environ.get("TEMP") or r"C:\Users\Public")
    report_path = root / "credui_typer_report.txt"

    # No pre-emptive guess about why a host might refuse to de-elevate: an
    # earlier version skipped on "UAC is disabled", and the hosted runner it was
    # written for reports EnableLUA=1 while still running a RunLevel Limited
    # task elevated. Whether de-elevation worked is decided below, from what the
    # typer reports about its own token.
    print(f"test process elevated: {is_elevated()}  UAC enabled: {uac_enabled()}")

    with CredentialPrompt() as prompt:
        window = prompt.window
        report = type_at_medium_integrity(
            window.hwnd, f"{PROBE_USER}\t{PROBE_PASSWORD}\n", report_path
        )
        print(f"de-elevated typer report:\n{report}")
        if "elevation=not-elevated" not in report:
            # Skip rather than fail: nothing was measured. Failing would be read
            # as a finding, and an xfail marker on the test would absorb it
            # entirely -- which is how an elevated run first came back green.
            pytest.skip(
                "the typer could not be dropped to ordinary integrity, so the ordinary "
                f"case was not measured. Report was: {report!r}"
            )
        assert "typed=yes" in report, f"the typer never delivered its keystrokes: {report!r}"
        yield prompt


@pytest.mark.xfail(
    strict=True,
    reason=(
        "keepassxreboot/keepassxc#12956: SendInput from an ordinary-integrity "
        "process does not reach the CredentialUIBroker dialog. Strict, so this "
        "fails loudly if it ever starts working rather than passing unnoticed."
    ),
)
def test_injected_input_reaches_the_dialog(medium_integrity_submission):
    """The reproduction, reduced to the one claim that can be wrong.

    KeePassXC's auto-type is exactly the call the fixture made:
    AutoTypeWindows.cpp sends KEYEVENTF_UNICODE and KEYEVENTF_SCANCODE through
    SendInput from an ordinary process. A difference in outcome between this and
    the uiAccess test below is a difference in privilege, not in API.
    """
    outcome = medium_integrity_submission.outcome()
    print(f"credui outcome: {outcome!r}")
    assert "RESULT=0" in outcome, (
        "the dialog was never submitted: CredUIPromptForWindowsCredentials had not "
        "returned by the time the wait expired, which is what a swallowed keystroke "
        "looks like from outside the dialog"
    )
    assert PROBE_USER in outcome, f"submitted, but not with the injected text: {outcome!r}"


@pytest.mark.skipif(
    not HELPER.exists(),
    reason=(
        f"no uiAccess helper at {HELPER}. Build and sign it first -- an absent "
        f"helper must not read as a working fix."
    ),
)
def test_uiaccess_helper_reaches_the_dialog():
    """The proposed fix: the same SendInput, from a uiAccess process.

    uiAccess is not elevation. The helper runs as the same user with no UAC
    prompt; what it gains is exemption from UIPI. If this passes while the test
    above xfails, the collision is UIPI and a signed sidecar is a fix that does
    not require running the whole application elevated.
    """
    with CredentialPrompt() as prompt:
        window = prompt.window
        # The whole sequence goes to the helper -- username, Tab, password,
        # Enter. Sending any part of it from here would reintroduce exactly the
        # unprivileged injection the test above shows does not arrive.
        sequence = f"{PROBE_USER}\t{PROBE_PASSWORD}\n"
        log = Path(os.environ.get("TEMP", r"C:\Users\Public")) / "uiaccess_helper.log"
        if log.exists():
            log.unlink()


        # ShellExecute, not CreateProcess: a uiAccess binary launched with
        # CreateProcess fails with ERROR_ELEVATION_REQUIRED (740). The grant
        # comes from the AppInfo service, and only the shell path consults it --
        # which is itself a constraint on any sidecar design, since the
        # application cannot simply spawn the helper.
        # The target window is handed over explicitly. Letting the helper pick
        # the foreground window is a race it lost once -- to a console -- and the
        # run then looked like uiAccess had failed when the mechanism was fine.
        started = _shell_execute(HELPER, f'"{sequence}" 2500 "{log}" {window.hwnd}')
        assert started, "ShellExecuteEx refused to start the helper"

        deadline = time.monotonic() + 40.0
        report = ""
        while time.monotonic() < deadline:
            if log.exists():
                report = log.read_text(encoding="utf-8", errors="replace")
                if "typed=" in report:
                    break
            time.sleep(0.5)
        print(f"helper report:\n{report}")
        assert "foreground_now=1" in report, (
            "the helper could not bring the dialog to the foreground, so it refused to "
            f"type; report was: {report!r}"
        )
        assert "uiAccess=1" in report, (
            "the helper did not get the uiAccess flag -- Windows grants it only to a "
            "signed binary under a protected path, so this is a deployment problem "
            "rather than a measurement of the dialog. Report was: " + repr(report)
        )

        outcome = prompt.outcome()
        print(f"credui outcome: {outcome!r}")
        assert "RESULT=0" in outcome and PROBE_USER in outcome, (
            f"the uiAccess helper's input did not submit the dialog either: {outcome!r}"
        )
