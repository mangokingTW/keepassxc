"""End-to-end check of the fix, driving KeePassXC itself.

The reproduction tests next to this file measure the platform behaviour with
KeePassXC's own SendInput calls reproduced in Python. This one runs the
application: unlock a database, raise a credential prompt, trigger auto-type,
and ask the prompt whether it was submitted with the entry's username.

Which build is under test comes from the command line, so the same script
answers both halves:

    verify_patched_keepassxc.py "C:\\Program Files\\KeePassXC\\KeePassXC.exe"
    verify_patched_keepassxc.py "C:\\bundle\\KeePassXC.exe"

Expected results, and why the host matters:

  * a released build on a patched host  -> the prompt is never submitted
  * a patched build on a patched host   -> submitted, with the username
  * either build on a host still on 2025-09 patches -> submitted; that machine
    predates the change and cannot tell the two builds apart

The witness is CredUIPromptForWindowsCredentials' return value, not the field
contents: UIA reports zero Edit children for this dialog even before anything is
typed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from wintegrate.diagnostics import WindowCensus
from wintegrate.element import UiaElement
from wintegrate.interop import send_keys, user32

RESULT = Path(os.environ.get("CREDUI_PROBE_RESULT", r"C:\Users\Public\credui_probe_result.txt"))
HOST_SCRIPT = Path(__file__).with_name("credui_host.py")
DATABASE = Path(os.environ.get("KPXC_TEST_DB", r"C:\Users\tester\probe.kdbx"))
DATABASE_PASSWORD = os.environ.get("KPXC_TEST_DB_PASSWORD", "probe-db-pass")
ENTRY_USERNAME = os.environ.get("KPXC_TEST_USERNAME", "probeuser")

DIALOG_CLASS = "Credential Dialog Xaml Host"


def say(key, value):
    print(f"{key} = {value}", flush=True)


def visible(predicate):
    return [s for s in WindowCensus.capture() if s.is_visible and predicate(s)]


def credential_dialog():
    found = visible(lambda s: (s.class_name or "") == DIALOG_CLASS)
    return found[0] if found else None


def keepassxc_window(pids):
    return next(
        (s for s in WindowCensus.capture()
         if s.pid in pids and "kdbx" in (s.title or "").lower()),
        None,
    )


def process_ids(name="KeePassXC"):
    listed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-Process -Name {name} -ErrorAction SilentlyContinue | "
         "Select-Object -ExpandProperty Id) -join ','"],
        capture_output=True, text=True, timeout=60,
    ).stdout.strip()
    return {int(p) for p in listed.split(",") if p}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    keepassxc = Path(sys.argv[1])
    say("build", f"{keepassxc} exists={keepassxc.exists()}")
    if not keepassxc.exists():
        return 1
    say("build_version", subprocess.run(
        ["powershell", "-NoProfile", "-Command", f"(Get-Item '{keepassxc}').VersionInfo.FileVersion"],
        capture_output=True, text=True, timeout=60).stdout.strip())
    say("helper_present", Path(r"C:\Program Files\keepassxc-uiaccess\typehelper.exe").exists())

    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Stop-Process -Name KeePassXC -Force -ErrorAction SilentlyContinue"],
                   capture_output=True, timeout=60)
    time.sleep(3.0)
    if RESULT.exists():
        RESULT.unlink()

    # A fresh instance, because --pw-stdin is ignored by an already running one:
    # the second invocation just hands the file to the first.
    unlock = subprocess.Popen(
        [str(keepassxc), "--pw-stdin", str(DATABASE)],
        stdin=subprocess.PIPE, text=True,
    )
    unlock.stdin.write(DATABASE_PASSWORD + "\n")
    unlock.stdin.flush()

    deadline = time.monotonic() + 60
    window = None
    while time.monotonic() < deadline:
        pids = process_ids()
        window = keepassxc_window(pids) if pids else None
        if window and "locked" not in (window.title or "").lower() and "\u9501\u5b9a" not in (window.title or ""):
            break
        time.sleep(1.0)
    say("keepassxc_window", None if window is None else ascii(window.title))
    if window is None:
        say("VERDICT", "inconclusive -- KeePassXC never showed an unlocked database")
        return 1

    # The prompt is raised second, so it is the window auto-type will target:
    # KeePassXC types into whatever was active before it.
    host = subprocess.Popen([sys.executable, str(HOST_SCRIPT)])
    deadline = time.monotonic() + 30
    dialog = None
    while time.monotonic() < deadline:
        dialog = credential_dialog()
        if dialog:
            break
        time.sleep(0.5)
    say("credential_dialog", None if dialog is None else hex(dialog.hwnd))
    if dialog is None:
        say("VERDICT", "inconclusive -- no credential prompt appeared")
        return 1

    user32.SetForegroundWindow(dialog.hwnd)
    time.sleep(1.0)
    user32.ShowWindow(window.hwnd, 9)  # SW_RESTORE
    user32.SetForegroundWindow(window.hwnd)
    time.sleep(1.5)

    root = UiaElement.from_handle(window.hwnd)
    rows = [e for e in root.find_all(control_type_id=50007) if e.name]
    say("entries", [ascii(r.name) for r in rows][:6])
    if not rows:
        say("VERDICT", "inconclusive -- no entry rows in the database view")
        return 1
    try:
        rows[0].select_verified()
    except Exception:
        rows[0].click()
    time.sleep(1.0)

    # Ctrl+Shift+V is "Perform Auto-Type" for the selected entry. KeePassXC is
    # at the same integrity level as this process, so triggering it needs no
    # privilege of its own -- the delegation under test is the *outgoing* half.
    send_keys("^+v")
    time.sleep(2.5)

    # The confirmation prompt appears when the target is not KeePassXC itself.
    for snapshot in visible(lambda s: (s.class_name or "").startswith("Qt")):
        dialog_root = UiaElement.from_handle(snapshot.hwnd)
        buttons = {(b.name or "").strip(): b for b in dialog_root.find_all(control_type_id=50000)}
        confirm = next((b for name, b in buttons.items()
                        if any(k in name for k in ("\u662f", "Yes", "OK"))), None)
        if confirm is not None:
            say("confirmation", [ascii(n) for n in buttons if n])
            confirm.invoke()
            break

    deadline = time.monotonic() + 25
    outcome = ""
    while time.monotonic() < deadline:
        if RESULT.exists():
            outcome = RESULT.read_text(encoding="utf-8", errors="replace").strip()
            if outcome:
                break
        time.sleep(0.5)
    say("credui_outcome", outcome.replace("\n", " | ") or "<the prompt was never submitted>")

    submitted = "RESULT=0" in outcome and ENTRY_USERNAME in outcome
    say("auto_type_reached_the_prompt", submitted)
    say("VERDICT", "fix works" if submitted else "auto-type did not reach the prompt")

    for process in (host, unlock):
        if process.poll() is None:
            process.terminate()
    subprocess.run(["powershell", "-NoProfile", "-Command",
                    "Stop-Process -Name KeePassXC -Force -ErrorAction SilentlyContinue"],
                   capture_output=True, timeout=60)
    print("done", flush=True)
    return 0 if submitted else 3


if __name__ == "__main__":
    sys.exit(main())
