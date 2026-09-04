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
# An empty password is a separate flag rather than an empty variable: `set VAR=`
# in a .cmd *deletes* the variable, so the default came back and the script tried
# to type a password into a database that has none.
DATABASE_PASSWORD = (
    "" if os.environ.get("KPXC_TEST_DB_EMPTY") else os.environ.get("KPXC_TEST_DB_PASSWORD", "probe-db-pass")
)
ENTRY_USERNAME = os.environ.get("KPXC_TEST_USERNAME", "probeuser")
ENTRY_TITLE = os.environ.get("KPXC_TEST_ENTRY_TITLE", "Windows")

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

    # KPXC_ASSUME_RUNNING: take an already unlocked KeePassXC as given and only
    # measure the part under test. Unlocking it from here turned into its own
    # project on one host -- Caps Lock silently upper-casing the typed password,
    # a masked field that cannot be verified, an empty-password confirmation
    # prompt -- none of which is what the fix is about. Where the desktop can be
    # driven at hardware level (a QEMU monitor, for instance), unlocking there
    # and setting this is both simpler and less fragile.
    assume_running = bool(os.environ.get("KPXC_ASSUME_RUNNING"))

    if not assume_running:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Stop-Process -Name KeePassXC -Force -ErrorAction SilentlyContinue"],
                       capture_output=True, timeout=60)
        time.sleep(3.0)
    if RESULT.exists():
        RESULT.unlink()

    # A fresh instance, because --pw-stdin is ignored by an already running one:
    # the second invocation just hands the file to the first.
    # Binary, not text mode: on Windows a text-mode pipe turns "\n" into
    # "\r\n", so KeePassXC read the password with a trailing carriage return and
    # answered "Invalid credentials were provided" -- while keepassxc-cli opened
    # the same database with the same password.
    unlock = None
    if not assume_running:
        unlock = subprocess.Popen(
            [str(keepassxc), "--pw-stdin", str(DATABASE)],
            stdin=subprocess.PIPE,
        )
        unlock.stdin.write((DATABASE_PASSWORD + "\n").encode("utf-8"))
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
        say("VERDICT", "inconclusive -- KeePassXC never showed a database window")
        return 1

    # --pw-stdin is not enough on its own: a first-run prompt can take the focus
    # before the password is consumed, and the run then continues against a
    # locked database with no entries -- which reads as "the test is broken"
    # rather than "the database never opened".
    if not assume_running and ("locked" in (window.title or "").lower()
                               or "锁定" in (window.title or "")):
        say("unlock", "typing the password into the unlock view")
        for snapshot in visible(lambda s: s.pid in process_ids() and (s.class_name or "").startswith("Qt")):
            dialog_root = UiaElement.from_handle(snapshot.hwnd)
            for button in dialog_root.find_all(control_type_id=50000):
                name = (button.name or "").strip()
                if any(k in name for k in ("否", "No", "Cancel", "取消")):
                    button.invoke()
                    time.sleep(1.5)
                    break

        refreshed = None
        for attempt in range(1, 4):
            user32.SetForegroundWindow(window.hwnd)
            time.sleep(1.0)
            fields = UiaElement.from_handle(window.hwnd).find_all(control_type_id=50004)
            if not fields:
                say(f"unlock{attempt}", "no password field in the unlock view")
                break
            if attempt == 1:
                say("unlock_fields", [ascii(f.automation_id) for f in fields][:3])
            # No typing at all for an empty-password database: clicking Unlock is
            # the whole interaction. Verification of a masked field can never
            # succeed either -- set_value_verified read '' back every time,
            # because that is what a password field reports.
            if not DATABASE_PASSWORD:
                say(f"unlock{attempt}", "empty password; clicking Unlock directly")
            else:
                try:
                    fields[0].set_focus(click=True)
                except Exception:
                    fields[0].click()
                time.sleep(0.8)
            # Cleared first: a screenshot of the previous run showed three dots
            # and a warning marker in the field, so part of an earlier attempt
            # was still sitting there and every retry made it worse.
                send_keys("^a")
                time.sleep(0.3)
                # Unicode, not scan codes: send_physical_keys maps each
                # character through the *active* layout, and this host was left
                # on a German one -- the field received thirteen characters that
                # were not this password.
                send_keys(DATABASE_PASSWORD)
                time.sleep(0.8)

            # The button, not Enter. A screenshot showed thirteen dots in the
            # field, no error, and the title still [Locked] -- the keystrokes had
            # arrived and nothing had submitted them.
            unlock_button = next(
                (b for b in UiaElement.from_handle(window.hwnd).find_all(control_type_id=50000)
                 if (b.name or "").strip() in ("Unlock", "解锁", "解密")),
                None,
            )
            if unlock_button is not None:
                say(f"unlock{attempt}.button", ascii(unlock_button.name))
                unlock_button.invoke()
            else:
                send_keys("{ENTER}")
            time.sleep(4.0)

            # An empty password is not accepted straight away: KeePassXC asks
            # "Unlock failed and no password given -- retry with an empty
            # password?" and waits. Three attempts sat on that prompt while the
            # log only said the database was still locked.
            for snapshot in visible(lambda s: s.pid in process_ids() and (s.class_name or "").startswith("Qt")):
                prompt = UiaElement.from_handle(snapshot.hwnd)
                retry = next(
                    (b for b in prompt.find_all(control_type_id=50000)
                     if "empty password" in (b.name or "").lower()
                     or "空密碼" in (b.name or "")),
                    None,
                )
                if retry is not None:
                    say(f"unlock{attempt}.retry", ascii(retry.name))
                    retry.invoke()
                    time.sleep(4.0)
                    break
            time.sleep(2.0)

            refreshed = next((s for s in WindowCensus.capture() if s.hwnd == window.hwnd), None)
            title = "" if refreshed is None else (refreshed.title or "")
            say(f"unlock{attempt}.title", ascii(title))
            if title and "锁定" not in title and "locked" not in title.lower():
                break

        title = "" if refreshed is None else (refreshed.title or "")
        if not title or "锁定" in title or "locked" in title.lower():
            say("VERDICT", "inconclusive -- the database stayed locked")
            return 1
        window = refreshed

    # CREATE_NO_WINDOW: the host's console window is otherwise a candidate for
    # "the last active window", and auto-type happily typed the password into
    # it instead of into the prompt it was hosting.
    host = subprocess.Popen([sys.executable, str(HOST_SCRIPT)],
                            creationflags=0x08000000)
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

    # TreeItem, not ListItem: KeePassXC's entry view is a QTreeView, and Qt maps
    # its rows to UIA TreeItem (50024). Asking for ListItem (50007) found
    # nothing at all -- the window has not one such element -- so the run
    # reported "no entry rows" with a populated database on screen.
    root = UiaElement.from_handle(window.hwnd)
    rows = [e for e in root.find_all(control_type_id=50024) if e.name]
    say("entries", [ascii(r.name) for r in rows][:8])
    # The group tree is TreeItems too, so pick by the entry's title rather than
    # by position: rows[0] was the "Passwords" group, which auto-types nothing.
    target = next((r for r in rows if (r.name or "").strip() == ENTRY_TITLE), None)
    say("entry_selected", None if target is None else ascii(target.name))
    if target is None:
        say("VERDICT", f"inconclusive -- no entry row titled {ENTRY_TITLE!r}")
        return 1
    # Selected through UIA rather than by clicking, because clicking would make
    # KeePassXC the active window -- and auto-type targets whatever was active
    # last. An earlier run raised KeePassXC here, and the password went into the
    # credential host's console window, which was the last other window active:
    # the screenshots showed a black console on top and no prompt at all.
    try:
        target.select_verified()
    except Exception:
        target.click()
    time.sleep(1.0)

    # The prompt must be the *previously* active window, and KeePassXC the
    # active one, when the hotkey fires. Firing it with the prompt still active
    # cannot work from here: the hotkey is itself injected input at medium
    # integrity, so UIPI drops it before KeePassXC ever sees it -- measured, the
    # run reached "is_the_prompt=True" and then no auto-type happened at all.
    user32.SetForegroundWindow(dialog.hwnd)
    time.sleep(1.0)
    say("prompt_activated", user32.GetForegroundWindow() == dialog.hwnd)
    user32.ShowWindow(window.hwnd, 9)  # SW_RESTORE
    user32.SetForegroundWindow(window.hwnd)
    time.sleep(1.5)
    foreground = user32.GetForegroundWindow()
    say("foreground_before_hotkey",
        "%s is_keepassxc=%s" % (hex(foreground), foreground == window.hwnd))
    if foreground != window.hwnd:
        say("VERDICT", "inconclusive -- KeePassXC was not active when auto-type fired")
        return 1

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
            # The prompt names the window it is about to type into, which is the
            # only direct read on what KeePassXC picked as the target.
            texts = [ascii(t.name) for t in dialog_root.find_all(control_type_id=50020) if t.name]
            say("confirmation_text", texts[:4])
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
        if process is not None and process.poll() is None:
            process.terminate()
    if not assume_running:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Stop-Process -Name KeePassXC -Force -ErrorAction SilentlyContinue"],
                       capture_output=True, timeout=60)
    print("done", flush=True)
    return 0 if submitted else 3


if __name__ == "__main__":
    sys.exit(main())
