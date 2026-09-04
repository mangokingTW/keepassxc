"""End-to-end check of the KeePassXC uiAccess fix, driven by wintegrate.

Hand-rolled focus handling is what made the earlier attempts unreadable: the
password went into a console window, the hotkey was dropped by UIPI, and every
"it didn't work" could equally have been the harness. wintegrate owns
activation and verifies it, so a failure here is the product's.

The report is the session's own artifacts -- recording, window census, event
timeline -- so measurements go into `log_event` rather than into prints of my
own. The one thing it has no API for is the integrity level of a process, and
that is the entire subject of this bug, so that part is measured here.
"""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

import wintegrate as w

# Settings come from the command line first and the environment second. The
# command line is not a convenience: on a hosted runner this harness is started
# through run_at_medium_integrity.py, which hands the child an environment block
# built from the user token rather than the calling step's environment -- so
# anything passed as an env var by the workflow would silently not arrive.


def _parse_args(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", default=os.environ.get("KPXC_EXE"))
    parser.add_argument("--db", default=os.environ.get("KPXC_DB"))
    parser.add_argument("--password", default=os.environ.get("KPXC_DB_PASSWORD", "autotype1"))
    parser.add_argument("--entry", default=os.environ.get("KPXC_ENTRY", "Windows"))
    parser.add_argument("--username", default=os.environ.get("KPXC_USERNAME", "probeuser"))
    parser.add_argument("--host-script", default=os.environ.get("KPXC_HOST_SCRIPT"))
    parser.add_argument("--result", default=os.environ.get("CREDUI_PROBE_RESULT"))
    parser.add_argument("--artifacts", default=os.environ.get("KPXC_ARTIFACTS"))
    args = parser.parse_args(argv)
    missing = [name for name in ("exe", "db", "host_script", "result", "artifacts")
               if not getattr(args, name)]
    if missing:
        parser.error("missing: " + ", ".join("--" + m.replace("_", "-") for m in missing))
    return args


ARGS = _parse_args()
EXE = Path(ARGS.exe)
DB = Path(ARGS.db)
PASSWORD = ARGS.password
ENTRY = ARGS.entry
USERNAME = ARGS.username
HOST = Path(ARGS.host_script)
RESULT = Path(ARGS.result)
ARTIFACTS = Path(ARGS.artifacts)

PROMPT_CLASS = "Credential Dialog Xaml Host"
LOCKED_MARKERS = ("\u9501\u5b9a", "locked")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)

# Declared, and on private handles rather than on the shared `ctypes.windll`:
# an undeclared pointer argument is marshalled as a C int, which raises
# "OverflowError: int too long to convert" on a real SID address, and pinning
# types on the shared handle would leak them to every other ctypes user in the
# process.
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.HANDLE)]
advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetWindow.restype = wintypes.HWND


def integrity_of(pid: int) -> str:
    """The integrity level of a process, or why it could not be read.

    "Could not read it" has to stay distinguishable from "Medium": an earlier
    round used TokenElevation, which answers a different question, and reported
    a de-elevated child as privileged.
    """
    names = {0x0000: "Untrusted", 0x1000: "Low", 0x2000: "Medium",
             0x2100: "MediumPlus", 0x3000: "High", 0x4000: "System"}
    process = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not process:
        return f"unreadable (OpenProcess err={ctypes.get_last_error()})"
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            return f"unreadable (OpenProcessToken err={ctypes.get_last_error()})"
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 25, buf, size, ctypes.byref(size)):
            return f"unreadable (GetTokenInformation err={ctypes.get_last_error()})"
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        count = advapi32.GetSidSubAuthorityCount(sid)[0]
        rid = advapi32.GetSidSubAuthority(sid, count - 1)[0]
        return f"{names.get(rid, hex(rid))} (0x{rid:04x})"
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def log_window(session, event_type: str, hwnd: int) -> None:
    pid = w.get_window_pid(hwnd)
    owner = user32.GetWindow(wintypes.HWND(hwnd), 4)  # GW_OWNER
    session.log_event(
        event_type,
        f"{w.get_window_title(hwnd)!r} ({w.get_window_class(hwnd)})",
        hwnd=hex(hwnd), pid=pid, image=w.get_process_image_name(pid),
        integrity=integrity_of(pid), owner=hex(owner) if owner else None,
    )


DISPLAY_AFFINITY = {0: "WDA_NONE", 1: "WDA_MONITOR", 0x11: "WDA_EXCLUDEFROMCAPTURE"}
user32.GetWindowDisplayAffinity.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]


def display_affinity(hwnd: int) -> str:
    value = wintypes.DWORD()
    if not user32.GetWindowDisplayAffinity(wintypes.HWND(hwnd), ctypes.byref(value)):
        return f"unreadable (err={ctypes.get_last_error()})"
    return DISPLAY_AFFINITY.get(value.value, hex(value.value))


class ForegroundTrace:
    """Samples which window has the foreground, for the length of a block.

    Auto-Type resolves its target as "whatever is active" at one instant, and
    on a runner the patched build never asked to delegate -- no helper process
    started and KeePassXC printed no warning, which together mean the predicate
    was handed a window that is not the credential prompt. The only way to know
    which window that was is to record what the foreground did while the
    sequence ran; on a machine where this passes, the prompt is simply there
    throughout.
    """

    def __init__(self, session, interval: float = 0.1):
        self.session = session
        self.interval = interval
        self.samples: list[tuple[float, int, str, str]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        start = time.monotonic()
        last = None
        while not self._stop.is_set():
            hwnd = w.get_foreground_window()
            if hwnd != last:
                last = hwnd
                self.samples.append((
                    round(time.monotonic() - start, 2), hwnd,
                    w.get_window_class(hwnd) or "", (w.get_window_title(hwnd) or "")[:40],
                ))
            time.sleep(self.interval)

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        # Only the changes, because a list of identical samples says nothing:
        # what matters is the order the foreground moved in.
        self.session.log_event(
            "foreground_trace",
            f"{len(self.samples)} changes while auto-type ran",
            samples=[{"t": t, "hwnd": hex(h), "class": c, "title": ti}
                     for t, h, c, ti in self.samples],
        )
        return False


def clear_background_windows(session, keep: set[int]) -> None:
    """Minimises every visible top-level window except the ones named.

    Not tidiness: KeePassXC hides its own window before typing, and Windows
    then activates whatever is next in the Z-order. That window is what
    Auto-Type resolves as its target. On a runner the next one was the agent's
    own terminal -- measured, in the foreground trace -- so the sequence was
    aimed at a console window, the credential-prompt predicate never matched,
    and no helper was ever started. On a clean desktop the prompt is next,
    which is the only reason this passes there.

    Minimised rather than closed: these windows belong to the machine, not to
    the test, and one of them is the agent that is running the job.
    """
    minimised = []
    for snapshot in w.WindowCensus.capture():
        if not snapshot.is_visible or snapshot.hwnd in keep:
            continue
        if not (snapshot.title or "").strip():
            continue
        user32.ShowWindow(wintypes.HWND(snapshot.hwnd), 6)  # SW_MINIMIZE
        minimised.append({"hwnd": hex(snapshot.hwnd), "class": snapshot.class_name,
                          "title": (snapshot.title or "")[:40]})
    session.log_event("background_cleared", f"{len(minimised)} windows minimised",
                      windows=minimised)


def ensure_foreground(session, window, attempts: int = 6) -> None:
    """Puts the window in front, and says who was there when it was not.

    A hosted runner is not an empty desktop. This run found the agent's own log
    window filling the screen and holding the foreground, so the password went
    there and the database simply stayed locked -- with every call in the
    harness reporting success. The window that has the foreground is minimised
    and the request repeated, which is bounded and leaves a record of what was
    in the way.

    wintegrate's own runner sanitisation does not cover it: it is gated on
    `env.is_desktop`, and `windows-latest` is Windows Server.
    """
    for attempt in range(attempts):
        window.set_foreground()
        time.sleep(0.4)
        foreground = w.get_foreground_window()
        if foreground == window.hwnd:
            if attempt:
                session.log_event("foreground", "recovered", attempts=attempt + 1)
            return
        log_window(session, "foreground_thief", foreground)
        # A modal of the application under test is a different problem, and
        # minimising it does not solve it: the main window comes back to the
        # foreground while the modal keeps swallowing every keystroke, which is
        # how "the database stayed locked" appeared with every call reporting
        # success. Named here instead, so the fix is to stop it appearing.
        if user32.GetWindow(wintypes.HWND(foreground), 4) == window.hwnd:
            raise AssertionError(
                f"{w.get_window_title(foreground)!r} is a modal dialog of the window "
                "under test; it holds the foreground and input to the main window "
                "will be swallowed. Seed the setting that suppresses it."
            )
        user32.ShowWindow(wintypes.HWND(foreground), 6)  # SW_MINIMIZE
        time.sleep(0.4)
    raise AssertionError(
        f"could not put {window.title!r} in front after {attempts} attempts; "
        "every keystroke below would have gone to whatever holds the foreground"
    )


def allow_screen_capture(session, window) -> None:
    """Turns off KeePassXC's own anti-screenshot protection, and verifies it.

    KeePassXC calls SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) on its
    windows, so Windows hides them from *every* capture API -- GDI, DXGI,
    Windows.Graphics.Capture, DWM thumbnails alike. A recording of this run
    therefore showed the credential prompt and the keystroke HUD with KeePassXC
    simply absent, while a hypervisor-level screenshot of the same moment had
    it filling the screen. There is no flag on the capture side that changes
    this and no way to clear the affinity from another process: only the app's
    own switch can.

    It is a menu action with no shortcut and it is not persisted, so there is no
    config key or registry value to seed -- `m_allowScreenCapture` is a
    hard-coded false in MainWindow.h. Positions come from MainWindow.ui (View is
    the 5th menu; Theme, Compact Mode, Always on Top, Allow Screen Capture), and
    the affinity is measured afterwards, because both the menu labels and their
    automation ids are useless here: every QAction publishes the menu bar's
    object path, and the labels are localised.
    """
    before = display_affinity(window.hwnd)
    if before == "WDA_NONE":
        session.log_event("screen_capture", "already capturable", affinity=before)
        return

    root = w.UiaElement.from_handle(window.hwnd)
    menu_bar = root.find_descendant(control_type_id=50010)
    menus = [c for c in menu_bar.children() if c.control_type_id == 50011]
    seen = {s.hwnd for s in w.WindowCensus.capture()}
    menus[4].expand_verified()
    time.sleep(1.0)
    popup = next(s for s in w.WindowCensus.capture()
                 if s.hwnd not in seen and s.is_visible and "Popup" in (s.class_name or ""))
    items = w.UiaElement.from_handle(popup.hwnd).find_all(control_type_id=50011)
    items[3].invoke()
    time.sleep(1.0)
    after = display_affinity(window.hwnd)
    session.log_event("screen_capture", f"{items[3].name!r} invoked",
                      before=before, after=after,
                      menu_items=[e.name for e in items])
    if after != "WDA_NONE":
        raise AssertionError(
            f"the window is still excluded from capture ({after}); the recording "
            "would show everything except the application under test")


def accept_button(session, dialog_hwnd: int):
    """The button that proceeds, decided by two independent measurements.

    `automation_id` cannot do it alone: both buttons of a QMessageBox publish
    the same one (`Application.QMessageBox.qt_msgbox_buttonbox.QPushButton`),
    which is Qt's habit of giving a container's object path to its children.

    What the source says (`MessageBox::question`, buttons `Yes | Cancel`,
    accepted when the result `== MessageBox::Yes`) is that the buttons are added
    with a `QMessageBox::ButtonRole`, and Qt lays a button box out by role for
    the platform -- on Windows the accepting role comes first visually, while
    the UIA tree keeps creation order. So position decides, and the label only
    corroborates: its text comes from Qt's own `stdButtonText`, so it follows
    the qtbase catalogue rather than KeePassXC's, which is why this dialog reads
    'Yes'/'Cancel' on an otherwise Chinese desktop.

    The two signals have to agree. If they do not, that is reported instead of
    clicked, because pressing the wrong one silently cancels the sequence under
    test -- and Cancel is the default button, so guessing with Enter is worse.
    """
    root = w.UiaElement.from_handle(dialog_hwnd)
    box = next((e for e in root.find_all(control_type_id=50026)  # Group
                if (e.automation_id or "").endswith("qt_msgbox_buttonbox")), None)
    buttons = (box or root).find_all(control_type_id=50000)  # Button
    measured = [(b.name, b.bounding_rectangle) for b in buttons]
    by_position = sorted((b for b in buttons if b.bounding_rectangle[2] > b.bounding_rectangle[0]),
                         key=lambda b: b.bounding_rectangle[0])
    leftmost = by_position[0] if by_position else None
    accepting = {"yes", "ok", "&yes", "是", "確定", "确定"}
    by_label = [b for b in buttons if (b.name or "").strip().lower() in accepting
                or (b.name or "").strip() in accepting]

    session.log_event("confirmation_buttons", f"{measured}",
                      leftmost=None if leftmost is None else leftmost.name,
                      by_label=[b.name for b in by_label])
    if leftmost is None or len(by_label) != 1:
        raise AssertionError(f"cannot identify the accepting button among {measured}")
    if leftmost.name != by_label[0].name:
        raise AssertionError(
            f"the two signals disagree: leftmost is {leftmost.name!r}, "
            f"the accepting label is {by_label[0].name!r} -- measured {measured}")
    return leftmost


def is_locked(window) -> bool:
    title = window.title or ""
    return any(m in title or m in title.lower() for m in LOCKED_MARKERS)


def main() -> int:
    # One at a time: two overlapping runs typed the password into the same box
    # and 'autotype1autotype1' then failed as an ordinary wrong password, which
    # reads as "the database stayed locked".
    running = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "@(Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' -and"
         " $_.CommandLine -like '*kpxc_credui*' }).Count"],
        # CREATE_NO_WINDOW: a console that flashes into the foreground is a
        # window that steals focus, and this suite is about which window has it.
        capture_output=True, text=True, creationflags=0x08000000).stdout.strip()
    if running not in ("", "0", "1"):
        print(f"VERDICT = refusing to start; {running} copies of this harness are running")
        return 2

    RESULT.unlink(missing_ok=True)
    # As a context manager, because that is what starts the recording and what
    # writes the census, the failure screenshot and the event timeline: built
    # without `with`, the session produced two screenshots and nothing else --
    # diagnostics that quietly did not run.
    # No virtual-desktop isolation: it is the right default for a test that
    # must not type into the user's own windows, but Windows cloaks windows
    # that live on another virtual desktop, so the recording showed the
    # credential prompt and the keystroke HUD with KeePassXC nowhere in frame.
    # This run's output is evidence someone reads, so everything stays on one
    # desktop.
    with w.Session(w.SessionConfig(artifact_dir=ARTIFACTS, record_video=True,
                                   isolated_virtual_desktop=False,
                                   # 'auto' is gated on env.is_desktop, and
                                   # windows-latest is Windows Server -- so the
                                   # runner cleanup silently did not run.
                                   sanitize_runner=bool(os.environ.get("CI")))) as session:
        return run(session)


def run(session) -> int:
    session.log_event("harness", f"wintegrate {w.__version__}",
                      integrity=integrity_of(os.getpid()), build=str(EXE))

    with session.step("open the database"):
        # Launched separately, then found by title: KeePassXC hands the command
        # line to its single instance, so the process that creates the window is
        # not the one launched here -- launch_and_discover reported "nothing new
        # appeared at all" while the window was in its own list.
        # Its own stderr is an artifact: the patch warns there when it finds a
        # window only a privileged process can reach and has no helper to hand
        # the keystrokes to, and that warning is what separates "delegation was
        # never attempted" from "it was attempted and failed".
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        stderr_log = open(ARTIFACTS / "keepassxc-stderr.log", "wb")
        environment = dict(os.environ, QT_FORCE_STDERR_LOGGING="1")
        subprocess.Popen([str(EXE), str(DB)], env=environment,
                         stdout=stderr_log, stderr=subprocess.STDOUT)
        window = session.find_window(title_pattern="KeePassXC", timeout=30)
        log_window(session, "keepassxc_window", window.hwnd)
        ensure_foreground(session, window)

        if is_locked(window):
            field = window.find_text_input()
            # Typed, not set: a masked QLineEdit reads back as '', so
            # set_value_verified can never confirm it. Cleared first so a stale
            # value cannot become a wrong password.
            field.click()
            w.send_keys("^a")
            w.send_keys(PASSWORD)
            w.send_keys("{ENTER}")
            for _ in range(20):
                time.sleep(1)
                if not is_locked(window):
                    break
        session.log_event("database", window.title, locked=is_locked(window))
        if is_locked(window):
            raise AssertionError(f"the database stayed locked: {window.title!r}")

    with session.step("allow screen capture"):
        allow_screen_capture(session, window)
        session.capture_screenshot("keepassxc-visible")

    with session.step("select the entry"):
        # The rows are TreeItem (50024), not ListItem: the entry view is a
        # QTreeView. Asking for ListItem found nothing at all -- the window has
        # not one such element -- so a run reported "no entry rows" with a
        # populated database on screen. The group tree is TreeItems too, so the
        # row is identified by automation id as well as by name.
        target = None
        for locator in window.get_by_role("treeitem").all():
            element = locator.element
            if element.name == ENTRY and (element.automation_id or "").endswith("entryView"):
                target = locator
                break
        if target is None:
            raise AssertionError(
                f"no entryView row named {ENTRY!r} among "
                f"{[l.element.name for l in window.get_by_role('treeitem').all()]}")
        # Selected through UIA, not by clicking: a click makes KeePassXC active,
        # and auto-type targets whatever was active last.
        element = target.element
        session.log_event("entry", f"{element.name!r}", rect=element.bounding_rectangle)
        try:
            element.select_verified()
        except Exception:
            target.click()

    with session.step("raise the credential prompt"):
        # CREATE_NO_WINDOW: the host's console window is otherwise a candidate
        # for "the last active window", and auto-type typed the password into it
        # instead of into the prompt it was hosting.
        host = subprocess.Popen([sys.executable, str(HOST)], creationflags=0x08000000)
        prompt = session.find_window(class_name=PROMPT_CLASS, timeout=30)
        log_window(session, "prompt", prompt.hwnd)

        # The prompt has to be the *previously* active window and KeePassXC the
        # active one. Firing the hotkey while the prompt is active cannot work
        # from here: the hotkey is injected input at medium integrity, so UIPI
        # drops it before KeePassXC sees it -- measured, a run reached
        # "prompt is foreground" and then no auto-type happened at all.
        ensure_foreground(session, prompt)
        session.log_event("prompt_activated", "prompt is the foreground window",
                          ok=w.get_foreground_window() == prompt.hwnd)
        session.capture_screenshot("prompt-up")

        # Everything else out of the way first, so that hiding KeePassXC leaves
        # the prompt as the next window in the Z-order rather than whatever the
        # machine happens to have open.
        clear_background_windows(session, keep={window.hwnd, prompt.hwnd})
        ensure_foreground(session, prompt)
        ensure_foreground(session, window)
        log_window(session, "foreground_before_hotkey", w.get_foreground_window())
        if w.get_foreground_window() != window.hwnd:
            raise AssertionError("KeePassXC was not active when auto-type fired")

    with session.step("perform auto-type"), ForegroundTrace(session):
        w.send_hotkey("ctrl+shift+v")
        time.sleep(2.5)
        # KeePassXC asks before typing into a window that is not its own. The
        # button is chosen by excluding the cancelling one rather than by
        # matching an affirmative label: this dialog came up as 'Yes'/'Cancel'
        # on a zh-TW desktop whose menus are all Chinese, so a run that looked
        # for \u662f clicked nothing and left the dialog sitting there.
        # The dialog is a separate top-level Qt window, found by class rather
        # than by title: its title is localised.
        dialog = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and dialog is None:
            for snapshot in w.WindowCensus.capture():
                if (snapshot.is_visible and snapshot.hwnd != window.hwnd
                        and (snapshot.class_name or "").startswith("Qt")):
                    dialog = snapshot
                    break
            time.sleep(0.2)
        if dialog is None:
            session.log_event("confirmation", "no confirmation dialog appeared")
        else:
            log_window(session, "confirmation", dialog.hwnd)
            accept_button(session, dialog.hwnd).invoke()

        outcome = ""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if RESULT.exists():
                outcome = RESULT.read_text(encoding="utf-8", errors="replace").strip()
                if outcome:
                    break
            time.sleep(0.5)
        session.capture_screenshot("after-auto-type")
        submitted = "RESULT=0" in outcome and USERNAME in outcome
        session.log_event("credui_outcome", outcome.replace("\n", " | ") or "never submitted",
                          submitted=submitted)

    if host.poll() is None:
        host.terminate()
    print(f"VERDICT = {'fix works' if submitted else 'auto-type did not reach the prompt'}",
          flush=True)
    return 0 if submitted else 3


if __name__ == "__main__":
    sys.exit(main())
