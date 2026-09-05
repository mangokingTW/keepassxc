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
import contextlib
import ctypes
import os
import re
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

import helper_watch
import wintegrate as w
from wintegrate.controls import Menu as MenuBar
from wintegrate.interop import SW_HIDE, SW_SHOW

# Settings come from the command line first and the environment second, which
# is what the workflow passes. KeePassXC is started through
# run_at_medium_integrity.py further down; that hands its child an environment
# block built from the user token rather than this process's, so nothing here
# should rely on an exported variable reaching it.


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
    # Pacing for the recording. The run asserts the same things either way; this
    # only decides whether a person can see the steps it went through.
    parser.add_argument("--dwell", type=float, default=float(os.environ.get("KPXC_DWELL", "0")))
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
DWELL = ARGS.dwell

PROMPT_CLASS = "Credential Dialog Xaml Host"

# From wintegrate rather than redefined here; SW_MINIMIZE is the one it does
# not export.
SW_MINIMIZE = 6

# The shell's own windows are left alone: hiding the taskbar or the desktop
# would outlast this process if anything went wrong afterwards.
SHELL_CLASSES = frozenset({"Shell_TrayWnd", "Progman", "WorkerW", "Shell_SecondaryTrayWnd"})

# Windows whose owner puts them back in the foreground no matter how often they
# are asked not to. On a GitHub hosted runner this is the agent's own terminal.
PERSISTENT_FOREGROUND_CLASSES = frozenset({"CASCADIA_HOSTING_WINDOW_CLASS"})
LOCKED_MARKERS = ("\u9501\u5b9a", "locked")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetWindow.restype = wintypes.HWND

# The integrity reading lives in helper_watch, which needs it too. It is the one
# thing in this suite wintegrate has no API for, and it is the entire subject of
# the bug, so it is measured -- once.
integrity_of = helper_watch.integrity
integrity_level = helper_watch.integrity_rid


def log_window(session, event_type: str, hwnd: int) -> None:
    pid = w.get_window_pid(hwnd)
    owner = user32.GetWindow(wintypes.HWND(hwnd), 4)  # GW_OWNER
    session.log_event(
        event_type,
        f"{w.get_window_title(hwnd)!r} ({w.get_window_class(hwnd)})",
        hwnd=hex(hwnd), pid=pid, image=w.get_process_image_name(pid),
        integrity=integrity_of(pid), owner=hex(owner) if owner else None,
    )


def affinity_of(window) -> str:
    """The window's own reading, as a word for the log.

    `None` from wintegrate deliberately means "could not be read" rather than
    "not excluded", and the two must not collapse into one string.
    """
    affinity = window.display_affinity
    return "unreadable" if affinity is None else affinity.name


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

    def __init__(self, session, interval: float = 0.1, hold: int | None = None):
        self.session = session
        self.interval = interval
        # When given, that window is put back in front whenever something else
        # takes it. The helper drops input whose target is not in front -- it
        # has to, or a delayed keystroke lands in whatever window arrived
        # instead -- so a window that surfaces mid-sequence eats the rest of it.
        self.hold = hold
        self.interventions: list[dict] = []
        self.hidden: set[int] = set()
        self.samples: list[tuple[float, int, str, str]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    @staticmethod
    def _hwnd_text(hwnd) -> str:
        """A window handle for the log, including "there was not one".

        GetForegroundWindow returns NULL while no window is active -- during a
        desktop transition, or between one window being destroyed and the next
        being raised. hex(None) raises, and this runs on a sampling thread
        whose exception surfaced as a failure of the thing being measured.
        """
        return hex(hwnd) if hwnd else "none"

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
            # No foreground window is not an intervention: nothing took it.
            if self.hold and hwnd and hwnd != self.hold:
                self.interventions.append({
                    "t": round(time.monotonic() - start, 2), "took_it": self._hwnd_text(hwnd),
                    "class": w.get_window_class(hwnd) or "",
                    "title": (w.get_window_title(hwnd) or "")[:40],
                })
                # Re-assert the target instead of pushing the intruder down.
                # Hiding or minimising other people's windows turned into a
                # fight -- 285 interventions in one sequence against a terminal
                # its owner kept re-activating -- and it is not what the rest of
                # this suite does: nothing else depends on the Z-order, only on
                # its own window being in front.
                #
                # Through wintegrate rather than a bare SetForegroundWindow:
                # that call is refused across processes unless the caller
                # already owns the foreground, and it fails silently, so the
                # trace would have shown interventions that did nothing.
                try:
                    w.Window(self.hold).set_foreground()
                except Exception as exc:  # noqa: BLE001 - a diagnostic thread
                    self.interventions[-1]["set_foreground_failed"] = f"{type(exc).__name__}"

                # One window on a hosted runner does not give the foreground
                # back: measured, the agent's terminal took it at t=4.55 and
                # sixteen set_foreground calls over the next twenty seconds
                # never won it back, while minimising it only had its owner
                # re-activate it. It is hidden for the rest of the sequence and
                # shown again afterwards -- targeted at that one class rather
                # than at the desktop, because everything else here is either
                # the target or harmless.
                if w.get_window_class(hwnd) in PERSISTENT_FOREGROUND_CLASSES:
                    user32.ShowWindow(wintypes.HWND(hwnd), SW_HIDE)
                    self.hidden.add(hwnd)
                    self.interventions[-1]["hidden"] = True
            time.sleep(self.interval)

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        # Put back whatever was hidden: those windows belong to the machine.
        for hwnd in self.hidden:
            user32.ShowWindow(wintypes.HWND(hwnd), SW_SHOW)
        # Only the changes, because a list of identical samples says nothing:
        # what matters is the order the foreground moved in.
        self.session.log_event(
            "foreground_trace",
            f"{len(self.samples)} changes while auto-type ran",
            samples=[{"t": t, "hwnd": self._hwnd_text(h), "class": c, "title": ti}
                     for t, h, c, ti in self.samples],
            pushed_back=self.interventions[:12],
            pushed_back_count=len(self.interventions),
        )
        return False


def click_to_activate(window) -> None:
    """Clicks the window's own title bar, away from its buttons."""
    rect = wintypes.RECT()
    if not user32.GetWindowRect(wintypes.HWND(window.hwnd), ctypes.byref(rect)):
        return
    # A third of the way in and a few pixels down: inside the caption, clear of
    # the icon on the left and of minimise/maximise/close on the right.
    x = rect.left + max(24, (rect.right - rect.left) // 3)
    y = rect.top + 12
    with contextlib.suppress(Exception):  # a diagnostic path, never fatal
        w.send_mouse_click(x, y)


# The toolbar's own Auto-Type button, from MainWindow.ui: the toolbar holds
# open, save, lock, new, edit, delete, copy-user, copy-password, copy-url,
# Perform Auto-Type -- tenth of the non-separator entries. The English label is
# tried first and the position is the fallback, because a translated build has
# no stable name and the automation ids are useless here (every QAction
# publishes the menu bar's object path).
AUTOTYPE_TOOLBAR_INDEX = 10

KEEPASSXC_PROCESS_NAMES = ("KeePassXC.exe",)

# Also from MainWindow.ui: View is the fifth menu, and its first items are
# Theme, Compact Mode, Always on Top, Allow Screen Capture.
VIEW_MENU_INDEX = 4
ALLOW_SCREEN_CAPTURE_INDEX = 3



def trigger_auto_type(session, window, foreground_is_ours: bool) -> str:
    """Starts Auto-Type, by the hotkey when possible and by UIA when not.

    The hotkey is injected input: it only reaches KeePassXC while KeePassXC is
    in front. Measured, that cannot be arranged while the credential prompt
    holds the foreground -- a Medium process can neither take the foreground
    from a window at 0x200a nor minimise it (ShowWindow returns
    ERROR_ACCESS_DENIED). UIA needs neither: invoking a control does not go
    through the input queue and does not require the window to be active, which
    is also what a screen reader relies on.
    """
    if foreground_is_ours:
        w.send_hotkey("ctrl+shift+v")
        session.log_event("trigger", "hotkey while KeePassXC was in front")
        return "hotkey"

    try:
        target = window.find_button(name="Perform Auto-Type", timeout=2.0)
        how = "toolbar button by name"
    except w.ElementNotFoundError:
        # A translated build has no stable name, so fall back to the position
        # from MainWindow.ui: open, save, lock, new, edit, delete, copy-user,
        # copy-password, copy-url, Perform Auto-Type.
        buttons = [b for b in window.re_resolve_element().find_all(control_type_id=50000)
                   if b.name]
        if len(buttons) < AUTOTYPE_TOOLBAR_INDEX:
            raise AssertionError(
                "no Auto-Type control on the main window; "
                f"buttons were {[b.name for b in buttons][:12]}") from None
        target = buttons[AUTOTYPE_TOOLBAR_INDEX - 1]
        how = f"toolbar button {AUTOTYPE_TOOLBAR_INDEX} by position"
    session.log_event("trigger", f"UIA invoke: {how}", control=target.name)
    try:
        target.invoke()
    except Exception as exc:  # noqa: BLE001 - the HRESULT is the information
        # UIA_E_TIMEOUT (0x80131505) is the expected answer here, not a
        # failure: Invoke does not return until the provider's thread does, and
        # KeePassXC types the whole sequence on that thread. Measured: the
        # button was found by name, Invoke raised after UIA's own timeout, and
        # the sequence had started. Whether it worked is decided further down by
        # the helper watcher and the prompt's own return code, which is where
        # that question belongs.
        session.log_event("trigger", f"invoke did not return cleanly: {exc}")
    return how


def find_live_prompt(session, timeout: float = 30.0):
    """The credential dialog that is actually on screen, not the first match.

    Measured: two windows of this class can exist at once -- a leftover from an
    earlier prompt and the live one, at identical rectangles -- and FindWindow
    returns the dead one first. Everything downstream then points at a handle
    that can never come to the foreground, and the run reports "could not raise
    the credential prompt" while the prompt is sitting there in the recording.
    So the choice is made explicitly: visible, owned by a live
    CredentialUIBroker, and the topmost of those.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        candidates = [
            snap for snap in w.WindowCensus.capture()
            if (snap.class_name or "") == PROMPT_CLASS
            and snap.is_visible
            and (w.get_process_image_name(w.get_window_pid(snap.hwnd)) or "").lower()
            == "credentialuibroker.exe"
        ]
        if candidates:
            # Z-order: EnumWindows hands them back front to back, and the
            # census keeps that order, so the first is the one in front.
            chosen = candidates[0]
            if len(candidates) > 1:
                session.log_event(
                    "prompt_candidates",
                    f"{len(candidates)} windows of this class; taking the front one",
                    hwnds=[hex(c.hwnd) for c in candidates],
                    chosen=hex(chosen.hwnd),
                )
            return w.Window(chosen.hwnd)
        time.sleep(0.2)
    raise AssertionError(
        f"no visible {PROMPT_CLASS} owned by CredentialUIBroker appeared within {timeout}s"
    )


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
    blocked_by_integrity = None
    for attempt in range(attempts):
        window.set_foreground()
        time.sleep(0.4)
        if w.get_foreground_window() != window.hwnd:
            # Activate it the way a person would. SetForegroundWindow is refused
            # unless the caller already owns the foreground or received the last
            # input event, and this process has no window and may have done
            # neither -- measured: with the 0x200a credential prompt in front,
            # six set_foreground calls in a row changed nothing. A click on a
            # window at this integrity level is not blocked by UIPI (only input
            # *to* the higher window is), it activates the window, and it leaves
            # this process holding the last input event for the retry.
            click_to_activate(window)
            time.sleep(0.4)
        foreground = w.get_foreground_window()
        if foreground == window.hwnd:
            if attempt:
                session.log_event("foreground", "recovered", attempts=attempt + 1)
            return
        # Named for what it is rather than "thief": the window in front is
        # often one this harness activated a moment earlier, and calling that
        # theft sent a diagnosis of this exact failure off after the runner's
        # terminal for an hour. The pair of hwnds is what identifies the case.
        log_window(session, "foreground_not_yielded", foreground)
        session.log_event(
            "foreground_not_yielded",
            f"wanted {window.hwnd:#x} {window.title!r}, in front {foreground:#x} "
            f"{w.get_window_title(foreground)!r}",
            attempt=attempt + 1,
            wanted=hex(window.hwnd),
            in_front=hex(foreground),
        )
        # Recorded, not raised. A window above this process will not hand the
        # foreground over on request, but minimising it below does work often
        # enough that the main sequence depends on it -- raising here instead
        # turned a recoverable retry into an immediate failure the first time it
        # was tried. The fact is carried into the final message instead.
        mine = integrity_level(os.getpid())
        theirs = integrity_level(w.get_window_pid(foreground))
        if mine is not None and theirs is not None and theirs > mine:
            blocked_by_integrity = (theirs, mine)
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
        user32.ShowWindow(wintypes.HWND(foreground), SW_MINIMIZE)
        time.sleep(0.4)
    reason = ""
    if blocked_by_integrity:
        theirs, mine = blocked_by_integrity
        reason = (f"; a window at 0x{theirs:04x} held it against this process at "
                  f"0x{mine:04x}, which cannot take the foreground from it and could "
                  "not minimise it either")
    raise AssertionError(
        f"could not put {window.title!r} in front after {attempts} attempts{reason}; "
        "every keystroke below would have gone to whatever holds the foreground"
    )


def invoke_view_menu_item(session, window, index: int) -> tuple[str, list[str]]:
    """Opens the View menu and invokes one item, by position.

    By position because neither the label nor the automation id identifies it:
    every QAction publishes the menu bar's object path, and the labels are
    localised. The names of everything in the popup come back with it, so the
    log carries the evidence that the index still points where this thinks.
    """
    # Every menu bar under the window, not the first one. A window has more
    # than one: the title-bar system menu is also a MenuBar, and asking for
    # "the" menu bar returned that -- the run failed with the bar holding
    # exactly ['System'], before and after unlocking alike, which is what
    # ruled out the database being locked as the cause.
    root = window.re_resolve_element()
    bars = [MenuBar(element) for element in root.find_all(control_type_id=50010)]
    described = [[item.name for item in bar.items] for bar in bars]
    session.log_event("menu", f"{len(bars)} menu bar(s) under the window", bars=described)

    # The one that has a View menu, by name where the build is English and by
    # size where it is not: the system menu has one item, the application's has
    # several.
    def view_item(bar):
        for item in bar.items:
            if re.sub(r"\(&.\)$", "", (item.name or "").strip()).strip() == "View":
                return item
        return None

    target = next((view_item(bar) for bar in bars if view_item(bar)), None)
    if target is None:
        widest = max(bars, key=lambda bar: len(bar.items), default=None)
        if widest is None or len(widest.items) <= VIEW_MENU_INDEX:
            raise AssertionError(f"no View menu under this window; the bars held {described}")
        target = widest.items[VIEW_MENU_INDEX]
    session.log_event("menu", f"opening {target.name!r}")

    before = w.WindowCensus.capture()
    target.expand()
    # The popup is found as a window rather than through sub_items(): Qt puts a
    # menu in a top-level Qt<ver>QWindowPopup of its own, so it is not a UIA
    # descendant of the item that opened it and sub_items() comes back empty.
    # Not Window.wait_for_new: it matches window_classes exactly and the real
    # class carries both the Qt version and a suffix
    # (Qt681QWindowPopupDropShadowSaveBits), and it requires a title before it
    # will accept a window, which a menu popup never has.
    time.sleep(1.0)
    opened = w.WindowCensus.diff(before, w.WindowCensus.capture())
    popup = next(snap for snap in opened.added
                 if snap.is_visible and "Popup" in (snap.class_name or ""))
    items = w.Menu(w.UiaElement.from_handle(popup.hwnd)).items
    items[index].invoke()
    time.sleep(1.0)
    return items[index].name, [item.name for item in items]


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
    hard-coded false in MainWindow.h.
    """
    # The menu is always used; the affinity is never read to decide whether to
    # skip it. The affinity belongs to one window and is applied when a window
    # gains focus, so a window that has not been focused yet reads NONE. An
    # earlier version sampled it, took NONE for "already capturable", left the
    # switch alone, and produced recordings in which every KeePassXC window --
    # the confirmation dialog included -- was simply absent.
    #
    # The action is checkable, so invoking it blind could switch protection on
    # rather than off. setAllowScreenCapture applies to every visible top-level
    # window immediately, so that is measurable and self-correcting: invoke,
    # measure, and invoke once more if the measurement went the wrong way.
    before = affinity_of(window)
    for _ in range(2):
        name, item_names = invoke_view_menu_item(session, window, ALLOW_SCREEN_CAPTURE_INDEX)
        after = affinity_of(window)
        session.log_event("screen_capture", f"{name!r} invoked",
                          before=before, after=after, menu_items=item_names)
        if not window.is_excluded_from_capture:
            return
        before = after
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
        try:
            return run(session)
        finally:
            terminate_spawned(session)
            shut_down_keepassxc(session)


# Everything this harness starts, so the teardown can reach it from anywhere.
# The credential-prompt host used to be stopped only on the way out of run(),
# so any exception before that left it running -- and an orphan holding the
# step's stdout is what keeps a runner from finishing the step at all.
SPAWNED: list[subprocess.Popen] = []
# Started through the medium-integrity launcher, so not reachable as a Popen.
HOST_PIDS: list[int] = []
# Hidden for the length of the run and shown again in the teardown.
HIDDEN_WINDOWS: list[int] = []


def hide_persistent_foreground(session) -> None:
    """Hides the windows that will not give the foreground back.

    Before the prompt is raised, not once typing has started. Hiding a window
    makes Windows choose a new foreground, and doing that mid-sequence is
    itself a theft: hidden at the start of Auto-Type, the desktop took the
    foreground from the prompt 1.6s in and kept taking it every couple of
    seconds. Done here, the reshuffle happens while nothing is being typed.

    On a hosted runner the window is the agent's own terminal, which takes the
    foreground and keeps it -- sixteen set_foreground calls over twenty seconds
    never won it back, and minimising it only had its owner re-activate it.
    Hiding is also all that is safe: it is the terminal hosting this step's
    console, so killing it ends the job.
    """
    for snapshot in w.WindowCensus.capture():
        if snapshot.is_visible and snapshot.class_name in PERSISTENT_FOREGROUND_CLASSES:
            user32.ShowWindow(wintypes.HWND(snapshot.hwnd), SW_HIDE)
            HIDDEN_WINDOWS.append(snapshot.hwnd)
    session.log_event("foreground", f"hid {len(HIDDEN_WINDOWS)} window(s) that do not yield",
                      classes=sorted(PERSISTENT_FOREGROUND_CLASSES))


def show_hidden_again(session) -> None:
    """Puts them back: those windows belong to the machine, not to this run."""
    for hwnd in HIDDEN_WINDOWS:
        user32.ShowWindow(wintypes.HWND(hwnd), SW_SHOW)
    if HIDDEN_WINDOWS:
        session.log_event("foreground", f"restored {len(HIDDEN_WINDOWS)} hidden window(s)")
    HIDDEN_WINDOWS.clear()


def terminate_spawned(session) -> None:
    """Kills what this process started, whatever went wrong.

    By pid rather than by Popen.terminate() alone, because the launcher is one
    process and the thing it launched is another; killing the launcher leaves
    the child. Failures are logged rather than raised: this runs in a finally,
    and the reason the run is ending matters more than the cleanup.
    """
    show_hidden_again(session)
    for pid in HOST_PIDS:
        killed = subprocess.run(["taskkill", "/f", "/pid", str(pid)],
                                capture_output=True, text=True)
        session.log_event("shutdown", f"taskkill host pid {pid}", rc=killed.returncode)
    HOST_PIDS.clear()
    for process in SPAWNED:
        if process.poll() is not None:
            continue
        try:
            process.kill()
            process.wait(timeout=5)
            session.log_event("shutdown", f"killed pid {process.pid}")
        except Exception as exc:  # noqa: BLE001 - cleanup must not mask the failure
            session.log_event("shutdown", f"could not kill pid {process.pid}",
                              error=f"{type(exc).__name__}: {exc}")
    SPAWNED.clear()


def shut_down_keepassxc(session) -> None:
    """Stops what this script started, because nothing else owns it.

    KeePassXC is launched with a bare Popen so that its stderr can be an
    artifact, and it is found again by window title because the single instance
    takes the command line -- the process that ends up owning the window is not
    the one launched here. Neither of those excuses leaving it running, which
    is what this script did for several runs: the process stayed up between
    steps, and the next step inherited a KeePassXC holding the previous step's
    settings, which are read once at startup.

    sweep_processes_verified rather than a kill of its own, because it waits
    until the windows are gone; that wait is the part a hand-written kill keeps
    getting wrong. It works from here now that this process is no longer the
    one being dropped to medium integrity -- while it was, the sweep was
    refused and reported success anyway, having watched the windows rather than
    the processes.
    """
    swept = w.sweep_processes_verified(KEEPASSXC_PROCESS_NAMES)
    session.log_event("shutdown", "swept KeePassXC", complete=swept)


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
        # Swept first, and the sweep is waited on: a leaked instance takes this
        # command line, so the launch produces no new window and the run
        # continues against a KeePassXC holding some earlier step's settings.
        session.log_event("sweep", "leftover KeePassXC instances",
                          complete=w.sweep_processes_verified(KEEPASSXC_PROCESS_NAMES))
        # KeePassXC is the process that has to be at medium integrity, not this
        # one: at high integrity the credential prompt accepts injected input
        # with or without the patch, so a medium KeePassXC is what makes the
        # measurement mean anything. This harness stays where it was launched.
        # It used to be the other way round -- the whole harness was dropped to
        # medium and KeePassXC inherited it -- which measured the same thing and
        # cost this process the ability to clean up after itself.
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        stderr_log = open(ARTIFACTS / "keepassxc-stderr.log", "wb")
        environment = dict(os.environ, QT_FORCE_STDERR_LOGGING="1")
        SPAWNED.append(subprocess.Popen(
            [sys.executable, str(Path(__file__).with_name("run_at_medium_integrity.py")),
             str(EXE), str(DB)],
            env=environment, stdout=stderr_log, stderr=subprocess.STDOUT))
        window = session.find_window(title_pattern="KeePassXC", timeout=30)
        log_window(session, "keepassxc_window", window.hwnd)
        ensure_foreground(session, window)

    with session.step("unlock the database"):
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

    # After unlocking, not before. It was moved earlier so the recording would
    # cover the password being typed, and that cost the run its menu: while the
    # database is locked the application menu bar does not exist yet, and the
    # only MenuBar under the window is the title-bar system menu -- measured,
    # the bar held exactly ['System']. So the unlock stays off the recording.
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
        # First, so the foreground settles before the prompt exists.
        hide_persistent_foreground(session)
        # CREATE_NO_WINDOW: the host's console window is otherwise a candidate
        # for "the last active window", and auto-type typed the password into it
        # instead of into the prompt it was hosting.
        # At medium integrity, like KeePassXC. The prompt's own integrity
        # follows the process that raises it: measured 0x200a when this ran
        # medium and High (0x3000) when it did not, and at High the premise of
        # the whole comparison is gone -- a medium KeePassXC cannot reach the
        # prompt whatever the patch does, and this harness can take the
        # foreground from it, which a medium one cannot.
        host = subprocess.Popen(
            [sys.executable, str(Path(__file__).with_name("run_at_medium_integrity.py")),
             sys.executable, str(HOST), str(RESULT)],
            stdout=subprocess.PIPE, text=True, creationflags=0x08000000)
        SPAWNED.append(host)
        # The launcher waits for its child, so killing the launcher leaves the
        # host running; it prints the pid it started for exactly this reason.
        first = host.stdout.readline().strip() if host.stdout else ""
        session.log_event("host", f"raised at medium integrity ({first or 'no pid reported'})")
        if first.startswith("child pid="):
            HOST_PIDS.append(int(first.split("=", 1)[1]))
        prompt = find_live_prompt(session, timeout=30)
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

        ensure_foreground(session, prompt)
        # Not fatal any more. Whether KeePassXC can be brought to the front
        # decides *how* Auto-Type is started, not whether the run is valid: the
        # prompt is at 0x200a and will not yield the foreground to a Medium
        # process, which is the normal case rather than an accident.
        foreground_is_ours = False
        try:
            ensure_foreground(session, window)
            foreground_is_ours = w.get_foreground_window() == window.hwnd
        except AssertionError as exc:
            session.log_event("foreground", f"KeePassXC could not be raised: {exc}")
        log_window(session, "foreground_before_trigger", w.get_foreground_window())

    with session.step("perform auto-type"):
        # Order matters, and getting it wrong looked like the bug under test.
        # The hotkey is injected input at medium integrity, so it only reaches
        # KeePassXC while KeePassXC is in front; holding the prompt first made
        # UIPI drop the hotkey and the run produced no auto-type at all -- no
        # helper, no confirmation, nothing to distinguish it from the failure it
        # was supposed to measure.
        trigger_auto_type(session, window, foreground_is_ours)

        # The confirmation dialog is handled before anything is held in front,
        # and it is raised and dwelt on rather than dismissed the moment UIA
        # can see it. UIA does not need a window to be visible, so the first
        # version invoked its button while the dialog had never been drawn on
        # top of anything -- it is nowhere in the recording, and a reviewer
        # cannot see the step the run depends on. Recordings are for people.
        dialog = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and dialog is None:
            for snapshot in w.WindowCensus.capture():
                if (snapshot.is_visible and snapshot.hwnd != window.hwnd
                        and (snapshot.class_name or "").startswith("Qt")):
                    dialog = snapshot
                    break
            time.sleep(0.1)

        if dialog is None:
            session.log_event("confirmation", "no confirmation dialog appeared")
        else:
            log_window(session, "confirmation", dialog.hwnd)
            try:
                w.Window(dialog.hwnd).set_foreground()
            except Exception as exc:  # noqa: BLE001 - visibility, not correctness
                session.log_event("confirmation", f"could not raise it ({type(exc).__name__})")
            session.capture_screenshot("confirmation-dialog")
            if DWELL:
                time.sleep(DWELL)
            # Clicked, not invoked. invoke() goes through the UIA pattern and
            # needs no window to be visible, so it dismissed a dialog that had
            # never been drawn on top of anything -- the step is missing from
            # the recording entirely. A click needs real coordinates and the
            # window in front, which is also what a user does, and the recorder
            # draws the pointer and the click where it landed. click() raises
            # when the element has no rectangle, so it cannot silently do
            # nothing either.
            button = accept_button(session, dialog.hwnd)
            session.log_event("confirmation_click", f"clicking {button.name!r}",
                              rect=button.bounding_rectangle)
            button.click()

        # Held in front only from here: KeePassXC hides its own window after the
        # dialog is answered and then resolves "the active window" as its
        # target, so what is in front during those few hundred milliseconds
        # decides where the keystrokes go.
        with ForegroundTrace(session, hold=prompt.hwnd):
            outcome = ""
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if RESULT.exists():
                    outcome = RESULT.read_text(encoding="utf-8", errors="replace").strip()
                    if outcome:
                        break
                time.sleep(0.5)
            submitted = "RESULT=0" in outcome and USERNAME in outcome
            session.capture_screenshot("after-auto-type")
            # A filled prompt closes as soon as it is submitted, so the state a
            # reviewer wants to see lasts a frame or two. Dwelling here keeps it
            # on screen for the recording without changing what was asserted.
            if submitted and DWELL:
                time.sleep(DWELL)
            session.log_event("credui_outcome", outcome.replace("\n", " | ") or "never submitted",
                              submitted=submitted)

    if host.poll() is None:
        host.terminate()
    print(f"VERDICT = {'fix works' if submitted else 'auto-type did not reach the prompt'}",
          flush=True)
    return 0 if submitted else 3


class _Tee:
    """Writes to the artifact and to the step's own output.

    Both, because they answer different questions. harness.log is the artifact
    somebody reads afterwards; the step output is the only thing visible while
    the run is still going. A round that hung produced neither a log line nor a
    recording -- the artifacts are uploaded after the step, and force-cancelling
    a hung step skips that -- so there was nothing at all to say where it
    stopped.
    """

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text: str) -> int:
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()

    def __getattr__(self, name):
        """Everything else comes from the real stream.

        Because this is installed as sys.stdout and sys.stderr, and a bare
        object there is a trap: a library that asks for fileno(), encoding,
        isatty() or buffer -- PyAV, logging and subprocess all do, one way or
        another -- gets an AttributeError from something that has nothing to do
        with it.
        """
        return getattr(self.streams[-1], name)


if __name__ == "__main__":
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    stream = open(ARTIFACTS / "harness.log", "w", encoding="utf-8", buffering=1)
    # Put the real streams back before the file closes. Left installed, sys.stderr
    # is a _Tee over a closed file, and the interpreter cannot report the
    # exception that is on its way out: a Ctrl-C during startup printed
    # "lost sys.stderr" and then wedged, so a cancelled run did not end, it hung
    # -- and the step that uploads the evidence never ran.
    sys.stdout = sys.stderr = _Tee(stream, sys.__stdout__)
    try:
        code = main()
    except BaseException:
        import traceback

        traceback.print_exc()
        raise
    finally:
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        stream.close()
    sys.exit(code)
