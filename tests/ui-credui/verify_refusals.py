"""Does the helper get started when it should not?

The rest of this suite measures the fix working. This measures the three
refusals it depends on, because each of them was a claim about the code before
it was a measurement, and a claim of the form "an attacker cannot" is worth
nothing unmeasured:

  1. **Opt-in off.** Delegation is a setting, off by default. If the setting is
     not consulted, everyone gets a privileged process they never asked for.
  2. **An unsigned helper.** KeePassXC launches this binary itself, so a
     KeePassXC installed somewhere a standard user can write -- the portable
     ZIP, a build tree -- would otherwise hand the keystrokes to whatever was
     dropped under that name. That is quieter than replacing KeePassXC.exe,
     which breaks its signature.
  3. **A target that is not a credential dialog.** The helper holds the
     exemption, so it re-checks the target rather than taking the caller's
     word; a compromised caller must not be able to widen its scope.

Every case is paired with a positive control **in the same run**: the same
sequence with the setting on and the real signed helper in place, which must
start the helper. A run that only shows refusals cannot tell "correctly
refused" from "nothing worked at all", and this suite has produced exactly that
false pass before.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import helper_watch
import wintegrate as w

HELPER_NAME = "keepassxc-uiaccess-helper.exe"


def read_ini(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def write_ini(path: Path, delegate: bool) -> None:
    """The configuration these cases need, and why one line of it is unusual.

    AutoTypeSkipMainWindowConfirmation is on. These cases trigger Auto-Type
    through the main window's own toolbar action, because the credential prompt
    holds the foreground and a Medium process cannot take it; KeePassXC treats
    that as a main-window Auto-Type and asks for confirmation. Answering that
    dialog is not possible here: the invoke has not returned -- KeePassXC types
    on the thread UIA is waiting on -- so any further UIA query to that process
    stalls behind it, and the dialog's default button is Cancel, so a blind
    Enter would answer it wrongly. KeePassXC already offers to skip exactly
    this confirmation, which is the same decision a user makes once.

    The main evidence run does not set it: there the hotkey path is available,
    the dialog appears, and the recording is expected to show it.
    """
    path.write_text(
        "[General]\nConfigVersion=2\nUpdateCheckMessageShown=true\n\n"
        "[GUI]\nCheckForUpdates=false\n\n"
        "[Security]\n"
        f"AutoTypeCredentialPrompts={'true' if delegate else 'false'}\n"
        "AutoTypeSkipMainWindowConfirmation=true\n",
        encoding="utf-8",
    )


def copy_to_writable_location(exe: Path, into: Path) -> Path:
    """The same bundle, somewhere a standard user can write.

    This replaced a case that broke the helper's signature. That check no
    longer exists -- the product decides by location now -- so the old case
    would have passed without testing anything, which is worse than failing.
    """
    into.mkdir(parents=True, exist_ok=True)
    for item in exe.parent.iterdir():
        target = into / item.name
        if item.is_dir():
            if not target.exists():
                shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
    return into / exe.name


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", wintypes.LPVOID), ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
    ]


def shell_execute_and_wait(path: Path, parameters: str, timeout_ms: int = 30000):
    """Starts the helper the way KeePassXC has to, and returns its exit code.

    Not subprocess.run: this is a uiAccess binary, and CreateProcess refuses it
    with ERROR_ELEVATION_REQUIRED (740) rather than starting it. The first
    version of this test used subprocess.run and died on exactly that, which is
    a fair demonstration of the constraint but not a measurement of the refusal.
    """
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040 | 0x00000100  # NOCLOSEPROCESS | NOASYNC
    info.lpVerb = "open"
    info.lpFile = str(path)
    info.lpParameters = parameters
    info.nShow = 0
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        # A launch that never happened is not a refusal by the helper, and
        # reporting it as one would credit the wrong check.
        return None
    kernel32.WaitForSingleObject(info.hProcess, timeout_ms)
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    kernel32.CloseHandle(info.hProcess)
    return code.value


class Watcher:
    """Records whether the helper ever exists while a sequence runs."""

    def __init__(self) -> None:
        self.seen: dict[int, str] = {}

    def sample(self) -> None:
        for pid, integrity in helper_watch.snapshot().items():
            self.seen.setdefault(pid, integrity)

    def watch(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.sample()
            time.sleep(0.05)


def pids_of(image: str) -> list[int]:
    listed = subprocess.run(["tasklist", "/fi", f"imagename eq {image}", "/nh", "/fo", "csv"],
                            capture_output=True, text=True).stdout
    pids = []
    for line in listed.splitlines():
        fields = [field.strip('"') for field in line.split('","')]
        if len(fields) >= 2 and fields[0].strip('"').lower() == image.lower():
            pids.append(int(fields[1]))
    return pids


def reset_desktop() -> None:
    """Leaves nothing of the previous case behind, and proves it.

    Every case needs a KeePassXC that reads the settings this case just wrote,
    and settings are read once at startup. A surviving process therefore does
    not merely dirty the desktop: it runs the whole case under the previous
    case's configuration.

    Measured, and the reason this is checked rather than asked for: a run where
    the kill silently did nothing put the same process -- one pid, one hwnd --
    through the main evidence step and all three cases. The positive control
    saw the confirmation dialog the previous configuration had enabled, its
    modal then held the foreground, and the two cases after it aborted before
    typing anything, so both "passed" without exercising a refusal at all. The
    kill was a fire-and-forget subprocess.run whose result was discarded, so
    nothing in the log said so.

    The helper is never killed, only waited for. It is granted uiAccess,
    which puts it at 0x2010, above this process; it needs no killing anyway,
    since it exits when the pipe closes and killing KeePassXC closes the pipe.
    But it does have to be gone before the next case starts, because the
    watcher that decides whether a refusal held counts helper processes by
    image name and would count a leftover from the case before.
    """
    swept = w.sweep_processes_verified(("KeePassXC.exe", "CredentialUIBroker.exe"))
    print(f"swept KeePassXC and the broker: complete={swept}", flush=True)

    deadline = time.monotonic() + 20
    while True:
        alive = {image: pids_of(image) for image in ("KeePassXC.exe", HELPER_NAME)}
        if not any(alive.values()):
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"still running after the reset: {alive}; every case below would run "
                "against the previous case's settings, and a leftover helper would be "
                "counted as this case's"
            )
        time.sleep(0.25)
    time.sleep(1.0)


def run_sequence(args, label: str, dwell: float, exe: str | None = None,
                 ini: Path | None = None, delegate: bool = True) -> dict:
    """One Auto-Type attempt at a real credential prompt, watched throughout."""
    reset_desktop()
    # Written here, not by the caller: a KeePassXC that is still running can
    # flush its own settings over the file, and it reads the file only when it
    # starts. Writing before the previous one was killed left the confirmation
    # dialog in place and the case failed on a setting it had already set.
    if ini is not None:
        write_ini(ini, delegate=delegate)
        print(f"--- {label}: effective {ini}", flush=True)
        print(ini.read_text(encoding="utf-8"), flush=True)
    watcher = Watcher()
    result = Path(args.result)
    result.unlink(missing_ok=True)

    harness = [
        sys.executable,
        str(Path(__file__).with_name("verify_with_wintegrate.py")),
        "--exe", exe or args.exe,
        "--db", args.db,
        "--password", args.password,
        "--entry", args.entry,
        "--username", args.username,
        "--host-script", str(Path(__file__).with_name("credui_host.py")),
        "--result", args.result,
        "--artifacts", str(Path(args.artifacts) / label),
        "--dwell", str(dwell),
    ]
    process = subprocess.Popen(harness, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    while process.poll() is None:
        watcher.sample()
        time.sleep(0.05)
    # The helper outlives nothing, but it can start late; keep looking briefly.
    watcher.watch(1.0)
    output = process.stdout.read() if process.stdout else ""

    return {
        "label": label,
        "harness_exit": process.returncode,
        "helper_pids": {str(pid): integrity for pid, integrity in watcher.seen.items()},
        "helper_started": bool(watcher.seen),
        "harness_tail": output[-2000:],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--entry", default="Windows")
    parser.add_argument("--username", default="probeuser")
    parser.add_argument("--result", required=True)
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--dwell", type=float, default=1.0)
    args = parser.parse_args()

    exe = Path(args.exe)
    helper = exe.with_name(HELPER_NAME)
    ini = Path(os.environ["APPDATA"]) / "KeePassXC" / "keepassxc.ini"
    ini.parent.mkdir(parents=True, exist_ok=True)
    cases: list[dict] = []

    try:
        # The positive control comes first: if this does not start the helper,
        # nothing below means anything and the run says so instead of passing.
        control = run_sequence(args, "control-delegates", args.dwell, ini=ini, delegate=True)
        control["expectation"] = "helper starts"
        control["passed"] = control["helper_started"]
        cases.append(control)

        opt_out = run_sequence(args, "refusal-opt-in-off", args.dwell, ini=ini, delegate=False)
        opt_out["expectation"] = "no helper: the setting is off"
        opt_out["passed"] = not opt_out["helper_started"]
        cases.append(opt_out)

        writable = Path(os.environ.get("RUNNER_TEMP", os.environ["TEMP"])) / "kpxc-writable"
        moved_exe = copy_to_writable_location(exe, writable)
        from_writable = run_sequence(
            args, "refusal-writable-location", args.dwell, exe=str(moved_exe),
            ini=ini, delegate=True
        )
        from_writable["expectation"] = "no helper: the application is in a writable location"
        from_writable["passed"] = not from_writable["helper_started"]
        cases.append(from_writable)
        shutil.rmtree(writable, ignore_errors=True)

        # The helper on its own, with a target that is not a credential dialog.
        # Nothing needs to be running for this one and nothing is typed: it is
        # the helper's own re-check, reached before it opens the pipe.
        reset_desktop()
        exit_code = shell_execute_and_wait(
            helper, "--pipe keepassxc-uiaccess-refusal-probe --target 1"
        )
        cases.append(
            {
                "label": "refusal-bad-target",
                "expectation": "the helper exits without opening the pipe",
                "helper_exit": exit_code,
                "passed": exit_code not in (0, None),
            }
        )
    except Exception as exc:
        # The report is the only thing the workflow reads, so a case that throws
        # must not take the results of the ones that ran with it.
        cases.append({"label": "harness", "expectation": "no exception",
                      "error": f"{type(exc).__name__}: {exc}", "passed": False})
    finally:
        report = {"cases": cases, "passed": bool(cases) and all(c["passed"] for c in cases)}
        Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    for case in cases:
        print(f"{case['label']:26} expected={case['expectation']:45} passed={case['passed']}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
