"""Types a sequence into one window and reports its own privilege level.

Run as a separate process so the *caller* can choose the integrity level. That
is the variable under test: the credential dialog accepts synthetic input from a
high-integrity process and drops it from an ordinary one, so a test that types
in-process measures whatever privilege the test runner happened to have. On a
GitHub hosted runner that is administrator, and the reproduction silently
inverted.

Usage: type_into.py <hwnd> <sequence> <report_path>
  In <sequence>, \t is Tab and \n is Enter, both sent as scan codes.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys
import time
from pathlib import Path

from wintegrate.interop import send_keys, user32

TOKEN_QUERY = 0x0008
TOKEN_ELEVATION = 20
TOKEN_INTEGRITY_LEVEL = 25


def elevation() -> str:
    """Whether this process is elevated, as a string for the report."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Declared, not inferred: an undeclared handle argument is passed as a C int
    # and raises "OverflowError: int too long to convert".
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
        return f"unknown (OpenProcessToken failed: {ctypes.get_last_error()})"
    elevated = wintypes.DWORD(0)
    size = wintypes.DWORD(0)
    ok = advapi32.GetTokenInformation(token, TOKEN_ELEVATION, ctypes.byref(elevated),
                                      ctypes.sizeof(elevated), ctypes.byref(size))
    if not ok:
        return f"unknown (GetTokenInformation failed: {ctypes.get_last_error()})"
    return "elevated" if elevated.value else "not-elevated"


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    hwnd = int(sys.argv[1])
    sequence = sys.argv[2]
    report = Path(sys.argv[3])

    lines = [f"elevation={elevation()}"]

    for _ in range(6):
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.3)
    foreground = user32.GetForegroundWindow()
    lines.append(f"target={hwnd} foreground={foreground} match={foreground == hwnd}")

    if foreground != hwnd:
        # Refusing to type is the honest outcome: whatever happened next would
        # have been measured against the wrong window.
        lines.append("typed=no (the target never took the foreground)")
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 3

    for ch in sequence:
        if ch == "\t":
            send_keys("{TAB}")
        elif ch in "\r\n":
            send_keys("{ENTER}")
        else:
            send_keys(ch)
        time.sleep(0.03)

    lines.append("typed=yes")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
