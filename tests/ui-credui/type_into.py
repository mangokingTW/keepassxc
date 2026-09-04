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
import os
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


def policy(name: str) -> str:
    """One UAC policy value, or why it could not be read.

    Reported rather than interpreted. Whether a process can be dropped to
    ordinary integrity depends on more than one of these, and guessing which one
    explains a given host has already been wrong once.
    """
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value)
    except OSError as exc:
        return f"unknown ({exc})"


def integrity_level() -> str:
    """The token's mandatory level, which is what UIPI actually consults.

    Not TokenElevation. That flag reports whether the token carries
    administrator privileges, and lowering a token's integrity level does not
    remove them -- so a child launched at the Medium level from an elevated
    session still reports "elevated", and a check written against that flag
    concluded the de-elevation had failed when it had worked.
    """
    TOKEN_INTEGRITY_LEVEL = 25
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008,
                                     ctypes.byref(token)):
        return f"unknown (OpenProcessToken: {ctypes.get_last_error()})"

    size = wintypes.DWORD(0)
    advapi32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token, TOKEN_INTEGRITY_LEVEL, buffer, size,
                                        ctypes.byref(size)):
        return f"unknown (GetTokenInformation: {ctypes.get_last_error()})"

    # TOKEN_MANDATORY_LABEL is a SID_AND_ATTRIBUTES; the level is the SID's last
    # subauthority.
    sid = ctypes.c_void_p.from_buffer(buffer).value
    count = advapi32.GetSidSubAuthorityCount(sid)[0]
    rid = advapi32.GetSidSubAuthority(sid, count - 1)[0]
    names = {0x0000: "Untrusted", 0x1000: "Low", 0x2000: "Medium",
             0x2100: "Medium Plus", 0x3000: "High", 0x4000: "System"}
    return f"0x{rid:04X} ({names.get(rid, 'unrecognised')})"


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    hwnd = int(sys.argv[1])
    sequence = sys.argv[2]
    report = Path(sys.argv[3])

    lines = [
        # The integrity level first: it is the one that decides UIPI.
        f"integrity={integrity_level()}",
        f"elevation={elevation()}",
        f"EnableLUA={policy('EnableLUA')}",
        # Printed because a run that could not de-elevate has to explain itself.
        # A GitHub hosted runner reports EnableLUA=1 and *still* runs a
        # RunLevel Limited task elevated, so "UAC is off" is not the reason --
        # this is where to look next.
        f"FilterAdministratorToken={policy('FilterAdministratorToken')}",
        f"user={os.environ.get('USERNAME')!r}",
    ]

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
