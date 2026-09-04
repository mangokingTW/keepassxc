"""Records whether the uiAccess helper is ever started, and at what integrity.

The helper lives for the length of one auto-type sequence, so a process list
sampled by hand misses it. Without this, "the prompt was not filled in" cannot
be told apart from "the helper never ran" -- and those have different fixes.

Enumeration is done in-process with a Toolhelp snapshot. The first version
shelled out to PowerShell ten times a second, and every one of those flashed a
console window that took the foreground -- a watcher that breaks the thing it
is watching, and the exact background-window hazard this whole suite exists to
avoid.
"""
from __future__ import annotations

import ctypes
import sys
import time
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

NAMES = {0x1000: "Low", 0x2000: "Medium", 0x2100: "MediumPlus", 0x3000: "High",
         0x4000: "System"}
TARGETS = ("typehelper", "uiaccess")

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


# Declared, and on private handles rather than the shared `ctypes.windll`: an
# undeclared pointer argument is marshalled as a C int and a real SID address
# overflows it.
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
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]


def integrity(pid: int) -> str:
    process = kernel32.OpenProcess(0x1000, False, pid)
    if not process:
        return f"unreadable(err={ctypes.get_last_error()})"
    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            return f"unreadable(err={ctypes.get_last_error()})"
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(token, 25, buf, size, ctypes.byref(size)):
            return f"unreadable(err={ctypes.get_last_error()})"
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        count = advapi32.GetSidSubAuthorityCount(sid)[0]
        rid = advapi32.GetSidSubAuthority(sid, count - 1)[0]
        return NAMES.get(rid, hex(rid))
    finally:
        if token:
            kernel32.CloseHandle(token)
        kernel32.CloseHandle(process)


def snapshot() -> dict[int, str]:
    found: dict[int, str] = {}
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value or not snap:
        return found
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return found
        while True:
            name = entry.szExeFile
            if any(t in name.lower() for t in TARGETS):
                found[entry.th32ProcessID] = name
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return found


def main() -> int:
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 180.0
    deadline = time.monotonic() + seconds
    seen: set[int] = set()
    print(f"watching for {TARGETS} for {seconds:.0f}s", flush=True)
    while time.monotonic() < deadline:
        for pid, name in snapshot().items():
            if pid not in seen:
                seen.add(pid)
                print(f"{time.strftime('%H:%M:%S')} started pid={pid} {name} "
                      f"integrity={integrity(pid)}", flush=True)
        time.sleep(0.1)
    # Stated either way: "no helper process was ever observed" is a result, and
    # an empty log would read as "the watcher did not run".
    print(f"done; {len(seen)} helper process(es) observed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
