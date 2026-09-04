"""Starts a process at medium integrity from an elevated one.

Needed because the ordinary case cannot be produced on a GitHub hosted runner
any other way. A scheduled task registered with RunLevel Limited still ran
elevated there -- the account is `runneradmin`, EnableLUA is 1, and
FilterAdministratorToken is unset, so the session simply has no filtered token
to fall back to.

This does not depend on UAC having prepared one. It duplicates the current
token, lowers the copy's integrity level to Medium, and launches the child with
it, which is the documented way to hand out less privilege than you hold.

Usage: run_at_medium_integrity.py <exe> [args...]
Prints the child's pid, and waits for it.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys
from ctypes import wintypes

TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_SESSIONID = 0x0100

SECURITY_MANDATORY_MEDIUM_RID = 0x2000
TOKEN_INTEGRITY_LEVEL = 25
TOKEN_PRIMARY = 1
SECURITY_IMPERSONATION = 2
CREATE_UNICODE_ENVIRONMENT = 0x00000400
INFINITE = 0xFFFFFFFF


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SID_AND_ATTRIBUTES)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)

# Declared, every one of them: an undeclared handle argument is passed as a C
# int and raises "OverflowError: int too long to convert", which reads as a
# broken script rather than a missing declaration.
kernel32.GetCurrentProcess.argtypes = []
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.DuplicateTokenEx.restype = wintypes.BOOL
advapi32.SetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
]
advapi32.SetTokenInformation.restype = wintypes.BOOL
advapi32.AllocateAndInitializeSid.argtypes = [
    ctypes.c_void_p, ctypes.c_ubyte, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
    ctypes.POINTER(ctypes.c_void_p),
]
advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL
advapi32.CreateProcessAsUserW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
    wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
]
advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
userenv.CreateEnvironmentBlock.argtypes = [
    ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.BOOL
]
userenv.CreateEnvironmentBlock.restype = wintypes.BOOL


def fail(what: str) -> None:
    raise OSError(f"{what} failed: {ctypes.get_last_error()}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    command = subprocess.list2cmdline(sys.argv[1:])

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_SESSIONID,
        ctypes.byref(token),
    ):
        fail("OpenProcessToken")

    duplicate = wintypes.HANDLE()
    if not advapi32.DuplicateTokenEx(
        token, 0, None, SECURITY_IMPERSONATION, TOKEN_PRIMARY, ctypes.byref(duplicate)
    ):
        fail("DuplicateTokenEx")

    # S-1-16-8192: the Medium mandatory level.
    sid = ctypes.c_void_p()
    authority = (ctypes.c_ubyte * 6)(0, 0, 0, 0, 0, 16)  # SECURITY_MANDATORY_LABEL_AUTHORITY
    if not advapi32.AllocateAndInitializeSid(
        ctypes.byref(authority), 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0,
        ctypes.byref(sid),
    ):
        fail("AllocateAndInitializeSid")

    label = TOKEN_MANDATORY_LABEL()
    label.Label.Sid = sid
    label.Label.Attributes = 0x00000020  # SE_GROUP_INTEGRITY
    if not advapi32.SetTokenInformation(
        duplicate, TOKEN_INTEGRITY_LEVEL, ctypes.byref(label), ctypes.sizeof(label)
    ):
        fail("SetTokenInformation(TokenIntegrityLevel)")

    environment = ctypes.c_void_p()
    if not userenv.CreateEnvironmentBlock(ctypes.byref(environment), duplicate, False):
        environment = None  # not fatal; the child inherits nothing instead

    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(STARTUPINFOW)
    # The same desktop as the caller, or the child would have no window station
    # to inject into.
    startup.lpDesktop = "winsta0\\default"
    info = PROCESS_INFORMATION()

    if not advapi32.CreateProcessAsUserW(
        duplicate, None, ctypes.create_unicode_buffer(command), None, None, False,
        CREATE_UNICODE_ENVIRONMENT, environment, None,
        ctypes.byref(startup), ctypes.byref(info),
    ):
        fail("CreateProcessAsUserW")

    print(f"child pid={info.dwProcessId}", flush=True)
    kernel32.WaitForSingleObject(info.hProcess, INFINITE)
    code = wintypes.DWORD(0)
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    print(f"child exit={code.value}", flush=True)
    for handle in (info.hProcess, info.hThread, duplicate, token):
        kernel32.CloseHandle(handle)
    return int(code.value)


if __name__ == "__main__":
    sys.exit(main())
