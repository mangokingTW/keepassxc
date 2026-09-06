"""What Windows does with a uiAccess executable, by signature and location.

Each rule is one test case, printed like a test report: the facts it starts
from, the action, the measured values, and PASS or FAIL against a fixed
expectation. The process exits non-zero if any test fails, so a green job is
the measurement itself.

Usage: uiaccess_launch_rules.py <out.json> <label|path|expect> ...
  expect: granted  -> starts and the token has UIAccess=1
          plain    -> starts and the token has UIAccess=0
          refused  -> ShellExecuteEx fails with ERROR_DS_REFERRAL (8235)
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import winreg
from ctypes import wintypes

shell32 = ctypes.windll.shell32
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
ERROR_DS_REFERRAL = 8235
LEVELS = {0x2000: "Medium", 0x2010: "Medium + UIAccess", 0x3000: "High"}


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
    ]


def token_facts(process: int) -> dict:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
        return {"token_error": kernel32.GetLastError()}
    ui, size = wintypes.DWORD(), wintypes.DWORD()
    ok_ui = advapi32.GetTokenInformation(token, 26, ctypes.byref(ui), 4, ctypes.byref(size))
    advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    rid = None
    if advapi32.GetTokenInformation(token, 25, buf, size, ctypes.byref(size)):
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        count = advapi32.GetSidSubAuthorityCount(ctypes.c_void_p(sid))[0]
        rid = int(advapi32.GetSidSubAuthority(ctypes.c_void_p(sid), count - 1)[0])
    kernel32.CloseHandle(token)
    return {"uiaccess": int(ui.value) if ok_ui else None, "integrity": rid}


def launch(path: str) -> dict:
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040 | 0x00000400  # NOCLOSEPROCESS | FLAG_NO_UI
    info.lpFile = path
    info.lpParameters = "--pipe x --target 1"  # fails the helper's own argument check: exits fast
    if not shell32.ShellExecuteExW(ctypes.byref(info)) or not info.hProcess:
        return {"started": False, "error": kernel32.GetLastError()}
    facts = token_facts(info.hProcess)  # the process object outlives its quick exit
    kernel32.WaitForSingleObject(info.hProcess, 10000)
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    kernel32.CloseHandle(info.hProcess)
    return {"started": True, "exit": int(code.value), **facts}


def ps(expr: str) -> str:
    # Explicit import: under a pwsh step the runner's PSModulePath points Windows
    # PowerShell at modules it cannot load, and autoloading the Security module fails.
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command", f"Import-Module Microsoft.PowerShell.Security; {expr}"],
        capture_output=True, text=True, env={k: v for k, v in os.environ.items() if k != "PSModulePath"},
    )
    return (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else "?"


def policy(name: str):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return "(not set)"


def level(rid) -> str:
    return f"{rid:#06x} ({LEVELS.get(rid, '?')})" if isinstance(rid, int) else "?"


def line(text: str = "", verdict: str | None = None) -> None:
    if verdict:
        print(f"{text:<72} | {verdict} |")
    else:
        print(text)


def main(argv: list[str]) -> int:
    out_path, specs = argv[0], argv[1:]
    # A real handle, not the pseudo-handle: OpenProcessToken on the latter is refused
    # under some runner tokens.
    own = kernel32.OpenProcess(0x1000, False, kernel32.GetCurrentProcessId())  # PROCESS_QUERY_LIMITED_INFORMATION
    me = token_facts(own)
    kernel32.CloseHandle(own)
    subject = specs[0].split("|", 2)[1]
    manifest = open(subject, "rb").read()
    attr = manifest[manifest.find(b"uiAccess="):][:16].decode("ascii", "replace") if b"uiAccess=" in manifest else "(absent)"

    line("=" * 78)
    line("uiAccess launch rules :: what Windows does with a uiAccess executable")
    line("=" * 78)
    line("Setup")
    line(f"  Windows                         {platform.platform()}")
    line(f"  Policy EnableSecureUIAPaths     {policy('EnableSecureUIAPaths')}")
    line(f"  Policy ValidateAdminCodeSign.   {policy('ValidateAdminCodeSignatures')}")
    line(f"  Policy EnableLUA                {policy('EnableLUA')}")
    line(f"  Launcher process                integrity {level(me.get('integrity'))}, UIAccess={me.get('uiaccess')}")
    line(f"  Subject manifest                {attr}")
    line(f"  Subject SHA-256                 {hashlib.sha256(manifest).hexdigest()[:16]}...")
    line("-" * 78)

    rows, failed = [], 0
    for spec in specs:
        label, path, expect = spec.split("|", 2)
        sig = ps(f"(Get-AuthenticodeSignature '{path}').Status.ToString()")
        r = launch(path)
        line(label)
        line(f"  Given the copy at {path}")
        line(f"        signature status            {sig}")
        line("  When it is started through ShellExecuteEx")
        if r["started"]:
            line(f"        started                     yes, exit code {r['exit']}")
            line(f"        token UIAccess              {r.get('uiaccess')}")
            line(f"        token integrity             {level(r.get('integrity'))}")
        else:
            why = ('ERROR_DS_REFERRAL, "A referral was returned from the server"'
                   if r["error"] == ERROR_DS_REFERRAL else ctypes.FormatError(r["error"]).strip())
            line(f"        started                     no, GetLastError {r['error']} ({why})")
        if expect == "granted":
            ok = r["started"] and r.get("uiaccess") == 1
            line("  Then the process starts with UIAccess=1", "PASS" if ok else "FAIL")
        elif expect == "plain":
            ok = r["started"] and r.get("uiaccess") == 0
            line("  Then the process starts, but without UIAccess", "PASS" if ok else "FAIL")
        else:
            ok = (not r["started"]) and r.get("error") == ERROR_DS_REFERRAL
            line("  Then the launch is refused with ERROR_DS_REFERRAL (8235)", "PASS" if ok else "FAIL")
        line("-" * 78)
        failed += 0 if ok else 1
        rows.append({**r, "label": label, "path": path, "expect": expect, "signature": sig, "ok": ok})

    line(f"{len(rows)} tests, {len(rows) - failed} passed, {failed} failed")
    line("=" * 78)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"launcher": me, "rows": rows}, fh, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
