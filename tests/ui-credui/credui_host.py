"""Raises a real "Windows Security" credential dialog and blocks on it.

`Get-Credential` refused to show UI in this host context ("Access is denied"),
so the dialog is raised through the API that produces it: credui's
CredUIPromptForWindowsCredentials, which is the same prompt the RDP client uses.

Kept in its own process because the call blocks until the dialog closes.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

CREDUIWIN_GENERIC = 0x00000001


class CREDUI_INFOW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hwndParent", wintypes.HWND),
        ("pszMessageText", wintypes.LPCWSTR),
        ("pszCaptionText", wintypes.LPCWSTR),
        ("hbmBanner", wintypes.HBITMAP),
    ]


credui = ctypes.WinDLL("credui", use_last_error=True)
credui.CredUIPromptForWindowsCredentialsW.argtypes = [
    ctypes.POINTER(CREDUI_INFOW),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.ULONG),
    wintypes.LPVOID,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.ULONG),
    ctypes.POINTER(wintypes.BOOL),
    wintypes.DWORD,
]
credui.CredUIPromptForWindowsCredentialsW.restype = wintypes.DWORD

info = CREDUI_INFOW(
    cbSize=ctypes.sizeof(CREDUI_INFOW),
    hwndParent=None,
    pszMessageText="wintegrate probe: does injected input reach this dialog?",
    pszCaptionText="Windows Security",
    hbmBanner=None,
)
package = wintypes.ULONG(0)
out_buffer = wintypes.LPVOID()
out_size = wintypes.ULONG(0)
save = wintypes.BOOL(False)

result = credui.CredUIPromptForWindowsCredentialsW(
    ctypes.byref(info), 0, ctypes.byref(package), None, 0,
    ctypes.byref(out_buffer), ctypes.byref(out_size), ctypes.byref(save),
    CREDUIWIN_GENERIC,
)
# The return code alone answers the question: 0 means the dialog was submitted,
# 1223 (ERROR_CANCELLED) means it was dismissed. UIA cannot read this dialog's
# fields at all -- reading them was the first version's witness, and it would
# have reported "nothing arrived" even on a run where everything worked.
username = ""
if result == 0 and out_buffer:
    credui.CredUnPackAuthenticationBufferW.argtypes = [
        wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    credui.CredUnPackAuthenticationBufferW.restype = wintypes.BOOL
    user = ctypes.create_unicode_buffer(513)
    user_len = wintypes.DWORD(513)
    domain = ctypes.create_unicode_buffer(513)
    domain_len = wintypes.DWORD(513)
    password = ctypes.create_unicode_buffer(513)
    password_len = wintypes.DWORD(513)
    ok = credui.CredUnPackAuthenticationBufferW(
        0, out_buffer, out_size, user, ctypes.byref(user_len),
        domain, ctypes.byref(domain_len), password, ctypes.byref(password_len),
    )
    if ok:
        username = user.value

# The path comes from the caller. It was hardcoded once, and because the
# replacement that was supposed to fix it silently matched nothing, the tests
# read an empty file and reported a working mechanism as broken.
result_path = os.environ.get(
    "CREDUI_PROBE_RESULT", r"C:\Users\Public\credui_probe_result.txt"
)
with open(result_path, "w", encoding="utf-8") as handle:
    handle.write(f"RESULT={result}\nUSER={username}\n")
print(f"CredUIPromptForWindowsCredentials returned {result} user={username!r}", flush=True)
