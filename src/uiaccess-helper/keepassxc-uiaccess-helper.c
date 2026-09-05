/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Injects the keystrokes KeePassXC cannot deliver itself.
 *
 * Since a 2026-01 Windows update, SendInput from KeePassXC no longer reaches
 * the "Windows Security" credential dialog (#12956): CredentialUIBroker owns
 * it, it runs at integrity 0x200a, and UIPI discards input from the 0x2000 of
 * an ordinary process -- silently, with SendInput reporting success.
 *
 * uiAccess is the exemption. It is a property of a whole binary and requires a
 * signature plus a path a standard user cannot write, which is why this is a
 * separate executable and not a mode of KeePassXC (#13070, reverted in #13116).
 * The grant measures at integrity 0x2010: above the dialog, far below High, no
 * administrator membership, no UAC prompt. It must be started through
 * ShellExecute; CreateProcess fails with ERROR_ELEVATION_REQUIRED.
 *
 * Anything that can talk to this process can type into that dialog, so the
 * scope is fixed before the pipe is opened and re-established for every batch:
 * the server must be the KeePassXC beside this binary, the target must be a
 * credential dialog owned by CredentialUIBroker and hold the foreground, batch
 * sizes are bounded, no file is written, and it exits with the pipe.
 *
 * Usage: keepassxc-uiaccess-helper.exe --pipe <name> --target <hwnd>
 */

/* FILE_ID_INFO / FileIdInfo need the Windows 8 SDK surface; the compiler's
 * default may be older. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <windows.h>

#include <shellapi.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

/* One Auto-Type action at a time; the caller splits longer sequences. */
#define MAX_BATCH 64

/* Long enough for the pauses in a sequence, short enough that a caller which
 * hangs while holding the pipe open does not leave this process running. */
/* A backstop, not the way a sequence ends: the pipe breaking is. It exists so a
 * process with a UIPI exemption does not outlive a caller that hung holding
 * the handle. Ten minutes rather than one, because a legal sequence can idle
 * longer than that -- {DELAY} is capped at 10 s per token but not in count. */
#define MAX_IDLE_MS 600000
#define POLL_MS 25

/* Nothing is injected into a window other than the one named at startup. */
static HWND g_target = NULL;

static void report(const char* format, ...)
{
    char message[512];
    va_list args;
    va_start(args, format);
    _vsnprintf_s(message, sizeof(message), _TRUNCATE, format, args);
    va_end(args);
    OutputDebugStringA(message);
}

/* A process that was not granted uiAccess looks exactly like one whose input
 * the dialog refused, so the flag is read rather than assumed. */
static DWORD ui_access_flag(void)
{
    HANDLE token = NULL;
    DWORD ui_access = 0;
    DWORD size = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        /* TokenUIAccess == 26; older SDK headers have no enumerator for it. */
        if (!GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)26, &ui_access, sizeof(ui_access), &size)) {
            report("keepassxc-uiaccess-helper: TokenUIAccess unreadable: %lu\n", GetLastError());
        }
        CloseHandle(token);
    }
    return ui_access;
}

/* The caller supplies only the name, so it may not escape the pipe namespace. */
static int valid_pipe_name(const wchar_t* name)
{
    size_t length = 0;
    if (!name || !*name) {
        return 0;
    }
    for (const wchar_t* c = name; *c; ++c) {
        if (*c == L'\\' || *c == L'/' || *c < 0x20) {
            return 0;
        }
        if (++length > 64) {
            return 0;
        }
    }
    return 1;
}

static int image_path_of(DWORD pid, wchar_t* out, DWORD chars)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return 0;
    }
    DWORD size = chars;
    const int ok = QueryFullProcessImageNameW(process, 0, out, &size) ? 1 : 0;
    CloseHandle(process);
    return ok;
}

/* One file, however it is spelled.
 *
 * A path compare answers the wrong question: an 8.3 alias, a SUBST drive, a
 * junction or a mapped drive all give a second name for the same bytes, and the
 * kernel hands back its own canonical form rather than the one the process was
 * launched with. Volume plus file index identifies the file itself. */
static HANDLE open_for_identity(const wchar_t* path)
{
    /* FILE_SHARE_DELETE too: a scanner or an update holding the broker's image
     * with delete sharing would otherwise make this open fail, and a failed
     * open reads as "not the same file" -- a genuine dialog refused. */
    return CreateFileW(path,
                       0,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS,
                       NULL);
}

static int same_file(const wchar_t* left, const wchar_t* right)
{
    HANDLE first = open_for_identity(left);
    if (first == INVALID_HANDLE_VALUE) {
        return 0;
    }
    HANDLE second = open_for_identity(right);
    if (second == INVALID_HANDLE_VALUE) {
        CloseHandle(first);
        return 0;
    }
    int ok = 0;
    /* The 128-bit identity first: NTFS has 64-bit file ids, ReFS (a Dev Drive
     * is one) has 128-bit ones and reports a truncated or zero 64-bit view.
     * Where the volume does not support the query, the 64-bit view is exact. */
    FILE_ID_INFO ia;
    FILE_ID_INFO ib;
    if (GetFileInformationByHandleEx(first, FileIdInfo, &ia, sizeof(ia))
        && GetFileInformationByHandleEx(second, FileIdInfo, &ib, sizeof(ib))) {
        ok = ia.VolumeSerialNumber == ib.VolumeSerialNumber
             && memcmp(&ia.FileId, &ib.FileId, sizeof(ia.FileId)) == 0;
    } else {
        BY_HANDLE_FILE_INFORMATION a;
        BY_HANDLE_FILE_INFORMATION b;
        ok = GetFileInformationByHandle(first, &a) && GetFileInformationByHandle(second, &b)
             && a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh
             && a.nFileIndexLow == b.nFileIndexLow;
    }
    CloseHandle(second);
    CloseHandle(first);
    return ok;
}

static int server_is_our_application(HANDLE pipe)
{
    DWORD server_pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &server_pid)) {
        report("keepassxc-uiaccess-helper: cannot identify the pipe server: %lu\n", GetLastError());
        return 0;
    }

    wchar_t expected[MAX_PATH] = {0};
    const DWORD own = GetModuleFileNameW(NULL, expected, MAX_PATH);
    if (own == 0 || own >= MAX_PATH) {
        return 0; /* truncated: not something to compare paths against */
    }
    wchar_t* slash = wcsrchr(expected, L'\\');
    if (!slash) {
        return 0;
    }
    if (_snwprintf_s(slash + 1, MAX_PATH - (size_t)(slash + 1 - expected), _TRUNCATE, L"KeePassXC.exe") < 0) {
        return 0;
    }

    /* Held for the whole check, so the id cannot be reused mid-check. */
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid);
    if (!process) {
        return 0;
    }

    wchar_t actual[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(process, 0, actual, &size)) {
        CloseHandle(process);
        return 0;
    }
    if (!same_file(actual, expected)) {
        report("keepassxc-uiaccess-helper: refusing a pipe served by %ls\n", actual);
        CloseHandle(process);
        return 0;
    }

    /* No signature check on top of the path. PowerToys needs one for its
     * always-reachable pipe (src/common/interop/pipe_caller_auth.cpp,
     * microsoft/PowerToys#49527); here the path is inside the directory Windows
     * granted uiAccess from, which a standard user cannot write to. */
    CloseHandle(process);
    return 1;
}

/* This process holds the exemption, so it does not widen its own scope on
 * request, however trusted the caller. */
static int target_is_credential_dialog(HWND window)
{
    wchar_t class_name[64] = {0};
    if (!GetClassNameW(window, class_name, 64)) {
        return 0;
    }
    if (wcscmp(class_name, L"Credential Dialog Xaml Host") != 0) {
        return 0;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    wchar_t image[MAX_PATH] = {0};
    if (!image_path_of(pid, image, MAX_PATH)) {
        return 0;
    }
    /* GetWindowsDirectoryW, not GetSystemDirectoryW: the latter is redirected
     * to SysWOW64 for a 32-bit process, while the broker it is compared against
     * is the 64-bit one in System32, so the check would reject every genuine
     * dialog. */
    wchar_t expected[MAX_PATH] = {0};
    const UINT length = GetWindowsDirectoryW(expected, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return 0;
    }
    if (_snwprintf_s(expected + length, MAX_PATH - length, _TRUNCATE, L"\\System32\\CredentialUIBroker.exe") < 0) {
        return 0;
    }
    /* This runs before every batch. When the two names are already the same
     * text there is nothing a file-identity comparison could add, and it saves
     * two CreateFileW per batch -- the case worth having on a machine whose
     * filter drivers make every open slow. Names that differ (8.3, a junction,
     * a mapped drive) still go through same_file. */
    if (_wcsicmp(image, expected) == 0) {
        return 1;
    }
    if (!same_file(image, expected)) {
        return 0;
    }
    return 1;
}

/* The modifiers a sequence presses, released after an abort and only then.
 *
 * A sequence types modifiers as separate down and up records, so abandoning it
 * in between leaves one held down for the whole desktop. It must not run on a
 * normal ending: the user may still be physically holding the modifier that
 * started Auto-Type, and a synthetic key-up while the key is down desyncs the
 * state for every window. The Windows keys are not in the list -- releasing
 * one can open the Start menu, taking the foreground away from the prompt that
 * was just filled in. */
static void release_modifiers(void)
{
    static const WORD keys[] = {
        VK_SHIFT, VK_CONTROL, VK_MENU, VK_LSHIFT, VK_RSHIFT, VK_LCONTROL, VK_RCONTROL, VK_LMENU, VK_RMENU};
    INPUT up[sizeof(keys) / sizeof(keys[0])];
    ZeroMemory(up, sizeof(up));
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        up[i].type = INPUT_KEYBOARD;
        up[i].ki.wVk = keys[i];
        up[i].ki.dwFlags = KEYEVENTF_KEYUP;
    }
    SendInput((UINT)(sizeof(up) / sizeof(up[0])), up, sizeof(INPUT));
}

static int pipe_mode(const wchar_t* name)
{
    wchar_t path[MAX_PATH];
    if (_snwprintf_s(path, MAX_PATH, _TRUNCATE, L"\\\\.\\pipe\\%ls", name) < 0) {
        return 4;
    }

    /* SECURITY_ANONYMOUS: the server never gets to impersonate this process.
     * Without it a server that is not our application -- checked only after
     * the connection is up -- could ImpersonateNamedPipeClient and hold this
     * process's uiAccess token for as long as the impersonation lasts.
     *
     * Retried briefly on ERROR_PIPE_BUSY: the server has one instance, and
     * anything in the session that connects first is dropped by the server
     * and disconnected -- but a single failed open here would have already
     * ended this process, so one stray client could disable the feature. */
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 20; ++attempt) {
        pipe = CreateFileW(
            path, GENERIC_READ, 0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
        if (pipe != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY) {
            break;
        }
        WaitNamedPipeW(path, 50);
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        report("keepassxc-uiaccess-helper: pipe open failed: %lu\n", GetLastError());
        return 4;
    }

    if (!server_is_our_application(pipe)) {
        CloseHandle(pipe);
        return 6;
    }

    /* Polled rather than blocked on: a blocking read is released when the
     * caller closes the pipe or exits, but not when it hangs holding the
     * handle, and no privileged process should outlive a sequence. */
    DWORD idle = 0;
    for (;;) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) {
            break; /* the caller closed the pipe: the sequence is over */
        }
        DWORD count = 0;
        DWORD peeked = 0;
        if (available >= sizeof(count) && !PeekNamedPipe(pipe, &count, sizeof(count), &peeked, NULL, NULL)) {
            break;
        }
        if (count > MAX_BATCH) {
            /* Every abort below returns non-zero. The caller reads the exit
             * code after the pipe closes, and it is the only channel that can
             * still say "the last batch did not go in": a batch dropped at the
             * end is never followed by a write that could fail. A zero here
             * ended a truncated sequence looking like a completed one. */
            report("keepassxc-uiaccess-helper: refusing a batch of %lu records\n", count);
            release_modifiers();
            CloseHandle(pipe);
            return 7;
        }

        /* Nothing is consumed until the whole message is here. Reading the
         * header and then blocking for the body puts this process in a wait
         * that MAX_IDLE_MS cannot end: a caller that stops between the two
         * would leave it there indefinitely. */
        const DWORD wanted = count * (DWORD)sizeof(INPUT);
        if (available >= sizeof(count) && count == 0) {
            report("keepassxc-uiaccess-helper: refusing a batch of 0 records\n");
            release_modifiers();
            CloseHandle(pipe);
            return 7;
        }
        if (available < sizeof(count) || available < sizeof(count) + wanted) {
            if (idle >= MAX_IDLE_MS) {
                report("keepassxc-uiaccess-helper: idle for %lums, exiting\n", idle);
                release_modifiers();
                CloseHandle(pipe);
                return 8;
            }
            Sleep(POLL_MS);
            idle += POLL_MS;
            continue;
        }
        idle = 0;

        INPUT batch[MAX_BATCH];
        DWORD got = 0;
        if (!ReadFile(pipe, &count, sizeof(count), &got, NULL) || got != sizeof(count)) {
            break;
        }
        DWORD total = 0;
        while (total < wanted) {
            if (!ReadFile(pipe, ((char*)batch) + total, wanted - total, &got, NULL) || got == 0) {
                report("keepassxc-uiaccess-helper: short read, %lu of %lu\n", total, wanted);
                SecureZeroMemory(batch, total);
                release_modifiers();
                CloseHandle(pipe);
                return 5;
            }
            total += got;
        }

        /* Re-established per batch, not once at startup: a window handle is
         * reusable, and a startup-only check would still point at the number
         * after the dialog it named was destroyed. */
        if (GetForegroundWindow() != g_target || !target_is_credential_dialog(g_target)) {
            /* Abort, not skip. Skipping a batch and continuing is invisible to
             * the caller -- its WriteFile succeeded -- so the rest of the
             * sequence still arrives and the user gets a truncated password. If
             * what went missing was the Tab, everything after it is typed into
             * the field before it: the password lands in the user name box, in
             * clear text. Closing the pipe makes the caller's next write fail,
             * which is what its own all-or-nothing rule needs. */
            report("keepassxc-uiaccess-helper: target lost the foreground, aborting the sequence\n");
            SecureZeroMemory(batch, wanted);
            release_modifiers();
            CloseHandle(pipe);
            return 9;
        }

        const UINT sent = SendInput(count, batch, sizeof(INPUT));
        /* The batch held a password; nothing reads it again. */
        SecureZeroMemory(batch, wanted);
        if (sent != count) {
            /* Part of the batch was dropped. Reporting it and carrying on is
             * the mistake this program already made once: the caller cannot
             * see it, and the rest of the sequence still arrives. */
            report("keepassxc-uiaccess-helper: SendInput queued %u of %lu: %lu\n", sent, count, GetLastError());
            release_modifiers();
            CloseHandle(pipe);
            return 10;
        }
    }

    CloseHandle(pipe);
    return 0;
}

/* Windowed, so no console appears on the taskbar for the length of a sequence.
 * A windowed entry point has no argv, hence CommandLineToArgvW. */
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show)
{
    UNREFERENCED_PARAMETER(instance);
    UNREFERENCED_PARAMETER(previous);
    UNREFERENCED_PARAMETER(command_line);
    UNREFERENCED_PARAMETER(show);

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        return 2;
    }

    const wchar_t* name = NULL;
    for (int i = 1; i + 1 < argc; ++i) {
        if (wcscmp(argv[i], L"--pipe") == 0) {
            name = argv[++i];
        } else if (wcscmp(argv[i], L"--target") == 0) {
            g_target = (HWND)(uintptr_t)_wcstoui64(argv[++i], NULL, 10);
        }
    }

    /* Both are required: without a target this would inject into whatever
     * holds the foreground. */
    if (!valid_pipe_name(name) || !g_target) {
        report("keepassxc-uiaccess-helper: usage: --pipe <name> --target <hwnd>\n");
        LocalFree(argv);
        return 2;
    }

    /* Exit rather than connect: without the exemption every SendInput would be
     * discarded exactly as the caller's own are, while the caller believed the
     * keystrokes had been handed over. */
    if (!ui_access_flag()) {
        report("keepassxc-uiaccess-helper: uiAccess was not granted\n");
        LocalFree(argv);
        return 3;
    }

    if (!target_is_credential_dialog(g_target)) {
        report("keepassxc-uiaccess-helper: the target is not a brokered credential dialog\n");
        LocalFree(argv);
        return 3;
    }

    report("keepassxc-uiaccess-helper: target=%p\n", (void*)g_target);
    const int rc = pipe_mode(name);
    LocalFree(argv);
    return rc;
}
