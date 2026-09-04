/*
 * A minimal uiAccess type-helper: the mechanism keepassxreboot/keepassxc#12956
 * needs verified before any patch is worth writing.
 *
 * The bug: after a 2026-01 Windows update, SendInput from an ordinary-integrity
 * process no longer reaches the "Windows Security" credential dialog, which
 * CredentialUIBroker owns. Measured on Windows 11 24H2 26100.9168, the dialog
 * accepts hardware-level input and drops injected input entirely.
 *
 * The workaround on the issue is to run the whole password manager elevated,
 * which breaks its SSH agent. uiAccess is the alternative: a process with
 * uiAccess="true" in its *embedded* manifest runs as the ordinary user, needs no
 * UAC prompt, and is exempted from UIPI -- so it may inject into windows of a
 * higher integrity level. Whether that exemption covers this particular dialog
 * is what this program measures.
 *
 * Deliberately not a service and not IPC-driven: this is the experiment, not the
 * design. A shipping helper would need an authenticated pipe -- see the notes
 * beside this file -- because a process that types into higher-IL windows on
 * request is a UIPI bypass for anything that can talk to it.
 *
 * Launching it: NOT with CreateProcess. A uiAccess binary started that way
 * fails with ERROR_ELEVATION_REQUIRED (740) -- the grant is issued by the
 * AppInfo service, which only ShellExecute goes through. That is a hard
 * constraint on any sidecar design: the application cannot simply spawn it.
 * Since ShellExecute gives no pipes, the report is written to the file named by
 * %UIACCESS_HELPER_LOG% as well as to stdout.
 *
 * Two modes:
 *
 *   typehelper.exe --pipe <name> --target <hwnd> [--log <path>]
 *       Connects to a named pipe the caller created, and injects the INPUT
 *       records it receives. Used by KeePassXC: auto-type is per-keystroke, so a
 *       process per character is not an option. It exits when the caller closes
 *       the pipe, so no privileged process outlives the sequence.
 *
 *   typehelper.exe <text> [delay_ms] [log_path] [target_hwnd]
 *       Types <text> once. This is what the reproduction tests drive.
 *   Types <text> one character at a time with KEYEVENTF_UNICODE -- the same call
 *   KeePassXC's AutoTypeWindows.cpp makes, so a difference in outcome is a
 *   difference in privilege, not in API. Tab and Enter in <text> are sent as
 *   scan codes from here rather than by the caller.
 *
 *   Pass target_hwnd (decimal) to have the helper raise that window itself.
 *   Without it the target is whatever holds the foreground after delay_ms, and
 *   that is a race: a console window won it once and the helper typed into it,
 *   which read as "uiAccess does not work" when the mechanism was fine.
 */

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

static FILE *g_log = NULL;

static void report(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
    if (g_log) {
        va_start(args, fmt);
        vfprintf(g_log, fmt, args);
        va_end(args);
        fflush(g_log);
    }
}

static int type_unicode(wchar_t ch)
{
    INPUT in[2];
    ZeroMemory(in, sizeof(in));

    in[0].type = INPUT_KEYBOARD;
    in[0].ki.wVk = 0;
    in[0].ki.wScan = ch;
    in[0].ki.dwFlags = KEYEVENTF_UNICODE;

    in[1] = in[0];
    in[1].ki.dwFlags |= KEYEVENTF_KEYUP;

    UINT sent = SendInput(2, in, sizeof(INPUT));
    if (sent != 2) {
        report("SendInput queued %u/2 events, GetLastError=%lu\n", sent, GetLastError());
        return 0;
    }
    return 1;
}

static int press_vk(WORD vk)
{
    INPUT in[2];
    ZeroMemory(in, sizeof(in));
    WORD scan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);

    in[0].type = INPUT_KEYBOARD;
    in[0].ki.wVk = 0;
    in[0].ki.wScan = scan;
    in[0].ki.dwFlags = KEYEVENTF_SCANCODE;

    in[1] = in[0];
    in[1].ki.dwFlags |= KEYEVENTF_KEYUP;

    UINT sent = SendInput(2, in, sizeof(INPUT));
    if (sent != 2) {
        report("SendInput(vk=%u) queued %u/2, GetLastError=%lu\n", vk, sent, GetLastError());
        return 0;
    }
    return 1;
}

/* Nothing is injected into a window other than the one named at startup: the
 * helper is a UIPI bypass, so its scope has to be fixed before any caller can
 * ask for something. */
static HWND g_target = NULL;


static int pipe_mode(const wchar_t *name)
{
    wchar_t full[MAX_PATH];
    _snwprintf(full, MAX_PATH, L"\\\\.\\pipe\\%ls", name);

    HANDLE pipe = CreateFileW(full, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        report("pipe open failed: %lu\n", GetLastError());
        return 4;
    }
    report("pipe connected: %ls\n", full);

    /* Records arrive as raw INPUT structures. The count is bounded so a
     * corrupt or hostile length cannot be turned into a huge allocation. */
    for (;;) {
        DWORD count = 0, got = 0;
        if (!ReadFile(pipe, &count, sizeof(count), &got, NULL) || got != sizeof(count)) {
            report("pipe closed by the caller\n");
            break;
        }
        if (count == 0 || count > 64) {
            report("refusing a batch of %lu records\n", count);
            break;
        }
        INPUT batch[64];
        DWORD wanted = count * (DWORD)sizeof(INPUT);
        DWORD read_total = 0;
        while (read_total < wanted) {
            if (!ReadFile(pipe, ((char *)batch) + read_total, wanted - read_total, &got, NULL) || got == 0) {
                report("short read: %lu of %lu\n", read_total, wanted);
                CloseHandle(pipe);
                return 5;
            }
            read_total += got;
        }

        if (g_target && GetForegroundWindow() != g_target) {
            /* Refusing is the safe answer: the keystrokes were meant for one
             * window and something else now has the focus. */
            report("foreground is not the target; dropping %lu records\n", count);
            continue;
        }

        UINT sent = SendInput(count, batch, sizeof(INPUT));
        if (sent != count) {
            report("SendInput queued %u/%lu, GetLastError=%lu\n", sent, count, GetLastError());
        }
    }

    CloseHandle(pipe);
    return 0;
}

static DWORD ui_access_flag(void)
{
    HANDLE token = NULL;
    DWORD ui_access = 0, size = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        /* TokenUIAccess == 26 */
        if (!GetTokenInformation(token, (TOKEN_INFORMATION_CLASS)26, &ui_access,
                                 sizeof(ui_access), &size)) {
            report("GetTokenInformation(TokenUIAccess) failed: %lu\n", GetLastError());
        }
        CloseHandle(token);
    }
    return ui_access;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2) {
        report("usage: typehelper.exe <text> [delay_ms]\n");
        return 2;
    }

    /* The log path is an argument, not an environment variable: a uiAccess
     * process is started by the AppInfo service, which does not inherit the
     * caller's environment -- %UIACCESS_HELPER_LOG% arrived unset and the run
     * looked like the helper had never executed. */
    const wchar_t *log_path = (argc > 3) ? argv[3] : L"C:\\Users\\Public\\uiaccess_helper.log";
    g_log = _wfopen(log_path, L"w");

    /* --pipe selects the mode KeePassXC uses. */
    if (argc >= 3 && wcscmp(argv[1], L"--pipe") == 0) {
        const wchar_t *name = argv[2];
        const wchar_t *log_path = L"";
        for (int i = 3; i + 1 < argc; i += 2) {
            if (wcscmp(argv[i], L"--target") == 0) {
                g_target = (HWND)(uintptr_t)_wtoi64(argv[i + 1]);
            } else if (wcscmp(argv[i], L"--log") == 0) {
                log_path = argv[i + 1];
            }
        }
        if (*log_path) {
            g_log = _wfopen(log_path, L"w");
        }
        report("uiAccess=%lu\n", ui_access_flag());
        report("target=%p\n", (void *)g_target);
        int rc = pipe_mode(name);
        if (g_log) {
            fclose(g_log);
        }
        return rc;
    }

    DWORD delay = (argc > 2) ? (DWORD)_wtoi(argv[2]) : 4000;

    /* Reported rather than asserted: a process only has uiAccess if the OS
     * granted it, and it is granted silently or not at all. Printing the token
     * flag is how a run that quietly lost the exemption stays distinguishable
     * from one where the dialog simply refused the input. */
    report("uiAccess=%lu\n", ui_access_flag());
    report("waiting %lu ms, then typing %d characters\n", delay, (int)wcslen(argv[1]));

    HWND requested = NULL;
    if (argc > 4) {
        requested = (HWND)(uintptr_t)_wtoi64(argv[4]);
    }

    if (requested) {
        /* A uiAccess process may take the foreground; that exemption is part of
         * what the flag grants, and it removes the race entirely. */
        for (int i = 0; i < 6; ++i) {
            SetForegroundWindow(requested);
            Sleep(200);
        }
        report("requested target hwnd=%p foreground_now=%d\n",
               (void *)requested, GetForegroundWindow() == requested);
    }

    Sleep(delay);

    HWND target = GetForegroundWindow();
    if (requested && target != requested) {
        report("target lost the foreground before typing; refusing to type\n");
        if (g_log) {
            fclose(g_log);
        }
        return 3;
    }
    wchar_t title[256] = {0};
    GetWindowTextW(target, title, 255);
    wchar_t cls[256] = {0};
    GetClassNameW(target, cls, 255);
    report("foreground hwnd=%p class=%ls\n", (void *)target, cls);

    /* Tab and Enter are sent as scan codes from *this* process. Sending them
     * from the caller instead would put unprivileged input back in the middle
     * of the sequence, which is the very thing under test -- an earlier version
     * of the test did that and would have failed even with a working helper. */
    int ok = 1;
    for (const wchar_t *p = argv[1]; *p; ++p) {
        int sent;
        if (*p == L'\t') {
            sent = press_vk(VK_TAB);
        } else if (*p == L'\n' || *p == L'\r') {
            sent = press_vk(VK_RETURN);
        } else {
            sent = type_unicode(*p);
        }
        if (!sent) {
            ok = 0;
            break;
        }
        Sleep(25);
    }

    report("typed=%s\n", ok ? "queued-all" : "failed");
    if (g_log) {
        fclose(g_log);
    }
    return ok ? 0 : 1;
}
