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

#include "UiAccessInjector.h"

#include "config-keepassx.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QUuid>

#include <cstring>

#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>

namespace
{
    // A constant rather than an #ifdef around the body below: compiling the
    // body out leaves this file's own helpers with no callers, and -Wall
    // -Werror turns an unused static function into a failed build.
#ifdef KPXC_FEATURE_UIACCESS_HELPER
    constexpr bool s_featureEnabled = true;
#else
    constexpr bool s_featureEnabled = false;
#endif

    const char* s_credentialDialogClass = "Credential Dialog Xaml Host";
    const char* s_brokerImage = "CredentialUIBroker.exe";

    /* One ACE, for this user's SID, protected against inherited ones -- tighter
     * than the default DACL, which also admits SYSTEM and Administrators.
     *
     * It cannot be narrowed further. Handle inheritance would be the stronger
     * binding, with no name in the namespace at all, but AppInfo creates the
     * process so no handle can be passed to it; the name has to travel on the
     * command line, which any process running as this user can read. So the
     * binding rests on the identity checks at both ends, not on the name. */
    QString currentUserDacl()
    {
        HANDLE token = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return {};
        }
        DWORD size = 0;
        ::GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        QByteArray buffer(static_cast<int>(size), 0);
        QString sddl;
        if (::GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
            LPWSTR sid = nullptr;
            const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.constData());
            if (::ConvertSidToStringSidW(user->User.Sid, &sid)) {
                sddl = QStringLiteral("D:P(A;;GA;;;%1)").arg(QString::fromWCharArray(sid));
                ::LocalFree(sid);
            }
        }
        ::CloseHandle(token);
        return sddl;
    }

    /* The list Windows itself requires a uiAccess binary to live under, and the
     * whole of the check that the helper was not planted: elsewhere the grant
     * cannot be issued anyway, and here the directory is one a standard user
     * cannot write to. PowerToys adds Authenticode for its always-reachable
     * pipe (src/common/interop/pipe_caller_auth.cpp, microsoft/PowerToys#49527);
     * the location rule carries the same thing for a per-sequence one. */
    bool inUiAccessLocation(const QString& directory)
    {
        // Asked of the OS, not of the environment. %ProgramFiles% and
        // %SystemRoot% are inherited from whoever started KeePassXC, so a
        // check against them is satisfied by anyone who can set a variable
        // before launching it.
        QStringList roots;
        for (const auto& id : {FOLDERID_ProgramFilesX64, FOLDERID_ProgramFilesX86, FOLDERID_ProgramFiles}) {
            PWSTR folder = nullptr;
            if (SUCCEEDED(::SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &folder))) {
                roots << QString::fromWCharArray(folder);
                ::CoTaskMemFree(folder);
            }
        }
        // Windows directory plus System32, rather than GetSystemDirectoryW:
        // that one is redirected to SysWOW64 for a 32-bit process.
        wchar_t windows[MAX_PATH] = {0};
        const UINT length = ::GetWindowsDirectoryW(windows, MAX_PATH);
        if (length > 0 && length < MAX_PATH) {
            roots << QDir(QString::fromWCharArray(windows)).filePath(QStringLiteral("System32"));
        }
        // Canonical first: launched through C:\PROGRA~1\... the path is an 8.3
        // alias of the same directory, and cleanPath does not expand it.
        const auto resolved = QFileInfo(directory).canonicalFilePath();
        const auto path = QDir::cleanPath(resolved.isEmpty() ? directory : resolved) + QLatin1Char('/');
        for (const auto& root : roots) {
            if (root.isEmpty()) {
                continue;
            }
            const auto prefix = QDir::cleanPath(root) + QLatin1Char('/');
            if (path.startsWith(prefix, Qt::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    }

    QString processImagePath(DWORD pid)
    {
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            return {};
        }
        wchar_t path[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        QString image;
        if (::QueryFullProcessImageNameW(process, 0, path, &size)) {
            image = QDir::fromNativeSeparators(QString::fromWCharArray(path, size));
        }
        ::CloseHandle(process);
        return image;
    }

    /** The full path the real credential broker runs from, or empty. */
    QString brokerImagePath()
    {
        wchar_t windows[MAX_PATH] = {0};
        const UINT length = ::GetWindowsDirectoryW(windows, MAX_PATH);
        if (length == 0 || length >= MAX_PATH) {
            return {};
        }
        return QDir(QString::fromWCharArray(windows))
            .filePath(QStringLiteral("System32/%1").arg(QLatin1String(s_brokerImage)));
    }
} // namespace

UiAccessInjector::~UiAccessInjector()
{
    end();
}

QString UiAccessInjector::helperPath()
{
    if (!s_featureEnabled) {
        return {};
    }
    // Installed beside the application, the way keepassxc-cli and
    // keepassxc-proxy are, and searched nowhere else: a second location would
    // mean a writable copy could be picked up instead.
    const auto helper =
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("keepassxc-uiaccess-helper.exe"));
    if (!QFileInfo::exists(helper)) {
        return {};
    }
    // In a writable install -- the portable ZIP, a build tree -- a helper next
    // to the application could have been dropped there by anything, and would
    // be handed the keystrokes despite having no uiAccess.
    if (!inUiAccessLocation(QCoreApplication::applicationDirPath())) {
        qWarning("Auto-Type: not delegating to a uiAccess helper outside a protected location");
        return {};
    }
    return QDir::toNativeSeparators(helper);
}

bool UiAccessInjector::isBrokeredCredentialDialog(HWND window)
{
    if (!window) {
        return false;
    }
    wchar_t className[256] = {0};
    if (::GetClassNameW(window, className, 255) <= 0) {
        return false;
    }
    if (QString::fromWCharArray(className) != QLatin1String(s_credentialDialogClass)) {
        return false;
    }
    // The class alone would match a look-alike in any process, and so would the
    // file name on its own: the broker is the one Windows ships in System32.
    // The helper repeats this check for itself; doing it here as well keeps a
    // privileged process from being started for a window that cannot be it.
    DWORD pid = 0;
    ::GetWindowThreadProcessId(window, &pid);
    const auto expected = brokerImagePath();
    if (expected.isEmpty()) {
        return false;
    }
    return processImagePath(pid).compare(expected, Qt::CaseInsensitive) == 0;
}

bool UiAccessInjector::begin(HWND target)
{
    m_helperFailed = false;
    if (active() && m_target == target) {
        return true;
    }
    end();

    const auto helper = helperPath();
    if (helper.isEmpty()) {
        return false;
    }

    const auto name = QStringLiteral("keepassxc-uiaccess-%1").arg(QUuid::createUuid().toString(QUuid::Id128));
    const auto pipeName = QStringLiteral("\\\\.\\pipe\\%1").arg(name);

    const auto sddl = currentUserDacl();
    if (sddl.isEmpty()) {
        return false;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            reinterpret_cast<LPCWSTR>(sddl.utf16()), SDDL_REVISION_1, &descriptor, nullptr)) {
        return false;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;

    // FIRST_PIPE_INSTANCE so creation fails rather than joining somebody
    // else's object, and one instance so nothing connects behind the helper.
    m_pipe = ::CreateNamedPipeW(reinterpret_cast<LPCWSTR>(pipeName.utf16()),
                                PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                1,
                                sizeof(DWORD) + 64 * sizeof(INPUT),
                                0,
                                5000,
                                &attributes);
    ::LocalFree(descriptor);
    if (m_pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // ShellExecuteEx, not CreateProcess, which fails with
    // ERROR_ELEVATION_REQUIRED: the grant comes from the AppInfo service and
    // only the shell path consults it. The helper inherits nothing from this
    // process, so everything it needs is an argument.
    const auto arguments = QStringLiteral("--pipe %1 --target %2").arg(name).arg(reinterpret_cast<quintptr>(target));

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"open";
    info.lpFile = reinterpret_cast<LPCWSTR>(helper.utf16());
    info.lpParameters = reinterpret_cast<LPCWSTR>(arguments.utf16());
    // The helper creates no window, and must not take the foreground from the
    // one it is about to type into.
    info.nShow = SW_HIDE;

    // hProcess can be null with the call reporting success (a shell that
    // delegated the launch). Without it there is no pid to admit at the pipe
    // and no exit code to read, so it is a failed launch, not a slow one.
    if (!::ShellExecuteExW(&info) || !info.hProcess) {
        end();
        return false;
    }
    m_process = info.hProcess;

    if (!waitForHelper()) {
        end();
        return false;
    }

    m_target = target;
    return true;
}

bool UiAccessInjector::waitForHelper()
{
    // Bounded, because this runs on the GUI thread: a blocking
    // ConnectNamedPipe would wait forever for a helper that never connects and
    // take the application with it. In non-blocking mode it returns
    // ERROR_PIPE_LISTENING until a client arrives, so the wait has a deadline.
    DWORD mode = PIPE_TYPE_BYTE | PIPE_NOWAIT;
    if (!::SetNamedPipeHandleState(m_pipe, &mode, nullptr, nullptr)) {
        return false;
    }

    const DWORD helperPid = m_process ? ::GetProcessId(m_process) : 0;
    bool connected = false;
    // Wall clock, not iteration count: counting iterations let a client that
    // reconnects in a tight loop exhaust the whole budget in under a
    // millisecond, which is the denial this loop is meant to survive.
    const ULONGLONG deadline = ::GetTickCount64() + s_helperConnectTimeoutMs;
    while (::GetTickCount64() < deadline) {
        if (::ConnectNamedPipe(m_pipe, nullptr) || ::GetLastError() == ERROR_PIPE_CONNECTED) {
            // The process that was started, not merely something owned by
            // this user: the name is random but readable from the helper's
            // command line, so the first arrival cannot be trusted.
            DWORD clientPid = 0;
            if (::GetNamedPipeClientProcessId(m_pipe, &clientPid) && clientPid == helperPid) {
                connected = true;
                break;
            }
            // Dropped rather than fatal: giving up here would let any process
            // disable this by connecting once. Paced, so a client that comes
            // straight back cannot spend the budget for us.
            ::DisconnectNamedPipe(m_pipe);
            ::Sleep(s_helperConnectPollMs);
            continue;
        }
        if (::GetLastError() != ERROR_PIPE_LISTENING) {
            return false;
        }
        // A helper that exited has already answered: it refuses to run without
        // the uiAccess it was started for.
        if (m_process && ::WaitForSingleObject(m_process, s_helperConnectPollMs) == WAIT_OBJECT_0) {
            return false;
        }
    }
    if (!connected) {
        return false;
    }

    // Left non-blocking on purpose. This all runs on the thread executing the
    // Auto-Type sequence, and a synchronous WriteFile to a helper that has
    // stopped draining the pipe would stop the application with it. A write
    // the buffer cannot take is retried for a bounded time in send() -- the
    // buffer holds exactly one message and the helper polls every 25 ms --
    // and only then treated as a failed send.
    return true;
}

bool UiAccessInjector::active() const
{
    return m_pipe != INVALID_HANDLE_VALUE && m_target;
}

bool UiAccessInjector::send(const INPUT* inputs, int count)
{
    if (!active() || count <= 0 || count > 64) {
        return false;
    }
    const DWORD records = static_cast<DWORD>(count);
    const DWORD bytes = records * static_cast<DWORD>(sizeof(INPUT));

    // One write, not two. Sent as a header followed by a separate body, a
    // caller that stops in between leaves the helper waiting on a read that its
    // own idle timeout cannot interrupt.
    char message[sizeof(DWORD) + 64 * sizeof(INPUT)];
    ::memcpy(message, &records, sizeof(records));
    ::memcpy(message + sizeof(records), inputs, bytes);
    const DWORD size = static_cast<DWORD>(sizeof(records) + bytes);

    // On a non-blocking pipe a full buffer does not wait: WriteFile fails with
    // ERROR_NO_DATA, or writes nothing, until the helper has read the previous
    // message. It polls every 25 ms, so at a low AutoTypeDelay the buffer is
    // often still full when the next batch arrives. Retried, bounded, so that
    // is a pause rather than a truncated password; a helper that has really
    // stopped reading still fails the send, after s_sendRetryMs.
    bool sent = false;
    const ULONGLONG deadline = ::GetTickCount64() + s_sendRetryMs;
    for (;;) {
        DWORD written = 0;
        const bool ok = ::WriteFile(m_pipe, message, size, &written, nullptr);
        if (ok && written == size) {
            sent = true;
            break;
        }
        // A partial write cannot be completed with the rest: the helper reads
        // whole messages. Anything but "try again" is final.
        const DWORD error = ::GetLastError();
        if ((ok && written != 0) || (!ok && error != ERROR_NO_DATA) || ::GetTickCount64() >= deadline) {
            break;
        }
        ::Sleep(5);
    }
    // The buffer held a password.
    ::SecureZeroMemory(message, sizeof(message));
    if (!sent) {
        // The caller's all-or-nothing rule takes it from here.
        end();
        return false;
    }
    return true;
}

void UiAccessInjector::end()
{
    // Fresh each time: it describes the helper this call ends, and stays false
    // when there was none. Left over from an earlier failure it would have
    // endSequence() release modifiers after every later sequence into any
    // window -- synthetic key-ups the user did not ask for.
    m_helperFailed = false;
    if (m_pipe != INVALID_HANDLE_VALUE) {
        // Disconnecting discards what the helper has not read yet, and the
        // helper reads on a 25 ms poll, so the last batch of a sequence --
        // typically the Enter -- was being thrown away while the helper
        // exited 0. Wait for it to drain first, but only while the helper is
        // alive to drain it: a dead helper has already broken the pipe, and
        // a live one takes at most one poll interval. Bounded either way.
        if (m_process) {
            const ULONGLONG deadline = ::GetTickCount64() + s_drainTimeoutMs;
            while (::GetTickCount64() < deadline && ::WaitForSingleObject(m_process, 0) == WAIT_TIMEOUT) {
                DWORD mode = PIPE_TYPE_BYTE | PIPE_WAIT;
                // In blocking mode FlushFileBuffers returns once the client has
                // read everything, or fails once the pipe is broken.
                if (::SetNamedPipeHandleState(m_pipe, &mode, nullptr, nullptr) && ::FlushFileBuffers(m_pipe)) {
                    break;
                }
                ::Sleep(5);
            }
        }
        ::DisconnectNamedPipe(m_pipe);
        ::CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
    if (m_process) {
        // Closing the pipe is how the helper is asked to exit. If it does not,
        // it is a process with a UIPI exemption still running, so it is not
        // left to its own devices.
        const bool exited = ::WaitForSingleObject(m_process, s_helperExitTimeoutMs) == WAIT_OBJECT_0;
        if (!exited) {
            qWarning("Auto-Type: the uiAccess helper did not exit; terminating it");
            ::TerminateProcess(m_process, 1);
            ::WaitForSingleObject(m_process, s_helperExitTimeoutMs);
        }
        // The pipe carries nothing back, so the exit code is the only thing the
        // helper can still say. It matters for the last batch of a sequence:
        // a batch dropped there is never followed by a write that could fail,
        // so without this the run ends looking like a success.
        DWORD code = 0;
        m_helperFailed = !exited || (::GetExitCodeProcess(m_process, &code) && code != 0);
        if (m_helperFailed) {
            qWarning("Auto-Type: the uiAccess helper ended with %lu; some keystrokes may not have arrived",
                     exited ? code : 1u);
        }
        ::CloseHandle(m_process);
        m_process = nullptr;
    }
    m_target = nullptr;
}
