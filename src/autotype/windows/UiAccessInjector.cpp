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
    const char* s_credentialDialogClass = "Credential Dialog Xaml Host";
    const char* s_brokerImage = "credentialuibroker.exe";

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
        wchar_t system32[MAX_PATH] = {0};
        if (::GetSystemDirectoryW(system32, MAX_PATH)) {
            roots << QString::fromWCharArray(system32);
        }
        const auto path = QDir::cleanPath(directory) + QLatin1Char('/');
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

    QString processImageName(DWORD pid)
    {
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            return {};
        }
        wchar_t path[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        QString name;
        if (::QueryFullProcessImageNameW(process, 0, path, &size)) {
            name = QFileInfo(QString::fromWCharArray(path, size)).fileName().toLower();
        }
        ::CloseHandle(process);
        return name;
    }
} // namespace

UiAccessInjector::~UiAccessInjector()
{
    end();
}

QString UiAccessInjector::helperPath()
{
#ifndef KPXC_FEATURE_UIACCESS_HELPER
    // The flag that decides whether the helper is built decides this too, so a
    // build without one never goes looking for it. Kept to this one place: the
    // alternative is #ifdef through the middle of the platform class, and the
    // fallback it would guard is the same fallback an absent file already takes.
    return {};
#else
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
#endif
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
    // The class alone would match a look-alike in any process.
    DWORD pid = 0;
    ::GetWindowThreadProcessId(window, &pid);
    return processImageName(pid) == QLatin1String(s_brokerImage);
}

bool UiAccessInjector::begin(HWND target)
{
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
                                64 * sizeof(INPUT),
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

    if (!::ShellExecuteExW(&info)) {
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
    // stopped draining the pipe would stop the application with it. A short
    // write is treated as a failed send instead.
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

    DWORD written = 0;
    const bool sent = ::WriteFile(m_pipe, message, size, &written, nullptr) && written == size;
    // The buffer held a password.
    ::SecureZeroMemory(message, sizeof(message));
    if (!sent) {
        // On a non-blocking pipe a full buffer reports a short write rather
        // than waiting: the helper is not keeping up, and the caller's
        // all-or-nothing rule takes it from here.
        end();
        return false;
    }
    return true;
}

void UiAccessInjector::end()
{
    if (m_pipe != INVALID_HANDLE_VALUE) {
        ::DisconnectNamedPipe(m_pipe);
        ::CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
    if (m_process) {
        // Closing the pipe is how the helper is asked to exit. If it does not,
        // it is a process with a UIPI exemption still running, so it is not
        // left to its own devices.
        if (::WaitForSingleObject(m_process, s_helperExitTimeoutMs) != WAIT_OBJECT_0) {
            qWarning("Auto-Type: the uiAccess helper did not exit; terminating it");
            ::TerminateProcess(m_process, 1);
            ::WaitForSingleObject(m_process, s_helperExitTimeoutMs);
        }
        ::CloseHandle(m_process);
        m_process = nullptr;
    }
    m_target = nullptr;
}
