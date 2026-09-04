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

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QUuid>

#include <shellapi.h>

namespace
{
    const char* kCredentialDialogClass = "Credential Dialog Xaml Host";
    const char* kBrokerImage = "credentialuibroker.exe";

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
    // Next to the application first, so a build tree and an installed copy both
    // work; then the protected directory the installer uses. Windows grants
    // uiAccess only from a location a standard user cannot write to, so the
    // second one is where a shipping build finds it.
    const QStringList candidates{
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("keepassxc-uiaccess-helper.exe")),
        QDir(QString::fromLocal8Bit(qgetenv("ProgramFiles")))
            .filePath(QStringLiteral("keepassxc-uiaccess/typehelper.exe")),
    };
    for (const auto& candidate : candidates) {
        if (QFileInfo::exists(candidate)) {
            return QDir::toNativeSeparators(candidate);
        }
    }
    return {};
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
    if (QString::fromWCharArray(className) != QLatin1String(kCredentialDialogClass)) {
        return false;
    }
    // The class name alone would match a look-alike in any process, and this
    // decides whether a privileged helper is started.
    DWORD pid = 0;
    ::GetWindowThreadProcessId(window, &pid);
    return processImageName(pid) == QLatin1String(kBrokerImage);
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

    const auto name = QStringLiteral("keepassxc-uiaccess-%1")
                          .arg(QUuid::createUuid().toString(QUuid::Id128));
    const auto pipeName = QStringLiteral("\\\\.\\pipe\\%1").arg(name);

    // Only the current user may open it. The helper bypasses UIPI on request,
    // so the pipe is the boundary that decides who may ask.
    m_pipe = ::CreateNamedPipeW(reinterpret_cast<LPCWSTR>(pipeName.utf16()),
                                PIPE_ACCESS_OUTBOUND,
                                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                1,
                                64 * sizeof(INPUT),
                                0,
                                5000,
                                nullptr);
    if (m_pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    // ShellExecuteEx, not CreateProcess: a uiAccess binary started with
    // CreateProcess fails with ERROR_ELEVATION_REQUIRED (740). The grant is
    // issued by the AppInfo service, and only the shell path consults it. The
    // helper also does not inherit this process's environment, so everything it
    // needs is an argument.
    const auto arguments = QStringLiteral("--pipe %1 --target %2")
                               .arg(name)
                               .arg(reinterpret_cast<quintptr>(target));

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"open";
    info.lpFile = reinterpret_cast<LPCWSTR>(helper.utf16());
    info.lpParameters = reinterpret_cast<LPCWSTR>(arguments.utf16());
    // Never activated: the helper must not take the foreground from the window
    // it is about to type into.
    info.nShow = SW_SHOWMINNOACTIVE;

    if (!::ShellExecuteExW(&info)) {
        end();
        return false;
    }
    m_process = info.hProcess;

    if (!::ConnectNamedPipe(m_pipe, nullptr) && ::GetLastError() != ERROR_PIPE_CONNECTED) {
        end();
        return false;
    }

    m_target = target;
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
    DWORD written = 0;
    if (!::WriteFile(m_pipe, &records, sizeof(records), &written, nullptr) || written != sizeof(records)) {
        end();
        return false;
    }
    const DWORD bytes = records * static_cast<DWORD>(sizeof(INPUT));
    if (!::WriteFile(m_pipe, inputs, bytes, &written, nullptr) || written != bytes) {
        end();
        return false;
    }
    // Flushed so the keystrokes keep their order relative to the delays the
    // executor inserts between actions.
    ::FlushFileBuffers(m_pipe);
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
        // Closing the pipe is how the helper is asked to exit; give it a moment
        // before letting go of the handle.
        ::WaitForSingleObject(m_process, 2000);
        ::CloseHandle(m_process);
        m_process = nullptr;
    }
    m_target = nullptr;
}
