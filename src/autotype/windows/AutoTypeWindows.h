/*
 *  Copyright (C) 2025 KeePassXC Team <team@keepassxc.org>
 *  Copyright (C) 2016 Lennart Glauer <mail@lennart-glauer.de>
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

#ifndef KEEPASSXC_AUTOTYPEWINDOWS_H
#define KEEPASSXC_AUTOTYPEWINDOWS_H

#undef NOMINMAX
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "autotype/AutoTypeAction.h"
#include "autotype/AutoTypePlatform.h"

#include <QScopedPointer>

class WinUtils;
class UiAccessInjector;

class AutoTypePlatformWin : public QObject, public AutoTypePlatformInterface
{
    Q_OBJECT

public:
    explicit AutoTypePlatformWin();
    // Declared here and defined in the .cpp on purpose: QScopedPointer needs the
    // complete type where the destructor is instantiated, and an implicit one in
    // this header only has the forward declaration --
    //   error C2027: use of undefined type 'UiAccessInjector'
    ~AutoTypePlatformWin() override;
    bool isAvailable() override;
    QStringList windowTitles() override;
    WId activeWindow() override;
    QString activeWindowTitle() override;
    bool raiseWindow(WId window) override;
    // The sequence hooks, not raiseWindow, are where delegation is decided:
    // entry-level Auto-Type never calls raiseWindow (it passes no window and
    // resolves the target afterwards), so the decision has to sit on a hook
    // that both paths reach.
    void beginSequence(WId window) override;
    void endSequence() override;
    AutoTypeExecutor& executor() const override;

    void sendCharVirtual(const QChar& ch);
    void sendChar(const QChar& ch);
    void setKeyState(Qt::Key key, bool down);

private:
    AutoTypeExecutor* m_executor = nullptr;
    // Delegation for windows an ordinary process cannot reach. See
    // UiAccessInjector for what those are and why this is a separate process;
    // with no helper installed it stays inactive and nothing changes.
    QScopedPointer<UiAccessInjector> m_injector;

    // The single exit for injected input. All three senders above go through
    // it, so delegation is in effect for a whole sequence or not at all --
    // three direct SendInput calls were one edit away from typing half a
    // password into the void.
    bool sendInputs(INPUT* inputs, int count);

    static bool isExtendedKey(DWORD nativeKeyCode);
    static bool isAltTabWindow(HWND hwnd);
    static BOOL CALLBACK windowTitleEnumProc(_In_ HWND hwnd, _In_ LPARAM lParam);
    static QString windowTitle(HWND hwnd);
};

class AutoTypeExecutorWin : public AutoTypeExecutor
{
public:
    explicit AutoTypeExecutorWin(AutoTypePlatformWin* platform);

    AutoTypeAction::Result execBegin(const AutoTypeBegin* action) override;
    AutoTypeAction::Result execType(const AutoTypeKey* action) override;
    AutoTypeAction::Result execClearField(const AutoTypeClearField* action) override;

private:
    AutoTypePlatformWin* const m_platform;
};

#endif // KEEPASSXC_AUTOTYPEWINDOWS_H
