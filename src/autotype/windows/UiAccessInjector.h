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

#ifndef KEEPASSXC_UIACCESSINJECTOR_H
#define KEEPASSXC_UIACCESSINJECTOR_H

#include <QString>
#include <windows.h>

/**
 * Sends keystrokes to windows an ordinary process cannot reach.
 *
 * Since a Windows update in January 2026, SendInput from a medium-integrity
 * process does not arrive at the "Windows Security" credential prompt, which
 * CredentialUIBroker owns and which runs at integrity 0x200a (#12956).
 *
 * uiAccess is the exemption, and it is a property of a whole binary: one that
 * requests it cannot start from a user-writable location, which is why #13070
 * was reverted in #13116. So it lives in a separate helper, started only for
 * that dialog and only for one sequence. Both ends authenticate the other
 * before anything is written, and the pipe admits only the current user.
 */
class UiAccessInjector
{
public:
    UiAccessInjector() = default;
    ~UiAccessInjector();

    Q_DISABLE_COPY(UiAccessInjector)

    /** The installed helper, or empty when there is none to trust. */
    static QString helperPath();

    /** True when @p window is the credential prompt CredentialUIBroker owns. */
    static bool isBrokeredCredentialDialog(HWND window);

    /**
     * Starts the helper for @p target.
     *
     * False when there is no helper, when Windows declined the grant, or when
     * it did not connect; the caller must then keep using SendInput.
     */
    bool begin(HWND target);

    /** True while a helper is connected and delegation is in effect. */
    bool active() const;

    /** Hands @p count INPUT records to the helper. False means nothing was sent. */
    bool send(const INPUT* inputs, int count);

    /** Closes the pipe, which is how the helper is asked to exit. */
    void end();

private:
    /** Waits for the helper to connect. Never blocks indefinitely. */
    bool waitForHelper();

    static constexpr int s_helperConnectTimeoutMs = 3000;
    static constexpr int s_helperConnectPollMs = 50;
    static constexpr int s_helperExitTimeoutMs = 2000;

    HANDLE m_pipe = INVALID_HANDLE_VALUE;
    HANDLE m_process = nullptr;
    HWND m_target = nullptr;
};

#endif // KEEPASSXC_UIACCESSINJECTOR_H
