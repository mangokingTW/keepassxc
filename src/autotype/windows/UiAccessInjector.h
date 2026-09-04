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
 * CredentialUIBroker owns (#12956). Measured on Windows 11 26100.9168: the
 * keystrokes are accepted by SendInput, the dialog does not receive them, and
 * the same input from a high-integrity or uiAccess process does arrive. What
 * decides it is the integrity level -- a de-elevated child that still holds
 * administrator privileges is blocked just the same.
 *
 * Running KeePassXC elevated works and is the workaround on the issue, at the
 * cost of the SSH agent and browser integration. Putting uiAccess on the main
 * binary was tried in #13070 and reverted in #13116, because such a binary
 * cannot start at all from a user-writable location, which rules out the
 * portable ZIP.
 *
 * So the exemption lives in a small separate helper, and only that helper needs
 * to be signed and installed under Program Files. Where it is missing --
 * portable builds, self-built binaries, distributions that do not ship it --
 * KeePassXC runs exactly as before and only this one path is unavailable.
 *
 * The helper is a UIPI bypass for whatever can talk to it, so the scope is
 * fixed at startup: it is told one target window and refuses to inject when
 * anything else holds the foreground, and the pipe's DACL admits only the
 * current user.
 */
class UiAccessInjector
{
public:
    UiAccessInjector() = default;
    ~UiAccessInjector();

    Q_DISABLE_COPY(UiAccessInjector)

    /** Path to the installed helper, or an empty string when there is none. */
    static QString helperPath();

    /** True when @p window is the credential prompt CredentialUIBroker owns. */
    static bool isBrokeredCredentialDialog(HWND window);

    /**
     * Starts the helper for @p target.
     *
     * Returns false when no helper is installed, when Windows declined to grant
     * it uiAccess, or when it did not connect. The caller then keeps using
     * SendInput directly: a failure here must not silently drop keystrokes.
     */
    bool begin(HWND target);

    /** True while a helper is connected and delegation is in effect. */
    bool active() const;

    /** Hands @p count INPUT records to the helper. False means nothing was sent. */
    bool send(const INPUT* inputs, int count);

    /** Closes the pipe, which is how the helper is asked to exit. */
    void end();

private:
    HANDLE m_pipe = INVALID_HANDLE_VALUE;
    HANDLE m_process = nullptr;
    HWND m_target = nullptr;
};

#endif // KEEPASSXC_UIACCESSINJECTOR_H
