#  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

if(KPXC_FEATURE_UIACCESS_HELPER)
    # Plain C and no Qt: this binary is granted uiAccess, so it stays small.
    # WIN32_EXECUTABLE because a console would appear on the taskbar for every
    # sequence; /MANIFEST:NO because the .rc already embeds one as RT_MANIFEST,
    # which is the only form uiAccess is honoured from.
    add_executable(keepassxc-uiaccess-helper
            keepassxc-uiaccess-helper.c
            keepassxc-uiaccess-helper.rc)
    target_link_libraries(keepassxc-uiaccess-helper user32 shell32 advapi32)
    set_target_properties(keepassxc-uiaccess-helper PROPERTIES WIN32_EXECUTABLE ON)
    target_link_options(keepassxc-uiaccess-helper PRIVATE "/MANIFEST:NO")

    # No BUNDLE destination, unlike keepassxc-proxy: the feature is forced off
    # outside Windows and MSVC, so this target does not exist there.
    install(TARGETS keepassxc-uiaccess-helper
            RUNTIME DESTINATION ${BIN_INSTALL_DIR} COMPONENT Runtime)
endif()
