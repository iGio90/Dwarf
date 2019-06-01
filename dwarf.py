"""
Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""
import os
import sys
import argparse

import frida
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication

from lib import utils
from lib.git import Git
from lib.prefs import Prefs
from ui.app import AppWindow


def process_args():
    """ process commandline params
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-t",
        "--type",
        type=str,
        help="SessionType - android, ios, local, remote - default: local")

    parser.add_argument(
        "-s",
        "--script",
        type=str,
        help="Path to an additional script to load with dwarf and frida js api"
    )

    parser.add_argument(
        "-p", "--package", help="Attach Dwarf to given packagename")
    #parser.add_argument("-a", "--attach", type=int, help="Attach Dwarf to given pid")

    parser.add_argument("-dev", "--device", help="DeviceSerial adb devices")

    parser.add_argument(
        "-sp", "--spawn", action='store_true', help="force spawn")

    parser.add_argument(
        "-ds",
        "--debug-script",
        action='store_true',
        help="debug outputs from frida script")

    args = parser.parse_args()
    return args


def _on_restart():
    print('restarting dwarf...')
    os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def run_dwarf():
    """ fire it up
    """
    _prefs = Prefs()
    local_update_disabled = _prefs.get('disable_local_frida_update', False)

    if not local_update_disabled:
        _git = Git()
        remote_frida = _git.get_frida_version()
        local_frida = frida.__version__

        if remote_frida and local_frida != remote_frida[0]['tag_name']:
            print('Updating local frida version to ' + remote_frida[0]['tag_name'])
            try:
                from pip import _internal
                _internal.main(["install", "--upgrade", "--user", "frida"])
                #_on_restart()
            except Exception as e: # pylint: disable=broad-except, invalid-name
                print('failed to update local frida')
                print(str(e))

    args = process_args()
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

    if os.name == 'nt':
        # windows stuff
        import ctypes
        try:
            # write ini to show folder with dwarficon
            folder_stuff = "[.ShellClassInfo]\n"
            folder_stuff += "IconResource=assets\\dwarf.ico,0\n"
            folder_stuff += "[ViewState]\n"
            folder_stuff += "Mode=\n"
            folder_stuff += "Vid=\n"
            folder_stuff += "FolderType=Generic\n"
            try:
                with open('desktop.ini', 'w') as ini:
                    ini.writelines(folder_stuff)

                # set fileattributes to hidden + systemfile
                ctypes.windll.kernel32.SetFileAttributesW(
                    r'desktop.ini', 0x02 | 0x04
                )  # FILE_ATTRIBUTE_HIDDEN = 0x02 | FILE_ATTRIBUTE_SYSTEM = 0x04
            except PermissionError:
                # its hidden+system already
                pass

            # fix for showing dwarf icon in windows taskbar instead of pythonicon
            _appid = u'iGio90.dwarf.debugger'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                _appid)

            ctypes.windll.user32.SetProcessDPIAware()

        except Exception:  # pylint: disable=broad-except
            pass

    qapp = QApplication([])

    qapp.setDesktopSettingsAware(True)
    qapp.setAttribute(Qt.AA_EnableHighDpiScaling)
    qapp.setAttribute(Qt.AA_UseHighDpiPixmaps)
    qapp.setLayoutDirection(Qt.LeftToRight)

    qapp.setOrganizationName("https://github.com/iGio90/Dwarf")
    qapp.setApplicationName("dwarf")

    # set icon
    if os.name == "nt" and os.path.exists(
            utils.resource_path('assets/dwarf.ico')):
        _icon = QIcon(utils.resource_path('assets/dwarf.ico'))
        qapp.setWindowIcon(_icon)
    else:
        if os.path.exists(utils.resource_path('assets/dwarf.png')):
            _icon = QIcon(utils.resource_path('assets/dwarf.png'))
            qapp.setWindowIcon(_icon)

    app_window = AppWindow(args)
    app_window.setWindowIcon(_icon)
    app_window.onRestart.connect(_on_restart)

    try:
        sys.exit(qapp.exec_())
    except SystemExit as sys_err:
        if sys_err.code == 0:
            # thanks for using dwarf
            print('Thank\'s for using Dwarf\nHave a nice day...')
        else:
            # something was wrong
            print('sysexit with: %d' % sys_err.code)


if __name__ == '__main__':
    run_dwarf()
