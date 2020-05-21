"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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
import shutil

DWARF_VERSION = '1.0.0'

__version__ = DWARF_VERSION


def pip_install_package(package_name):
    try:
        from dwarf_debugger.lib.utils import do_shell_command
        res = do_shell_command('pip3 install ' + package_name + ' --upgrade --user')
        if 'Successfully installed' in res:
            return True
        elif 'Requirement already up-to-date' in res:
            return True
        else:
            return False
    except Exception:  # pylint: disable=broad-except
        return False


def _check_package_version(package_name, min_version):
    try:
        installed_version = None
        if package_name == 'frida':
            import frida
            installed_version = frida.__version__
        elif package_name == 'capstone':
            import capstone
            installed_version = capstone.__version__
        elif package_name == 'requests':
            import requests
            installed_version = requests.__version__
        elif package_name == 'pyqt5':
            from PyQt5 import QtCore
            installed_version = QtCore.PYQT_VERSION_STR
        elif package_name == 'pyperclip':
            import pyperclip
            installed_version = pyperclip.__version__
        if installed_version is not None:
            installed_version = installed_version.split('.')
            _min_version = min_version.split('.')
            needs_update = False
            if int(installed_version[0]) < int(_min_version[0]):
                needs_update = True
            elif (int(installed_version[0]) <= int(_min_version[0])) and (
                    int(installed_version[1]) < int(_min_version[1])):
                needs_update = True
            elif (int(installed_version[1]) <= int(_min_version[1])) and (
                    int(installed_version[2]) < int(_min_version[2])):
                needs_update = True

            if needs_update:
                print('updating ' + package_name + '... to ' + min_version)
                if pip_install_package(package_name + '>=' + min_version):
                    print('*** success ***')
    except Exception:  # pylint: disable=broad-except
        print('installing ' + package_name + '...')
        if pip_install_package(package_name + '>=' + min_version):
            print('*** success ***')


def _check_dependencies():
    _check_package_version('frida', '12.6.23')
    _check_package_version('requests', '2.18.4')
    _check_package_version('pyqt5', '5.13.2')
    _check_package_version('pyperclip', '1.7.0')
    _check_package_version('capstone', '4.0.0')  # problem with 4.0.1 as installed 4.0.1 returns 4.0.0


def process_args():
    """ process commandline params
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="SessionType - android, ios, local, remote - default: local")

    parser.add_argument(
        "-s",
        "--script",
        type=str,
        help="Path to an additional script to load with dwarf and frida js api"
    )

    parser.add_argument("-dev", "--device", help="DeviceSerial adb devices")

    parser.add_argument(
        "-bs", "--break-start", action='store_true', help="break at start")

    parser.add_argument(
        "-ds",
        "--debug-script",
        action='store_true',
        help="debug outputs from frida script")

    parser.add_argument('any', nargs='?', default='', help='path/pid/package')
    parser.add_argument('args', nargs='*', default=[''], help='arguments')

    args = parser.parse_args()

    return args


def _on_restart():
    print('restarting dwarf...')
    os.execl(sys.executable, os.path.abspath(__file__), *sys.argv)


def run_dwarf():
    """ fire it up
    """
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    # os.environ["QT_SCALE_FACTOR"] = "1"
    # os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "0"
    # os.environ["QT_SCREEN_SCALE_FACTORS"] = "1"

    from dwarf_debugger.lib import utils
    from dwarf_debugger.lib.git import Git
    from dwarf_debugger.lib.prefs import Prefs
    from dwarf_debugger.ui.app import AppWindow

    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QIcon
    from PyQt5.QtWidgets import QApplication

    import dwarf_debugger.resources  # pylint: disable=unused-import

    QApplication.setDesktopSettingsAware(True)
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    QApplication.setLayoutDirection(Qt.LeftToRight)

    QApplication.setOrganizationName("https://github.com/iGio90/Dwarf")
    QApplication.setApplicationName("Dwarf")
    QApplication.setApplicationDisplayName('Dwarf')

    qapp = QApplication([])

    # set icon
    _icon = None
    if os.name == "nt":
        if os.path.exists(utils.resource_path('assets/dwarf.ico')):
            _icon = QIcon(utils.resource_path('assets/dwarf.ico'))
        else:
            _icon = QIcon(':/assets/dwarf.ico')
    else:
        if os.path.exists(utils.resource_path('assets/dwarf.png')):
            _icon = QIcon(utils.resource_path('assets/dwarf.png'))
        else:
            _icon = QIcon(':/assets/dwarf.png')

    if _icon:
        qapp.setWindowIcon(_icon)

    _prefs = Prefs()
    local_update_disabled = _prefs.get('disable_local_frida_update', False)

    args = process_args()

    """
    did_first_run = _prefs.get('did_first_run', False)
    if False:
        from dwarf_debugger.ui.dialogs.dialog_setup import SetupDialog
        # did_first_run:
        _prefs.put('did_first_run', True)
        SetupDialog.showDialog(_prefs)
    """

    if not local_update_disabled:
        _git = Git()
        import frida
        remote_frida = _git.get_frida_version()
        local_frida = frida.__version__

        if remote_frida and local_frida != remote_frida['tag_name']:
            print('Updating local frida version to ' + remote_frida['tag_name'])
            try:
                res = utils.do_shell_command('pip3 install frida --upgrade --user')
                if 'Successfully installed frida-' + remote_frida['tag_name'] in res:
                    _on_restart()
                elif 'Requirement already up-to-date' in res:
                    if os.path.exists('.git_cache'):
                        shutil.rmtree('.git_cache', ignore_errors=True)
                else:
                    print('failed to update local frida')
                    print(res)
            except Exception as e:  # pylint: disable=broad-except, invalid-name
                print('failed to update local frida')
                print(str(e))

    if os.name == 'nt':
        # windows stuff
        import ctypes
        try:
            if os.path.exists(utils.resource_path('assets/dwarf.ico')):
                # write ini to show folder with dwarficon
                folder_stuff = "[.ShellClassInfo]\n"
                folder_stuff += "IconResource=dwarf\\assets\\dwarf.ico,0\n"
                folder_stuff += "[ViewState]\n"
                folder_stuff += "Mode=\n"
                folder_stuff += "Vid=\n"
                folder_stuff += "FolderType=Generic\n"
                try:
                    ini_path = os.path.dirname(os.path.abspath(__file__)) + os.sep + os.pardir + os.sep + 'desktop.ini'
                    with open(ini_path, 'w') as ini:
                        ini.writelines(folder_stuff)

                    # set fileattributes to hidden + systemfile
                    ctypes.windll.kernel32.SetFileAttributesW(
                        ini_path, 0x02 | 0x04 | ~0x20
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

    try:
        # parse target as pid
        args.pid = int(args.any)
    except ValueError:
        args.pid = 0

    # default to local if not specified
    if args.target is None:
        args.target = 'local'

    app_window = AppWindow(args)
    if _icon:
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


def main():
    run_dwarf()
