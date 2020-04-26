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
import frida
from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import QMenu

from dwarf_debugger.lib import utils
from dwarf_debugger.lib.core import Dwarf
from dwarf_debugger.ui.device_window import DeviceWindow


class SessionUINotReadyException(Exception):
    """ SessionUI not created
    """


class Session(QObject):
    onCreated = pyqtSignal(name='onCreated')
    onStopped = pyqtSignal(name='onStopped')
    onClosed = pyqtSignal(name='onClosed')

    def __init__(self, parent=None, session_type=''):
        super(Session, self).__init__(parent)
        self._app_window = parent
        self._dwarf = Dwarf(self, parent)
        self._session_type = session_type

        # main menu every session needs
        self._menu = []

        if self._app_window.dwarf_args.any == '':
            self._device_window = DeviceWindow(self._app_window, self.device_manager_type)

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def dwarf(self):
        return self._dwarf

    @dwarf.setter
    def dwarf(self, value):
        if isinstance(value, Dwarf):
            self._dwarf = value

    @property
    def session_type(self):
        return self._session_type

    @property
    def device_manager_type(self):
        return ''

    @property
    def main_menu(self):
        return self._menu

    @property
    def session_ui_sections(self):
        return ['breakpoints', 'bookmarks', 'threads', 'registers', 'console', 'watchpoints', 'backtrace', 'debug']

    @property
    def frida_device(self):
        return None

    def set_config(self, config):
        pass

    def load_config(self, config_filename):
        pass

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def initialize(self):
        # setup menu
        self._setup_menu()
        # all fine were done wait for ui_ready
        self.onCreated.emit()

    def _setup_menu(self):
        """ Build Menus
        """
        process_menu = QMenu('&Process')
        process_menu.addAction('Resume', self._on_proc_resume, Qt.Key_F5)
        process_menu.addAction('Restart', self._on_proc_restart, Qt.Key_F9)
        process_menu.addAction('Detach', self._on_detach, Qt.Key_F10)

        process_menu.addSeparator()
        process_menu.addAction('Step', lambda: self.dwarf.dwarf_api('_step'), Qt.Key_F7)
        process_menu.addAction('Step call', lambda: self.dwarf.dwarf_api('_step', 'call'), Qt.Key_F8)
        process_menu.addAction('Step block', lambda: self.dwarf.dwarf_api('_step', 'block'))

        self._menu.append(process_menu)

    def start(self, args):
        self.dwarf.onScriptDestroyed.connect(self.stop)

        if not args.device:
            self.dwarf.device = self.frida_device
        else:
            self.dwarf.device = frida.get_device(id=args.device)

        if args.any == '':
            self._device_window.onSelectedProcess.connect(self._on_proc_selected)
            self._device_window.onSpawnSelected.connect(self._on_spawn_selected)
            self._device_window.onClosed.connect(self._on_device_dialog_closed)
            self._device_window.show()
        else:
            if args.pid > 0:
                print('* Trying to attach to {0}'.format(args.pid))
                try:
                    self.dwarf.attach(args.pid, args.script, False)
                    print('* Dwarf attached to {0}'.format(args.pid))
                except Exception as e:  # pylint: disable=broad-except
                    print('-failed-')
                    print('Reason: ' + str(e))
                    print('Help: you can use -sp to force spawn')
                    self.stop()
                    exit(0)
            else:
                print('* Trying to spawn {0}'.format(args.any))
                try:
                    _pid = self.dwarf.spawn(args.any, args=args.args, script=args.script)
                    print('* Dwarf attached to {0}'.format(_pid))
                except Exception as e:  # pylint: disable=broad-except
                    print('-failed-')
                    print('Reason: ' + str(e))
                    self.stop()
                    exit(0)

    def stop(self):
        try:
            self.dwarf.detach()
        except frida.InvalidOperationError:
            # device detached
            pass
        except frida.PermissionDeniedError:
            # no permissions to kill the target
            pass
        self.onStopped.emit()
        self.onClosed.emit()

    def _on_proc_resume(self, tid=0):
        if not self.dwarf.resumed:
            self.dwarf.dwarf_api('resume')

        self.dwarf.dwarf_api('release', tid)

    def _on_proc_restart(self):
        self.dwarf.restart_proc()

    def _on_detach(self):
        self.dwarf.detach()

    def _on_proc_selected(self, data):
        device, pid = data
        if device:
            self.dwarf.device = device
        if pid:
            try:
                self.dwarf.attach(pid)
            except Exception as e:
                utils.show_message_box('Failed attaching to {0}'.format(pid), str(e))
                self.stop()
                return

    def _on_spawn_selected(self, data):
        pass

    def _on_device_dialog_closed(self):
        self.stop()
