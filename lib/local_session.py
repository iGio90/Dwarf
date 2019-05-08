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
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtWidgets import QMenu, QAction, QFileDialog, QApplication

import frida
from lib.core import Dwarf
from lib.session import Session

from ui.device_window import DeviceWindow
from ui.dialog_list import ListDialog
from ui.dialog_input import InputDialog


class LocalSession(Session):

    def __init__(self, app_window):
        super(LocalSession, self).__init__(app_window)

        self._app_window = app_window
        self._device_window = DeviceWindow(self._app_window, 'local')

        # main menu every session needs
        self._menu = [QMenu(self.session_type + ' Session')]
        self._menu[0].addAction('Close Session', self.stop)

    @property
    def session_ui_sections(self):
        # what sections we want in session_ui
        return ['hooks', 'threads', 'registers', 'memory', 'console', 'watchers']

    @property
    def session_type(self):
        """ return session name to show in menus etc
        """
        return 'Local'

    @property
    def main_menu(self):
        """ return our created menu
        """
        return self._menu

    def initialize(self, config):

        # setup ui etc for android
        self._setup_menu()
        # all fine were done wait for ui_ready
        self.onCreated.emit()

    def _setup_menu(self):
        """ Build Menus
        """
        file_menu = QMenu('&File')
        self._menu.append(file_menu)

        process_menu = QMenu('&Process')
        process_menu.addAction('Resume', self._on_proc_resume, Qt.Key_F5)
        process_menu.addAction('Restart', self._on_proc_restart, Qt.Key_F9)
        process_menu.addAction('Detach', self._on_detach, Qt.Key_F10)

        self._menu.append(process_menu)

        # additional menus
        #device_menu = QMenu('&Device')
        # self._menu.append(device_menu)

    def stop(self):
        # cleanup ur stuff

        # end session
        super().stop()

    def start(self, args):
        self.dwarf.onScriptDestroyed.connect(self.stop)
        if args.package is None:
            self._device_window.setModal(True)
            self._device_window.onSelectedProcess.connect(self.on_proc_selected)
            self._device_window.onClosed.connect(self._on_devdlg_closed)
            self._device_window.show()
        else:
            self.dwarf.device = frida.get_local_device()
            if not args.spawn:
                print('* Trying to attach to {0}'.format(args.package))
                ret_val = self.dwarf.attach(args.package, args.script, False)
                if ret_val == 2:
                    print('Failed to attach: use -sp to force spawn')
                    self.stop()
                    exit()
            else:
                print('* Trying to spawn {0}'.format(args.package))
                ret_val = self.dwarf.spawn(args.package, args.script)
                if ret_val != 0:
                    print('-failed-')
                    exit(ret_val)

    def on_proc_selected(self, data):
        device, pid = data
        if device:
            self.dwarf.device = device
        if pid:
            self.dwarf.attach(pid)

    def _on_proc_resume(self, tid=0):
        if tid == 0:
            # self.dwarf.device.resume(self.dwarf.pid)
            self._app_window.contexts_list_panel.clear()
            self._app_window.context_panel.clear()
            # self._app_window.backtrace_panel.setRowCount(0)
            self.dwarf.contexts.clear()

        self.dwarf.dwarf_api('release', tid)

    def _on_proc_restart(self):
        self.dwarf.dwarf_api('restart')
        self._on_proc_resume()

    def _on_detach(self):
        self.dwarf.detach()

    def _on_devdlg_closed(self):
        self.stop()
