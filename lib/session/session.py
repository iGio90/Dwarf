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
import frida
from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import QMenu

from lib.core import Dwarf


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
    def main_menu(self):
        return self._menu

    @property
    def session_ui_sections(self):
        return None

    @property
    def non_closable(self):
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

        self._menu.append(process_menu)

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
