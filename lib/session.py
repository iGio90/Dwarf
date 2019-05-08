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
from PyQt5.QtCore import QObject, pyqtSignal

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
        self._dwarf = Dwarf(self, parent)
        self._dwarf.onScriptDestroyed.connect(self.stop)
        self._session_type = session_type

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
        return None

    @property
    def session_ui_sections(self):
        return None

    def set_config(self, config):
        pass

    def load_config(self, config_filename):
        pass

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def stop(self):
        self.dwarf.detach()
        self.onStopped.emit()
        self.onClosed.emit()
