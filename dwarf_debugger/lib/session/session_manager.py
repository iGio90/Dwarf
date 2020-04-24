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
import json

from PyQt5.QtCore import QObject, pyqtSignal

from dwarf_debugger.lib.session.android_session import AndroidSession
from dwarf_debugger.lib.session.local_session import LocalSession
from dwarf_debugger.lib.session.remote_session import RemoteSession
from dwarf_debugger.lib.session.ios_session import IosSession


class SessionRunningException(Exception):
    """ Exception
    """


class SessionManager(QObject):

    sessionCreated = pyqtSignal(name='sessionCreated')
    sessionStarted = pyqtSignal(name='sessionStarted')
    sessionStopped = pyqtSignal(name='sessionStopped')
    sessionClosed = pyqtSignal(name='sessionClosed')

    def __init__(self, parent=None):
        super(SessionManager, self).__init__(parent)
        self._app_window = parent

        self._session = None
        self._restored_session_data = None

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def session(self):
        if self._session is not None:
            return self._session

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def create_session(self, session_type, session_data=None):
        session_type = session_type.join(session_type.split()).lower()
        self._restored_session_data = session_data

        if self._session is not None:
            raise SessionRunningException('there is an active session')
        else:
            if session_type == 'android':
                self._session = AndroidSession(self._app_window)
            elif session_type == 'local':
                self._session = LocalSession(self._app_window)
            elif session_type == 'remote':
                self._session = RemoteSession(self._app_window)
            elif session_type == 'ios':
                self._session = IosSession(self._app_window)
            else:
                self._session = None

            if self._session is not None:
                self._session.onCreated.connect(self._session_ready)
                self._session.onClosed.connect(self._clear_session)
                self._session.onStopped.connect(self._session_finished)
                self._session.initialize()

    def start_session(self, args=None):
        if self._session is not None:
            self.sessionStarted.emit()
            self._session.start(args)

    def stop_session(self):
        if self._session is not None:
            self._session.stop()

    def _session_ready(self):
        if self._session is not None:
            self.sessionCreated.emit()

    def _clear_session(self):
        if self._session is not None:
            self._session = None
            self.sessionClosed.emit()

    def _session_finished(self):
        if self._session is not None:
            self.sessionStopped.emit()

    def _get_session_restore_ptr(self, breakpoint):
        module = breakpoint['debugSymbols']['moduleName']
        if module is not None and module != '':
            name = breakpoint['debugSymbols']['name']
        else:
            return 0
        add = 0
        if name.startswith('0x'):
            if '+' in name:
                p = name.split('+')
                name = int(p[0], 16)
                add = int(p[1], 16)

            module = self._app_window.dwarf.dwarf_api('findModule', module)
            if module is not None:
                module = json.loads(module)
                return int(module['base'], 16) + name + add
        else:
            if '+' in name:
                p = name.split('+')
                name = p[0]
                add = int(p[1], 16)
            ptr = self._app_window.dwarf.dwarf_api('findExport', [name, module])
            if ptr is not None:
                return int(ptr, 16) + add
        return 0

    def restore_session(self):
        if self._restored_session_data is not None:
            # restore user script
            if 'user_script' in self._restored_session_data:
                self._app_window.console_panel.get_js_console().set_js_script_text(
                    self._restored_session_data['user_script'])
                self.session.dwarf.dwarf_api(
                    'evaluateFunction', self._app_window.console_panel.get_js_console().get_js_script_text())

        # invalidation
        self._restored_session_data = None
