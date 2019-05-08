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

from lib.android_session import AndroidSession
from lib.local_session import LocalSession


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
    def create_session(self, session_type):
        session_type = session_type.join(session_type.split()).lower()
        if self._session is not None:
            raise SessionRunningException('there is an active session')
        else:
            if session_type == 'android':
                self._session = AndroidSession(self._app_window)
            elif session_type == 'local':
                self._session = LocalSession(self._app_window)
            else:
                self._session = None

            if self._session is not None:
                self._session.onCreated.connect(self._session_ready)
                self._session.onClosed.connect(self._clear_session)
                self._session.onStopped.connect(self._session_finished)
                self._session.initialize(config='')

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
