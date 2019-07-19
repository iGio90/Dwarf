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
import json
import os

from PyQt5.QtCore import QObject, pyqtSignal

VIEW_BACKTRACE = 'view_backtrace'
VIEW_CONTEXT = 'view_context'
VIEW_HOOKS = 'view_hooks'
VIEW_WATCHERS = 'view_watchers'


class Prefs(QObject):
    """ Preferences

        json settings '.dwarf'

        signals:
            settingChanged(key, value)
            prefsChanged()
    """

    prefsChanged = pyqtSignal(name='prefsChanged')

    def __init__(self):
        super(Prefs, self).__init__()

        self._prefs = {}
        self._prefs_file = '.dwarf'

        if os.path.exists(self._prefs_file):
            with open(self._prefs_file, 'r') as f:
                try:
                    self._prefs = json.load(f)
                except:
                    pass

    def get(self, key, default=None):
        """ Get Setting

            key - setting name
            default
        """
        if key in self._prefs:
            return self._prefs[key]
        return default

    def put(self, key, value):
        """ Set Setting

            key - setting name
            value

            emits
                settingChanged(key, value)
                prefsChanged()
        """
        self._prefs[key] = value
        with open(self._prefs_file, 'w') as f:
            f.write(json.dumps(self._prefs))

        self.prefsChanged.emit()
