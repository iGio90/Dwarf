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
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QListWidget


class PickList(QListWidget):
    def __init__(self, callback, *__args):
        super().__init__(*__args)

        self.callback = callback
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.itemDoubleClicked.connect(self._callback)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Return:
            self._callback()
        else:
            super(PickList, self).keyPressEvent(event)

    def _callback(self):
        if len(self.selectedItems()) > 0:
            self.callback(self.selectedItems()[0])
