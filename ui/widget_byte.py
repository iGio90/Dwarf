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
from PyQt5.QtCore import Qt

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ByteWidget(NotEditableTableWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)

        self.setTextAlignment(Qt.AlignCenter)

        self.value = 0
        self.ptr = 0
        self.offset = 0

    def get_offset(self):
        return self.offset

    def get_ptr(self):
        return self.ptr

    def get_value(self):
        return self.value

    def set_offset(self, offset):
        self.offset = offset

    def set_ptr(self, ptr):
        self.ptr = ptr

    def set_value(self, value):
        self.value = value
        t = '%x' % self.value
        if len(t) < 2:
            t = '0' + t
        self.setText(t)

        if self.value == 0:
            self.setForeground(Qt.gray)
