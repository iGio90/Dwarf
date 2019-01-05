"""
Dwarf - Copyright (C) 2018 iGio90

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

from ui.widget_memory_address import MemoryAddressWidget


class NativeRegisterWidget(MemoryAddressWidget):
    def __init__(self, app, register, value, *__args):
        super().__init__(*__args)

        self.register = register
        self.value = value
        self.valid_ptr = app.dwarf_api('isValidPointer', self.value)
        if self.valid_ptr:
            self.setForeground(Qt.red)
        else:
            self.setForeground(Qt.lightGray)
        self.setText(value)
        self.set_address(value)

    def is_valid_ptr(self):
        return self.valid_ptr
