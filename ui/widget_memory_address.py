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
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class MemoryAddressWidget(NotEditableTableWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)

        self.offset = 0
        self.address = 0

    def set_address(self, address):
        self.address = address

    def set_offset(self, offset):
        self.offset = offset

    def get_address(self):
        return self.address

    def get_offset(self):
        return self.offset
