"""
Dwarf - Copyright (C) 2019 iGio90

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
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class RangesPanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 4)
        self.setHorizontalHeaderLabels(['base', 'size', 'protection', 'file'])
        self.setColumnWidth(0, 120)

    def set_menu_actions(self, item, menu):
        action_refresh = menu.addAction("Refresh")
        action_refresh.setData('refresh')

    def on_menu_action(self, action_data, item):
        if action_data == 'refresh':
            self.app.dwarf_api('updateRanges')
            return False

    def set_ranges(self, ranges):
        self.setRowCount(0)
        i = 0
        for range in ranges:
            self.insertRow(i)
            q = MemoryAddressWidget(range['base'])
            q.set_size(range['size'])
            self.setItem(i, 0, q)
            q = NotEditableTableWidgetItem(str(range['size']))
            q.setFlags(Qt.NoItemFlags)
            self.setItem(i, 1, q)
            q = NotEditableTableWidgetItem(range['protection'])
            q.setFlags(Qt.NoItemFlags)
            q.setTextAlignment(Qt.AlignCenter)
            self.setItem(i, 2, q)
            if 'file' in range:
                q = NotEditableTableWidgetItem(range['file']['path'])
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.lightGray)
                self.setItem(i, 3, q)
            else:
                self.setItem(i, 3, NotEditableTableWidgetItem(''))
            i += 1
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)
        self.sortByColumn(0, 0)
