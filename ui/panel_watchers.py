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

from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class WatchersPanel(TableBaseWidget):
    def __init__(self, app):
        super().__init__(app, 0, 0)

    def set_menu_actions(self, item, menu):
        if item is None:
            native = menu.addAction("Add memory watcher\t(A)")
            native.setData('add')

    def on_menu_action(self, action_data, item):
        if action_data == 'add':
            self.app.get_dwarf().add_watcher()
            return False
        return True

    def clear(self):
        self.setRowCount(0)
        self.setColumnCount(0)

    def add_watcher_callback(self, ptr):
        if self.columnCount() == 0:
            self.setColumnCount(1)
            self.setHorizontalHeaderLabels(['address'])

        self.insertRow(self.rowCount())

        q = MemoryAddressWidget(ptr)
        self.setItem(self.rowCount() - 1, 0, q)

        if self.rowCount() == 1:
            self.resizeRowsToContents()
            self.horizontalHeader().setStretchLastSection(True)

    def remove_watcher_callback(self, ptr):
        items = self.findItems(ptr, Qt.MatchExactly)
        if len(items) > 0:
            self.removeRow(items[0].row())
        if self.rowCount() == 0:
            self.setColumnCount(0)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_A:
            self.app.get_dwarf().add_watcher()
        super(WatchersPanel, self).keyPressEvent(event)

    def is_search_enabled(self):
        return False
