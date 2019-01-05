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
from PyQt5.QtWidgets import QTableWidget, QScrollBar

from ui.widget_context import ContextItem
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget


class ContextsPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(0, 3)
        self.app = app

        self.setHorizontalHeaderLabels(['tid', 'pc', 'symbol'])
        self.verticalHeader().hide()
        scrollbar = QScrollBar()
        scrollbar.setFixedWidth(0)
        scrollbar.setFixedHeight(0)
        self.setHorizontalScrollBar(scrollbar)
        self.itemDoubleClicked.connect(self.on_context_item_double_click)
        self.horizontalHeader().setStretchLastSection(True)
        self.setShowGrid(False)

    def add_context(self, data, library_onload=None):
        row = self.rowCount()
        self.insertRow(row)
        q = ContextItem(data, str(data['tid']))
        q.setForeground(Qt.darkCyan)
        self.setItem(row, 0, q)
        is_java = data['is_java']
        if not is_java:
            q = MemoryAddressWidget(data['ptr'])
            q.set_address(int(data['ptr'], 16))
        else:
            parts = data['ptr'].split('.')
            q = NotEditableTableWidgetItem(parts[len(parts) - 1])
            q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.red)
        self.setItem(row, 1, q)
        if library_onload is None:
            if not is_java:
                q = NotEditableTableWidgetItem('%s - %s' % (
                    data['symbol']['moduleName'], data['symbol']['name']))
            else:
                q = NotEditableTableWidgetItem('.'.join(parts[:len(parts) - 1]))
        else:
            q = NotEditableTableWidgetItem('loading %s' % library_onload)

        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.gray)
        self.setItem(row, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def on_context_item_double_click(self, item):
        if isinstance(item, ContextItem):
            self.app.apply_context(item.get_context())
        elif isinstance(item, MemoryAddressWidget):
            self.app.get_memory_panel().read_memory(item.get_address())
