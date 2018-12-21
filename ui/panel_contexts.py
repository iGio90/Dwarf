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
from PyQt5.QtWidgets import QTableWidget

from ui.widget_context import ContextItem
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ContextsPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.setHorizontalHeaderLabels(['tid', 'pc', 'symbol'])
        self.verticalHeader().hide()
        self.itemDoubleClicked.connect(self.on_context_item_double_click)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def add_context(self, data, library_onload=None):
        row = self.rowCount()
        self.insertRow(row)
        q = ContextItem(data, str(data['tid']))
        q.setForeground(Qt.darkCyan)
        self.setItem(row, 0, q)
        is_java = data['is_java']
        if not is_java:
            q = NotEditableTableWidgetItem(data['ptr'])
        else:
            parts = data['ptr'].split('.')
            q = NotEditableTableWidgetItem(parts[len(parts) - 1])
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

        q.setForeground(Qt.gray)
        self.setItem(row, 2, q)
        self.resizeRowToContents(0)
        self.resizeRowToContents(1)

    def on_context_item_double_click(self, item):
        self.app.apply_context(self.item(item.row(), 0).get_context())
