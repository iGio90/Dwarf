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
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class BacktracePanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 0)

    def set_backtrace(self, bt):
        if 'type' not in bt:
            return
        self.setRowCount(0)
        if self.columnCount() == 0:
            self.setColumnCount(2)
        if bt['type'] == 'native':
            bt = bt['bt']
            self.setHorizontalHeaderLabels(['symbol', 'address'])
            for a in bt:
                row = self.rowCount()
                self.insertRow(row)

                name = a['name']
                if name is None:
                    q = NotEditableTableWidgetItem('-')
                    q.setFlags(Qt.NoItemFlags)
                    q.setForeground(Qt.gray)
                    self.setItem(row, 0, q)
                else:
                    q = NotEditableTableWidgetItem(name)
                    q.setFlags(Qt.NoItemFlags)
                    q.setForeground(Qt.darkGreen)
                    self.setItem(row, 0, q)
                q = MemoryAddressWidget(a['address'])
                self.setItem(row, 1, q)
        elif bt['type'] == 'java':
            bt = bt['bt']
            # Java backtrace
            self.setHorizontalHeaderLabels(['method', 'source'])
            parts = bt.split('\n')
            for i in range(0, len(parts)):
                if i == 0:
                    continue
                p = parts[i].replace('\t', '')
                p = p.split('(')
                if len(p) != 2:
                    continue

                row = self.rowCount()
                self.insertRow(row)

                q = NotEditableTableWidgetItem(p[0])
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.darkYellow)
                self.setItem(row, 0, q)

                q = NotEditableTableWidgetItem(p[1].replace(')', ''))
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.gray)
                self.setItem(row, 1, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)
