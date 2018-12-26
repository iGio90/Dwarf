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

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class BacktracePanel(QTableWidget):
    def __init__(self, *__args):
        super().__init__(0, 2)

        self.verticalHeader().hide()
        self.setHorizontalHeaderLabels(['symbol', 'address'])
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def set_backtrace(self, bt):
        self.setRowCount(0)
        self.setHorizontalHeaderLabels(['symbol', 'address'])
        if type(bt) is list:
            # native hook
            for a in bt:
                row = self.rowCount()
                self.insertRow(row)

                name = a['name']
                if name is None:
                    q = NotEditableTableWidgetItem('-')
                    q.setForeground(Qt.gray)
                    self.setItem(row, 0, q)
                else:
                    q = NotEditableTableWidgetItem(name)
                    q.setForeground(Qt.darkGreen)
                    self.setItem(row, 0, q)
                q = NotEditableTableWidgetItem(a['address'])
                q.setForeground(Qt.red)
                self.setItem(row, 1, q)
            self.resizeRowToContents(1)
        elif type(bt) is str:
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
                q.setForeground(Qt.darkYellow)
                self.setItem(row, 0, q)

                q = NotEditableTableWidgetItem(p[1].replace(')', ''))
                q.setForeground(Qt.gray)
                self.setItem(row, 1, q)
            self.resizeRowToContents(1)
