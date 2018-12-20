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


class RegistersPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])
        self.verticalHeader().hide()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cellDoubleClicked.connect(self.register_cell_double_clicked)

    def set_context(self, context):
        self.setRowCount(0)
        i = 0
        is_java = 'classMethod' in context
        if is_java:
            self.setColumnCount(2)
            self.setHorizontalHeaderLabels(['argument', 'value'])
        else:
            self.setColumnCount(4)
            self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])
        for reg in context:
            if reg == 'classMethod':
                continue

            self.insertRow(i)
            q = NotEditableTableWidgetItem(reg)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)
            if context[reg] is not None:
                q = NotEditableTableWidgetItem(str(context[reg]))
            else:
                q = NotEditableTableWidgetItem('null')
            q.setForeground(Qt.red)
            self.setItem(i, 1, q)
            if is_java:
                continue
            q = NotEditableTableWidgetItem(str(int(context[reg], 16)))
            q.setForeground(Qt.darkCyan)
            self.setItem(i, 2, q)
            data = self.app.get_script().exports.ts(context[reg])
            q = NotEditableTableWidgetItem(str(data[1]))
            if data[0] == 0:
                q.setForeground(Qt.darkGreen)
            elif data[0] == 1:
                q.setForeground(Qt.red)
            elif data[0] == 2:
                q.setForeground(Qt.white)
            else:
                q.setForeground(Qt.darkGray)
            self.setItem(i, 3, q)
            self.resizeColumnsToContents()
            i += 1

    def register_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())
