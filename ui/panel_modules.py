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
from PyQt5.QtWidgets import QTableWidget, QMenu

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ModulesPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalHeaderLabels(['name', 'base', 'size'])
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cellDoubleClicked.connect(self.modules_cell_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        menu = QMenu()

        action_refresh = menu.addAction("Refresh\t(R)")

        action = menu.exec_(self.mapToGlobal(pos))
        if action == action_refresh:
            self.app.dwarf_api('updateModules')

    def set_modules(self, modules):
        self.setRowCount(0)
        i = 0
        for module in sorted(modules, key=lambda x: x['name']):
            self.insertRow(i)
            q = NotEditableTableWidgetItem(module['name'])
            q.setForeground(Qt.gray)
            self.setItem(i, 0, NotEditableTableWidgetItem(q))
            q = NotEditableTableWidgetItem(module['base'])
            q.setForeground(Qt.red)
            self.setItem(i, 1, q)
            q = NotEditableTableWidgetItem(str(module['size']))
            self.setItem(i, 2, q)
            i += 1
        self.resizeRowToContents(0)
        self.resizeRowToContents(1)

    def modules_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_R:
            self.app.dwarf_api('updateModules')
        else:
            # dispatch those to super
            super(ModulesPanel, self).keyPressEvent(event)
