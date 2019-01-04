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
import json
from pprint import pprint

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu

from lib import utils
from ui.dialog_table import TableDialog
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ModulesPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(0, 4)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalHeaderLabels(['name', 'base', 'size', 'path'])
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cellDoubleClicked.connect(self.modules_cell_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        menu = QMenu()
        item = self.itemAt(pos)

        action_refresh = menu.addAction("Refresh")
        if item is not None:
            sep1 = utils.get_qmenu_separator()
            menu.addAction(sep1)

            action_exports = menu.addAction('Exports')
            action_imports = menu.addAction('Imports')
            action_symbols = menu.addAction('Symbols')

        action = menu.exec_(self.mapToGlobal(pos))

        if action == action_refresh:
            self.app.dwarf_api('updateModules')
        if item is not None:
            if action == action_exports:
                exports = self.app.dwarf_api('enumerateExports', self.item(item.row(), 0).text())
                if exports:
                    exports = json.loads(exports)
                    TableDialog().build_and_show(self.build_exports_table, exports)
            elif action == action_imports:
                imports = self.app.dwarf_api('enumerateImports', self.item(item.row(), 0).text())
                if imports:
                    imports = json.loads(imports)
                    TableDialog().build_and_show(self.build_exports_table, imports)
            elif action == action_symbols:
                symbols = self.app.dwarf_api('enumerateSymbols', self.item(item.row(), 0).text())
                if symbols:
                    symbols = json.loads(symbols)
                    TableDialog().build_and_show(self.build_exports_table, symbols)

    def build_exports_table(self, table, exports):
        if len(exports) > 0:
            table.setMinimumWidth(int(self.app.width() / 3))
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(['name', 'address', 'type'])
            for export in exports:
                row = table.rowCount()
                table.insertRow(row)

                q = NotEditableTableWidgetItem(export['name'])
                q.setForeground(Qt.gray)
                table.setItem(row, 0, q)

                q = NotEditableTableWidgetItem(export['address'])
                q.setForeground(Qt.red)
                table.setItem(row, 1, q)

                q = NotEditableTableWidgetItem(export['type'])
                table.setItem(row, 2, q)
            table.resizeColumnsToContents()
            table.horizontalHeader().setStretchLastSection(True)

    def build_imports_table(self, table, imports):
        if len(imports) > 0:
            table.setMinimumWidth(int(self.app.width() / 3))
            table.setColumnCount(4)
            table.setHorizontalHeaderLabels(['name', 'address', 'module', 'type'])
            for imp in imports:
                row = table.rowCount()
                table.insertRow(row)

                q = NotEditableTableWidgetItem(imp['name'])
                q.setForeground(Qt.gray)
                table.setItem(row, 0, q)

                q = NotEditableTableWidgetItem(imp['address'])
                q.setForeground(Qt.red)
                table.setItem(row, 1, q)

                q = NotEditableTableWidgetItem(imp['module'])
                table.setItem(row, 2, q)

                q = NotEditableTableWidgetItem(imp['type'])
                table.setItem(row, 3, q)
            table.resizeColumnsToContents()
            table.horizontalHeader().setStretchLastSection(True)

    def set_modules(self, modules):
        self.setRowCount(0)
        i = 0
        for module in sorted(modules, key=lambda x: x['name']):
            self.insertRow(i)
            q = NotEditableTableWidgetItem(module['name'])
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)
            q = NotEditableTableWidgetItem(module['base'])
            q.setForeground(Qt.red)
            self.setItem(i, 1, q)
            q = NotEditableTableWidgetItem(str(module['size']))
            q.setFlags(Qt.NoItemFlags)
            self.setItem(i, 2, q)
            q = NotEditableTableWidgetItem(module['path'])
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.lightGray)
            self.setItem(i, 3, q)
            i += 1
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def modules_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())
