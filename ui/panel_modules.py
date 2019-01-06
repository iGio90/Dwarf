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
import json

from PyQt5.QtCore import Qt

from ui.dialog_table import TableDialog
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class ModulesPanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 4)
        self.setHorizontalHeaderLabels(['name', 'base', 'size', 'path'])

    def set_menu_actions(self, item, menu):
        action_refresh = menu.addAction("Refresh")
        action_refresh.setData('refresh')
        if item is not None:
            menu.addSeparator()
            action_exports = menu.addAction('Exports')
            action_exports.setData('exports')
            action_imports = menu.addAction('Imports')
            action_imports.setData('imports')
            action_symbols = menu.addAction('Symbols')
            action_symbols.setData('symbols')

    def on_menu_action(self, action_data, item):
        if action_data == 'refresh':
            self.app.dwarf_api('updateModules')
            return False
        elif action_data == 'exports':
            module = self.item(item.row(), 0).text()
            table = TableBaseWidget(self.app, 0, 3)
            self.app.get_session_ui().add_tab(table, 'exports %s' % module)
            exports = self.app.dwarf_api('enumerateExports', module)
            if exports:
                exports = json.loads(exports)
                if len(exports) > 0:
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
            return False
        elif action_data == 'imports':
            imports = self.app.dwarf_api('enumerateImports', self.item(item.row(), 0).text())
            if imports:
                imports = json.loads(imports)
                TableDialog().build_and_show(self.build_exports_table, imports)
            return False
        elif action_data == 'symbols':
            symbols = self.app.dwarf_api('enumerateSymbols', self.item(item.row(), 0).text())
            if symbols:
                symbols = json.loads(symbols)
                TableDialog().build_and_show(self.build_exports_table, symbols)
        return True

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
        for module in modules:
            self.insertRow(i)
            q = NotEditableTableWidgetItem(module['name'])
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)
            q = MemoryAddressWidget(module['base'])
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
        self.sortByColumn(1, 0)
