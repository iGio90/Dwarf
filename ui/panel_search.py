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
from threading import Thread

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget


class SearchPanel(QTableWidget):
    def __init__(self, app, headers):
        self.app = app
        self.headers = headers

        super().__init__(0, len(headers))

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalHeaderLabels(headers)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.itemDoubleClicked.connect(self.item_double_clicked)

    def item_double_clicked(self, item):
        if isinstance(item, MemoryAddressWidget):
            self.app.get_memory_panel().read_memory(item.get_address())

    @staticmethod
    def debug_symbol_search_panel(app, input):
        panel = SearchPanel(app, [])
        app.get_session_ui().add_search_tab(panel, input)

        def _work():
            matches = app.dwarf_api('findSymbol', input)
            if len(matches) > 0:
                panel.setColumnCount(3)
                panel.setHorizontalHeaderLabels(['name', 'address', 'module'])
                for ptr in matches:
                    sym = app.dwarf_api('getSymbolByAddress', ptr)
                    if sym['name'] == '' or sym['name'] is None:
                        sym['name'] = sym['address']

                    row = panel.rowCount()
                    panel.insertRow(row)

                    q = NotEditableTableWidgetItem(sym['name'])
                    q.setFlags(Qt.NoItemFlags)
                    q.setForeground(Qt.white)
                    panel.setItem(row, 0, q)

                    q = MemoryAddressWidget(sym['address'])
                    q.set_address(sym['address'])
                    q.setForeground(Qt.red)
                    panel.setItem(row, 1, q)

                    q = NotEditableTableWidgetItem(sym['moduleName'])
                    q.setFlags(Qt.NoItemFlags)
                    q.setForeground(Qt.lightGray)
                    panel.setItem(row, 2, q)
                    panel.sortByColumn(0, 0)
                    if row == 0:
                        panel.resizeColumnsToContents()
                        panel.horizontalHeader().setStretchLastSection(True)
        Thread(target=_work).start()
