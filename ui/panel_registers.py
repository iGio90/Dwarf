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
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QMenu

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_native_register import NativeRegisterWidget


class RegistersPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])
        self.verticalHeader().hide()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

        self.context_ptr = ''

    def show_menu(self, pos):
        menu = QMenu()

        item = self.itemAt(pos)
        if item is not None and isinstance(item, NativeRegisterWidget) and item.is_valid_ptr():
            jump_to_ptr = menu.addAction("Jump to pointer")

            action = menu.exec_(self.mapToGlobal(pos))
            if action == jump_to_ptr:
                self.app.get_memory_panel().read_memory(item.value)

    def set_context(self, ptr, is_java, context):
        self.setRowCount(0)
        i = 0

        self.context_ptr = ptr
        if self.app.get_dwarf().get_loading_library() is not None:
            self.context_ptr = self.app.get_dwarf().get_loading_library()

        if is_java:
            self.setColumnCount(3)
            self.setHorizontalHeaderLabels(['argument', 'class', 'value'])
        else:
            self.setColumnCount(4)
            self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])
        for reg in context:
            self.insertRow(i)

            q = NotEditableTableWidgetItem(reg)
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            if is_java:
                q = NotEditableTableWidgetItem(context[reg]['className'])
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.white)
                self.setItem(i, 1, q)

            if context[reg] is not None:
                if is_java:
                    if context[reg]['arg'] is None:
                        q = QTableWidgetItem('null')
                        q.setForeground(Qt.gray)
                    else:
                        q = QTableWidgetItem(str(context[reg]['arg']))
                else:
                    q = NativeRegisterWidget(self.app, reg, context[reg])
                q.setFlags(Qt.NoItemFlags)
                if is_java:
                    self.setItem(i, 2, q)
                else:
                    self.setItem(i, 1, q)

                    q = NotEditableTableWidgetItem(str(int(context[reg], 16)))
                    q.setForeground(Qt.darkCyan)
                    self.setItem(i, 2, q)
                    data = self.app.dwarf_api('getAddressTs', context[reg])
                    if data is not None:
                        q = NotEditableTableWidgetItem(str(data[1]))
                        q.setFlags(Qt.NoItemFlags)
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
