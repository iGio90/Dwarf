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
from PyQt5.QtWidgets import QTableWidgetItem

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_native_register import NativeRegisterWidget
from ui.widget_table_base import TableBaseWidget


class ContextPanel(TableBaseWidget):
    CONTEXT_TYPE_NATIVE = 0
    CONTEXT_TYPE_JAVA = 1
    CONTEXT_TYPE_EMULATOR = 2

    def __init__(self, app, *__args):
        super().__init__(app, *__args)
        self.context_ptr = ''
        self.is_java_context = False

    def item_double_clicked(self, item):
        if isinstance(item, NativeRegisterWidget) and item.is_valid_ptr():
            self.app.get_memory_panel().read_memory(item.value)
        elif isinstance(item, MemoryAddressWidget):
            self.app.get_memory_panel().read_memory(item.get_address())
        elif self.is_java_context:
            self.on_menu_action('expand', item)

        # return false and manage double click here
        return False

    def set_menu_actions(self, item, menu):
        if self.is_java_context:
            if item is not None:
                action_expand = menu.addAction("Explorer")
                action_expand.setData('expand')

    def on_menu_action(self, action_data, item):
        if action_data == 'expand':
            self.app.get_java_explorer_panel().set_handle_arg(item.row())
            return False
        return True

    def __initialize_context(self):
        self.setRowCount(0)
        self.setColumnCount(0)

    def __set_emulator_context(self, ptr, context):
        self.__initialize_context()
        self.context_ptr = ptr
        self.is_java_context = False
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal'])
        for reg in sorted(context.__dict__):
            if reg.startswith('_'):
                continue

            i = self.rowCount()
            self.insertRow(i)

            q = NotEditableTableWidgetItem(reg)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)
            q = NotEditableTableWidgetItem(reg)
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            q = NativeRegisterWidget(reg, {
                'value': hex(context.__dict__[reg]),
                'isValidPointer': False  # @todo!
            })
            self.setItem(i, 1, q)

            q = NotEditableTableWidgetItem(str(context.__dict__[reg]))
            q.setForeground(Qt.darkCyan)
            self.setItem(i, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def __set_java_context(self, ptr, context):
        self.__initialize_context()
        self.context_ptr = ptr
        self.is_java_context = True
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['argument', 'class', 'value'])
        for arg in context:
            i = self.rowCount()
            self.insertRow(i)

            q = NotEditableTableWidgetItem(arg)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            q = NotEditableTableWidgetItem(context[arg]['className'])
            if isinstance(context[arg]['handle'], str):
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.lightGray)
                self.item(i, 0).setFlags(Qt.NoItemFlags)
                self.item(i, 0).setForeground(Qt.lightGray)
            self.setItem(i, 1, q)

            if context[arg] is not None:
                q = QTableWidgetItem('null')
                q.setForeground(Qt.gray)
                q.setForeground(Qt.gray)
                self.setItem(i, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def __set_native_context(self, ptr, context):
        self.__initialize_context()
        self.context_ptr = ptr
        self.is_java_context = False
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])

        if self.app.get_dwarf().get_loading_library() is not None:
            self.context_ptr = self.app.get_dwarf().get_loading_library()

        for reg in context:
            if reg.lower() == 'tojson':
                continue

            i = self.rowCount()
            self.insertRow(i)

            q = NotEditableTableWidgetItem(reg)
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            if context[reg] is not None:
                q = NativeRegisterWidget(reg, context[reg])

                self.setItem(i, 1, q)

                q = NotEditableTableWidgetItem(str(int(context[reg]['value'], 16)))
                q.setForeground(Qt.darkCyan)
                self.setItem(i, 2, q)

                if context[reg]['isValidPointer']:
                    ts = context[reg]['telescope']
                    if ts is not None:
                        if ts[0] == 1:
                            q = MemoryAddressWidget(str(ts[1]))
                        else:
                            q = NotEditableTableWidgetItem(str(ts[1]))
                            q.setFlags(Qt.NoItemFlags)

                        if ts[0] == 0:
                            q.setForeground(Qt.darkGreen)
                        elif ts[0] == 2:
                            q.setForeground(Qt.white)
                        elif ts[0] != 1:
                            q.setForeground(Qt.darkGray)

                        self.setItem(i, 3, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def set_context(self, ptr, context_type, context):
        if context_type == ContextPanel.CONTEXT_TYPE_NATIVE:
            self.__set_native_context(ptr, context)
        elif context_type == ContextPanel.CONTEXT_TYPE_JAVA:
            self.__set_java_context(ptr, context)
        elif context_type == ContextPanel.CONTEXT_TYPE_EMULATOR:
            self.__set_emulator_context(ptr, context)
        else:
            raise Exception('unknown context type')

    def have_context(self):
        return self.rowCount() > 0
