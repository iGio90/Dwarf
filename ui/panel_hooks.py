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
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QTextEdit, QLabel

from lib.hook import Hook
from ui.dialog_input import InputDialog
from ui.dialog_input_multiline import InputMultilineDialog
from ui.widget_hook import HookWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_table_base import TableBaseWidget


class HooksPanel(TableBaseWidget):
    def __init__(self, app):
        super().__init__(app, 0, 0)

    def set_menu_actions(self, item, menu):
        native = menu.addAction("Native\t(N)")
        native.setData('native')

        if self.app.get_dwarf().java_available:
            java = menu.addAction("Java\t(J)")
            java.setData('java')
            on_load = menu.addAction("Module load\t(O)")
            on_load.setData('onload')

        if item is not None:
            item = self.item(item.row(), 0)
        is_hook_item = item is not None and isinstance(item, HookWidget)
        if is_hook_item:
            menu.addSeparator()

            if item.get_hook_data().ptr > 0:
                # is either a native or java hook
                cond = menu.addAction("Condition")
                cond.setData('condition')
                logic = menu.addAction("Logic")
                logic.setData('logic')

                menu.addSeparator()

            delete = menu.addAction("Delete")
            delete.setData('delete')

    def on_menu_action(self, action_data, item):
        if action_data == 'native':
            self.hook_native()
            return False
        elif action_data == 'java':
            self.hook_java()
            return False
        elif action_data == 'onload':
            self.hook_onload()
            return False
        elif action_data == 'delete':
            self.delete_hook(item, self.item(item.row(), 0).get_hook_data())
            return False
        elif action_data == 'logic':
            self.set_logic(item)
            return False
        elif action_data == 'condition':
            self.set_condition(item)
            return False
        return True

    def hook_native_callback(self, hook):
        if self.columnCount() == 0:
            self.setColumnCount(2)
            self.setHorizontalHeaderLabels(['input', 'address'])

        self.insertRow(self.rowCount())

        q = HookWidget(hook.get_input())
        q.set_hook_data(hook)
        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 0, q)
        q = MemoryAddressWidget(hex(hook.get_ptr()))
        self.setItem(self.rowCount() - 1, 1, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def hook_onload_callback(self, input=None):
        if self.columnCount() == 0:
            self.setColumnCount(2)
            self.setHorizontalHeaderLabels(['input', 'address'])

        h = self.app.get_dwarf().hook_onload(input)

        self.insertRow(self.rowCount())
        q = HookWidget(h.get_input())
        q.set_hook_data(h)
        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.darkGreen)
        self.setItem(self.rowCount() - 1, 0, q)
        q = NotEditableTableWidgetItem(hex(0))
        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 1, q)

        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def hook_java_callback(self, hook):
        if self.columnCount() == 0:
            self.setColumnCount(2)
            self.setHorizontalHeaderLabels(['input', 'address'])

        self.insertRow(self.rowCount())

        parts = hook.get_input().split('.')
        q = HookWidget('.'.join(parts[:len(parts)-1]))
        q.set_hook_data(hook)
        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.darkYellow)
        self.setItem(self.rowCount() - 1, 0, q)
        q = NotEditableTableWidgetItem(parts[len(parts) - 1])
        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.white)
        self.setItem(self.rowCount() - 1, 1, q)

        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def set_condition(self, item):
        item = self.item(item.row(), 0)
        accept, input = InputDialog().input(
            self.app, 'insert condition', input_content=item.get_hook_data().get_condition())
        if accept:
            what = item.get_hook_data().get_ptr()
            if what == 0:
                what = item.get_hook_data().get_input()
            if self.app.dwarf_api('setHookCondition', [what, input]):
                item.get_hook_data().set_condition(input)

    def set_logic(self, item):
        item = self.item(item.row(), 0)
        inp = InputMultilineDialog().input(
            'insert logic', input_content=item.get_hook_data().get_logic())

        what = item.get_hook_data().get_ptr()
        if what == 0:
            what = item.get_hook_data().get_input()
        if self.app.dwarf_api('setHookLogic', [what, inp[1]]):
            item.get_hook_data().set_logic(inp[1])

    def hit_onload(self, module, base):
        if module in self.app.get_dwarf().on_loads:
            items = self.findItems(module, Qt.MatchExactly)
            for item in items:
                self.item(item.row(), 1).setText(base)

    def delete_hook(self, item, hook):
        self.removeRow(item.row())
        if hook.hook_type == Hook.HOOK_NATIVE:
            self.app.dwarf_api('deleteHook', hook.get_ptr())
        elif hook.hook_type == Hook.HOOK_JAVA:
            self.app.dwarf_api('deleteHook', hook.get_input())
        elif hook.hook_type == Hook.HOOK_ONLOAD:
            self.app.dwarf_api('deleteHook', hook.get_input())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_N:
            self.hook_native()
        if self.app.get_dwarf().java_available:
            if event.key() == Qt.Key_O:
                self.hook_onload()
            elif event.key() == Qt.Key_J:
                self.hook_java()
        super(HooksPanel, self).keyPressEvent(event)
