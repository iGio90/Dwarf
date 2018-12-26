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

from lib import utils
from lib.hook import Hook
from ui.dialog_input import InputDialog
from ui.dialog_input_multiline import InputMultilineDialog
from ui.widget_hook import HookWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class HooksPanel(QTableWidget):
    def __init__(self, app):
        super().__init__(0, 3)
        self.app = app

        self.hooks = {}
        self.onloads = {}
        self.java_hooks = {}

        self.temporary_input = ''
        self.native_pending_args = None
        self.java_pending_args = None

        self.setHorizontalHeaderLabels(['input', 'address', 'hit'])
        self.verticalHeader().hide()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.cellDoubleClicked.connect(self.hooks_cell_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        menu = QMenu()
        add_action = menu.addAction("Native\t(N)")
        hook_java_action = menu.addAction("Java\t(J)")
        on_load_action = menu.addAction("Module load\t(O)")

        item = self.itemAt(pos)
        if item is not None:
            item = self.item(self.itemAt(pos).row(), 0)
        is_hook_item = item is not None and isinstance(item, HookWidget) and item.get_hook_data().ptr > 0
        if is_hook_item:
            sep = utils.get_qmenu_separator()
            menu.addAction(sep)

            cond_action = menu.addAction("Condition\t(C)")
            logic_action = menu.addAction("Logic\t(L)")

        action = menu.exec_(self.mapToGlobal(pos))
        if action == add_action:
            self.hook_native()
        elif action == on_load_action:
            self.hook_onload()
        elif action == hook_java_action:
            self.hook_java()
        if is_hook_item:
            if action == cond_action:
                self.set_condition()
            elif action == logic_action:
                self.set_logic()

    def hook_native(self, input=None, pending_args=None):
        if input is None or not isinstance(input, str):
            input = InputDialog.input(hint='insert pointer')
            if not input[0]:
                return
            input = input[1]

        ptr = int(self.app.dwarf_api('evaluatePtr', input), 16)
        if ptr > 0:
            self.temporary_input = input
            self.native_pending_args = pending_args
            self.app.dwarf_api('hookNative', ptr)

    def hook_native_callback(self, ptr):
        self.insertRow(self.rowCount())

        h = Hook()
        h.set_ptr(ptr)
        h.set_input(self.temporary_input)
        if self.native_pending_args:
            h.set_condition(self.native_pending_args['condition'])
            h.set_logic(self.native_pending_args['logic'])

        self.hooks[ptr] = h
        q = HookWidget(h.get_input())
        q.set_hook_data(h)
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 0, q)
        q = NotEditableTableWidgetItem(hex(ptr))
        q.setForeground(Qt.red)
        self.setItem(self.rowCount() - 1, 1, q)
        q = NotEditableTableWidgetItem('0')
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 2, q)
        self.resizeRowToContents(0)
        self.resizeRowToContents(1)

    def hook_onload(self, input=None):
        if input is None or not isinstance(input, str):
            input = InputDialog.input(hint='insert module name')
            if not input[0]:
                return
            input = input[1]

        if not input.endswith('.so'):
            input += '.so'

        if input in self.onloads:
            return

        self.insertRow(self.rowCount())

        h = Hook()
        h.set_ptr(0)
        h.set_input(input)

        self.onloads[input] = h

        q = HookWidget(h.get_input())
        q.set_hook_data(h)
        q.setForeground(Qt.darkGreen)
        self.setItem(self.rowCount() - 1, 0, q)
        q = NotEditableTableWidgetItem(hex(0))
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 1, q)
        q = NotEditableTableWidgetItem('-')
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 2, q)

        self.app.dwarf_api('hookOnLoad', input)
        self.resizeRowToContents(0)
        self.resizeRowToContents(1)

    def hook_java(self, input=None, pending_args=None):
        if input is None or not isinstance(input, str):
            input = InputDialog.input(hint='com.package.class.[method or \'$new\']')
            if not input[1]:
                return
            input = input[1]
        self.java_pending_args = pending_args
        self.app.dwarf_api('hookJavaMethod', input)

    def hook_java_callback(self, class_method):
        self.insertRow(self.rowCount())

        h = Hook()
        h.set_ptr(1)
        h.set_input(class_method)
        if self.java_pending_args:
            h.set_condition(self.java_pending_args['condition'])
            h.set_logic(self.java_pending_args['logic'])

        parts = class_method.split('.')
        self.java_hooks[class_method] = h
        q = HookWidget('.'.join(parts[:len(parts)-1]))
        q.set_hook_data(h)
        q.setForeground(Qt.darkYellow)
        self.setItem(self.rowCount() - 1, 0, q)
        q = NotEditableTableWidgetItem(parts[len(parts) - 1])
        self.setItem(self.rowCount() - 1, 1, q)
        q = NotEditableTableWidgetItem('0')
        q.setForeground(Qt.gray)
        self.setItem(self.rowCount() - 1, 2, q)

        self.resizeRowToContents(0)
        self.resizeRowToContents(1)

    def set_condition(self):
        if len(self.selectedItems()) < 1:
            return
        item = self.item(self.selectedItems()[0].row(), 0)

        inp = InputDialog().input('insert condition', input_content=item.get_hook_data().get_condition())
        if inp[0]:
            if self.app.dwarf_api('setHookCondition', [item.get_hook_data().get_ptr(), inp[1]]):
                item.get_hook_data().set_condition(inp[1])

    def set_logic(self):
        if len(self.selectedItems()) < 1:
            return
        item = self.item(self.selectedItems()[0].row(), 0)
        inp = InputMultilineDialog().input('insert logic', input_content=item.get_hook_data().get_logic())
        if inp[0]:
            if self.app.dwarf_api('setHookLogic', [item.get_hook_data().get_ptr(), inp[1]]):
                item.get_hook_data().set_logic(inp[1])

    def increment_hook_count(self, ptr):
        items = self.findItems(ptr, Qt.MatchExactly)
        for item in items:
            self.item(item.row(), 2).setText(str(int(self.item(item.row(), 2).text()) + 1))

    def reset_hook_count(self):
        for ptr in self.hooks:
            items = self.findItems(ptr, Qt.MatchExactly)
            for item in items:
                self.item(item.row(), 2).setText('0')

    def hit_onload(self, module, base):
        if module in self.onloads:
            items = self.findItems(module, Qt.MatchExactly)
            for item in items:
                self.item(item.row(), 1).setText(base)

    def hooks_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_N:
            self.hook_native()
        elif event.key() == Qt.Key_C:
            self.set_condition()
        elif event.key() == Qt.Key_L:
            self.set_logic()
        elif event.key() == Qt.Key_O:
            self.hook_onload()
        elif event.key() == Qt.Key_J:
            self.hook_java()
        else:
            # dispatch those to super
            super(HooksPanel, self).keyPressEvent(event)

    def get_hooks(self):
        return self.hooks

    def get_java_hooks(self):
        return self.java_hooks

    def get_onloads(self):
        return self.onloads
