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

        self.setHorizontalHeaderLabels(['input', 'address', 'hit'])
        self.verticalHeader().hide()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.cellDoubleClicked.connect(self.hooks_cell_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        menu = QMenu()
        add_action = menu.addAction("Hook address\t(A)")
        on_load_action = menu.addAction("Hook module load\t(O)")

        item = self.itemAt(pos)
        if item is not None:
            item = self.item(self.itemAt(pos).row(), 0)
        is_hook_item = item is not None and isinstance(item, HookWidget) and item.get_hook_data().get_ptr() > 0
        if is_hook_item:
            sep = utils.get_qmenu_separator()
            menu.addAction(sep)

            cond_action = menu.addAction("Condition\t(C)")
            logic_action = menu.addAction("Logic\t(L)")

        action = menu.exec_(self.mapToGlobal(pos))
        if action == add_action:
            self.add_hook()
        elif action == on_load_action:
            self.hook_on_load()
        if is_hook_item:
            if action == cond_action:
                self.set_condition()
            elif action == logic_action:
                self.set_logic()

    def add_hook(self):
        input = InputDialog.input(hint='insert pointer')
        if input[0]:
            ptr = int(self.app.get_script().exports.getpt(input[1]), 16)

            if ptr > 0:
                hook = self.app.get_script().exports.hook(ptr)
                if hook:
                    self.insertRow(self.rowCount())

                    h = Hook()
                    h.set_ptr(ptr)
                    h.set_input(input[1])
                    h.set_widget_row(self.rowCount() - 1)

                    self.hooks[ptr] = h
                    q = HookWidget(h.get_input())
                    q.set_hook_data(h)
                    q.setForeground(Qt.gray)
                    self.setItem(self.rowCount() - 1, 0, q)
                    q = NotEditableTableWidgetItem(hex(ptr))
                    q.setForeground(Qt.red)
                    self.setItem(self.rowCount() - 1, 1, q)
                    q = NotEditableTableWidgetItem('0')
                    self.setItem(self.rowCount() - 1, 2, q)
                    self.resizeColumnsToContents()

    def hook_on_load(self):
        input = InputDialog.input(hint='insert module name')
        if input[0]:
            module = input[1]
            if not module.endswith('.so'):
                module += '.so'

            self.insertRow(self.rowCount())

            h = Hook()
            h.set_ptr(0)
            h.set_input(module)
            h.set_widget_row(self.rowCount() - 1)

            self.onloads[module] = h

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

            self.app.get_script().exports.onload(module)

    def set_condition(self):
        if len(self.selectedItems()) < 1:
            return
        item = self.item(self.selectedItems()[0].row(), 0)

        inp = InputDialog().input('insert condition', input_content=item.get_hook_data().get_condition())
        if inp[0]:
            if self.app.get_script().exports.hookcond(item.get_hook_data().get_ptr(), inp[1]):
                item.get_hook_data().set_condition(inp[1])

    def set_logic(self):
        if len(self.selectedItems()) < 1:
            return
        item = self.item(self.selectedItems()[0].row(), 0)
        inp = InputMultilineDialog().input('insert logic', input_content=item.get_hook_data().get_condition())
        if inp[0]:
            if self.app.get_script().exports.hooklogic(item.get_hook_data().get_ptr(), inp[1]):
                item.get_hook_data().set_condition(inp[1])

    def increment_hook_count(self, ptr):
        if ptr in self.hooks:
            row = self.hooks[ptr].get_widget_row()
            self.item(row, 2).setText(str(int(self.item(row, 2).text()) + 1))
            self.resizeColumnsToContents()

    def reset_hook_count(self):
        for ptr in self.hooks:
            row = self.hooks[ptr].get_widget_row()
            self.item(row, 2).setText('0')
        self.resizeColumnsToContents()

    def hit_onload(self, module, base):
        if module in self.onloads:
            row = self.onloads[module].get_widget_row()
            self.item(row, 1).setText(base)
            self.resizeColumnsToContents()

    def get_hooks(self):
        return self.hooks

    def hooks_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_A:
            self.add_hook()
        elif event.key() == Qt.Key_C:
            self.set_condition()
        elif event.key() == Qt.Key_L:
            self.set_logic()
        elif event.key() == Qt.Key_O:
            self.hook_on_load()
        else:
            # dispatch those to super
            super(HooksPanel, self).keyPressEvent(event)
