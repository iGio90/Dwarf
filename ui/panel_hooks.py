from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu

from ui.dialog_input import InputDialog
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class HooksPanel(QTableWidget):
    def __init__(self, app):
        super().__init__(0, 3)
        self.app = app

        self.hooks = {}

        self.setHorizontalHeaderLabels(['input', 'address', 'hit'])
        self.verticalHeader().hide()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.cellDoubleClicked.connect(self.hooks_cell_double_clicked)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

    def show_menu(self, pos):
        menu = QMenu()
        add_action = menu.addAction("Add\t(A)")
        action = menu.exec_(self.mapToGlobal(pos))
        if action == add_action:
            self.add_hook()

    def add_hook(self):
        input = InputDialog.input(hint='insert pointer (input evaluated)')
        if input[0]:
            ptr = self.app.get_script().exports.getpt(input[1])
            if int(ptr, 16) > 0:
                hook = self.app.get_script().exports.hook(ptr)
                if hook:
                    self.hooks[int(ptr, 16)] = {
                        'input': input[1],
                        'row': self.rowCount()
                    }
                    self.insertRow(self.rowCount())
                    q = NotEditableTableWidgetItem(input[1])
                    q.setForeground(Qt.gray)
                    self.setItem(self.rowCount() - 1, 0, q)
                    q = NotEditableTableWidgetItem(ptr)
                    q.setForeground(Qt.red)
                    self.setItem(self.rowCount() - 1, 1, q)
                    q = NotEditableTableWidgetItem('0')
                    self.setItem(self.rowCount() - 1, 2, q)
                    self.resizeColumnsToContents()

    def increment_hook_count(self, ptr):
        row = self.hooks[ptr]['row']
        self.item(row, 2).setText(str(int(self.item(row, 2).text()) + 1))
        self.resizeColumnsToContents()

    def reset_hook_count(self):
        for ptr in self.hooks:
            row = self.hooks[ptr]['row']
            self.item(row, 2).setText('0')
        self.resizeColumnsToContents()

    def get_hooks(self):
        return self.hooks

    def hooks_cell_double_clicked(self, row, c):
        if c == 0:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_A:
            self.add_hook()