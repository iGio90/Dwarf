from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu

from lib.variable import Variable
from ui.dialog_input import InputDialog
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class VarsPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(0, 2)

        self.app = app

        self.setHorizontalHeaderLabels(['name', 'value'])
        self.verticalHeader().hide()
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_menu)

        self.vars = {}

    def show_menu(self, pos):
        cell = self.itemAt(pos)
        menu = QMenu()
        add_action = menu.addAction("Add\t(A)")
        if cell:
            remove_action = menu.addAction("Delete")
        action = menu.exec_(self.mapToGlobal(pos))
        if action == add_action:
            self.insert_var()
        if cell:
            if action == remove_action:
                self.find_and_remove_row(cell.row())

    def remove_var(self, row):
        k = self.item(row, 0).text()
        self.removeRow(row)
        del self.vars[k]
        self.app.get_script().exports.addvar('%s = %s' % (k, 'null'))

    def append_var(self, var):
        row = self.rowCount()
        self.insertRow(row)
        q = NotEditableTableWidgetItem(var.get_key())
        q.setForeground(Qt.gray)
        self.setItem(row, 0, q)
        q = NotEditableTableWidgetItem(str(var.get_value()))
        if var.get_type() == 0:
            q.setForeground(Qt.red)
        elif var.get_type() == 1:
            q.setForeground(Qt.darkGreen)
        else:
            q.setForeground(Qt.darkCyan)
        self.setItem(row, 1, q)

        self.resizeColumnsToContents()
        return row

    def insert_var(self, input=None):
        if input is None:
            i = InputDialog().input('create global variable')
            if not i[0]:
                return
            input = i[1]
        if input.startswith('var '):
            input = input[4:]
        parts = input.split('=')
        if len(parts) == 2:
            res = self.app.get_script().exports.addvar(input)
            k = parts[0].replace(' ', '')
            if res[0]:
                self.find_and_remove_row(k)
                v = Variable(k, res[0], res[1], input)
                self.vars[k] = v
                self.append_var(v)
            elif k in self.vars:
                self.find_and_remove_row(k)

    def find_and_remove_row(self, var_key):
        if var_key not in self.vars:
            return

        del self.vars[var_key]
        items = self.findItems(var_key, Qt.MatchExactly)
        for item in items:
            self.removeRow(item.row())

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_A:
            self.insert_var()

    def get_vars(self):
        return self.vars
