from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget, QMenu

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
            self.trigger_insert_var()
        if cell:
            if action == remove_action:
                print(cell.row())
                self.remove_var(cell.row())

    def remove_var(self, row):
        k = self.item(row, 0).text()
        self.removeRow(row)
        del self.vars[k]
        self.app.get_script().exports.addvar('%s = %s' % (k, 'null'))

    def append_var(self, key, var, type):
        row = self.rowCount()
        self.insertRow(row)
        q = NotEditableTableWidgetItem(key)
        q.setForeground(Qt.gray)
        self.setItem(row, 0, q)
        q = NotEditableTableWidgetItem(str(var))
        if type == 0:
            q.setForeground(Qt.red)
        elif type == 1:
            q.setForeground(Qt.darkGreen)
        else:
            q.setForeground(Qt.darkCyan)
        self.setItem(row, 1, q)

        self.resizeColumnsToContents()
        return row

    def trigger_insert_var(self):
        i = InputDialog().input('create global variable')
        if i[0]:
            content = i[1]
            if content.startswith('var '):
                content = content[4:]
            parts = content.split('=')
            if len(parts) == 2:
                res = self.app.get_script().exports.addvar(content)
                k = parts[0].replace(' ', '')
                if res[0]:
                    if k in self.vars:
                        self.removeRow(self.vars[k][1])
                    row = self.append_var(k, res[0], res[1])
                    self.vars[k] = [
                        res[0], row
                    ]
                elif k in self.vars:
                    self.remove_var(self.vars[k][1])

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_A:
            self.trigger_insert_var()
