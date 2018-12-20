from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class BacktracePanel(QTableWidget):
    def __init__(self, *__args):
        super().__init__(0, 2)

        self.verticalHeader().hide()
        self.setHorizontalHeaderLabels(['symbol', 'address'])

    def set_backtrace(self, bt):
        self.setRowCount(0)
        self.setHorizontalHeaderLabels(['symbol', 'address'])
        if type(bt) is list:
            # native hook
            for a in bt:
                row = self.rowCount()
                self.insertRow(row)

                name = a['name']
                if name is None:
                    q = NotEditableTableWidgetItem('-')
                    q.setForeground(Qt.gray)
                    self.setItem(row, 0, q)
                else:
                    q = NotEditableTableWidgetItem(name)
                    q.setForeground(Qt.darkGreen)
                    self.setItem(row, 0, q)
                q = NotEditableTableWidgetItem(a['address'])
                q.setForeground(Qt.red)
                self.setItem(row, 1, q)
            self.resizeRowToContents(1)
        elif type(bt) is str:
            self.setHorizontalHeaderLabels(['method', 'source'])
            parts = bt.split('\n')
            for i in range(0, len(parts)):
                if i == 0:
                    continue
                p = parts[i].replace('\t', '')
                p = p.split('(')
                if len(p) != 2:
                    continue

                row = self.rowCount()
                self.insertRow(row)

                q = NotEditableTableWidgetItem(p[0])
                q.setForeground(Qt.darkYellow)
                self.setItem(row, 0, q)

                q = NotEditableTableWidgetItem(p[1].replace(')', ''))
                q.setForeground(Qt.gray)
                self.setItem(row, 1, q)
            self.resizeRowToContents(1)
