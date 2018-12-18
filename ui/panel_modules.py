from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ModulesPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalHeaderLabels(['name', 'base', 'size'])
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cellDoubleClicked.connect(self.modules_cell_double_clicked)

    def set_modules(self, modules):
        self.setRowCount(0)
        i = 0
        for module in sorted(modules, key=lambda x: x['name']):
            self.insertRow(i)
            q = NotEditableTableWidgetItem(module['name'])
            q.setForeground(Qt.gray)
            self.setItem(i, 0, NotEditableTableWidgetItem(q))
            q = NotEditableTableWidgetItem(module['base'])
            q.setForeground(Qt.red)
            self.setItem(i, 1, q)
            q = NotEditableTableWidgetItem(str(module['size']))
            self.setItem(i, 2, q)
            i += 1
        self.resizeColumnToContents(1)

    def modules_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())
