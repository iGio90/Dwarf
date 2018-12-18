from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class RegistersPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.verticalHeader().hide()
        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cellDoubleClicked.connect(self.register_cell_double_clicked)

    def set_context(self, context):
        self.setRowCount(0)
        i = 0
        for reg in context:
            self.insertRow(i)
            q = NotEditableTableWidgetItem(reg)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)
            q = NotEditableTableWidgetItem(context[reg])
            q.setForeground(Qt.red)
            self.setItem(i, 1, q)
            q = NotEditableTableWidgetItem(str(int(context[reg], 16)))
            q.setForeground(Qt.darkCyan)
            self.setItem(i, 2, q)
            data = self.app.get_script().exports.ts(context[reg])
            q = NotEditableTableWidgetItem(str(data[1]))
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

    def register_cell_double_clicked(self, row, c):
        if c == 1:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())
