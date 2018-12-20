from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class RangesPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.verticalHeader().hide()
        self.horizontalScrollBar().hide()
        self.setShowGrid(False)
        self.setHorizontalHeaderLabels(['base', 'size', 'protection', 'file'])
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cellDoubleClicked.connect(self.ranges_cell_double_clicked)

    def set_ranges(self, ranges):
        self.setRowCount(0)
        i = 0
        for range in sorted(ranges, key=lambda x: x['base'], reverse=True):
            self.insertRow(i)
            q = NotEditableTableWidgetItem(range['base'])
            q.setForeground(Qt.red)
            self.setItem(i, 0, q)
            self.setItem(i, 1, NotEditableTableWidgetItem(str(range['size'])))
            self.setItem(i, 2, NotEditableTableWidgetItem(range['protection']))
            if 'file' in range:
                q = NotEditableTableWidgetItem(range['file']['path'])
                q.setForeground(Qt.gray)
                self.setItem(i, 3, q)
            else:
                self.setItem(i, 3, NotEditableTableWidgetItem(''))
            i += 1
        self.resizeRowToContents(1)

    def ranges_cell_double_clicked(self, row, c):
        if c == 0:
            self.app.get_memory_panel().read_memory(self.item(row, c).text())
