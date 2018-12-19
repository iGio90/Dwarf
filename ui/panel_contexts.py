from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidget

from ui.widget_context import ContextItem
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ContextsPanel(QTableWidget):
    def __init__(self, app, *__args):
        super().__init__(*__args)
        self.app = app

        self.setHorizontalHeaderLabels(['tid', 'pc', 'sym'])
        self.verticalHeader().hide()
        self.itemDoubleClicked.connect(self.on_context_item_double_click)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

    def add_context(self, data, library_onload=None):
        row = self.rowCount()
        self.insertRow(row)
        q = ContextItem(data, str(data['tid']))
        q.setForeground(Qt.darkCyan)
        self.setItem(row, 0, q)
        q = NotEditableTableWidgetItem(data['context']['pc'])
        q.setForeground(Qt.red)
        self.setItem(row, 1, q)
        if library_onload is None:
            q = NotEditableTableWidgetItem('%s - %s' % (
                data['symbol']['moduleName'], data['symbol']['name']))
        else:
            q = NotEditableTableWidgetItem('loading %s' % library_onload)

        q.setForeground(Qt.gray)
        self.setItem(row, 2, q)
        self.resizeColumnsToContents()

    def on_context_item_double_click(self, item):
        self.app.apply_context(self.item(item.row(), 0).get_context())
