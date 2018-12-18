from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTableWidgetItem


class ContextItem(QTableWidgetItem):
    def __init__(self, context, *__args):
        super().__init__(*__args)

        self.context = context
        self.setFlags(Qt.ItemIsEnabled | Qt.ItemIsEditable)

    def get_context(self):
        return self.context
